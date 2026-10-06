// Hermetic tests for the live-demo seed (B4): gating, refusal, idempotence and
// the execution adapter against a fake chain that applies every sent
// transaction. No live RPC, no devnet, no demo-api, no GTK.
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, verify as ed25519Verify } from "node:crypto";
import { execFile } from "node:child_process";
import { once } from "node:events";
import { createServer, type Server } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type { Address, ReadonlyUint8Array } from "@solana/kit";
import { registryIdHash, toHex } from "../../../packages/canonical-ts/src/index.ts";
import {
  CREATE_LEDGER_SEGMENT_DISCRIMINATOR,
  GRANT_OPERATOR_DISCRIMINATOR,
  INITIALIZE_REGISTRY_DISCRIMINATOR,
  getCreateLedgerSegmentInstructionDataDecoder,
  getDailyAnchorLedgerSegmentEncoder,
  getGrantOperatorInstructionDataDecoder,
  getInitializeRegistryInstructionDataDecoder,
  getOperatorRoleEncoder,
  getRegistryConfigEncoder,
} from "../../../packages/onchain-client/src/index.ts";
import {
  DEVNET_GENESIS_HASH,
  derivePdas,
  PROGRAM_ID,
  REGISTRY_ID,
  REQUIRED_OPERATOR_PERMISSIONS,
} from "../../../apps/demo-api/scripts/live-demo-registry.ts";
import { ensureKeyPair, persistentKeyRoot } from "../../../apps/demo-api/scripts/live-demo-key-store.ts";
import {
  kit,
  loadSeedSigner,
  SeedRefusal,
  toAddress,
  type SeedChain,
  type SeedSigner,
} from "./live-demo-seed-kit.ts";
import {
  actionGate,
  buildInstructionForAction,
  MAX_FUNDING_LAMPORTS,
  prepareDemoChain,
  type PrepareOptions,
} from "./live-demo-seed-executor.ts";

const run = promisify(execFile);
const CLI = fileURLToPath(new URL("./live-demo-seed-cli.ts", import.meta.url));
const NODE_ARGS = ["--experimental-transform-types", "--disable-warning=ExperimentalWarning"];

interface CliOutcome {
  code: number;
  stdout: string;
  stderr: string;
}

/** Runs the seed CLI and normalizes the exit code onto one outcome shape. */
async function runCli(args: readonly string[], env: NodeJS.ProcessEnv): Promise<CliOutcome> {
  try {
    const result = await run(process.execPath, [...args], { env });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    const failure = error as { code?: number | string; stdout?: string; stderr?: string };
    return {
      code: typeof failure.code === "number" ? failure.code : 1,
      stdout: failure.stdout ?? "",
      stderr: failure.stderr ?? "",
    };
  }
}

const DAY = 20261006;
const NOW = new Date("2026-10-06T12:00:00Z");

function addr(fill: number): Address {
  return kit.getAddressDecoder().decode(new Uint8Array(32).fill(fill));
}

function keypairBytesFor(fill: number): Uint8Array {
  const keypair = new Uint8Array(64);
  keypair.set(new Uint8Array(32).fill(fill), 0);
  const secret = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), keypair.subarray(0, 32)]),
    format: "der",
    type: "pkcs8",
  });
  const publicDer = createPublicKey(secret).export({ format: "der", type: "spki" });
  keypair.set(new Uint8Array(publicDer).slice(-32), 32);
  return keypair;
}

/** Decodes one compiled message and narrows it to the v0 shape the program uses. */
function compiledMessageV0(bytes: ReadonlyUint8Array) {
  const message = kit.getCompiledTransactionMessageDecoder().decode(Uint8Array.from(bytes));
  if (message.version !== 0) {
    throw new Error(`expected a v0 compiled message, saw ${String(message.version)}`);
  }
  return message;
}

const GOVERNANCE = String(addr(22));

let home = "";
let signer: SeedSigner;
let OPERATOR = "";

before(async () => {
  home = await mkdtemp(path.join(tmpdir(), "onelayer-seed-home-"));
  const keypair = keypairBytesFor(7);
  const ensured = await ensureKeyPair({ home, keypair });
  OPERATOR = ensured.address;
  signer = await loadSeedSigner(ensured.path, { home });
});

after(async () => {
  await rm(home, { recursive: true, force: true });
});

function configAccount(
  governance: string,
  paused = false,
  idHash: Uint8Array = registryIdHash(REGISTRY_ID),
): { owner: string; data: Uint8Array } {
  return {
    owner: String(PROGRAM_ID),
    data: Buffer.from(
      getRegistryConfigEncoder().encode({
        version: 1,
        bump: 255,
        registryIdHash: idHash,
        governanceAuthority: toAddress(governance),
        emergencyAuthority: toAddress(governance),
        currentBatchSequence: 1,
        currentRegistryVersion: 1,
        lastAnchorHash: new Uint8Array(32),
        incidentCount: 0,
        schemaVersion: 1,
        hashAlgorithm: 1,
        treeAlgorithm: 1,
        anchorIntervalSeconds: 60,
        maxEntriesPerDay: 1000,
        paused,
        createdAt: 0,
        reserved: new Uint8Array(96),
      }),
    ),
  };
}

function roleAccount(registry: string, operator: string, permissions: number): { owner: string; data: Uint8Array } {
  return {
    owner: String(PROGRAM_ID),
    data: Buffer.from(
      getOperatorRoleEncoder().encode({
        version: 1,
        bump: 255,
        registry: toAddress(registry),
        operator: toAddress(operator),
        permissions,
        validFrom: 0n,
        validUntil: 0n,
        revokedAt: 0n,
        keyIdHash: new Uint8Array(32),
        reserved: new Uint8Array(32),
      }),
    ),
  };
}

const ENTRY = {
  batchSequence: 0n,
  registryVersion: 0n,
  sourceCursorStart: 0n,
  sourceCursorEnd: 0n,
  merkleRoot: new Uint8Array(32),
  manifestHash: new Uint8Array(32),
  snapshotHash: new Uint8Array(32),
  previousAnchorHash: new Uint8Array(32),
  leafCount: 0,
  schemaVersion: 1,
  flags: 0,
  hashAlgorithm: 1,
  treeAlgorithm: 1,
  pad0: new Uint8Array(6),
  operator: toAddress(addr(1)),
  publishedAt: 0n,
};

function segmentAccount(
  registry: string,
  dayUtc: number,
  index: number,
  state: { sealed?: number; entryCount?: number; capacity?: number } = {},
): { owner: string; data: Uint8Array } {
  return {
    owner: String(PROGRAM_ID),
    data: Buffer.from(
      getDailyAnchorLedgerSegmentEncoder().encode({
        version: 1,
        bump: 255,
        sealed: state.sealed ?? 0,
        pad0: 0,
        registry: toAddress(registry),
        dayUtc,
        segmentIndex: index,
        entryCount: state.entryCount ?? 0,
        capacity: state.capacity ?? 46,
        pad1: new Uint8Array(2),
        createdAt: 0,
        sealedAt: 0,
        entriesHash: new Uint8Array(32),
        entries: Array.from({ length: 46 }, () => ENTRY),
      }),
    ),
  };
}

/**
 * A hermetic fake chain that records every mutation and *applies* the sent
 * transactions to its account/balance state, so rechecks, idempotence and
 * duplicate prevention are exercised against moving state.
 */
class ApplyingFakeChain implements SeedChain {
  accounts = new Map<string, { owner: string; data: Uint8Array }>();
  balances = new Map<string, bigint>();
  rent = 2_000_000n;
  genesis = DEVNET_GENESIS_HASH;
  health = "ok";
  sent: string[] = [];
  airdrops: Array<{ address: string; lamports: bigint }> = [];
  /** Confirmation status every polled signature reports. */
  signatureStatus: { confirmationStatus?: string; err?: unknown } | null = {
    confirmationStatus: "finalized",
    err: null,
  };
  /** When set, `sendTransaction` refuses with this code (RPC writer failure). */
  sendFailure: string | null = null;

  mutations(): number {
    return this.sent.length + this.airdrops.length;
  }

  async getGenesisHash(): Promise<string> {
    return this.genesis;
  }

  async getHealth(): Promise<string> {
    return this.health;
  }

  async getAccountInfo(account: string): Promise<{ owner: string; data: Uint8Array } | null> {
    return this.accounts.get(account) ?? null;
  }

  async getBalanceLamports(account: string): Promise<bigint> {
    return this.balances.get(account) ?? 0n;
  }

  async getMinimumBalanceForRentExemption(_dataLength = 0): Promise<bigint> {
    return this.rent;
  }

  async getLatestBlockhash(): Promise<{ blockhash: string; lastValidBlockHeight: bigint }> {
    return { blockhash: String(addr(3)), lastValidBlockHeight: 1_000n };
  }

  async sendTransaction(transactionBase64: string): Promise<string> {
    if (this.sendFailure !== null) throw new SeedRefusal(this.sendFailure);
    this.sent.push(transactionBase64);
    this.apply(transactionBase64);
    return `sig-${this.sent.length}`;
  }

  async getSignatureStatuses(signatures: string[]): Promise<Array<{ confirmationStatus?: string; err?: unknown } | null>> {
    return signatures.map(() => this.signatureStatus);
  }

  async requestAirdrop(address: string, lamports: bigint): Promise<string> {
    this.airdrops.push({ address, lamports });
    this.balances.set(address, (this.balances.get(address) ?? 0n) + lamports);
    return `air-${this.airdrops.length}`;
  }

  apply(transactionBase64: string): void {
    const transaction = kit.getTransactionDecoder().decode(Buffer.from(transactionBase64, "base64"));
    const message = compiledMessageV0(transaction.messageBytes);
    const feePayer = message.staticAccounts[0];
    const [instruction] = message.instructions;
    const at = (index: number): string => String(message.staticAccounts[index]);
    const data = Buffer.from(instruction.data ?? []);
    const discriminator = data.subarray(0, 8);
    if (discriminator.equals(Buffer.from(INITIALIZE_REGISTRY_DISCRIMINATOR))) {
      const args = getInitializeRegistryInstructionDataDecoder().decode(data);
      this.accounts.set(at(instruction.accountIndices![0]), {
        owner: String(PROGRAM_ID),
        data: Buffer.from(
          getRegistryConfigEncoder().encode({
            version: 1,
            bump: 255,
            registryIdHash: new Uint8Array(args.registryIdHash),
            governanceAuthority: toAddress(feePayer),
            emergencyAuthority: args.emergencyAuthority,
            currentBatchSequence: 0n,
            currentRegistryVersion: 0n,
            lastAnchorHash: new Uint8Array(32),
            incidentCount: 0,
            schemaVersion: args.schemaVersion,
            hashAlgorithm: args.hashAlgorithm,
            treeAlgorithm: args.treeAlgorithm,
            anchorIntervalSeconds: args.anchorIntervalSeconds,
            maxEntriesPerDay: args.maxEntriesPerDay,
            paused: false,
            createdAt: 0n,
            reserved: new Uint8Array(96),
          }),
        ),
      });
      return;
    }
    if (discriminator.equals(Buffer.from(GRANT_OPERATOR_DISCRIMINATOR))) {
      const args = getGrantOperatorInstructionDataDecoder().decode(data);
      this.accounts.set(at(instruction.accountIndices![1]), {
        owner: String(PROGRAM_ID),
        data: Buffer.from(
          getOperatorRoleEncoder().encode({
            version: 1,
            bump: 255,
            registry: toAddress(at(instruction.accountIndices![0])),
            operator: toAddress(at(instruction.accountIndices![2])),
            permissions: args.permissions,
            validFrom: BigInt(args.validFrom),
            validUntil: BigInt(args.validUntil),
            revokedAt: 0n,
            keyIdHash: new Uint8Array(args.keyIdHash),
            reserved: new Uint8Array(32),
          }),
        ),
      });
      return;
    }
    if (discriminator.equals(Buffer.from(CREATE_LEDGER_SEGMENT_DISCRIMINATOR))) {
      const args = getCreateLedgerSegmentInstructionDataDecoder().decode(data);
      this.accounts.set(at(instruction.accountIndices![3]), {
        owner: String(PROGRAM_ID),
        data: Buffer.from(
          getDailyAnchorLedgerSegmentEncoder().encode({
            version: 1,
            bump: 255,
            sealed: 0,
            pad0: 0,
            registry: toAddress(at(instruction.accountIndices![0])),
            dayUtc: args.dayUtc,
            segmentIndex: args.segmentIndex,
            entryCount: 0,
            capacity: args.capacity,
            pad1: new Uint8Array(2),
            createdAt: 0,
            sealedAt: 0,
            entriesHash: new Uint8Array(32),
            entries: Array.from({ length: 46 }, () => ENTRY),
          }),
        ),
      });
      return;
    }
    throw new Error(`unexpected instruction discriminator ${discriminator.toString("hex")}`);
  }
}

function fakeFetch(): typeof fetch {
  return (async (url: unknown) => {
    const target = String(url);
    if (!target.endsWith("/v1/health")) throw new Error(`unexpected url ${target}`);
    return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
  }) as typeof fetch;
}

function optionsFor(chain: ApplyingFakeChain, extra: Partial<PrepareOptions> = {}): PrepareOptions {
  return {
    chain,
    request: fakeFetch(),
    dayUtc: DAY,
    now: NOW,
    keyStore: { home },
    prepare: false,
    signer,
    ...extra,
  };
}

async function provision(
  options: { governance?: string; config?: boolean; grantRole?: boolean; segment?: boolean; balance?: bigint } = {},
): Promise<ApplyingFakeChain> {
  const chain = new ApplyingFakeChain();
  const pdas = await derivePdas(OPERATOR, DAY);
  if (options.config !== false) {
    chain.accounts.set(String(pdas.configPda), configAccount(options.governance ?? GOVERNANCE));
  }
  if (options.grantRole === true) {
    chain.accounts.set(
      String(pdas.operatorRolePda),
      roleAccount(String(pdas.configPda), OPERATOR, REQUIRED_OPERATOR_PERMISSIONS),
    );
  }
  if (options.segment === true) {
    chain.accounts.set(String(pdas.segments[0].pda), segmentAccount(String(pdas.configPda), DAY, 0));
  }
  chain.balances.set(OPERATOR, options.balance ?? 10_000_000n);
  return chain;
}

test("gating: without --prepare the seed is assessment only and mutates nothing", async () => {
  const chain = await provision({ config: false });
  const report = await prepareDemoChain(optionsFor(chain));
  assert.equal(report.prepared, false);
  assert.equal(report.mutations, 0);
  assert.equal(chain.mutations(), 0);
  assert.equal(report.refusal, null);
  assert.equal(report.ok, false);
  const registry = report.steps.find((step) => step.id === "registry");
  assert.equal(registry?.action?.kind, "initialize_registry");
});

test("refusal: a missing governance authority fails before any chain mutation", async () => {
  const chain = await provision({ governance: GOVERNANCE, grantRole: false });
  const report = await prepareDemoChain(optionsFor(chain, { prepare: true }));
  assert.equal(report.refusal?.code, "GOVERNANCE_KEY_UNAVAILABLE");
  assert.equal(report.mutations, 0);
  assert.equal(chain.mutations(), 0, "nothing is sent, signed or airdropped");
  assert.equal(report.ok, false);
  assert.match(String(report.refusal?.detail), /nothing is substituted/);
});

test("refusal: a local key that is not the expected authority is never substituted", () => {
  const mismatched = actionGate(
    {
      kind: "grant_operator",
      requiredSigner: { role: "governance", address: GOVERNANCE },
      args: {},
    },
    signer,
  );
  assert.equal(mismatched?.code, "GOVERNANCE_KEY_UNAVAILABLE");
  const missing = actionGate(
    {
      kind: "grant_operator",
      requiredSigner: { role: "governance", address: GOVERNANCE },
      args: {},
    },
    null,
  );
  assert.equal(missing?.code, "GOVERNANCE_KEY_UNAVAILABLE");
  const allowed = actionGate(
    {
      kind: "grant_operator",
      requiredSigner: { role: "governance", address: OPERATOR },
      args: {},
    },
    signer,
  );
  assert.equal(allowed, null);
  // Funding carries A2's funder signer (the governance authority) and is
  // gated exactly like every other planned action.
  const funded = actionGate(
    {
      kind: "fund_operator",
      requiredSigner: { role: "funder", address: GOVERNANCE },
      args: {},
    },
    signer,
  );
  assert.equal(funded?.code, "GOVERNANCE_KEY_UNAVAILABLE");
  const fundedByUs = actionGate(
    {
      kind: "fund_operator",
      requiredSigner: { role: "funder", address: OPERATOR },
      args: {},
    },
    signer,
  );
  assert.equal(fundedByUs, null);
});

test("refusal: a funding-only shortfall under a lost authority mutates nothing", async () => {
  // The reviewed case: the registry is initialized and the operator role is
  // granted under a governance key that is permanently lost, the ledger
  // segment is open, and the operator balance is zero. Funding is then the
  // only pending action and its planned signer is that lost authority — so
  // the run must refuse before any chain mutation, faucet credits included.
  const chain = await provision({ governance: GOVERNANCE, grantRole: true, segment: true, balance: 0n });
  const report = await prepareDemoChain(optionsFor(chain, { prepare: true }));
  assert.equal(report.refusal?.code, "GOVERNANCE_KEY_UNAVAILABLE");
  assert.equal(report.mutations, 0);
  assert.equal(report.mutationsAttempted, 0);
  assert.equal(report.mutationsBroadcast, 0);
  assert.equal(chain.mutations(), 0, "nothing is sent, signed or airdropped");
  assert.equal(chain.airdrops.length, 0, "the faucet is never touched");
  assert.equal(report.ok, false);
});

test("counters: a broadcast transaction whose confirmation fails is still a reported mutation", async () => {
  const chain = await provision({ config: false, grantRole: false, balance: 10_000_000n });
  chain.signatureStatus = { confirmationStatus: "confirmed", err: { custom: 42 } };
  const report = await prepareDemoChain(optionsFor(chain, { prepare: true }));
  assert.equal(report.refusal?.code, "TRANSACTION_FAILED");
  assert.equal(report.mutations, 1);
  assert.equal(report.mutationsAttempted, 1);
  assert.equal(report.mutationsBroadcast, 1);
  assert.equal(report.mutationsFinalized, 0);
  assert.equal(chain.sent.length, 1, "the initialize transaction was broadcast");
  const step = report.steps.find((entry) => entry.id === "registry");
  assert.ok(step?.signatures.includes("sig-1"), "the broadcast signature is reported");
});

test("counters: a faucet credit whose confirmation fails is still a reported mutation", async () => {
  const chain = await provision({ governance: OPERATOR, grantRole: true, segment: true, balance: 0n });
  chain.signatureStatus = { confirmationStatus: "confirmed", err: { custom: 7 } };
  const report = await prepareDemoChain(optionsFor(chain, { prepare: true }));
  assert.equal(report.refusal?.code, "TRANSACTION_FAILED");
  assert.equal(report.mutations, 1);
  assert.equal(report.mutationsAttempted, 1);
  assert.equal(report.mutationsBroadcast, 1);
  assert.equal(report.mutationsFinalized, 0);
  assert.equal(chain.airdrops.length, 1, "the faucet credit happened");
});

test("counters: a submission the RPC writer rejects is attempted but never broadcast", async () => {
  const chain = await provision({ config: false, grantRole: false, balance: 10_000_000n });
  chain.sendFailure = "RPC_UNREACHABLE";
  const report = await prepareDemoChain(optionsFor(chain, { prepare: true }));
  assert.equal(report.refusal?.code, "RPC_UNREACHABLE");
  assert.equal(report.mutations, 0);
  assert.equal(report.mutationsAttempted, 1);
  assert.equal(report.mutationsBroadcast, 0);
  assert.equal(report.mutationsFinalized, 0);
  assert.equal(chain.sent.length, 0);
});

test("refusal: a non-devnet genesis is refused before any mutation", async () => {
  const chain = await provision({ config: false });
  chain.genesis = String(addr(9));
  const report = await prepareDemoChain(optionsFor(chain, { prepare: true }));
  assert.equal(report.refusal?.code, "CLUSTER_NOT_DEVNET");
  assert.equal(chain.mutations(), 0);
});

test("executor: synthetic preparation executes init, grant, bounded funding and one segment", async () => {
  const chain = await provision({ config: false, grantRole: false, balance: 0n });
  const report = await prepareDemoChain(optionsFor(chain, { prepare: true }));
  assert.equal(report.refusal, null);
  assert.equal(report.ok, true);
  assert.equal(report.mutations, 4);
  assert.equal(chain.sent.length, 3);
  assert.equal(chain.airdrops.length, 1);
  // Funding is bounded to the exact rent + fee shortfall the assessment saw.
  assert.equal(chain.airdrops[0].address, OPERATOR);
  assert.ok(chain.airdrops[0].lamports > 0n);
  assert.ok(chain.airdrops[0].lamports <= MAX_FUNDING_LAMPORTS);
  assert.equal(chain.airdrops[0].lamports, chain.rent + 50_000n);
  for (const step of report.steps) {
    assert.ok(step.status === "READY" || step.status === "EXECUTED", `${step.id}=${step.status}`);
  }
  const executed = report.steps.filter((step) => step.status === "EXECUTED").map((step) => step.id).sort();
  assert.deepEqual(executed, ["funding", "ledger-segment", "operator-role", "registry"]);
});

test("executor: every sent transaction is signed by the exact expected authority", async () => {
  const chain = await provision({ config: false, grantRole: false, balance: 0n });
  await prepareDemoChain(optionsFor(chain, { prepare: true }));
  const pdas = await derivePdas(OPERATOR, DAY);
  for (const wire of chain.sent) {
    const transaction = kit.getTransactionDecoder().decode(Buffer.from(wire, "base64"));
    const message = Buffer.from(transaction.messageBytes);
    const messageDecoded = kit.getCompiledTransactionMessageDecoder().decode(Uint8Array.from(message));
    const feePayer = String(messageDecoded.staticAccounts[0]);
    assert.equal(feePayer, OPERATOR, "the local development key pays and signs");
    const signature = transaction.signatures[feePayer as Address];
    assert.ok(signature instanceof Uint8Array && signature.length === 64);
    const publicKey = createPublicKey({
      key: Buffer.concat([
        Buffer.from("302a300506032b6570032100", "hex"),
        Buffer.from(kit.getAddressEncoder().encode(toAddress(feePayer))),
      ]),
      format: "der",
      type: "spki",
    });
    assert.ok(ed25519Verify(null, message, publicKey, Buffer.from(signature)), "signature verifies");
  }
  // The instruction bytes are exactly the generated encoders' output.
  const [initWire, grantWire, segmentWire] = chain.sent;
  const dataOf = (wire: string): Buffer => {
    const transaction = kit.getTransactionDecoder().decode(Buffer.from(wire, "base64"));
    const message = compiledMessageV0(transaction.messageBytes);
    return Buffer.from(message.instructions[0].data ?? []);
  };
  const initArgs = getInitializeRegistryInstructionDataDecoder().decode(dataOf(initWire));
  assert.equal(toHex(new Uint8Array(initArgs.registryIdHash)), toHex(new Uint8Array(registryIdHash(REGISTRY_ID))));
  assert.equal(initArgs.schemaVersion, 1);
  assert.equal(initArgs.maxEntriesPerDay, 3 * 46);
  const grantArgs = getGrantOperatorInstructionDataDecoder().decode(dataOf(grantWire));
  assert.equal(grantArgs.permissions, REQUIRED_OPERATOR_PERMISSIONS);
  assert.equal(toHex(new Uint8Array(grantArgs.keyIdHash)), "0".repeat(64));
  const segmentArgs = getCreateLedgerSegmentInstructionDataDecoder().decode(dataOf(segmentWire));
  assert.equal(segmentArgs.dayUtc, DAY);
  assert.equal(segmentArgs.segmentIndex, 0);
  assert.equal(segmentArgs.capacity, 46);
  const transaction = kit.getTransactionDecoder().decode(Buffer.from(segmentWire, "base64"));
  const message = compiledMessageV0(transaction.messageBytes);
  const at = (index: number) => String(message.staticAccounts[index]);
  const [meta] = message.instructions;
  assert.equal(at(meta.accountIndices![0]), String(pdas.configPda));
  assert.equal(at(meta.accountIndices![1]), String(pdas.operatorRolePda));
  assert.equal(at(meta.accountIndices![3]), String(pdas.segments[0].pda));
});

test("idempotence: an already prepared chain is not mutated again", async () => {
  const chain = await provision({ config: false, grantRole: false, balance: 0n });
  const first = await prepareDemoChain(optionsFor(chain, { prepare: true }));
  assert.equal(first.refusal, null);
  assert.equal(chain.mutations(), 4);
  const second = await prepareDemoChain(optionsFor(chain, { prepare: true }));
  assert.equal(second.refusal, null);
  assert.equal(second.ok, true);
  assert.equal(second.mutations, 0, "no duplicate actions after recheck");
  assert.equal(chain.mutations(), 4, "the chain sees no further traffic");
  const third = await prepareDemoChain(optionsFor(chain, { prepare: true }));
  assert.equal(third.mutations, 0);
  assert.equal(chain.mutations(), 4);
});

test("idempotence: an existing registry is initialized only once and never mutated", async () => {
  const chain = await provision({ config: false, grantRole: true, balance: 5_000_000n });
  // grantRole for a registry that does not exist yet is ignored by the
  // assessment; the run initializes once and then leaves the registry alone.
  await prepareDemoChain(optionsFor(chain, { prepare: true }));
  const inits = chain.sent.length;
  await prepareDemoChain(optionsFor(chain, { prepare: true }));
  assert.equal(chain.sent.length, inits, "no re-initialization and no registry mutation");
});

test("executor: plans rebuild into the real generated instructions", async () => {
  const chain = await provision({ config: false, grantRole: false });
  const pdas = await derivePdas(OPERATOR, DAY);
  const init = await buildInstructionForAction(
    {
      kind: "initialize_registry",
      requiredSigner: { role: "governance", address: OPERATOR },
      args: {
        registryId: REGISTRY_ID,
        registryIdHash: toHex(new Uint8Array(registryIdHash(REGISTRY_ID))),
        configPda: String(pdas.configPda),
        programId: String(PROGRAM_ID),
        emergencyAuthority: OPERATOR,
        schemaVersion: 1,
        hashAlgorithm: 1,
        treeAlgorithm: 1,
        anchorIntervalSeconds: 3600,
        maxEntriesPerDay: 138,
      },
    },
    pdas,
  );
  assert.equal(init.signerAddress, OPERATOR);
  // build only the instruction data: compile a one-instruction message
  const initMessage = compiledMessageV0(
    kit.compileTransaction(
      kit.pipe(
        kit.createTransactionMessage({ version: 0 }),
        (draft) => kit.setTransactionMessageFeePayerSigner(kit.createNoopSigner(toAddress(OPERATOR)), draft),
        (draft) =>
          kit.setTransactionMessageLifetimeUsingBlockhash(
            { blockhash: String(addr(3)) as never, lastValidBlockHeight: 9n },
            draft,
          ),
        (draft) => kit.appendTransactionMessageInstruction(init.instruction, draft),
      ),
    ).messageBytes,
  );
  const initData = Buffer.from(initMessage.instructions[0].data ?? []);
  const decoded = getInitializeRegistryInstructionDataDecoder().decode(initData);
  assert.equal(decoded.maxEntriesPerDay, 138);
  void chain;
});

test("executor: funding above the bound is refused instead of sent", async () => {
  // The planned funder is the local signer, so the authority gate passes and
  // the bound itself is what refuses the credit.
  const chain = await provision({ governance: OPERATOR, config: true, grantRole: true, segment: true, balance: 0n });
  chain.rent = 600_000_000n;
  const report = await prepareDemoChain(optionsFor(chain, { prepare: true }));
  assert.equal(report.refusal?.code, "FUNDING_EXCEEDS_BOUND");
  assert.equal(chain.mutations(), 0);
  assert.equal(report.mutationsAttempted, 0, "the faucet is never asked");
});

async function startFakeRpc(chain: ApplyingFakeChain): Promise<{ url: string; methods: string[]; close: () => Promise<void> }> {
  const methods: string[] = [];
  const server: Server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", async () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { id: number; method: string; params: unknown[] };
      methods.push(body.method);
      let result: unknown = null;
      switch (body.method) {
        case "getHealth":
          result = await chain.getHealth();
          break;
        case "getGenesisHash":
          result = await chain.getGenesisHash();
          break;
        case "getAccountInfo": {
          const account = String((body.params as unknown[])[0]);
          const found = await chain.getAccountInfo(account);
          result = {
            value:
              found === null
                ? null
                : { owner: found.owner, data: [Buffer.from(found.data).toString("base64"), "base64"] },
          };
          break;
        }
        case "getBalance":
          result = { value: Number(await chain.getBalanceLamports(String((body.params as unknown[])[0]))) };
          break;
        case "getMinimumBalanceForRentExemption":
          result = Number(await chain.getMinimumBalanceForRentExemption(0));
          break;
        case "getLatestBlockhash": {
          const blockhash = await chain.getLatestBlockhash();
          result = { value: { blockhash: blockhash.blockhash, lastValidBlockHeight: Number(blockhash.lastValidBlockHeight) } };
          break;
        }
        case "sendTransaction":
          result = await chain.sendTransaction(String((body.params as unknown[])[0]));
          break;
        case "getSignatureStatuses":
          result = {
            value: ((body.params as unknown[])[0] as string[]).map(() => ({
              confirmationStatus: "finalized",
              err: null,
            })),
          };
          break;
        case "requestAirdrop": {
          const [address, lamports] = body.params as [string, number];
          result = await chain.requestAirdrop(address, BigInt(lamports));
          break;
        }
        default:
          response.writeHead(500).end();
          return;
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const addressInfo = server.address();
  assert.ok(addressInfo !== null && typeof addressInfo === "object");
  return {
    url: `http://127.0.0.1:${addressInfo.port}`,
    methods,
    close: async () => {
      await new Promise((resolve) => server.close(() => resolve(undefined)));
    },
  };
}

test("cli: assessment-only reports not ready with exit 4 and sends nothing", async () => {
  const chain = await provision({ governance: GOVERNANCE, grantRole: false });
  const rpc = await startFakeRpc(chain);
  try {
    const result = await runCli([
      ...NODE_ARGS,
      CLI,
      "--rpc-url",
      rpc.url,
      "--demo-api-url",
      "http://127.0.0.1:8090",
      "--verifier-url",
      "http://127.0.0.1:8080",
      "--key-file",
      path.join(persistentKeyRoot({ home }), "demo-operator.json"),
    ], { ...process.env, HOME: home });
    assert.equal(result.code, 4);
    const report = JSON.parse(result.stdout);
    assert.equal(report.schema, "onelayer.live-demo.seed.v1");
    assert.equal(report.ok, false);
    assert.equal(report.mutations, 0);
    assert.ok(!rpc.methods.includes("sendTransaction"));
    assert.ok(!rpc.methods.includes("requestAirdrop"));
  } finally {
    await rpc.close();
  }
});

test("cli: --prepare on a lost authority exits 3 with GOVERNANCE_KEY_UNAVAILABLE and zero mutations", async () => {
  const chain = await provision({ governance: GOVERNANCE, grantRole: false });
  const rpc = await startFakeRpc(chain);
  try {
    const result = await runCli([
      ...NODE_ARGS,
      CLI,
      "--rpc-url",
      rpc.url,
      "--key-file",
      path.join(persistentKeyRoot({ home }), "demo-operator.json"),
      "--prepare",
    ], { ...process.env, HOME: home });
    assert.equal(result.code, 3);
    assert.deepEqual(JSON.parse(result.stderr), { error: { code: "GOVERNANCE_KEY_UNAVAILABLE" } });
    const report = JSON.parse(result.stdout);
    assert.equal(report.refusal.code, "GOVERNANCE_KEY_UNAVAILABLE");
    assert.equal(report.mutations, 0);
    assert.ok(!rpc.methods.includes("sendTransaction"), "no transaction is ever sent");
    assert.ok(!rpc.methods.includes("requestAirdrop"), "no faucet request is ever sent");
  } finally {
    await rpc.close();
  }
});

test("cli: unknown flags are request errors (exit 2)", async () => {
  const result = await runCli([...NODE_ARGS, CLI, "--nope"], { ...process.env, HOME: home });
  assert.equal(result.code, 2);
  assert.deepEqual(JSON.parse(result.stderr), { error: { code: "REQUEST_INVALID" } });
});

test("cli: --approve-fallback without a ready preparation publishes nothing", async () => {
  const chain = await provision({ governance: GOVERNANCE, grantRole: false });
  const rpc = await startFakeRpc(chain);
  try {
    const result = await runCli([
      ...NODE_ARGS,
      CLI,
      "--rpc-url",
      rpc.url,
      "--key-file",
      path.join(persistentKeyRoot({ home }), "demo-operator.json"),
      "--prepare",
      "--approve-fallback",
    ], { ...process.env, HOME: home });
    assert.equal(result.code, 3);
    const report = JSON.parse(result.stdout);
    assert.equal(report.refusal.code, "GOVERNANCE_KEY_UNAVAILABLE");
    assert.equal(report.fallback, null);
    assert.match(String(report.fallbackSkipped), /no fallback certificate was published/);
    assert.ok(!rpc.methods.includes("sendTransaction"));
  } finally {
    await rpc.close();
  }
});

test("cli: unknown devnet with --prepare refuses CLUSTER_NOT_DEVNET before mutations", async () => {
  const chain = await provision({ config: false });
  chain.genesis = String(addr(9));
  const rpc = await startFakeRpc(chain);
  try {
    const result = await runCli([
      ...NODE_ARGS,
      CLI,
      "--rpc-url",
      rpc.url,
      "--key-file",
      path.join(persistentKeyRoot({ home }), "demo-operator.json"),
      "--prepare",
    ], { ...process.env, HOME: home });
    assert.equal(result.code, 3);
    assert.deepEqual(JSON.parse(result.stderr), { error: { code: "CLUSTER_NOT_DEVNET" } });
    assert.ok(!rpc.methods.includes("sendTransaction"));
    assert.ok(!rpc.methods.includes("requestAirdrop"));
  } finally {
    await rpc.close();
  }
});

void SeedRefusal;
