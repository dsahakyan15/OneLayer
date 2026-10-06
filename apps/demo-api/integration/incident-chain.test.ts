// Real chain integration for the incident index (ticket 04).
//
// A disposable solana-test-validator runs the repository's onelayer-registry
// program (built from source) plus a synthetic "foreign" program. The real
// `SolanaIncidentRpc` + `refreshIncidentIndex` + `PostgresIncidentStore` run
// against it and a disposable PostgreSQL cluster. Only synthetic keys are used;
// nothing is sent to devnet or mainnet.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  AccountRole,
  address,
  appendTransactionMessageInstructions,
  createTransactionMessage,
  generateKeyPairSigner,
  getAddressEncoder,
  getBase64EncodedWireTransaction,
  getSignatureFromTransaction,
  pipe,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  type Address,
  type KeyPairSigner,
} from "@solana/kit";
import {
  findIncidentNoticePda,
  findRegistryConfigPda,
  findRolePda,
  getGrantOperatorInstructionAsync,
  getInitializeRegistryInstruction,
  getOpenIncidentInstruction,
  getResolveIncidentInstruction,
} from "../../../packages/onchain-client/src/index.ts";
import { registryIdHash } from "../../../packages/canonical-ts/src/index.ts";
import { eventDiscriminator } from "../src/incident-events.ts";
import { refreshIncidentIndex, type IndexedNotice, type RegistryBinding, type TransactionLogs } from "../src/incident-index.ts";
import { PostgresIncidentStore } from "../src/incident-store.ts";
import { SolanaIncidentRpc } from "../src/solana-rpc.ts";
import { isolatedPostgres } from "./support/postgres.ts";
import { buildSbfProgram, rpcCall, startLocalValidator } from "./support/solana-validator.ts";

type Status = IndexedNotice["status"];
const STATUS_CODE = { CONFIRMED: 2, FALSE_POSITIVE: 3, RESOLVED: 4 } as const;
const PERM_REPORT_INCIDENT = 1 << 3;
const REGISTRY_PROGRAM = "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo";
const repo = (path: string) => fileURLToPath(new URL(`../../../${path}`, import.meta.url));

interface ModelNotice { firstSuspectBatch: bigint; lastSuspectBatch: bigint; incidentType: number; status: Status }

/** Thin transaction sender over the validator's JSON-RPC. */
class Chain {
  readonly rpcUrl: string;
  constructor(rpcUrl: string) { this.rpcUrl = rpcUrl; }

  async send(feePayer: KeyPairSigner, instructions: any[], options: { expectFailure?: boolean } = {}): Promise<string> {
    const blockhash = await rpcCall(this.rpcUrl, "getLatestBlockhash", [{ commitment: "processed" }]);
    const message = pipe(
      createTransactionMessage({ version: 0 }),
      m => setTransactionMessageFeePayerSigner(feePayer, m),
      m => setTransactionMessageLifetimeUsingBlockhash({ blockhash: blockhash.value.blockhash, lastValidBlockHeight: BigInt(blockhash.value.lastValidBlockHeight) }, m),
      m => appendTransactionMessageInstructions(instructions, m),
    );
    const signed = await signTransactionMessageWithSigners(message as any);
    const signature = getSignatureFromTransaction(signed as any);
    // Failing transactions skip preflight so that they land (with `err`) and
    // appear in the registry's signature history exactly like an attacker's.
    await rpcCall(this.rpcUrl, "sendTransaction", [getBase64EncodedWireTransaction(signed as any), {
      encoding: "base64", skipPreflight: options.expectFailure === true, preflightCommitment: "processed",
    }]);
    const status = await this.wait([signature], "processed");
    if (options.expectFailure === true) assert.notEqual(status[0].err, null, "synthetic failing transaction unexpectedly succeeded");
    else assert.equal(status[0].err, null, `transaction ${signature} failed: ${JSON.stringify(status[0].err)}`);
    return signature;
  }

  async wait(signatures: string[], level: "processed" | "confirmed" | "finalized", timeoutMs = 120_000): Promise<any[]> {
    const rank = { processed: 0, confirmed: 1, finalized: 2 } as const;
    const deadline = performance.now() + timeoutMs;
    for (;;) {
      const statuses: any[] = [];
      for (let i = 0; i < signatures.length; i += 256) {
        const page = await rpcCall(this.rpcUrl, "getSignatureStatuses", [signatures.slice(i, i + 256), { searchTransactionHistory: true }]);
        statuses.push(...page.value);
      }
      if (statuses.every(s => s !== null && rank[s.confirmationStatus as keyof typeof rank] >= rank[level])) return statuses;
      if (performance.now() > deadline) throw new Error(`transactions did not reach ${level}`);
      await new Promise(resolve => setTimeout(resolve, 200));
    }
  }

  async fund(...signers: KeyPairSigner[]): Promise<void> {
    const signatures: string[] = [];
    for (const signer of signers) signatures.push(await rpcCall(this.rpcUrl, "requestAirdrop", [signer.address, 100_000_000_000]));
    await this.wait(signatures, "confirmed");
  }
}

function forgedOpened(config: Address, sequence: bigint, firstBatch: bigint, lastBatch: bigint): Uint8Array {
  const data = new Uint8Array(8 + 32 + 24 + 2 + 32);
  const view = new DataView(data.buffer);
  data.set(eventDiscriminator("IncidentOpened"), 0);
  data.set(getAddressEncoder().encode(config), 8);
  view.setBigUint64(40, sequence, true);
  view.setBigUint64(48, firstBatch, true);
  view.setBigUint64(56, lastBatch, true);
  view.setUint16(64, 1, true);
  return data;
}

function forgedResolved(config: Address, sequence: bigint, status: number): Uint8Array {
  const data = new Uint8Array(8 + 32 + 8 + 1 + 32);
  data.set(eventDiscriminator("IncidentResolved"), 0);
  data.set(getAddressEncoder().encode(config), 8);
  new DataView(data.buffer).setBigUint64(40, sequence, true);
  data[48] = status;
  return data;
}

/** Wraps the real RPC adapter to inject crash/pruning/corruption at chosen points. */
class FaultyRpc extends SolanaIncidentRpc {
  transactionReads = 0;
  failOnTransactionRead: number | null = null;
  missingOnTransactionRead: number | null = null;
  truncateOnTransactionRead: number | null = null;
  prunedHistory = false;
  /** Deterministic finalized head (a slot the real chain has already finalized). */
  pinnedHead: bigint | null = null;

  override async getFinalizedHeadSlot(): Promise<bigint> {
    return this.pinnedHead ?? super.getFinalizedHeadSlot();
  }

  override async getSignaturesForAddress(addr: string, until: string | null) {
    if (this.prunedHistory) return [];
    return super.getSignaturesForAddress(addr, until);
  }

  override async getTransactionLogs(signature: string): Promise<TransactionLogs | null> {
    this.transactionReads += 1;
    if (this.transactionReads === this.failOnTransactionRead) throw new Error("synthetic indexer crash");
    if (this.transactionReads === this.missingOnTransactionRead) return null;
    const result = await super.getTransactionLogs(signature);
    if (result !== null && this.transactionReads === this.truncateOnTransactionRead) {
      return { ...result, logs: [...result.logs.slice(0, 3), "Log truncated"] };
    }
    return result;
  }
}

test("incident index against a live local validator: >100 notices, pagination, finality, resume, foreign/CPI events", { timeout: 20 * 60_000 }, async context => {
  const registryBuild = await buildSbfProgram({
    crateDir: repo("onchain/programs/onelayer-registry"),
    libName: "onelayer_registry",
    extraInputs: [repo("onchain/Cargo.lock"), repo("onchain/Cargo.toml")],
  });
  const foreignBuild = await buildSbfProgram({
    crateDir: fileURLToPath(new URL("./support/foreign-log-program", import.meta.url)),
    libName: "onelayer_foreign_log_fixture",
  });
  const foreignProgram = (await generateKeyPairSigner()).address;
  const validator = await startLocalValidator(context, [
    { programId: REGISTRY_PROGRAM, so: registryBuild.so },
    { programId: foreignProgram, so: foreignBuild.so },
  ]);
  context.diagnostic(`validator ${validator.version}; registry.so sha256=${registryBuild.sha256}; foreign.so sha256=${foreignBuild.sha256}`);
  const { pool, connectionString } = await isolatedPostgres(context);
  const chain = new Chain(validator.rpcUrl);
  const programAddress = address(REGISTRY_PROGRAM);

  const governance = await generateKeyPairSigner();
  const operator = await generateKeyPairSigner();
  await chain.fund(governance, operator);

  const createRegistry = async (registryId: string): Promise<Address> => {
    const [config] = await findRegistryConfigPda(registryIdHash(registryId), { programAddress });
    await chain.send(governance, [getInitializeRegistryInstruction({
      config, governance, registryIdHash: registryIdHash(registryId), emergencyAuthority: governance.address,
      schemaVersion: 1, hashAlgorithm: 1, treeAlgorithm: 1, anchorIntervalSeconds: 3600, maxEntriesPerDay: 46,
    }, { programAddress })]);
    await chain.send(governance, [await getGrantOperatorInstructionAsync({
      config, operator: operator.address, governanceAuthority: governance,
      permissions: PERM_REPORT_INCIDENT, validFrom: 0, validUntil: 0, keyIdHash: new Uint8Array(32),
    }, { programAddress })]);
    return config;
  };

  const registryId = `synthetic-chain-it-${randomBytes(6).toString("hex")}`;
  const config = await createRegistry(registryId);
  const otherConfig = await createRegistry(`${registryId}-other`);
  const [role] = await findRolePda({ config, operator: operator.address }, { programAddress });
  const [otherRole] = await findRolePda({ config: otherConfig, operator: operator.address }, { programAddress });

  const model = new Map<bigint, ModelNotice>();
  let nextSequence = 0n;
  let otherNext = 0n;
  const allSignatures: string[] = [];
  // Per-incident opening/resolution signatures (slots are read back at
  // finalized commitment) and the number of genuine registry events sent.
  const openSig = new Map<bigint, string>();
  const resolveSig = new Map<bigint, string>();
  let genuineEvents = 0;

  const openIx = async (cfg: Address, roleAddress: Address, sequence: bigint, notice: Omit<ModelNotice, "status">) => {
    const [incident] = await findIncidentNoticePda({ config: cfg, incidentSequence: sequence }, { programAddress });
    return getOpenIncidentInstruction({
      config: cfg, role: roleAddress, operator, incident,
      firstSuspectBatch: notice.firstSuspectBatch, lastSuspectBatch: notice.lastSuspectBatch,
      incidentType: notice.incidentType, evidenceManifestHash: randomBytes(32),
    }, { programAddress });
  };
  const resolveIx = async (sequence: bigint, status: Exclude<Status, "OPEN">) => {
    const [incident] = await findIncidentNoticePda({ config, incidentSequence: sequence }, { programAddress });
    return getResolveIncidentInstruction({ config, incident, governanceAuthority: governance, status: STATUS_CODE[status], resolutionHash: randomBytes(32) }, { programAddress });
  };
  const noticeFor = (sequence: bigint): Omit<ModelNotice, "status"> => ({
    firstSuspectBatch: sequence * 10n + 1n, lastSuspectBatch: sequence * 10n + 1n + (sequence % 3n), incidentType: 1 + Number(sequence % 5n),
  });
  const targetStatus = (sequence: bigint): Status => (["OPEN", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"] as const)[Number(sequence % 4n)];

  const openMany = async (count: number) => {
    for (let i = 0; i < count; i += 1) {
      const sequence = nextSequence;
      const signature = await chain.send(operator, [await openIx(config, role, sequence, noticeFor(sequence))]);
      allSignatures.push(signature);
      openSig.set(sequence, signature);
      genuineEvents += 1;
      model.set(sequence, { ...noticeFor(sequence), status: "OPEN" });
      nextSequence += 1n;
    }
  };
  const resolveMany = async (sequences: bigint[]) => {
    // Resolutions touch independent incident accounts, so they are sent concurrently.
    const signatures = await Promise.all(sequences.map(async sequence => {
      const status = targetStatus(sequence);
      if (status === "OPEN") return null;
      const signature = await chain.send(governance, [await resolveIx(sequence, status)]);
      model.get(sequence)!.status = status;
      resolveSig.set(sequence, signature);
      genuineEvents += 1;
      return signature;
    }));
    allSignatures.push(...signatures.filter((s): s is string => s !== null));
  };

  const binding: RegistryBinding = {
    registryId, programId: REGISTRY_PROGRAM, configAddress: config, configBytes: new Uint8Array(getAddressEncoder().encode(config)),
  };
  const newStore = () => new PostgresIncidentStore(pool, config);
  const newRpc = () => new FaultyRpc(validator.rpcUrl);
  const finalizedSlots = async (signatures: string[]) => {
    const statuses = await chain.wait(signatures, "finalized");
    return new Map(signatures.map((signature, index) => [signature, BigInt(statuses[index].slot)]));
  };
  const assertIndexMatchesModel = async (store: PostgresIncidentStore) => {
    const notices = await store.listNotices(registryId);
    assert.equal(notices.length, model.size, "indexed notice count differs from chain model");
    const slots = await finalizedSlots([...openSig.values(), ...resolveSig.values()]);
    for (const notice of notices) {
      assert.equal(notice.openedSlot, slots.get(openSig.get(notice.incidentSequence)!), `incident ${notice.incidentSequence} openedSlot`);
      const resolved = resolveSig.get(notice.incidentSequence);
      assert.equal(notice.resolvedSlot, resolved === undefined ? null : slots.get(resolved), `incident ${notice.incidentSequence} resolvedSlot`);
    }
    for (const notice of notices) {
      const expected = model.get(notice.incidentSequence);
      assert.ok(expected, `unexpected indexed incident ${notice.incidentSequence}`);
      assert.deepEqual(
        { firstSuspectBatch: notice.firstSuspectBatch, lastSuspectBatch: notice.lastSuspectBatch, incidentType: notice.incidentType, status: notice.status },
        expected,
        `incident ${notice.incidentSequence} differs`,
      );
    }
  };

  // ---- Phase A: 70 notices + resolutions (>100 signatures before first scan).
  await openMany(70);
  await resolveMany([...model.keys()].filter(sequence => sequence < 60n));
  await chain.wait(allSignatures, "finalized");

  // Crash in the middle of the very first (bootstrap) scan: nothing is committed.
  const crashing = newRpc();
  crashing.failOnTransactionRead = 57;
  await assert.rejects(refreshIncidentIndex(binding, crashing, newStore()), /synthetic indexer crash/);
  assert.deepEqual(await newStore().loadState(registryId), { indexedThroughSlot: 0n, lastSignature: null });
  assert.equal((await newStore().listNotices(registryId)).length, 0);

  // Pruned/empty history on bootstrap must not look like "no incidents".
  const pruned = newRpc();
  pruned.prunedHistory = true;
  await assert.rejects(refreshIncidentIndex(binding, pruned, newStore()), /history is incomplete/);
  assert.equal((await newStore().loadState(registryId)).indexedThroughSlot, 0n);

  // "Restart": a fresh adapter and store instance complete the bootstrap scan.
  const bootstrap = await refreshIncidentIndex(binding, newRpc(), newStore());
  // Every signature of the config: initialize + grant_operator + phase A.
  const phaseASignatures = allSignatures.length;
  const phaseAEvents = genuineEvents;
  assert.equal(bootstrap.scannedSignatures, 2 + phaseASignatures);
  assert.ok(bootstrap.scannedSignatures > 100, "bootstrap must span more than one page");
  assert.equal(bootstrap.appliedEvents, phaseAEvents);
  await assertIndexMatchesModel(newStore());
  const afterBootstrap = await newStore().loadState(registryId);
  const [newestFinalized] = await rpcCall(validator.rpcUrl, "getSignaturesForAddress", [config, { commitment: "finalized", limit: 1 }]);
  assert.equal(afterBootstrap.lastSignature, newestFinalized.signature, "cursor must be the newest finalized signature");
  context.diagnostic(`bootstrap: ${JSON.stringify({ ...bootstrap, indexedThroughSlot: String(bootstrap.indexedThroughSlot) })}`);

  // ---- Phase B: >100 new signatures after the saved cursor, incl. adverse ones.
  await openMany(60);                                                  // total 130 notices
  await resolveMany([...model.keys()].filter(sequence => sequence >= 60n));
  // Open + resolve of one incident inside a single transaction (same slot).
  {
    const sequence = nextSequence;
    // Governance co-signs as the resolver; the operator pays and opens.
    const signature = await chain.send(operator, [
      await openIx(config, role, sequence, noticeFor(sequence)),
      await resolveIx(sequence, "FALSE_POSITIVE"),
    ]);
    allSignatures.push(signature);
    openSig.set(sequence, signature);
    resolveSig.set(sequence, signature);
    genuineEvents += 2;
    model.set(sequence, { ...noticeFor(sequence), status: "FALSE_POSITIVE" });
    nextSequence += 1n;
  }
  // Genuine events emitted by the registry program under a foreign caller (CPI).
  const cpiMeta = (addr: Address, role: AccountRole, signer?: KeyPairSigner) => (signer ? { address: addr, role, signer } : { address: addr, role });
  const viaForeign = (mode: number, inner: any, signerFor: Map<string, KeyPairSigner>) => ({
    programAddress: foreignProgram,
    accounts: [cpiMeta(programAddress, AccountRole.READONLY), ...inner.accounts.map((meta: any) => cpiMeta(meta.address, meta.role, signerFor.get(meta.address)))],
    data: new Uint8Array([mode, ...inner.data]),
  });
  const signers = new Map([[operator.address as string, operator], [governance.address as string, governance]]);
  {
    const sequence = nextSequence;
    const opened = await chain.send(operator, [viaForeign(2, await openIx(config, role, sequence, noticeFor(sequence)), signers)]);
    allSignatures.push(opened);
    openSig.set(sequence, opened);
    model.set(sequence, { ...noticeFor(sequence), status: "OPEN" });
    nextSequence += 1n;
    const resolved = await chain.send(governance, [viaForeign(2, await resolveIx(sequence, "CONFIRMED"), signers)]);
    allSignatures.push(resolved);
    resolveSig.set(sequence, resolved);
    genuineEvents += 2;
    model.get(sequence)!.status = "CONFIRMED";
  }
  // Genuine CPI open inside a transaction that ultimately fails: nothing may be indexed.
  allSignatures.push(await chain.send(operator, [viaForeign(3, await openIx(config, role, nextSequence, noticeFor(nextSequence)), signers)], { expectFailure: true }));
  // Forged payloads from a foreign program, carrying our registry bytes and
  // referencing our config account so they show up in its signature history.
  const openVictim = [...model.entries()].find(([, notice]) => notice.status === "OPEN")![0];
  const forge = (payload: Uint8Array, mode = 0) => ({
    programAddress: foreignProgram,
    accounts: [{ address: config, role: AccountRole.READONLY }],
    data: new Uint8Array([mode, ...payload]),
  });
  allSignatures.push(await chain.send(operator, [forge(forgedResolved(config, openVictim, 4))]));
  allSignatures.push(await chain.send(operator, [forge(forgedOpened(config, 999n, 5_000n, 5_010n))]));
  allSignatures.push(await chain.send(operator, [forge(forgedOpened(config, nextSequence, 7_000n, 7_000n))]));
  allSignatures.push(await chain.send(operator, [forge(forgedResolved(config, openVictim, 3), 1)], { expectFailure: true }));
  // A genuine event of the same program for a different registry, in a
  // transaction that also references our config account.
  {
    const ix = await openIx(otherConfig, otherRole, otherNext, { firstSuspectBatch: 8_000n, lastSuspectBatch: 8_000n, incidentType: 2 });
    otherNext += 1n;
    allSignatures.push(await chain.send(operator, [{ ...ix, accounts: [...ix.accounts, { address: config, role: AccountRole.READONLY }] }]));
  }
  await chain.wait(allSignatures, "finalized");

  // Hard crash (SIGKILL) of a separate indexer process while it holds the
  // registry lock inside an open DB transaction part-way through the scan.
  {
    const child = spawn(process.execPath, ["--experimental-transform-types", "--no-warnings", fileURLToPath(new URL("./support/incident-refresh-child.ts", import.meta.url))], {
      env: { ...process.env, CHILD_HANG_AT: "40", CHILD_CONFIG: config, CHILD_DATABASE_URL: connectionString, CHILD_REGISTRY_ID: registryId, CHILD_PROGRAM_ID: REGISTRY_PROGRAM, CHILD_RPC_URL: validator.rpcUrl },
      stdio: ["ignore", "pipe", "pipe"],
    });
    context.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); });
    let output = "";
    child.stderr.on("data", chunk => { output += String(chunk); });
    await new Promise<void>((resolve, reject) => {
      child.stdout.on("data", chunk => { output += String(chunk); if (output.includes("HANG")) resolve(); });
      child.once("exit", code => reject(new Error(`refresh child exited (${code}) before hanging: ${output}`)));
    });
    const exited = new Promise(resolve => child.once("exit", resolve));
    child.kill("SIGKILL");
    await exited;
    // The killed writer's transaction is rolled back and its advisory lock is
    // released when the server notices the dropped connection.
    assert.deepEqual(await newStore().loadState(registryId), afterBootstrap);
    assert.equal((await newStore().listNotices(registryId)).length, 70);
  }

  // Crash part-way through the resume scan: the previous committed state survives.
  const midCrash = newRpc();
  midCrash.failOnTransactionRead = 50;
  await assert.rejects(refreshIncidentIndex(binding, midCrash, newStore()), /synthetic indexer crash/);
  assert.deepEqual(await newStore().loadState(registryId), afterBootstrap);
  const bootstrapModelCount = 70;
  assert.equal((await newStore().listNotices(registryId)).length, bootstrapModelCount);

  // Missing finalized transaction and truncated logs: fail closed, no watermark move.
  const missing = newRpc();
  missing.missingOnTransactionRead = 30;
  await assert.rejects(refreshIncidentIndex(binding, missing, newStore()), /unavailable/);
  const truncated = newRpc();
  truncated.truncateOnTransactionRead = 5;
  await assert.rejects(refreshIncidentIndex(binding, truncated, newStore()), /truncated|invocation/);
  const prunedResume = newRpc();
  prunedResume.prunedHistory = true;
  await assert.rejects(refreshIncidentIndex(binding, prunedResume, newStore()), /history is incomplete/);
  assert.deepEqual(await newStore().loadState(registryId), afterBootstrap);

  // Resume from the saved cursor after the failures.
  const resumed = await refreshIncidentIndex(binding, newRpc(), newStore());
  // Exactly the phase B signatures after the cursor, and exactly the genuine
  // events among them (forged, failed and other-registry ones contribute 0).
  assert.equal(resumed.scannedSignatures, allSignatures.length - phaseASignatures);
  assert.ok(resumed.scannedSignatures > 100, "resume must span more than one page");
  assert.equal(resumed.appliedEvents, genuineEvents - phaseAEvents);
  assert.ok(resumed.indexedThroughSlot > afterBootstrap.indexedThroughSlot);
  await assertIndexMatchesModel(newStore());
  assert.equal(model.size, 132);
  assert.deepEqual(new Set([...model.values()].map(n => n.status)), new Set(["OPEN", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"]));
  const victim = (await newStore().listNotices(registryId, noticeFor(openVictim).firstSuspectBatch))
    .find(n => n.incidentSequence === openVictim);
  assert.equal(victim?.status, "OPEN", "forged foreign resolution must not clear an open incident");
  assert.deepEqual(await newStore().listNotices(registryId, 5_000n), [], "forged foreign opening must not be indexed");
  assert.deepEqual(await newStore().listNotices(registryId, 8_000n), [], "other registry's events must not be indexed");
  context.diagnostic(`resume: ${JSON.stringify({ ...resumed, indexedThroughSlot: String(resumed.indexedThroughSlot) })}`);

  // A second refresh with nothing new is a no-op scan that keeps completeness.
  const idle = await refreshIncidentIndex(binding, newRpc(), newStore());
  assert.deepEqual([idle.appliedEvents, idle.scannedSignatures], [0, 0]);

  // ---- Phase C: the watermark is the finalized head observed before the scan,
  // never the slot of data that is only confirmed.
  const stateBeforeC = await newStore().loadState(registryId);
  const pinnedHead = BigInt(await rpcCall(validator.rpcUrl, "getSlot", [{ commitment: "finalized" }]));
  const pendingSequence = nextSequence;
  const pendingSignature = await chain.send(operator, [await openIx(config, role, pendingSequence, { firstSuspectBatch: 9_000n, lastSuspectBatch: 9_000n, incidentType: 4 })]);
  nextSequence += 1n;
  const [pendingStatus] = await chain.wait([pendingSignature], "confirmed");
  const pendingSlot = BigInt(pendingStatus.slot);
  assert.ok(pendingSlot > pinnedHead);
  // Deterministic variant: the finalized head is pinned to a slot the chain had
  // finalized before the pending notice was sent. Whatever the pending notice's
  // commitment is meanwhile, the watermark must equal that head (< its slot).
  // A reject (e.g. the notice finalizes between history and account reads) is
  // allowed only with the committed state unchanged.
  {
    const pinned = newRpc();
    pinned.pinnedHead = pinnedHead;
    try {
      const result = await refreshIncidentIndex(binding, pinned, newStore());
      const expected = pinnedHead > stateBeforeC.indexedThroughSlot ? pinnedHead : stateBeforeC.indexedThroughSlot;
      assert.equal(result.indexedThroughSlot, expected);
      assert.ok(result.indexedThroughSlot < pendingSlot, "watermark must not cover the pending notice's slot");
    } catch (error) {
      assert.match(String(error), /count mismatch|does not match/);
      assert.deepEqual(await newStore().loadState(registryId), stateBeforeC, "rejected scan must not change state");
    }
  }
  // Live variant against the real finalized head.
  const beforeEarly = await newStore().loadState(registryId);
  let early: Awaited<ReturnType<typeof refreshIncidentIndex>> | null = null;
  try {
    early = await refreshIncidentIndex(binding, newRpc(), newStore());
  } catch (error) {
    assert.match(String(error), /count mismatch|does not match/);
    assert.deepEqual(await newStore().loadState(registryId), beforeEarly, "rejected scan must not change state");
  }
  const [stillPending] = await chain.wait([pendingSignature], "processed");
  const pendingIndexed = (await newStore().listNotices(registryId, 9_000n)).length === 1;
  if (pendingIndexed) {
    // Only possible when the notice was finalized before the scan.
    assert.equal(stillPending.confirmationStatus, "finalized", "a non-finalized notice was indexed");
    context.diagnostic("pending notice finalized before the live scan (deterministic pinned-head variant still applied)");
  } else if (early !== null) {
    assert.ok(early.indexedThroughSlot < pendingSlot, "watermark covers a slot whose notice is not indexed (false CLEAR)");
    context.diagnostic(`unfinalized notice at slot ${pendingSlot} (status ${stillPending.confirmationStatus}) excluded; watermark ${early.indexedThroughSlot}; pinned head ${pinnedHead}`);
  }
  await chain.wait([pendingSignature], "finalized");
  const final = await refreshIncidentIndex(binding, newRpc(), newStore());
  assert.ok(final.indexedThroughSlot >= pendingSlot);
  const pending = await newStore().listNotices(registryId, 9_000n);
  assert.equal(pending.length, 1);
  assert.equal(pending[0].status, "OPEN");
  assert.equal(pending[0].incidentSequence, pendingSequence);

  // ---- D1 regression: the program accepts any u64 range with first <= last;
  // the projection (migration 0014) must store and match it exactly. Before
  // 0014 these notices made every refresh roll back forever.
  const U64_MAX = 0xffff_ffff_ffff_ffffn;
  for (const [label, range] of [
    ["zero-first", { firstSuspectBatch: 0n, lastSuspectBatch: 3n }],
    ["u64-max-last", { firstSuspectBatch: 1n, lastSuspectBatch: U64_MAX }],
    ["above-i64", { firstSuspectBatch: 0x8000_0000_0000_0000n, lastSuspectBatch: U64_MAX }],
  ] as const) {
    const edgeId = `${registryId}-${label}`;
    const edgeConfig = await createRegistry(edgeId);
    const [edgeRole] = await findRolePda({ config: edgeConfig, operator: operator.address }, { programAddress });
    const signature = await chain.send(operator, [await openIx(edgeConfig, edgeRole, 0n, { ...range, incidentType: 1 })]);
    await chain.wait([signature], "finalized");
    const edgeStore = new PostgresIncidentStore(pool, edgeConfig);
    const edgeBinding: RegistryBinding = { registryId: edgeId, programId: REGISTRY_PROGRAM, configAddress: edgeConfig, configBytes: new Uint8Array(getAddressEncoder().encode(edgeConfig)) };
    const result = await refreshIncidentIndex(edgeBinding, newRpc(), edgeStore);
    assert.equal(result.appliedEvents, 1, `${label}: notice must be indexed`);
    const [stored] = await edgeStore.listNotices(edgeId);
    assert.deepEqual([stored.firstSuspectBatch, stored.lastSuspectBatch, stored.status], [range.firstSuspectBatch, range.lastSuspectBatch, "OPEN"], `${label}: exact round-trip`);
    // Batches at both ends of the range are covered; outside it they are not.
    assert.equal((await edgeStore.listNotices(edgeId, range.firstSuspectBatch)).length, 1);
    assert.equal((await edgeStore.listNotices(edgeId, range.lastSuspectBatch)).length, 1);
    if (range.lastSuspectBatch < U64_MAX) assert.equal((await edgeStore.listNotices(edgeId, range.lastSuspectBatch + 1n)).length, 0);
    if (range.firstSuspectBatch > 0n) assert.equal((await edgeStore.listNotices(edgeId, range.firstSuspectBatch - 1n)).length, 0);
    const raw = await pool.query("SELECT first_suspect_batch::text AS f, last_suspect_batch::text AS l FROM incident_index_notice WHERE registry_id = $1", [edgeId]);
    assert.deepEqual(raw.rows[0], { f: range.firstSuspectBatch.toString(), l: range.lastSuspectBatch.toString() });
  }
});
