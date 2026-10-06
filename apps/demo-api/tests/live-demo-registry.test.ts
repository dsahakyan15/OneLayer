import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { address as toAddress, getAddressDecoder, type Address } from "@solana/kit";
import { registryIdHash, toHex } from "../../../packages/canonical-ts/src/index.ts";
import {
  getCreateLedgerSegmentInstructionDataEncoder,
  getDailyAnchorLedgerSegmentEncoder,
  getGrantOperatorInstructionDataEncoder,
  getInitializeRegistryInstructionDataEncoder,
  getOperatorRoleEncoder,
  getRegistryConfigEncoder,
} from "../../../packages/onchain-client/src/index.ts";
import {
  checkReadiness,
  DEFAULT_DEMO_API_URL,
  DEFAULT_VERIFIER_URL,
  derivePdas,
  DEVNET_GENESIS_HASH,
  JsonRpcRegistryReader,
  MAX_HTTP_BODY_BYTES,
  PROGRAM_ID,
  REGISTRY_ID,
  RegistryRefusal,
  REQUIRED_OPERATOR_PERMISSIONS,
  UNBOUND_KEY_ID_HASH_HEX,
  type ReadinessOptions,
  type ReadinessReport,
  type RegistryChainReader,
} from "../scripts/live-demo-registry.ts";
import { ensureKeyPair, persistentKeyRoot } from "../scripts/live-demo-key-store.ts";

const run = promisify(execFile);
const SCRIPT = fileURLToPath(new URL("../scripts/live-demo-registry.ts", import.meta.url));
const NODE_ARGS = ["--experimental-transform-types", "--disable-warning=ExperimentalWarning"];

const DAY = 20261006;
const NOW = new Date("2026-10-06T12:00:00Z");

function addr(fill: number): Address {
  return getAddressDecoder().decode(new Uint8Array(32).fill(fill));
}

// Filled in `before()` from a real key-store keypair: the operator in these
// tests has a local signing key (the generated demo-operator) while the
// governance authority is a different, unavailable address.
let OPERATOR = String(addr(11));
const GOVERNANCE = String(addr(22));

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

class FakeChain implements RegistryChainReader {
  accounts = new Map<string, { owner: string; data: Uint8Array }>();
  balances = new Map<string, bigint>();
  rent = 2_000_000n;
  genesis = DEVNET_GENESIS_HASH;
  health = "ok";

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

  async getMinimumBalanceForRentExemption(): Promise<bigint> {
    return this.rent;
  }
}

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

function roleAccount(
  registry: string,
  operator: string,
  permissions: number,
  validity: { validFrom?: bigint; validUntil?: bigint; revokedAt?: bigint } = {},
): { owner: string; data: Uint8Array } {
  return {
    owner: String(PROGRAM_ID),
    data: Buffer.from(
      getOperatorRoleEncoder().encode({
        version: 1,
        bump: 255,
        registry: toAddress(registry),
        operator: toAddress(operator),
        permissions,
        validFrom: validity.validFrom ?? 0n,
        validUntil: validity.validUntil ?? 0n,
        revokedAt: validity.revokedAt ?? 0n,
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

function fakeFetch(mode: "ok" | "down" | "bad-payload" = "ok"): typeof fetch {
  return (async (url: unknown) => {
    const target = String(url);
    if (!target.endsWith("/v1/health")) throw new Error(`unexpected url ${target}`);
    if (mode === "down") return new Response("nope", { status: 503 });
    if (mode === "bad-payload") return new Response(JSON.stringify({ status: "degraded" }), { status: 200 });
    return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
  }) as typeof fetch;
}

function rpcFetch(handlers: Record<string, (params: unknown[]) => unknown>): typeof fetch {
  return (async (_url: unknown, init?: unknown) => {
    const body = JSON.parse(String((init as { body?: string }).body));
    const handler = handlers[body.method];
    if (handler === undefined) throw new Error(`unexpected method ${body.method}`);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: handler(body.params) }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
}

interface Provisioned {
  chain: FakeChain;
  configPda: string;
  rolePda: string;
  segments: string[];
}

async function provision(
  options: {
    operator?: string;
    governance?: string;
    paused?: boolean;
    grantRole?: boolean;
    rolePermissions?: number;
    segments?: Array<{ index: number; sealed?: number; entryCount?: number; capacity?: number }>;
    balance?: bigint;
  } = {},
): Promise<Provisioned> {
  const operator = options.operator ?? OPERATOR;
  const governance = options.governance ?? GOVERNANCE;
  const chain = new FakeChain();
  const pdas = await derivePdas(operator, DAY);
  const configPda = String(pdas.configPda);
  chain.accounts.set(configPda, configAccount(governance, options.paused ?? false));
  const rolePda = String(pdas.operatorRolePda);
  if (options.grantRole !== false) {
    chain.accounts.set(
      rolePda,
      roleAccount(configPda, operator, options.rolePermissions ?? REQUIRED_OPERATOR_PERMISSIONS),
    );
  }
  const segments: string[] = [];
  for (const entry of pdas.segments) {
    const pda = String(entry.pda);
    segments.push(pda);
    const wanted = (options.segments ?? [{ index: 0 }]).find((candidate) => candidate.index === entry.index);
    if (wanted !== undefined) {
      chain.accounts.set(pda, segmentAccount(configPda, DAY, entry.index, wanted));
    }
  }
  chain.balances.set(operator, options.balance ?? 10_000_000n);
  return { chain, configPda, rolePda, segments };
}

function baseOptions(chain: FakeChain, extra: Partial<ReadinessOptions> = {}): ReadinessOptions {
  // The operator comes from the shared persistent key store (a real local
  // signing key), mirroring the launcher profile.
  return {
    chain,
    request: fakeFetch(),
    dayUtc: DAY,
    now: NOW,
    keyStore: { home },
    ...extra,
  };
}

function itemOf(report: ReadinessReport, id: string) {
  const found = report.items.find((entry) => entry.id === id);
  assert.ok(found, `missing item ${id}`);
  return found;
}

function blockerCodes(report: ReadinessReport, id: string): string[] {
  return itemOf(report, id).blockers.map((entry) => entry.code);
}

let home = "";

before(async () => {
  home = await mkdtemp(path.join(tmpdir(), "live-demo-registry-"));
  const ensured = await ensureKeyPair({ home, keypair: keypairBytesFor(7) });
  OPERATOR = ensured.address;
});

after(async () => {
  await rm(home, { recursive: true, force: true });
});

test("a provisioned devnet profile reports READY for every item and stays idempotent", async () => {
  const { chain } = await provision();
  const first = await checkReadiness(baseOptions(chain));
  const second = await checkReadiness(baseOptions(chain));
  assert.deepEqual(first, second, "the probe is idempotent");
  assert.equal(first.ok, true);
  assert.equal(first.cluster, "solana:devnet");
  assert.equal(first.registryId, "gov.registry.land");
  assert.equal(first.dayUtc, DAY);
  for (const entry of first.items) {
    assert.equal(entry.status, "READY", `${entry.id}: ${entry.detail}`);
    assert.equal(entry.action, null);
    assert.deepEqual(entry.blockers, []);
  }
  assert.deepEqual(
    first.items.map((entry) => entry.id),
    ["demo-api-health", "verifier-health", "chain", "registry", "operator-role", "ledger-segment", "funding"],
  );
});

test("the report never claims a generated key governs an existing registry", async () => {
  const { chain, configPda } = await provision({ grantRole: false, balance: 10_000_000n });
  const report = await checkReadiness(baseOptions(chain));
  assert.equal(report.ok, false);
  assert.equal(report.operator.governsRegistry, false);
  assert.equal(report.operator.signingKeyAvailable, true);
  assert.equal(itemOf(report, "registry").observed.localKeyGovernsRegistry, false);
  assert.equal(itemOf(report, "registry").observed.governanceAuthority, GOVERNANCE);
  assert.deepEqual(blockerCodes(report, "operator-role"), ["GOVERNANCE_KEY_UNAVAILABLE"]);
  const detail = itemOf(report, "operator-role").blockers[0].detail;
  assert.match(detail, /does not govern this registry/);
  assert.match(detail, new RegExp(GOVERNANCE));
  assert.equal(itemOf(report, "registry").status, "READY");
  assert.equal(itemOf(report, "registry").observed.configPda, configPda);
});

test("grant_operator is planned with the on-chain governance signer when the role is missing", async () => {
  const { chain, configPda, rolePda } = await provision({ grantRole: false });
  const report = await checkReadiness(baseOptions(chain));
  const role = itemOf(report, "operator-role");
  assert.equal(role.status, "ACTION_REQUIRED");
  assert.equal(role.action?.kind, "grant_operator");
  assert.deepEqual(role.action?.requiredSigner, { role: "governance", address: GOVERNANCE });
  assert.equal(role.action?.args.rolePda, rolePda);
  assert.equal(role.action?.args.configPda, configPda);
  assert.equal(role.action?.args.permissions, REQUIRED_OPERATOR_PERMISSIONS);
  assert.ok(blockerCodes(report, "operator-role").includes("GOVERNANCE_KEY_UNAVAILABLE"));
});

test("authority mismatch blocks funding before any transfer is attempted", async () => {
  const { chain } = await provision({ grantRole: false, balance: 0n });
  const report = await checkReadiness(baseOptions(chain));
  const funding = itemOf(report, "funding");
  assert.equal(funding.status, "ACTION_REQUIRED");
  assert.equal(funding.action?.kind, "fund_operator");
  assert.deepEqual(funding.action?.requiredSigner, { role: "funder", address: GOVERNANCE });
  assert.ok(blockerCodes(report, "funding").includes("GOVERNANCE_KEY_UNAVAILABLE"));
  assert.equal(funding.observed.shortfallLamports, (2_000_000n + 50_000n).toString());
  // The action is a plan only: nothing in the report pretends the transfer ran.
  assert.deepEqual(Object.keys(funding.action?.args ?? {}).sort(), ["lamports", "to"]);
});

test("when the local signing key is the governance authority the blockers are gone", async () => {
  const { chain } = await provision({ governance: OPERATOR, grantRole: false, balance: 0n });
  const report = await checkReadiness(baseOptions(chain));
  assert.equal(report.operator.governsRegistry, true);
  assert.equal(report.operator.signingKeyAvailable, true);
  assert.equal(report.operator.source, "persistent-store");
  const json = JSON.stringify(report);
  assert.ok(!json.includes("GOVERNANCE_KEY_UNAVAILABLE"));
  assert.ok(!json.includes("PRIVATE"), "no key material in the report");
  const role = itemOf(report, "operator-role");
  assert.equal(role.status, "ACTION_REQUIRED");
  assert.equal(role.action?.kind, "grant_operator");
  assert.deepEqual(role.action?.requiredSigner, { role: "governance", address: OPERATOR });
  assert.deepEqual(role.blockers, []);
  assert.deepEqual(blockerCodes(report, "funding"), []);
  assert.equal(itemOf(report, "registry").observed.localKeyGovernsRegistry, true);
});

test("ledger segment creation is planned for the day and blocked without the operator role", async () => {
  const missingRole = await provision({ grantRole: false, segments: [] });
  const report = await checkReadiness(baseOptions(missingRole.chain));
  const segment = itemOf(report, "ledger-segment");
  assert.equal(segment.status, "ACTION_REQUIRED");
  assert.equal(segment.action?.kind, "create_ledger_segment");
  assert.deepEqual(segment.action?.requiredSigner, { role: "operator", address: OPERATOR });
  assert.equal(segment.action?.args.dayUtc, DAY);
  assert.equal(segment.action?.args.segmentIndex, 0);
  assert.deepEqual(blockerCodes(report, "ledger-segment"), ["OPERATOR_ROLE_MISSING", "GOVERNANCE_KEY_UNAVAILABLE"]);

  const withRole = await provision({ segments: [] });
  const ready = await checkReadiness(baseOptions(withRole.chain));
  assert.deepEqual(blockerCodes(ready, "ledger-segment"), []);
  assert.equal(itemOf(ready, "ledger-segment").action?.kind, "create_ledger_segment");

  // A bare address with no local signing key cannot create the segment either.
  const addressOnly = await checkReadiness({
    ...baseOptions(withRole.chain),
    keyStore: undefined,
    operator: OPERATOR,
  });
  assert.deepEqual(blockerCodes(addressOnly, "ledger-segment"), ["OPERATOR_KEY_UNAVAILABLE"]);
});

test("a non-devnet RPC is refused as CLUSTER_NOT_DEVNET and dependents are not assessed", async () => {
  const { chain } = await provision();
  chain.genesis = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
  const report = await checkReadiness(baseOptions(chain));
  assert.equal(report.ok, false);
  assert.deepEqual(blockerCodes(report, "chain"), ["CLUSTER_NOT_DEVNET"]);
  for (const id of ["registry", "operator-role", "ledger-segment", "funding"]) {
    assert.equal(itemOf(report, id).status, "UNAVAILABLE");
    assert.deepEqual(blockerCodes(report, id), ["CHAIN_UNAVAILABLE"]);
    assert.equal(itemOf(report, id).action, null);
  }
});

test("a paused registry plans an unpause action and never a silent substitute", async () => {
  const { chain } = await provision({ paused: true });
  const report = await checkReadiness(baseOptions(chain));
  const registry = itemOf(report, "registry");
  assert.equal(registry.status, "ACTION_REQUIRED");
  assert.equal(registry.action?.kind, "unpause_registry");
  assert.deepEqual(registry.action?.requiredSigner, { role: "governance", address: GOVERNANCE });
  assert.deepEqual(blockerCodes(report, "registry"), ["REGISTRY_PAUSED", "GOVERNANCE_KEY_UNAVAILABLE"]);
});

test("unreachable or unhealthy loopback services are reported as SERVICE_UNREACHABLE", async () => {
  const { chain } = await provision();
  const down = await checkReadiness(baseOptions(chain, { request: fakeFetch("down") }));
  assert.equal(itemOf(down, "demo-api-health").status, "UNAVAILABLE");
  assert.deepEqual(blockerCodes(down, "demo-api-health"), ["SERVICE_UNREACHABLE"]);
  const bad = await checkReadiness(baseOptions(chain, { request: fakeFetch("bad-payload") }));
  assert.deepEqual(blockerCodes(bad, "verifier-health"), ["SERVICE_UNREACHABLE"]);
});

test("insufficient role permissions are reported and a re-grant is planned", async () => {
  const { chain } = await provision({ rolePermissions: 1 });
  const report = await checkReadiness(baseOptions(chain));
  const role = itemOf(report, "operator-role");
  assert.equal(role.status, "ACTION_REQUIRED");
  assert.ok(blockerCodes(report, "operator-role").includes("OPERATOR_PERMISSIONS_INSUFFICIENT"));
  assert.equal(role.action?.kind, "grant_operator");
  assert.ok(blockerCodes(report, "operator-role").includes("GOVERNANCE_KEY_UNAVAILABLE"));
});

test("expired and revoked roles are ACTION_REQUIRED with exact blocker codes", async () => {
  const expired = await provision();
  const expiredPdas = await derivePdas(OPERATOR, DAY);
  expired.chain.accounts.set(
    String(expiredPdas.operatorRolePda),
    roleAccount(String(expiredPdas.configPda), OPERATOR, 3, { validUntil: 1n }),
  );
  const expiredReport = await checkReadiness(baseOptions(expired.chain));
  assert.ok(blockerCodes(expiredReport, "operator-role").includes("OPERATOR_ROLE_EXPIRED"));

  const revoked = await provision();
  const revokedPdas = await derivePdas(OPERATOR, DAY);
  revoked.chain.accounts.set(
    String(revokedPdas.operatorRolePda),
    roleAccount(String(revokedPdas.configPda), OPERATOR, 3, { revokedAt: 5n }),
  );
  const revokedReport = await checkReadiness(baseOptions(revoked.chain));
  assert.ok(blockerCodes(revokedReport, "operator-role").includes("OPERATOR_ROLE_REVOKED"));
});

test("sealed and full day segments plan the next index, then LEDGER_SEGMENT_FULL", async () => {
  const { chain } = await provision({
    segments: [
      { index: 0, sealed: 1, entryCount: 46 },
      { index: 1, sealed: 0, entryCount: 46 },
    ],
  });
  const report = await checkReadiness(baseOptions(chain));
  const segment = itemOf(report, "ledger-segment");
  assert.equal(segment.status, "ACTION_REQUIRED");
  assert.equal(segment.action?.args.segmentIndex, 2);
  assert.deepEqual(blockerCodes(report, "ledger-segment"), []);

  const full = await provision({
    segments: [
      { index: 0, sealed: 1, entryCount: 46 },
      { index: 1, sealed: 1, entryCount: 46 },
      { index: 2, sealed: 1, entryCount: 46 },
    ],
  });
  const fullReport = await checkReadiness(baseOptions(full.chain));
  assert.equal(itemOf(fullReport, "ledger-segment").status, "UNAVAILABLE");
  assert.deepEqual(blockerCodes(fullReport, "ledger-segment"), ["LEDGER_SEGMENT_FULL"]);
});

test("funding is READY above the rent plus fee threshold and ACTION_REQUIRED below it", async () => {
  const rich = await provision({ balance: 2_050_000n });
  const richReport = await checkReadiness(baseOptions(rich.chain));
  assert.equal(itemOf(richReport, "funding").status, "READY");
  assert.equal(itemOf(richReport, "funding").observed.shortfallLamports, "0");

  const poor = await provision({ balance: 1n });
  const poorReport = await checkReadiness(baseOptions(poor.chain));
  assert.equal(itemOf(poorReport, "funding").status, "ACTION_REQUIRED");
  assert.equal(itemOf(poorReport, "funding").action?.args.lamports, "2049999");
});

test("with no local operator key the report plans ensure_operator_key", async () => {
  const emptyHome = await mkdtemp(path.join(tmpdir(), "live-demo-registry-empty-"));
  try {
    const { chain } = await provision();
    const report = await checkReadiness({
      chain,
      request: fakeFetch(),
      dayUtc: DAY,
      now: NOW,
      keyStore: { home: emptyHome },
    });
    assert.equal(report.operator.address, null);
    assert.equal(report.operator.source, "none");
    assert.equal(report.ok, false);
    const role = itemOf(report, "operator-role");
    assert.equal(role.action?.kind, "ensure_operator_key");
    assert.deepEqual(blockerCodes(report, "operator-role"), ["OPERATOR_KEY_UNAVAILABLE"]);
  } finally {
    await rm(emptyHome, { recursive: true, force: true });
  }
});

test("the persistent store key is discovered without an explicit key file", async () => {
  const storeHome = await mkdtemp(path.join(tmpdir(), "live-demo-registry-store-"));
  try {
    const ensured = await ensureKeyPair({ home: storeHome, keypair: keypairBytesFor(3) });
    const { chain } = await provision({ operator: ensured.address, balance: 10_000_000n });
    const report = await checkReadiness({
      chain,
      request: fakeFetch(),
      dayUtc: DAY,
      now: NOW,
      keyStore: { home: storeHome },
    });
    assert.equal(report.operator.address, ensured.address);
    assert.equal(report.operator.signingKeyAvailable, true);
    assert.equal(report.operator.source, "persistent-store");
    assert.equal(report.operator.keyPath, path.join(persistentKeyRoot({ home: storeHome }), "demo-operator.json"));
  } finally {
    await rm(storeHome, { recursive: true, force: true });
  }
});

test("JsonRpcRegistryReader parses accounts and refuses an unhealthy RPC", async () => {
  const accountData = configAccount(GOVERNANCE);
  const reader = new JsonRpcRegistryReader(
    "https://api.devnet.solana.com",
    rpcFetch({
      getHealth: () => "ok",
      getGenesisHash: () => DEVNET_GENESIS_HASH,
      getAccountInfo: (params) => ({
        value: { owner: String(PROGRAM_ID), data: [Buffer.from(accountData.data).toString("base64"), "base64"] },
      }),
      getBalance: () => ({ value: 42 }),
      getMinimumBalanceForRentExemption: () => 2_000_000,
    }),
  );
  assert.equal(await reader.getHealth(), "ok");
  assert.equal(await reader.getGenesisHash(), DEVNET_GENESIS_HASH);
  const info = await reader.getAccountInfo(addr(1));
  assert.equal(info?.owner, String(PROGRAM_ID));
  assert.equal(await reader.getBalanceLamports(addr(1)), 42n);
  assert.equal(await reader.getMinimumBalanceForRentExemption(200), 2_000_000n);

  const broken = new JsonRpcRegistryReader(
    "https://api.devnet.solana.com",
    rpcFetch({
      getHealth: () => {
        throw new Error("should not reach handler");
      },
    }),
  );
  const failing = new JsonRpcRegistryReader("https://api.devnet.solana.com", (async () => {
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { message: "boom" } }), { status: 200 });
  }) as typeof fetch);
  await assert.rejects(() => failing.getHealth(), (error: unknown) => {
    assert.ok(error instanceof RegistryRefusal);
    assert.equal(error.code, "RPC_UNREACHABLE");
    return true;
  });
  assert.ok(broken instanceof JsonRpcRegistryReader);
});

test("non-loopback service URLs are refused and the request shape is validated", async () => {
  const { chain } = await provision();
  await assert.rejects(
    () => checkReadiness(baseOptions(chain, { demoApiUrl: "http://example.com" })),
    (error: unknown) => {
      assert.ok(error instanceof RegistryRefusal);
      assert.equal(error.code, "LINK_REFUSED");
      return true;
    },
  );
  await assert.rejects(
    () => checkReadiness(baseOptions(chain, { verifierUrl: "file:///etc/passwd" })),
    (error: unknown) => {
      assert.ok(error instanceof RegistryRefusal);
      assert.equal(error.code, "REQUEST_INVALID");
      return true;
    },
  );
  await assert.rejects(
    () => checkReadiness(baseOptions(chain, { demoApiUrl: "http://user:pass@127.0.0.1:8090" })),
    (error: unknown) => {
      assert.ok(error instanceof RegistryRefusal);
      assert.equal(error.code, "REQUEST_INVALID");
      return true;
    },
  );
  await assert.rejects(
    () => checkReadiness(baseOptions(chain, { operator: "not-base58" })),
    (error: unknown) => {
      assert.ok(error instanceof RegistryRefusal);
      assert.equal(error.code, "REQUEST_INVALID");
      return true;
    },
  );
  await assert.rejects(
    () => checkReadiness(baseOptions(chain, { dayUtc: 20261301 })),
    (error: unknown) => {
      assert.ok(error instanceof RegistryRefusal);
      assert.equal(error.code, "REQUEST_INVALID");
      return true;
    },
  );
});

test("the JSON-RPC reader and probe never leak key material into the report", async () => {
  const storeHome = await mkdtemp(path.join(tmpdir(), "live-demo-registry-leak-"));
  try {
    const keypair = keypairBytesFor(5);
    const ensured = await ensureKeyPair({ home: storeHome, keypair });
    const { chain } = await provision({ operator: ensured.address, grantRole: false, balance: 0n });
    const report = await checkReadiness({
      chain,
      request: fakeFetch(),
      dayUtc: DAY,
      now: NOW,
      keyStore: { home: storeHome },
    });
    const json = JSON.stringify(report);
    // The public address may appear; the 64-byte keypair payload may not.
    assert.ok(json.includes(ensured.address));
    assert.ok(!json.includes(Buffer.from(keypair.subarray(0, 32)).toString("hex")));
    assert.ok(!json.includes(Buffer.from(keypair).toString("hex")));
    assert.ok(!json.includes(Buffer.from(keypair).toString("base64")));
  } finally {
    await rm(storeHome, { recursive: true, force: true });
  }
});

test("default URLs point at the loopback demo profile", () => {
  assert.equal(DEFAULT_DEMO_API_URL, "http://127.0.0.1:8090");
  assert.equal(DEFAULT_VERIFIER_URL, "http://127.0.0.1:8080");
});

test("planned actions are execution-complete: the real instruction encoders accept them", async () => {
  const { chain, configPda } = await provision({ grantRole: false, segments: [], balance: 0n });
  const report = await checkReadiness(baseOptions(chain));
  const grant = itemOf(report, "operator-role").action;
  assert.equal(grant?.kind, "grant_operator");
  assert.equal(grant?.args.keyIdHash, UNBOUND_KEY_ID_HASH_HEX);
  assert.match(String(grant?.args.keyIdHash), /^[0-9a-f]{64}$/);
  // Rebuilding the instruction from the plan alone must work.
  const grantData = getGrantOperatorInstructionDataEncoder().encode({
    permissions: Number(grant?.args.permissions),
    validFrom: Number(grant?.args.validFrom),
    validUntil: Number(grant?.args.validUntil),
    keyIdHash: Buffer.from(String(grant?.args.keyIdHash), "hex"),
  });
  assert.equal(grantData.length, 8 + 4 + 8 + 8 + 32);

  const create = itemOf(report, "ledger-segment").action;
  assert.equal(create?.kind, "create_ledger_segment");
  const createData = getCreateLedgerSegmentInstructionDataEncoder().encode({
    dayUtc: Number(create?.args.dayUtc),
    segmentIndex: Number(create?.args.segmentIndex),
    capacity: Number(create?.args.capacity),
  });
  assert.equal(createData.length, 8 + 4 + 2 + 2);
  assert.equal(create?.args.capacity, 46);
  assert.equal(create?.args.configPda, configPda);

  const empty = new FakeChain();
  const fresh = await checkReadiness(baseOptions(empty));
  const init = itemOf(fresh, "registry").action;
  assert.equal(init?.kind, "initialize_registry");
  assert.equal(init?.args.registryIdHash, toHex(new Uint8Array(registryIdHash(REGISTRY_ID))));
  assert.equal(init?.args.programId, String(PROGRAM_ID));
  assert.equal(init?.args.schemaVersion, 1);
  assert.equal(init?.args.hashAlgorithm, 1);
  assert.equal(init?.args.treeAlgorithm, 1);
  assert.ok(Number(init?.args.anchorIntervalSeconds) > 0);
  assert.equal(Number(init?.args.maxEntriesPerDay), 3 * 46);
  const initData = getInitializeRegistryInstructionDataEncoder().encode({
    registryIdHash: Buffer.from(String(init?.args.registryIdHash), "hex"),
    emergencyAuthority: toAddress(String(init?.args.emergencyAuthority)),
    schemaVersion: Number(init?.args.schemaVersion),
    hashAlgorithm: Number(init?.args.hashAlgorithm),
    treeAlgorithm: Number(init?.args.treeAlgorithm),
    anchorIntervalSeconds: Number(init?.args.anchorIntervalSeconds),
    maxEntriesPerDay: Number(init?.args.maxEntriesPerDay),
  });
  assert.equal(initData.length, 8 + 32 + 32 + 2 + 1 + 1 + 4 + 2);
});

test("a named missing key file is reported with every plan targeting that file", async () => {
  const { chain } = await provision();
  const named = path.join(persistentKeyRoot({ home }), "named-operator.json");
  const report = await checkReadiness(baseOptions(chain, { keyFile: named }));
  assert.equal(report.operator.address, null);
  assert.equal(report.operator.source, "key-file");
  assert.equal(report.operator.signingKeyAvailable, false);
  assert.equal(report.operator.keyPath, named);
  const role = itemOf(report, "operator-role");
  assert.equal(role.action?.kind, "ensure_operator_key");
  assert.equal(role.action?.args.keyFile, named);
  assert.ok(!String(role.action?.args.keyFile).endsWith("demo-operator.json"), "the default path is not substituted");
});

test("an unsafe key-file path is refused as a request error, never silently downgraded", async () => {
  const { chain } = await provision();
  await assert.rejects(
    () => checkReadiness(baseOptions(chain, { keyFile: "/etc/passwd" })),
    (error: unknown) => {
      assert.ok(error instanceof RegistryRefusal);
      assert.equal(error.code, "REQUEST_INVALID");
      return true;
    },
  );
  await assert.rejects(
    () => checkReadiness(baseOptions(chain, { keyFile: "relative-key.json" })),
    (error: unknown) => {
      assert.ok(error instanceof RegistryRefusal);
      assert.equal(error.code, "REQUEST_INVALID");
      return true;
    },
  );
});

test("config data that does not match the expected registry is refused as ACCOUNT_DATA_MISMATCH", async () => {
  const { chain, configPda } = await provision();
  chain.accounts.set(configPda, configAccount(GOVERNANCE, false, new Uint8Array(32).fill(9)));
  const report = await checkReadiness(baseOptions(chain));
  const registry = itemOf(report, "registry");
  assert.equal(registry.status, "UNAVAILABLE");
  assert.deepEqual(blockerCodes(report, "registry"), ["ACCOUNT_DATA_MISMATCH"]);
  assert.equal(registry.action, null);
  for (const id of ["operator-role", "ledger-segment", "funding"]) {
    assert.equal(itemOf(report, id).status, "UNAVAILABLE", id);
    assert.deepEqual(blockerCodes(report, id), ["ACCOUNT_DATA_MISMATCH"], id);
    assert.equal(itemOf(report, id).action, null, id);
  }
  assert.equal(report.operator.governsRegistry, false);
  assert.equal(report.ok, false);
});

test("role data bound to a foreign registry is refused as ACCOUNT_DATA_MISMATCH", async () => {
  const { chain, rolePda } = await provision();
  chain.accounts.set(rolePda, roleAccount(String(addr(99)), OPERATOR, REQUIRED_OPERATOR_PERMISSIONS));
  const report = await checkReadiness(baseOptions(chain));
  const role = itemOf(report, "operator-role");
  assert.equal(role.status, "UNAVAILABLE");
  assert.deepEqual(blockerCodes(report, "operator-role"), ["ACCOUNT_DATA_MISMATCH"]);
  assert.equal(role.action, null);
  assert.match(role.detail, /does not match the expected registry/);
});

test("segment data with the wrong registry, day or index is refused as ACCOUNT_DATA_MISMATCH", async () => {
  const scenarios: Array<{
    label: string;
    build: (configPda: string) => { owner: string; data: Uint8Array };
  }> = [
    { label: "foreign registry", build: () => segmentAccount(String(addr(99)), DAY, 0) },
    { label: "wrong day", build: (configPda) => segmentAccount(configPda, 20260101, 0) },
    { label: "wrong index", build: (configPda) => segmentAccount(configPda, DAY, 2) },
  ];
  for (const scenario of scenarios) {
    const { chain, configPda, segments } = await provision();
    chain.accounts.set(segments[0], scenario.build(configPda));
    const report = await checkReadiness(baseOptions(chain));
    const segment = itemOf(report, "ledger-segment");
    assert.equal(segment.status, "UNAVAILABLE", scenario.label);
    assert.deepEqual(blockerCodes(report, "ledger-segment"), ["ACCOUNT_DATA_MISMATCH"], scenario.label);
    assert.equal(segment.action, null, scenario.label);
    assert.match(segment.detail, /registry\/day\/index/, scenario.label);
  }
});

test("oversized RPC and health bodies are refused within the bound", async () => {
  const huge = JSON.stringify({ jsonrpc: "2.0", id: 1, result: "ok", pad: "x".repeat(MAX_HTTP_BODY_BYTES) });
  const reader = new JsonRpcRegistryReader(
    "https://api.devnet.solana.com",
    (async () => new Response(huge, { status: 200, headers: { "content-type": "application/json" } })) as typeof fetch,
  );
  await assert.rejects(
    () => reader.getHealth(),
    (error: unknown) => {
      assert.ok(error instanceof RegistryRefusal);
      assert.equal(error.code, "HTTP_BODY_TOO_LARGE");
      return true;
    },
  );

  const { chain } = await provision();
  const report = await checkReadiness(
    baseOptions(chain, {
      request: (async (url: unknown) => {
        const target = String(url);
        if (!target.endsWith("/v1/health")) throw new Error(`unexpected url ${target}`);
        return new Response(JSON.stringify({ status: "ok", pad: "x".repeat(MAX_HTTP_BODY_BYTES) }), { status: 200 });
      }) as typeof fetch,
    }),
  );
  assert.equal(itemOf(report, "demo-api-health").status, "UNAVAILABLE");
  assert.deepEqual(blockerCodes(report, "demo-api-health"), ["SERVICE_UNREACHABLE"]);
  assert.match(itemOf(report, "demo-api-health").detail, /byte bound/);
});

async function withServer(
  rpc: (method: string, params: unknown[]) => unknown,
  exercise: (url: string) => Promise<void>,
): Promise<void> {
  const server = createServer((req, res) => {
    if (req.url !== undefined && req.url.endsWith("/v1/health")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "ok" }));
      return;
    }
    let body = "";
    req.on("data", (chunk: Buffer) => {
      body += String(chunk);
    });
    req.on("end", () => {
      const message = JSON.parse(body) as { id: number; method: string; params: unknown[] };
      let payload: unknown;
      try {
        payload = { jsonrpc: "2.0", id: message.id, result: rpc(message.method, message.params) };
      } catch {
        payload = { jsonrpc: "2.0", id: message.id, result: null };
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(payload));
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address !== null && typeof address === "object");
  try {
    await exercise(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test("CLI exit codes: ACCOUNT_* refusals are environment failures (exit 3, the drift repro)", async () => {
  const configData = configAccount(GOVERNANCE);
  await withServer(
    (method) => {
      switch (method) {
        case "getHealth":
          return "ok";
        case "getGenesisHash":
          return DEVNET_GENESIS_HASH;
        case "getAccountInfo":
          // Right size and discriminator, wrong owner.
          return {
            value: {
              owner: "11111111111111111111111111111111",
              data: [Buffer.from(configData.data).toString("base64"), "base64"],
            },
          };
        default:
          throw new Error(`unexpected method ${method}`);
      }
    },
    async (url) => {
      await assert.rejects(
        run(process.execPath, [
          ...NODE_ARGS,
          SCRIPT,
          "--rpc-url",
          url,
          "--demo-api-url",
          url,
          "--verifier-url",
          url,
          "--operator",
          OPERATOR,
          "--day",
          String(DAY),
        ]),
        (error: unknown) => {
          const failure = error as { code?: number; stderr?: string };
          assert.equal(failure.code, 3, "ACCOUNT_* is exit 3 (refused environment), not 2");
          assert.match(String(failure.stderr), /ACCOUNT_OWNER_MISMATCH/);
          return true;
        },
      );
    },
  );
});

test("CLI exit codes: request 2, link 3, report-not-ready 4 with one JSON report", async () => {
  await assert.rejects(run(process.execPath, [...NODE_ARGS, SCRIPT, "--day", "20261301"]), (error: unknown) => {
    const failure = error as { code?: number; stderr?: string };
    assert.equal(failure.code, 2);
    assert.match(String(failure.stderr), /REQUEST_INVALID/);
    return true;
  });
  await assert.rejects(
    run(process.execPath, [...NODE_ARGS, SCRIPT, "--demo-api-url", "http://example.com"]),
    (error: unknown) => {
      const failure = error as { code?: number; stderr?: string };
      assert.equal(failure.code, 3);
      assert.match(String(failure.stderr), /LINK_REFUSED/);
      return true;
    },
  );
  await assert.rejects(
    run(process.execPath, [...NODE_ARGS, SCRIPT, "--key-file", "/etc/passwd"]),
    (error: unknown) => {
      const failure = error as { code?: number; stderr?: string };
      assert.equal(failure.code, 2);
      assert.match(String(failure.stderr), /REQUEST_INVALID/);
      return true;
    },
  );

  await withServer(
    (method) => {
      switch (method) {
        case "getHealth":
          return "ok";
        case "getGenesisHash":
          return DEVNET_GENESIS_HASH;
        case "getAccountInfo":
          return { value: null };
        case "getBalance":
          return { value: 0 };
        case "getMinimumBalanceForRentExemption":
          return 2_000_000;
        default:
          throw new Error(`unexpected method ${method}`);
      }
    },
    async (url) => {
      await assert.rejects(
        run(process.execPath, [
          ...NODE_ARGS,
          SCRIPT,
          "--rpc-url",
          url,
          "--demo-api-url",
          url,
          "--verifier-url",
          url,
          "--operator",
          OPERATOR,
          "--day",
          String(DAY),
        ]),
        (error: unknown) => {
          const failure = error as { code?: number; stderr?: string; stdout?: string };
          assert.equal(failure.code, 4);
          const report = JSON.parse(String(failure.stdout)) as ReadinessReport;
          assert.equal(report.ok, false);
          assert.equal(itemOf(report, "registry").action?.kind, "initialize_registry");
          assert.match(String(failure.stderr), /^$/);
          return true;
        },
      );
    },
  );
});

