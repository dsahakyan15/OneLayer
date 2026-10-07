// Idempotent devnet readiness probe for the live-demo launcher and seed (A2).
//
// Reads only: loopback service health, the devnet RPC, and the on-chain
// accounts the publish path needs (registry config, operator role, the day's
// ledger segments), plus the local operator key store. It never sends a
// transaction, never deploys, never re-initializes the registry and never
// rotates trust: every idempotent action that is not already satisfied is
// reported as `ACTION_REQUIRED` with the exact planned action and its exact
// blocker (for the current devnet deployment the on-chain governance key was
// permanently lost, so governance-signed actions report
// `GOVERNANCE_KEY_UNAVAILABLE` instead of pretending they can run).
//
// Authority rules: a locally generated or supplied key never "governs" the
// registry unless its address equals the on-chain governance authority, and an
// authority mismatch blocks every funding or transaction plan before anything
// is attempted. Key material never reaches the report: only public addresses
// and the key file path appear.
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { address as toAddress, type Address } from "@solana/kit";
import { registryIdHash, toHex } from "../../../packages/canonical-ts/src/index.ts";
import {
  DAILY_ANCHOR_LEDGER_SEGMENT_DISCRIMINATOR,
  findLedgerSegmentPda,
  findRegistryConfigPda,
  findRolePda,
  getDailyAnchorLedgerSegmentDecoder,
  getDailyAnchorLedgerSegmentSize,
  getOperatorRoleDecoder,
  getOperatorRoleSize,
  getRegistryConfigDecoder,
  getRegistryConfigSize,
  ONELAYER_REGISTRY_PROGRAM_ADDRESS,
  OPERATOR_ROLE_DISCRIMINATOR,
  REGISTRY_CONFIG_DISCRIMINATOR,
} from "../../../packages/onchain-client/src/index.ts";
import { ledgerDay } from "../src/ledger-day.ts";
import {
  defaultKeyFile,
  ensureKeyPair,
  KeyStoreError,
  loadSigningKey,
  type KeyStoreOptions,
} from "./live-demo-key-store.ts";

process.removeAllListeners("warning");
process.on("warning", () => undefined);

export const REGISTRY_ID = "gov.registry.land";
export const PROGRAM_ID: Address = toAddress(ONELAYER_REGISTRY_PROGRAM_ADDRESS);
export const DEVNET_GENESIS_HASH = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
export const CLUSTER = "solana:devnet" as const;
export const PROFILE = "local-devnet-demo" as const;

export const PERM_PUBLISH_ANCHOR = 1;
export const PERM_CREATE_LEDGER = 2;
export const REQUIRED_OPERATOR_PERMISSIONS = PERM_PUBLISH_ANCHOR | PERM_CREATE_LEDGER;
export const SEGMENTS_PER_DAY = 3;
export const LEDGER_SEGMENT_CAPACITY = 46;
export const SIGNATURE_FEE_BUFFER_LAMPORTS = 50_000n;
/** Health/RPC JSON bodies are capped: nothing on these channels is large. */
export const MAX_HTTP_BODY_BYTES = 262_144;

/**
 * Parameter set for a fresh `initialize_registry`, exported so the seed can
 * rebuild the exact instruction from a plan. The current devnet registry was
 * created by the lost authority; these are the profile values for any new one.
 */
export const PLAN_SCHEMA_VERSION = 1;
export const PLAN_HASH_ALGORITHM = 1;
export const PLAN_TREE_ALGORITHM = 1;
export const PLAN_ANCHOR_INTERVAL_SECONDS = 3_600;
/** The ledger can physically hold `SEGMENTS_PER_DAY × LEDGER_SEGMENT_CAPACITY` entries per day. */
export const PLAN_MAX_ENTRIES_PER_DAY = SEGMENTS_PER_DAY * LEDGER_SEGMENT_CAPACITY;
/** `grant_operator` key-id binding for the demo operator: 32 zero bytes (unbound). */
export const UNBOUND_KEY_ID_HASH_HEX = "0".repeat(64);

export const DEFAULT_DEMO_API_URL = "http://127.0.0.1:8090";
export const DEFAULT_VERIFIER_URL = "http://127.0.0.1:8080";
export const DEFAULT_RPC_URL = "https://api.devnet.solana.com";

export class RegistryRefusal extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

export type ReadinessStatus = "READY" | "ACTION_REQUIRED" | "UNAVAILABLE";

export interface Blocker {
  code: string;
  detail: string;
}

export type ActionKind =
  | "ensure_operator_key"
  | "initialize_registry"
  | "unpause_registry"
  | "grant_operator"
  | "create_ledger_segment"
  | "fund_operator";

export interface PlannedAction {
  kind: ActionKind;
  /** Identity whose signature the action needs; `address` is null when unknown. */
  requiredSigner: { role: "governance" | "operator" | "funder"; address: string | null };
  /** Public parameters only: PDAs, permission bits, amounts. Never key bytes. */
  args: Record<string, string | number | null>;
}

export interface ReadinessItem {
  id: string;
  status: ReadinessStatus;
  detail: string;
  blockers: Blocker[];
  action: PlannedAction | null;
  observed: Record<string, string | number | boolean | null>;
}

export interface OperatorInfo {
  address: string | null;
  source: "argument" | "key-file" | "persistent-store" | "none";
  signingKeyAvailable: boolean;
  /** True only when the operator address equals the on-chain governance authority. */
  governsRegistry: boolean;
  keyPath: string | null;
}

export interface ReadinessReport {
  profile: typeof PROFILE;
  cluster: typeof CLUSTER;
  checkedAt: string;
  registryId: string;
  programId: string;
  configPda: string;
  dayUtc: number;
  operator: OperatorInfo;
  items: ReadinessItem[];
  ok: boolean;
}

export interface RegistryChainReader {
  getGenesisHash(): Promise<string>;
  getHealth(): Promise<string>;
  getAccountInfo(account: string): Promise<{ owner: string; data: Uint8Array } | null>;
  getBalanceLamports(account: string): Promise<bigint>;
  getMinimumBalanceForRentExemption(dataLength: number): Promise<bigint>;
}

interface JsonRpcResponse {
  result?: unknown;
  error?: { message?: unknown };
}

/** Streams a response body with a hard cap; refuses anything larger. */
async function readBodyBounded(response: Response, maxBytes: number = MAX_HTTP_BODY_BYTES): Promise<string> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const size = Number(declared);
    if (Number.isFinite(size) && size > maxBytes) throw new RegistryRefusal("HTTP_BODY_TOO_LARGE");
  }
  const body = response.body;
  if (body === null) return "";
  const reader = body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.byteLength;
      if (total > maxBytes) throw new RegistryRefusal("HTTP_BODY_TOO_LARGE");
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** Minimal JSON-RPC reader; `request` is injectable so tests stay hermetic. */
export class JsonRpcRegistryReader implements RegistryChainReader {
  private readonly rpcUrl: string;
  private readonly request: typeof fetch;
  private id = 0;

  constructor(rpcUrl: string, request: typeof fetch = fetch) {
    this.rpcUrl = rpcUrl;
    this.request = request;
  }

  private async rpc(method: string, params: unknown[]): Promise<unknown> {
    const response = await this.request(this.rpcUrl, {
      method: "POST",
      signal: AbortSignal.timeout(15_000),
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++this.id, method, params }),
    });
    if (!response.ok) throw new RegistryRefusal("RPC_UNREACHABLE");
    const text = await readBodyBounded(response);
    let payload: JsonRpcResponse;
    try {
      payload = JSON.parse(text) as JsonRpcResponse;
    } catch {
      throw new RegistryRefusal("RPC_UNREACHABLE");
    }
    if (payload.error !== undefined) throw new RegistryRefusal("RPC_UNREACHABLE");
    if (payload.result === undefined) throw new TypeError(`${method} returned no result`);
    return payload.result;
  }

  async getGenesisHash(): Promise<string> {
    const result = await this.rpc("getGenesisHash", []);
    if (typeof result !== "string" || result.length === 0) throw new TypeError("genesis hash is invalid");
    return result;
  }

  async getHealth(): Promise<string> {
    const result = await this.rpc("getHealth", []);
    if (typeof result !== "string") throw new TypeError("health is invalid");
    return result;
  }

  async getAccountInfo(account: string): Promise<{ owner: string; data: Uint8Array } | null> {
    const result = (await this.rpc("getAccountInfo", [account, { encoding: "base64", commitment: "finalized" }])) as {
      value?: { owner?: unknown; data?: unknown } | null;
    };
    const value = result?.value;
    if (value === null || value === undefined) return null;
    if (
      typeof value.owner !== "string" ||
      !Array.isArray(value.data) ||
      value.data[1] !== "base64" ||
      typeof value.data[0] !== "string"
    ) {
      throw new TypeError("account info is invalid");
    }
    return { owner: value.owner, data: Buffer.from(value.data[0], "base64") };
  }

  async getBalanceLamports(account: string): Promise<bigint> {
    const result = (await this.rpc("getBalance", [account, { commitment: "finalized" }])) as { value?: unknown };
    if (typeof result?.value !== "number" || !Number.isSafeInteger(result.value) || result.value < 0) {
      throw new TypeError("balance is invalid");
    }
    return BigInt(result.value);
  }

  async getMinimumBalanceForRentExemption(dataLength: number): Promise<bigint> {
    const result = await this.rpc("getMinimumBalanceForRentExemption", [dataLength]);
    if (typeof result !== "number" || !Number.isSafeInteger(result) || result < 0) {
      throw new TypeError("rent exemption is invalid");
    }
    return BigInt(result);
  }
}

export interface ReadinessOptions {
  rpcUrl?: string;
  demoApiUrl?: string;
  verifierUrl?: string;
  /** Explicit operator address (no key material involved). */
  operator?: string;
  /** Key file whose address is the operator; contents are never returned. */
  keyFile?: string;
  /** Idempotently create the persistent demo-operator key when missing. */
  initOperatorKey?: boolean;
  /** Ledger day override (UTC YYYYMMDD); defaults to the probe's clock. */
  dayUtc?: number;
  now?: Date;
  request?: typeof fetch;
  chain?: RegistryChainReader;
  keyStore?: KeyStoreOptions;
}

function requireHttpUrl(value: string, label: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new RegistryRefusal("REQUEST_INVALID");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new RegistryRefusal("REQUEST_INVALID");
  if (parsed.username !== "" || parsed.password !== "" || parsed.hash !== "") throw new RegistryRefusal("REQUEST_INVALID");
  if (label !== "rpcUrl" && parsed.hostname !== "127.0.0.1" && parsed.hostname !== "localhost") {
    // Service endpoints are loopback-only (ADR0006). The chain RPC is the one
    // endpoint allowed to leave the host.
    throw new RegistryRefusal("LINK_REFUSED");
  }
  return parsed;
}

function validDayUtc(value: number): boolean {
  if (!Number.isInteger(value) || value < 19700101 || value > 99991231) return false;
  const year = Math.floor(value / 10_000);
  const month = Math.floor(value / 100) % 100;
  const day = value % 100;
  const roundTrip = new Date(Date.UTC(year, month - 1, day));
  return (
    roundTrip.getUTCFullYear() === year &&
    roundTrip.getUTCMonth() === month - 1 &&
    roundTrip.getUTCDate() === day
  );
}

function requireBase58(value: string): Address {
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)) throw new RegistryRefusal("REQUEST_INVALID");
  try {
    return toAddress(value);
  } catch {
    throw new RegistryRefusal("REQUEST_INVALID");
  }
}

export interface RegistryPdas {
  programId: Address;
  configPda: Address;
  operatorRolePda: Address | null;
  segments: Array<{ index: number; pda: Address }>;
}

/** PDAs the publish path uses; exported so the seed can reuse the derivation. */
export async function derivePdas(operator: string | null, dayUtc: number): Promise<RegistryPdas> {
  const [configPda] = await findRegistryConfigPda(registryIdHash(REGISTRY_ID), { programAddress: PROGRAM_ID });
  const segments: Array<{ index: number; pda: Address }> = [];
  for (let index = 0; index < SEGMENTS_PER_DAY; index += 1) {
    const [pda] = await findLedgerSegmentPda(
      { config: configPda, dayUtc, segmentIndex: index },
      { programAddress: PROGRAM_ID },
    );
    segments.push({ index, pda });
  }
  if (operator === null) return { programId: PROGRAM_ID, configPda, operatorRolePda: null, segments };
  const [rolePda] = await findRolePda(
    { config: configPda, operator: toAddress(operator) },
    { programAddress: PROGRAM_ID },
  );
  return { programId: PROGRAM_ID, configPda, operatorRolePda: rolePda, segments };
}

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * `grant_operator` plan: every argument the instruction needs, so the seed can
 * rebuild `getGrantOperatorInstruction` from the report alone.
 */
export function planGrantOperator(args: {
  configPda: string;
  operator: string | null;
  rolePda: string | null;
  governanceAuthority: string | null;
  permissions?: number;
  /** 64 lowercase hex chars (32 bytes); defaults to the unbound zero digest. */
  keyIdHash?: string;
}): PlannedAction {
  const keyIdHash = args.keyIdHash ?? UNBOUND_KEY_ID_HASH_HEX;
  if (!HEX64.test(keyIdHash)) throw new RegistryRefusal("REQUEST_INVALID");
  return {
    kind: "grant_operator",
    requiredSigner: { role: "governance", address: args.governanceAuthority },
    args: {
      registryId: REGISTRY_ID,
      configPda: args.configPda,
      operator: args.operator,
      rolePda: args.rolePda,
      permissions: args.permissions ?? REQUIRED_OPERATOR_PERMISSIONS,
      validFrom: 0,
      validUntil: 0,
      keyIdHash,
    },
  };
}

/**
 * `initialize_registry` plan: the complete instruction data set (registry id
 * hash, emergency authority, schema/hash/tree identifiers, anchor interval
 * and daily entry limit) so the action is rebuildable from the report alone.
 */
export function planInitializeRegistry(args: {
  configPda: string;
  /** Signer that becomes the governance authority; also the emergency authority unless overridden. */
  initializer: string | null;
  emergencyAuthority?: string | null;
  registryIdHashHex?: string;
  schemaVersion?: number;
  hashAlgorithm?: number;
  treeAlgorithm?: number;
  anchorIntervalSeconds?: number;
  maxEntriesPerDay?: number;
}): PlannedAction {
  const emergencyAuthority = args.emergencyAuthority ?? args.initializer;
  return {
    kind: "initialize_registry",
    requiredSigner: { role: "governance", address: args.initializer },
    args: {
      registryId: REGISTRY_ID,
      registryIdHash: args.registryIdHashHex ?? toHex(registryIdHash(REGISTRY_ID)),
      configPda: args.configPda,
      programId: String(PROGRAM_ID),
      emergencyAuthority,
      schemaVersion: args.schemaVersion ?? PLAN_SCHEMA_VERSION,
      hashAlgorithm: args.hashAlgorithm ?? PLAN_HASH_ALGORITHM,
      treeAlgorithm: args.treeAlgorithm ?? PLAN_TREE_ALGORITHM,
      anchorIntervalSeconds: args.anchorIntervalSeconds ?? PLAN_ANCHOR_INTERVAL_SECONDS,
      maxEntriesPerDay: args.maxEntriesPerDay ?? PLAN_MAX_ENTRIES_PER_DAY,
    },
  };
}

export function planCreateLedgerSegment(args: {
  configPda: string;
  segmentPda: string | null;
  segmentIndex: number;
  dayUtc: number;
  capacity?: number;
  operator: string | null;
}): PlannedAction {
  return {
    kind: "create_ledger_segment",
    requiredSigner: { role: "operator", address: args.operator },
    args: {
      registryId: REGISTRY_ID,
      configPda: args.configPda,
      segmentPda: args.segmentPda,
      segmentIndex: args.segmentIndex,
      dayUtc: args.dayUtc,
      capacity: args.capacity ?? LEDGER_SEGMENT_CAPACITY,
    },
  };
}

export function planFundOperator(args: {
  operator: string | null;
  funder: string | null;
  lamports: bigint;
}): PlannedAction {
  return {
    kind: "fund_operator",
    requiredSigner: { role: "funder", address: args.funder },
    args: { to: args.operator, lamports: args.lamports.toString() },
  };
}

interface DecodedRegistry {
  paused: boolean;
  governanceAuthority: string;
  currentBatchSequence: string;
  /** Hex digest stored in the account; cross-checked against the expected registry. */
  registryIdHash: string;
}

interface DecodedRole {
  permissions: number;
  validFrom: string;
  validUntil: string;
  revokedAt: string;
  operator: string;
  /** Config PDA the role is bound to; cross-checked against the expected config. */
  registry: string;
}

interface DecodedSegment {
  sealed: number;
  entryCount: number;
  capacity: number;
  segmentIndex: number;
  /** Cross-checked against the expected registry, day and index. */
  registry: string;
  dayUtc: number;
}

function decodeAccount(
  account: { owner: string; data: Uint8Array } | null,
  discriminator: ArrayLike<number>,
  size: number,
): Uint8Array | null {
  if (account === null) return null;
  if (account.owner !== String(PROGRAM_ID)) throw new RegistryRefusal("ACCOUNT_OWNER_MISMATCH");
  const bytes = account.data;
  if (bytes.length !== size) throw new RegistryRefusal("ACCOUNT_SIZE_MISMATCH");
  if (!Buffer.from(discriminator).equals(Buffer.from(bytes.subarray(0, 8)))) {
    throw new RegistryRefusal("ACCOUNT_DISCRIMINATOR_MISMATCH");
  }
  return bytes;
}

function decodeRegistryConfig(account: { owner: string; data: Uint8Array } | null): DecodedRegistry | null {
  const bytes = decodeAccount(account, REGISTRY_CONFIG_DISCRIMINATOR, getRegistryConfigSize());
  if (bytes === null) return null;
  const config = getRegistryConfigDecoder().decode(bytes);
  return {
    paused: config.paused,
    governanceAuthority: String(config.governanceAuthority),
    currentBatchSequence: config.currentBatchSequence.toString(),
    registryIdHash: toHex(new Uint8Array(config.registryIdHash)),
  };
}

function decodeOperatorRole(account: { owner: string; data: Uint8Array } | null): DecodedRole | null {
  const bytes = decodeAccount(account, OPERATOR_ROLE_DISCRIMINATOR, getOperatorRoleSize());
  if (bytes === null) return null;
  const role = getOperatorRoleDecoder().decode(bytes);
  return {
    permissions: role.permissions,
    validFrom: role.validFrom.toString(),
    validUntil: role.validUntil.toString(),
    revokedAt: role.revokedAt.toString(),
    operator: String(role.operator),
    registry: String(role.registry),
  };
}

function decodeSegment(account: { owner: string; data: Uint8Array } | null): DecodedSegment | null {
  const bytes = decodeAccount(account, DAILY_ANCHOR_LEDGER_SEGMENT_DISCRIMINATOR, getDailyAnchorLedgerSegmentSize());
  if (bytes === null) return null;
  const segment = getDailyAnchorLedgerSegmentDecoder().decode(bytes);
  return {
    sealed: segment.sealed,
    entryCount: segment.entryCount,
    capacity: segment.capacity,
    segmentIndex: segment.segmentIndex,
    registry: String(segment.registry),
    dayUtc: segment.dayUtc,
  };
}

interface OperatorResolution {
  address: string | null;
  source: OperatorInfo["source"];
  signingKeyAvailable: boolean;
  keyPath: string | null;
  /** The key file this probe targets: explicit `--key-file` or the persistent default. */
  targetKeyFile: string;
}

async function resolveOperator(options: ReadinessOptions): Promise<OperatorResolution> {
  const targetKeyFile = options.keyFile ?? defaultKeyFile(options.keyStore);
  if (options.operator !== undefined) {
    requireBase58(options.operator);
    return { address: options.operator, source: "argument", signingKeyAvailable: false, keyPath: null, targetKeyFile };
  }
  const explicitKeyFile = options.keyFile !== undefined;
  const source = explicitKeyFile ? ("key-file" as const) : ("persistent-store" as const);
  const missing = (error: KeyStoreError): OperatorResolution => {
    // An explicitly named key file is never silently downgraded: an unsafe
    // path is refused as a request error, a missing/invalid file is reported
    // as the requested source so every plan targets FILE instead of the
    // default key file. The implicit default keeps its "no key yet" meaning.
    if (explicitKeyFile && error.code === "KEYFILE_REJECTED") {
      throw new RegistryRefusal("REQUEST_INVALID");
    }
    return {
      address: null,
      source: explicitKeyFile ? "key-file" : "none",
      signingKeyAvailable: false,
      keyPath: explicitKeyFile ? targetKeyFile : null,
      targetKeyFile,
    };
  };
  if (options.initOperatorKey === true) {
    try {
      const ensured = await ensureKeyPair({ ...options.keyStore, keyFile: targetKeyFile });
      return { address: ensured.address, source, signingKeyAvailable: true, keyPath: ensured.path, targetKeyFile };
    } catch (error) {
      if (error instanceof KeyStoreError) return missing(error);
      throw error;
    }
  }
  try {
    const loaded = await loadSigningKey(targetKeyFile, options.keyStore);
    return {
      address: String(loaded.address),
      source,
      signingKeyAvailable: true,
      keyPath: targetKeyFile,
      targetKeyFile,
    };
  } catch (error) {
    if (error instanceof KeyStoreError) return missing(error);
    throw error;
  }
}

/**
 * The honest authority story: governance-signed work is blocked unless the
 * local signing key IS the on-chain governance authority. A generated or
 * supplied key is never treated as governing, and nothing is substituted for
 * the lost authority.
 */
function governanceBlockers(config: DecodedRegistry | null, operator: OperatorResolution): Blocker[] {
  if (config === null) {
    if (operator.signingKeyAvailable && operator.address !== null) return [];
    return [{ code: "OPERATOR_KEY_UNAVAILABLE", detail: "no local operator key is available to govern a fresh registry" }];
  }
  if (operator.signingKeyAvailable && operator.address === config.governanceAuthority) return [];
  const local = operator.address === null ? "none" : operator.address;
  return [
    {
      code: "GOVERNANCE_KEY_UNAVAILABLE",
      detail:
        `on-chain governance authority ${config.governanceAuthority} has no local key; ` +
        `local operator ${local} does not govern this registry and nothing is substituted for the lost authority`,
    },
  ];
}

function item(
  id: string,
  status: ReadinessStatus,
  detail: string,
  extra: {
    blockers?: Blocker[];
    action?: PlannedAction | null;
    observed?: Record<string, string | number | boolean | null>;
  } = {},
): ReadinessItem {
  return {
    id,
    status,
    detail,
    blockers: extra.blockers ?? [],
    action: extra.action ?? null,
    observed: extra.observed ?? {},
  };
}

async function probeHealth(url: string, request: typeof fetch): Promise<{ ok: boolean; detail: string }> {
  try {
    const response = await request(url, { method: "GET", signal: AbortSignal.timeout(5_000) });
    if (!response.ok) return { ok: false, detail: `health returned HTTP ${response.status}` };
    const text = await readBodyBounded(response);
    let body: { status?: unknown };
    try {
      body = JSON.parse(text) as { status?: unknown };
    } catch {
      return { ok: false, detail: "health payload is not valid JSON" };
    }
    if (body?.status !== "ok") return { ok: false, detail: "health payload is not ok" };
    return { ok: true, detail: "healthy" };
  } catch (error) {
    if (error instanceof RegistryRefusal && error.code === "HTTP_BODY_TOO_LARGE") {
      return { ok: false, detail: `health response exceeded the ${MAX_HTTP_BODY_BYTES} byte bound` };
    }
    return { ok: false, detail: "health endpoint is unreachable" };
  }
}

/**
 * Idempotent readiness probe. Running it twice yields the same report and it
 * performs no chain mutation of any kind: satisfied state is `READY`, missing
 * state is `ACTION_REQUIRED` with the exact planned action and blockers.
 */
export async function checkReadiness(options: ReadinessOptions = {}): Promise<ReadinessReport> {
  const request = options.request ?? fetch;
  const rpcUrl = requireHttpUrl(options.rpcUrl ?? DEFAULT_RPC_URL, "rpcUrl");
  const demoApiUrl = requireHttpUrl(options.demoApiUrl ?? DEFAULT_DEMO_API_URL, "demoApiUrl");
  const verifierUrl = requireHttpUrl(options.verifierUrl ?? DEFAULT_VERIFIER_URL, "verifierUrl");
  const now = options.now ?? new Date();
  const dayUtc = options.dayUtc ?? ledgerDay(now);
  if (!validDayUtc(dayUtc)) {
    throw new RegistryRefusal("REQUEST_INVALID");
  }

  const operator = await resolveOperator(options);
  const chain = options.chain ?? new JsonRpcRegistryReader(rpcUrl.toString(), request);
  const pdas = await derivePdas(operator.address, dayUtc);
  const items: ReadinessItem[] = [];

  const demoHealth = await probeHealth(new URL("/v1/health", demoApiUrl).toString(), request);
  items.push(
    demoHealth.ok
      ? item("demo-api-health", "READY", demoHealth.detail, { observed: { url: demoApiUrl.toString() } })
      : item("demo-api-health", "UNAVAILABLE", demoHealth.detail, {
          blockers: [
            { code: "SERVICE_UNREACHABLE", detail: `demo-api health check failed at ${demoApiUrl.toString()}` },
          ],
          observed: { url: demoApiUrl.toString() },
        }),
  );

  const verifierHealth = await probeHealth(new URL("/v1/health", verifierUrl).toString(), request);
  items.push(
    verifierHealth.ok
      ? item("verifier-health", "READY", verifierHealth.detail, { observed: { url: verifierUrl.toString() } })
      : item("verifier-health", "UNAVAILABLE", verifierHealth.detail, {
          blockers: [
            { code: "SERVICE_UNREACHABLE", detail: `verifier health check failed at ${verifierUrl.toString()}` },
          ],
          observed: { url: verifierUrl.toString() },
        }),
  );

  let chainReady = false;
  try {
    const health = await chain.getHealth();
    if (health !== "ok") throw new RegistryRefusal("RPC_UNREACHABLE");
    const genesis = await chain.getGenesisHash();
    if (genesis !== DEVNET_GENESIS_HASH) {
      items.push(
        item("chain", "UNAVAILABLE", "the configured RPC is not Solana devnet", {
          blockers: [
            {
              code: "CLUSTER_NOT_DEVNET",
              detail: `genesis ${genesis} is not the devnet genesis ${DEVNET_GENESIS_HASH}`,
            },
          ],
          observed: { rpcUrl: rpcUrl.toString(), genesisHash: genesis },
        }),
      );
    } else {
      chainReady = true;
      items.push(
        item("chain", "READY", "devnet genesis confirmed", {
          observed: { rpcUrl: rpcUrl.toString(), genesisHash: genesis },
        }),
      );
    }
  } catch (error) {
    const code = error instanceof RegistryRefusal ? error.code : "RPC_UNREACHABLE";
    items.push(
      item("chain", "UNAVAILABLE", `chain read failed: ${code}`, {
        blockers: [{ code, detail: `unable to read ${rpcUrl.toString()}` }],
        observed: { rpcUrl: rpcUrl.toString(), genesisHash: null },
      }),
    );
  }

  let config: DecodedRegistry | null = null;
  let configTrusted = false;
  if (!chainReady) {
    const blocked = {
      blockers: [{ code: "CHAIN_UNAVAILABLE", detail: "devnet chain is not available; chain state was not assessed" }],
    };
    items.push(item("registry", "UNAVAILABLE", "not assessed", blocked));
    items.push(item("operator-role", "UNAVAILABLE", "not assessed", blocked));
    items.push(item("ledger-segment", "UNAVAILABLE", "not assessed", blocked));
    items.push(item("funding", "UNAVAILABLE", "not assessed", blocked));
  } else {
    config = decodeRegistryConfig(await chain.getAccountInfo(pdas.configPda));
    const expectedRegistryIdHash = toHex(new Uint8Array(registryIdHash(REGISTRY_ID)));
    const configMismatch =
      config !== null && config.registryIdHash !== expectedRegistryIdHash
        ? {
            detail: `config at ${pdas.configPda} carries registryIdHash ${config.registryIdHash}, expected ${expectedRegistryIdHash}`,
            observedHash: config.registryIdHash,
          }
        : null;
    configTrusted = config !== null && configMismatch === null;
    const govBlockers = governanceBlockers(config, operator);
    const governsRegistry =
      configTrusted &&
      config !== null &&
      operator.signingKeyAvailable &&
      operator.address === config.governanceAuthority;

    if (configMismatch !== null) {
      // The account at the derived config PDA is not this registry: nothing
      // decoded from this RPC response is trusted for further planning.
      const blocked = {
        blockers: [{ code: "ACCOUNT_DATA_MISMATCH", detail: configMismatch.detail }],
        action: null,
      };
      items.push(item("registry", "UNAVAILABLE", "registry config account does not match the expected registry", {
        ...blocked,
        observed: { configPda: pdas.configPda, exists: true, registryIdHash: configMismatch.observedHash },
      }));
      items.push(item("operator-role", "UNAVAILABLE", "not assessed: registry config data mismatch", blocked));
      items.push(item("ledger-segment", "UNAVAILABLE", "not assessed: registry config data mismatch", blocked));
      items.push(item("funding", "UNAVAILABLE", "not assessed: registry config data mismatch", blocked));
    } else {
      // The assessment below runs only when the config account is absent
      // or its data matches the expected registry; a mismatched config
      // means none of the decoded chain data can be trusted.
      if (config === null) {
        items.push(
          item("registry", "ACTION_REQUIRED", "registry config account does not exist", {
            blockers: govBlockers,
            action: planInitializeRegistry({ configPda: pdas.configPda, initializer: operator.address }),
            observed: { configPda: pdas.configPda, exists: false },
          }),
        );
      } else if (config.paused) {
        items.push(
          item("registry", "ACTION_REQUIRED", "registry is paused", {
            blockers: [
              { code: "REGISTRY_PAUSED", detail: "the on-chain pause flag is set; publishing cannot proceed" },
              ...govBlockers,
            ],
            action: {
              kind: "unpause_registry",
              requiredSigner: { role: "governance", address: config.governanceAuthority },
              args: { registryId: REGISTRY_ID, configPda: pdas.configPda },
            },
            observed: {
              configPda: pdas.configPda,
              exists: true,
              paused: true,
              governanceAuthority: config.governanceAuthority,
              currentBatchSequence: config.currentBatchSequence,
              localKeyGovernsRegistry: governsRegistry,
            },
          }),
        );
      } else {
        items.push(
          item("registry", "READY", "registry is initialized and not paused", {
            observed: {
              configPda: pdas.configPda,
              exists: true,
              paused: false,
              governanceAuthority: config.governanceAuthority,
              currentBatchSequence: config.currentBatchSequence,
              localKeyGovernsRegistry: governsRegistry,
            },
          }),
        );
      }

      const rolePda = pdas.operatorRolePda;
      const role =
        operator.address === null || rolePda === null ? null : decodeOperatorRole(await chain.getAccountInfo(rolePda));
      const nowSeconds = BigInt(Math.floor(now.getTime() / 1000));
      if (operator.address === null) {
        items.push(
          item("operator-role", "ACTION_REQUIRED", "no local operator address is known", {
            blockers: [
              {
                code: "OPERATOR_KEY_UNAVAILABLE",
                detail:
                  operator.keyPath !== null
                    ? `the key file ${operator.keyPath} did not yield a signing key`
                    : "no local operator key or address was supplied",
              },
            ],
            action: {
              kind: "ensure_operator_key",
              requiredSigner: { role: "operator", address: null },
              args: { keyFile: operator.targetKeyFile },
            },
            observed: { rolePda: null, exists: false, keyFile: operator.targetKeyFile },
          }),
        );
      } else if (role !== null && role.registry !== pdas.configPda) {
        items.push(
          item("operator-role", "UNAVAILABLE", "operator role data does not match the expected registry", {
            blockers: [
              {
                code: "ACCOUNT_DATA_MISMATCH",
                detail: `role at ${rolePda} is bound to registry ${role.registry}, expected ${pdas.configPda}`,
              },
            ],
            action: null,
            observed: { rolePda: rolePda === null ? null : String(rolePda), exists: true, registry: role.registry },
          }),
        );
      } else if (role === null) {
        items.push(
          item("operator-role", "ACTION_REQUIRED", "operator role is not granted on chain", {
            blockers: govBlockers,
            action: planGrantOperator({
              configPda: pdas.configPda,
              operator: operator.address,
              rolePda: rolePda === null ? null : String(rolePda),
              governanceAuthority: config?.governanceAuthority ?? null,
            }),
            observed: { rolePda: rolePda === null ? null : String(rolePda), exists: false, operator: operator.address },
          }),
        );
      } else {
        const problems: Blocker[] = [];
        if (role.operator !== operator.address) {
          problems.push({ code: "OPERATOR_MISMATCH", detail: "role account does not belong to the operator address" });
        }
        if (role.revokedAt !== "0") {
          problems.push({ code: "OPERATOR_ROLE_REVOKED", detail: "operator role is revoked on chain" });
        } else {
          if (BigInt(role.validFrom) > nowSeconds) {
            problems.push({ code: "OPERATOR_ROLE_NOT_YET_VALID", detail: "operator role validity has not started" });
          }
          if (role.validUntil !== "0" && BigInt(role.validUntil) < nowSeconds) {
            problems.push({ code: "OPERATOR_ROLE_EXPIRED", detail: "operator role validity has ended" });
          }
        }
        if ((role.permissions & REQUIRED_OPERATOR_PERMISSIONS) !== REQUIRED_OPERATOR_PERMISSIONS) {
          problems.push({
            code: "OPERATOR_PERMISSIONS_INSUFFICIENT",
            detail: `role permissions ${role.permissions} lack ${REQUIRED_OPERATOR_PERMISSIONS}`,
          });
        }
        const granted: PlannedAction | null =
          problems.length === 0
            ? null
            : planGrantOperator({
                configPda: pdas.configPda,
                operator: operator.address,
                rolePda: rolePda === null ? null : String(rolePda),
                governanceAuthority: config?.governanceAuthority ?? null,
              });
        items.push(
          item(
            "operator-role",
            problems.length === 0 ? "READY" : "ACTION_REQUIRED",
            problems.length === 0 ? "operator role is active" : "operator role is not usable",
            {
              blockers: problems.length === 0 ? [] : [...problems, ...govBlockers],
              action: granted,
              observed: {
                rolePda: rolePda === null ? null : String(rolePda),
                exists: true,
                operator: role.operator,
                permissions: role.permissions,
                validFrom: role.validFrom,
                validUntil: role.validUntil,
                revokedAt: role.revokedAt,
              },
            },
          ),
        );
      }

      let openSegment: { index: number; pda: Address } | null = null;
      let existingSegments = 0;
      let nextIndex = 0;
      let segmentMismatch: string | null = null;
      for (const entry of pdas.segments) {
        const decoded = decodeSegment(await chain.getAccountInfo(entry.pda));
        if (decoded !== null) {
          existingSegments += 1;
          nextIndex = entry.index + 1;
          if (
            decoded.registry !== pdas.configPda ||
            decoded.dayUtc !== dayUtc ||
            decoded.segmentIndex !== entry.index
          ) {
            segmentMismatch ??=
              `segment ${entry.index} at ${entry.pda} carries registry/dayUtc/segmentIndex ` +
              `${decoded.registry}/${decoded.dayUtc}/${decoded.segmentIndex}, expected ` +
              `${pdas.configPda}/${dayUtc}/${entry.index}`;
            continue;
          }
          if (openSegment === null && decoded.sealed === 0 && decoded.entryCount < decoded.capacity) openSegment = entry;
        }
      }
      if (segmentMismatch !== null) {
        items.push(
          item("ledger-segment", "UNAVAILABLE", "ledger segment data does not match the expected registry/day/index", {
            blockers: [{ code: "ACCOUNT_DATA_MISMATCH", detail: segmentMismatch }],
            action: null,
            observed: { dayUtc, existingSegments },
          }),
        );
      } else if (openSegment !== null) {
        items.push(
          item("ledger-segment", "READY", "an open ledger segment exists for the day", {
            observed: {
              dayUtc,
              segmentPda: String(openSegment.pda),
              segmentIndex: openSegment.index,
              existingSegments,
            },
          }),
        );
      } else if (existingSegments === 0) {
        const action = planCreateLedgerSegment({
          configPda: pdas.configPda,
          segmentPda: String(pdas.segments[0].pda),
          segmentIndex: 0,
          dayUtc,
          operator: operator.address,
        });
        items.push(
          item("ledger-segment", "ACTION_REQUIRED", "no ledger segment exists for the day", {
            blockers:
              role === null
                ? [
                    {
                      code: "OPERATOR_ROLE_MISSING",
                      detail: "the operator role is not active on chain, so no ledger segment can be created",
                    },
                    ...govBlockers,
                  ]
                : operator.signingKeyAvailable
                  ? []
                  : [
                      {
                        code: "OPERATOR_KEY_UNAVAILABLE",
                        detail: "the local operator signing key is unavailable to create the ledger segment",
                      },
                    ],
            action,
            observed: { dayUtc, segmentPda: String(pdas.segments[0].pda), segmentIndex: 0, existingSegments: 0 },
          }),
        );
      } else if (nextIndex < SEGMENTS_PER_DAY) {
        items.push(
          item("ledger-segment", "ACTION_REQUIRED", "the day's ledger segments are sealed or full", {
            blockers:
              role === null
                ? [
                    {
                      code: "OPERATOR_ROLE_MISSING",
                      detail: "the operator role is not active on chain, so no ledger segment can be created",
                    },
                    ...govBlockers,
                  ]
                : operator.signingKeyAvailable
                  ? []
                  : [
                      {
                        code: "OPERATOR_KEY_UNAVAILABLE",
                        detail: "the local operator signing key is unavailable to create the ledger segment",
                      },
                    ],
            action: planCreateLedgerSegment({
              configPda: pdas.configPda,
              segmentPda: String(pdas.segments[nextIndex].pda),
              segmentIndex: nextIndex,
              dayUtc,
              operator: operator.address,
            }),
            observed: { dayUtc, segmentIndex: nextIndex, existingSegments },
          }),
        );
      } else {
        items.push(
          item("ledger-segment", "UNAVAILABLE", "every ledger segment for the day is full", {
            blockers: [{ code: "LEDGER_SEGMENT_FULL", detail: `all ${SEGMENTS_PER_DAY} segments for ${dayUtc} are sealed or full` }],
            observed: { dayUtc, existingSegments },
          }),
        );
      }

      if (operator.address === null) {
        items.push(
          item("funding", "UNAVAILABLE", "no operator address to fund", {
            blockers: [{ code: "OPERATOR_KEY_UNAVAILABLE", detail: "no local operator key or address was supplied" }],
            observed: {},
          }),
        );
      } else {
        const balance = await chain.getBalanceLamports(operator.address);
        const rent = await chain.getMinimumBalanceForRentExemption(getDailyAnchorLedgerSegmentSize());
        const required = rent + SIGNATURE_FEE_BUFFER_LAMPORTS;
        const shortfall = required > balance ? required - balance : 0n;
        const funder = config?.governanceAuthority ?? null;
        if (shortfall === 0n) {
          items.push(
            item("funding", "READY", "operator holds enough devnet SOL for rent and fees", {
              observed: {
                operator: operator.address,
                balanceLamports: balance.toString(),
                requiredLamports: required.toString(),
                shortfallLamports: "0",
              },
            }),
          );
        } else {
          items.push(
            item("funding", "ACTION_REQUIRED", "operator devnet SOL is below the rent and fee requirement", {
              // Funding is a transfer of value: it is planned only, and the
              // authority check keeps it blocked before anything is attempted.
              blockers: govBlockers,
              action: planFundOperator({ operator: operator.address, funder, lamports: shortfall }),
              observed: {
                operator: operator.address,
                balanceLamports: balance.toString(),
                requiredLamports: required.toString(),
                shortfallLamports: shortfall.toString(),
              },
            }),
          );
        }
      }
    }
  }

  const report: ReadinessReport = {
    profile: PROFILE,
    cluster: CLUSTER,
    checkedAt: now.toISOString(),
    registryId: REGISTRY_ID,
    programId: String(PROGRAM_ID),
    configPda: pdas.configPda,
    dayUtc,
    operator: {
      address: operator.address,
      source: operator.source,
      signingKeyAvailable: operator.signingKeyAvailable,
      governsRegistry:
        configTrusted && operator.signingKeyAvailable && config !== null && operator.address === config.governanceAuthority,
      keyPath: operator.keyPath,
    },
    items,
    ok: items.every((entry) => entry.status === "READY"),
  };
  return report;
}

const USAGE = `Usage: live-demo-registry.ts [options]

Idempotent devnet readiness probe for the live-demo launcher and seed. Reads
loopback service health, the devnet RPC and the registry/operator-role/ledger
accounts, then prints one JSON readiness report. It never sends a transaction,
never deploys and never rotates trust: not-yet-satisfied state is reported as
ACTION_REQUIRED with the exact planned action and its exact blocker.

Options:
  --rpc-url URL         Solana RPC endpoint (default: ${DEFAULT_RPC_URL})
  --demo-api-url URL    loopback demo-api base URL (default: ${DEFAULT_DEMO_API_URL})
  --verifier-url URL    loopback verifier base URL (default: ${DEFAULT_VERIFIER_URL})
  --operator ADDRESS    operator address to assess (no key access)
  --key-file FILE       resolve the operator address from this key file
                        (unsafe paths are refused; a missing/invalid file is
                        reported and every plan targets FILE, not the default)
  --init-operator-key   idempotently create the persistent demo-operator key
  --day YYYYMMDD        ledger day override (UTC)
  -h, --help            show this help

Output (success): one JSON readiness report on stdout
Output (failure): {"error":{"code":"..."}} on stderr
Exit codes: 0 ready, 2 refused request (REQUEST_INVALID — including unsafe
--key-file paths), 3 refused environment (LINK_REFUSED, RPC_UNREACHABLE,
HTTP_BODY_TOO_LARGE, ACCOUNT_*), 4 report produced but not ready,
1 internal error.
`;

/**
 * Exit mapping: only an invalid request is exit 2; every other refusal is an
 * environment problem (exit 3). Internal errors are exit 1.
 */
function exitCodeFor(error: unknown): number {
  if (!(error instanceof RegistryRefusal)) return 1;
  return error.code === "REQUEST_INVALID" ? 2 : 3;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const options: ReadinessOptions = {};
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "-h" || argument === "--help") {
      process.stdout.write(USAGE);
      return;
    }
    const take = (): string => {
      const value = args[index + 1];
      if (value === undefined || value === "") throw new RegistryRefusal("REQUEST_INVALID");
      index += 1;
      return value;
    };
    if (argument === "--rpc-url") options.rpcUrl = take();
    else if (argument === "--demo-api-url") options.demoApiUrl = take();
    else if (argument === "--verifier-url") options.verifierUrl = take();
    else if (argument === "--operator") options.operator = take();
    else if (argument === "--key-file") options.keyFile = take();
    else if (argument === "--init-operator-key") options.initOperatorKey = true;
    else if (argument === "--day") {
      const value = take();
      if (!/^[0-9]{8}$/.test(value)) throw new RegistryRefusal("REQUEST_INVALID");
      options.dayUtc = Number(value);
    } else throw new RegistryRefusal("REQUEST_INVALID");
  }
  const report = await checkReadiness(options);
  process.stdout.write(`${JSON.stringify(report)}\n`);
  if (!report.ok) process.exitCode = 4;
}

const entry = process.argv[1] === undefined ? "" : pathToFileURL(path.resolve(process.argv[1])).href;
if (entry !== "" && import.meta.url === entry) {
  main().catch((error: unknown) => {
    const code = error instanceof RegistryRefusal ? error.code : "REGISTRY_INTERNAL_ERROR";
    process.stderr.write(`${JSON.stringify({ error: { code } })}\n`);
    process.exit(exitCodeFor(error));
  });
}
