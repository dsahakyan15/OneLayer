// Standalone fallback-certificate path for the live-demo seed (B4).
//
// With the explicit `--approve-fallback` confirmation the seed drives the real
// demo-api publication flow end to end — session, publish intent, the accepted
// A1 signer (`signApprovedTransaction`) over the server-prepared bytes,
// reconciliation to FINALIZED, and certificate issuance with selective
// disclosure (status + areaSquareMeters) — then verifies the result with the
// loopback verifier before it is stored. Artifacts are fresh private files
// outside the repository; a previous finalized fallback is reused only after
// the same verification passes again. Nothing here is fixture data: there is
// no synthetic issuer, no fake anchor and no demo presented as live. The
// password is read only from the private runtime credential file and never
// printed; key material stays in the A1 loader.
import { lstat, mkdir, open, readFile, readdir } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  signApprovedTransaction,
  SignerRefusal,
} from "../../../apps/demo-api/scripts/live-demo-sign.ts";
import type { KeyStoreOptions } from "../../../apps/demo-api/scripts/live-demo-key-store.ts";
import {
  assertCertificateId,
  SeedRefusal,
  randomIdempotencyKey,
  requireServiceUrl,
  type SeedSigner,
} from "./live-demo-seed-kit.ts";

export const FALLBACK_DISCLOSED_PATHS = ["areaSquareMeters", "status"] as const;
export const FALLBACK_RECORD_ID = "SYNTHETIC-1";
export const DEFAULT_CREDENTIAL_PATH = "/dev/shm/onelayer-devnet-demo/admin-credentials.json";
export const MAX_FALLBACK_BODY_BYTES = 1 << 20;
export const MAX_CREDENTIAL_BYTES = 8_192;

const VERIFIED_STATUSES = new Set(["VERIFIED", "VERIFIED_HISTORICAL", "VERIFIED_NO_INCIDENT_CHECK"]);
const LIVE_CERTIFICATE_STATUSES = new Set(["ACTIVE"]);

export interface FallbackArtifacts {
  dir: string;
  manifest: string;
  packageFile: string;
  qrFile: string;
}

export interface FallbackVerification {
  status: string;
  code: string | null;
}

export interface FallbackReport {
  schema: "onelayer.live-demo.fallback.v1";
  mode: "reused" | "created";
  recordId: string;
  certificateId: string;
  certificateHash: string;
  qrUrl: string;
  transactionSignature: string;
  anchorSlot: string;
  disclosureMode: string;
  disclosedPaths: string[];
  verified: FallbackVerification | null;
  certificateStatus: string | null;
  artifacts: FallbackArtifacts | null;
  detail: string;
  ok: boolean;
}

export interface FallbackOptions {
  demoApiUrl: string;
  verifierUrl: string;
  signer: SeedSigner;
  approveFallback: boolean;
  /** Operator key file for the accepted A1 signer (persistent store policy). */
  keyFile?: string;
  /** Key-store home override for out-of-band seeding and tests. */
  keyStore?: KeyStoreOptions;
  credentialPath?: string;
  privateRoot?: string;
  artifactsDir?: string;
  recordId?: string;
  now?: Date;
  request?: typeof fetch;
  reconcileAttempts?: number;
  reconcileDelayMs?: number;
}

async function boundedBytes(response: Response, maxBytes = MAX_FALLBACK_BODY_BYTES): Promise<Buffer> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const size = Number(declared);
    if (Number.isFinite(size) && size > maxBytes) throw new SeedRefusal("HTTP_BODY_TOO_LARGE");
  }
  const body = response.body;
  if (body === null) return Buffer.alloc(0);
  const reader = body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value === undefined) continue;
    total += value.byteLength;
    if (total > maxBytes) throw new SeedRefusal("HTTP_BODY_TOO_LARGE");
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

/** The private runtime credential file policy of the B1 session layer. */
export async function loadOperatorPassword(
  credentialPath: string = DEFAULT_CREDENTIAL_PATH,
  privateRoot: string = "/dev/shm",
): Promise<string> {
  const root = path.resolve(privateRoot);
  const target = path.resolve(credentialPath);
  if (!path.isAbsolute(credentialPath)) throw new SeedRefusal("CREDENTIALS_UNAVAILABLE");
  const relative = path.relative(root, target);
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new SeedRefusal("CREDENTIALS_UNAVAILABLE");
  }
  const stats = await lstat(target).catch(() => undefined);
  if (stats === undefined || !stats.isFile() || stats.isSymbolicLink()) {
    throw new SeedRefusal("CREDENTIALS_UNAVAILABLE");
  }
  const uid = process.getuid?.();
  if (uid !== undefined && stats.uid !== uid) throw new SeedRefusal("CREDENTIALS_UNAVAILABLE");
  if ((stats.mode & 0o077) !== 0) throw new SeedRefusal("CREDENTIALS_UNAVAILABLE");
  const parent = await lstat(path.dirname(target)).catch(() => undefined);
  if (parent === undefined || !parent.isDirectory() || parent.isSymbolicLink()) {
    throw new SeedRefusal("CREDENTIALS_UNAVAILABLE");
  }
  if (uid !== undefined && parent.uid !== uid) throw new SeedRefusal("CREDENTIALS_UNAVAILABLE");
  if ((parent.mode & 0o077) !== 0) throw new SeedRefusal("CREDENTIALS_UNAVAILABLE");
  if (stats.size <= 0 || stats.size > MAX_CREDENTIAL_BYTES) throw new SeedRefusal("CREDENTIALS_UNAVAILABLE");
  const raw = await readFile(target);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new SeedRefusal("CREDENTIALS_UNAVAILABLE");
  }
  const password = (parsed as { operator?: unknown } | null)?.operator;
  if (typeof password !== "string" || password.length < 16) throw new SeedRefusal("CREDENTIALS_UNAVAILABLE");
  for (const character of password) {
    if (character < " " || character === "\x7f") throw new SeedRefusal("CREDENTIALS_UNAVAILABLE");
  }
  return password;
}

interface SessionState {
  cookie: string | null;
  csrf: string | null;
}

class LoopbackClient {
  readonly origin: URL;
  private readonly request: typeof fetch;
  private readonly session: SessionState = { cookie: null, csrf: null };

  constructor(origin: string, request: typeof fetch = fetch) {
    this.origin = requireServiceUrl(origin, "serviceUrl");
    this.request = request;
  }

  async call(
    method: string,
    route: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ): Promise<{ status: number; payload: unknown; raw: Buffer }> {
    const url = new URL(route, this.origin);
    if (url.origin !== this.origin.origin) throw new SeedRefusal("REQUEST_INVALID");
    const requestHeaders: Record<string, string> = { ...headers };
    if (this.session.cookie !== null) requestHeaders.cookie = this.session.cookie;
    if (method !== "GET" && method !== "HEAD" && this.session.csrf !== null) {
      requestHeaders["x-onelayer-csrf"] = this.session.csrf;
    }
    let payload: string | undefined;
    if (body !== undefined) {
      payload = JSON.stringify(body);
      requestHeaders["content-type"] = "application/json; charset=utf-8";
      if (Buffer.byteLength(payload, "utf8") > 262_144) throw new SeedRefusal("REQUEST_TOO_LARGE");
    }
    let response: Response;
    try {
      response = await this.request(url.toString(), {
        method,
        redirect: "manual",
        signal: AbortSignal.timeout(20_000),
        headers: requestHeaders,
        body: payload,
      });
    } catch {
      throw new SeedRefusal("SERVICE_UNREACHABLE");
    }
    const raw = await boundedBytes(response);
    const setCookie = response.headers.get("set-cookie");
    if (setCookie !== null) {
      const match = /(^|;\s*)onelayer_admin_session=([^;]+)/.exec(setCookie);
      if (match !== null) this.session.cookie = `onelayer_admin_session=${match[2]}`;
    }
    let parsed: unknown = null;
    if (raw.length > 0) {
      try {
        parsed = JSON.parse(raw.toString("utf8"));
      } catch {
        parsed = null;
      }
    }
    return { status: response.status, payload: parsed, raw };
  }

  adoptSession(payload: unknown): void {
    const csrf = (payload as { csrfToken?: unknown } | null)?.csrfToken;
    if (typeof csrf === "string" && csrf.length > 0 && csrf.length <= 256) this.session.csrf = csrf;
  }

  clearSession(): void {
    this.session.cookie = null;
    this.session.csrf = null;
  }
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new SeedRefusal("RESPONSE_INVALID");
  }
  void label;
  return value as Record<string, unknown>;
}

function asString(value: unknown, label: string, max = 256): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    throw new SeedRefusal("RESPONSE_INVALID");
  }
  void label;
  return value;
}

function asOptionalString(value: unknown, max = 256): string {
  return typeof value === "string" && value.length > 0 && value.length <= max ? value : "";
}

function asDecimal(value: unknown): string {
  const text = asString(value, "decimal", 20);
  if (!/^(0|[1-9][0-9]{0,19})$/.test(text)) throw new SeedRefusal("RESPONSE_INVALID");
  return text;
}

function asInt(value: unknown, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) {
    throw new SeedRefusal("RESPONSE_INVALID");
  }
  return value;
}

/** The ledger day is the UTC calendar day `YYYYMMDD` (`utc_day` / `ledgerDay`). */
function asDayUtc(value: unknown): number {
  const day = asInt(value, 19700101, 99991231);
  const year = Math.floor(day / 10_000);
  const month = Math.floor(day / 100) % 100;
  const date = day % 100;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const monthDays = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || date < 1 || date > monthDays[month - 1]) {
    throw new SeedRefusal("RESPONSE_INVALID");
  }
  return day;
}

export interface ParsedIntent {
  intentId: string;
  intentHash: string;
  state: string;
  replayed: boolean;
  plan: Record<string, unknown>;
  recentBlockhash: string;
  lastValidBlockHeight: string;
}

function parseIntent(payload: unknown): ParsedIntent {
  const root = asObject(payload, "intent");
  const plan = asObject(root.review, "review");
  const simulation = asObject(plan.simulation, "simulation");
  if (simulation.ok !== true) throw new SeedRefusal("SIMULATION_FAILED");
  if (asString(plan.cluster, "cluster", 32) !== "solana:devnet") throw new SeedRefusal("CLUSTER_UNSUPPORTED");
  for (const key of [
    "registryId",
    "programId",
    "configPda",
    "rolePda",
    "segmentPda",
    "feePayer",
    "merkleRoot",
    "manifestHash",
    "previousAnchorHash",
    "instructionData",
    "transactionBase64",
  ]) {
    asString(plan[key], key, 4096);
  }
  asInt(plan.segmentIndex, 0, 2);
  asDayUtc(plan.dayUtc);
  asInt(plan.leafCount, 1, 10_000);
  asDecimal(plan.batchSequence);
  asDecimal(plan.registryVersion);
  asDecimal(plan.cursorStart);
  asDecimal(plan.cursorEnd);
  return {
    intentId: asString(root.intentId, "intentId", 36),
    intentHash: asString(root.intentHash, "intentHash", 64),
    state: asString(root.state, "state", 32),
    replayed: root.replayed === true,
    plan,
    recentBlockhash: asString(root.recentBlockhash, "recentBlockhash", 44),
    lastValidBlockHeight: asDecimal(root.lastValidBlockHeight),
  };
}

/**
 * Maps one server-prepared intent to the accepted A1 signer request, exactly
 * the `signer_request_fields()` field set the launcher approves (the three
 * review hashes use the signer's *Hex names). No signing happens here.
 */
export function signRequestForIntent(intent: ParsedIntent): Record<string, unknown> {
  const plan = intent.plan;
  return {
    // The explicit `--approve-fallback` gate has already been confirmed; the
    // A1 contract requires this marker on every request it signs.
    approved: true,
    intentId: intent.intentId,
    cluster: "solana:devnet",
    intentHash: intent.intentHash,
    transactionBase64: String(plan.transactionBase64),
    instructionData: String(plan.instructionData),
    intent: {
      registryId: String(plan.registryId),
      batchSequence: String(plan.batchSequence),
      registryVersion: String(plan.registryVersion),
      cursorStart: String(plan.cursorStart),
      cursorEnd: String(plan.cursorEnd),
      leafCount: Number(plan.leafCount),
      merkleRootHex: String(plan.merkleRoot),
      manifestHashHex: String(plan.manifestHash),
      previousAnchorHashHex: String(plan.previousAnchorHash),
      programId: String(plan.programId),
      configPda: String(plan.configPda),
      rolePda: String(plan.rolePda),
      segmentPda: String(plan.segmentPda),
      segmentIndex: Number(plan.segmentIndex),
      dayUtc: Number(plan.dayUtc),
      feePayer: String(plan.feePayer),
      recentBlockhash: intent.recentBlockhash,
      lastValidBlockHeight: intent.lastValidBlockHeight,
    },
  };
}

/**
 * Signs the server-prepared wire transaction with the accepted A1 signer and
 * no local reimplementation: `signApprovedTransaction` re-validates the whole
 * approved publish-anchor message (program, single instruction, account metas
 * and roles, instruction data, unsigned precondition, intent-hash binding)
 * before the key is read, and re-checks the produced signature before it is
 * returned. A message that is not exactly the approved publish is refused —
 * the demo-api then re-validates message identity and signature again before
 * broadcast.
 */
export async function signApprovedFallback(
  intent: ParsedIntent,
  keyFile?: string,
  keyStore?: KeyStoreOptions,
): Promise<string> {
  try {
    return await signApprovedTransaction(signRequestForIntent(intent), keyFile, keyStore);
  } catch (error) {
    if (error instanceof SignerRefusal) throw new SeedRefusal(error.code);
    throw error;
  }
}

function artifactsRoot(explicit?: string): string {
  const base =
    explicit ??
    path.join(os.homedir(), ".local", "state", "onelayer-devnet-demo", "seed");
  return path.resolve(base);
}

export async function createRunArtifacts(root: string, now: Date): Promise<FallbackArtifacts> {
  const stamp = now.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const dir = path.join(root, `run-${stamp}-${Math.random().toString(16).slice(2, 6)}`);
    try {
      await mkdir(root, { recursive: true, mode: 0o700 });
      await mkdir(dir, { recursive: false, mode: 0o700 });
      return {
        dir,
        manifest: path.join(dir, "fallback.json"),
        packageFile: path.join(dir, "fallback-package.json"),
        qrFile: path.join(dir, "fallback-qr.png"),
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") continue;
      if ((error as NodeJS.ErrnoException).code === "EACCES") throw new SeedRefusal("OUTPUT_UNWRITABLE");
      throw new SeedRefusal("OUTPUT_UNWRITABLE");
    }
  }
  throw new SeedRefusal("OUTPUT_REFUSED");
}

/** Fresh-file writes only: never an existing file, never through a symlink. */
export async function writeFreshFile(target: string, data: Buffer): Promise<void> {
  let handle;
  try {
    handle = await open(target, "wx", 0o600);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "EEXIST") throw new SeedRefusal("OUTPUT_REFUSED");
    throw new SeedRefusal("OUTPUT_UNWRITABLE");
  }
  try {
    await handle.write(data, 0, data.length, 0);
    await handle.sync();
  } finally {
    await handle.close().catch(() => undefined);
  }
}

interface ReuseCandidate {
  dir: string;
  manifest: Record<string, unknown>;
}

async function reuseCandidates(root: string): Promise<ReuseCandidate[]> {
  const entries = await readdir(root, { withFileTypes: true }).catch(() => []);
  const candidates: ReuseCandidate[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || !entry.name.startsWith("run-")) continue;
    const dir = path.join(root, entry.name);
    const manifestPath = path.join(dir, "fallback.json");
    const raw = await readFile(manifestPath).catch(() => null);
    if (raw === null || raw.length === 0 || raw.length > 16_384) continue;
    try {
      const parsed = JSON.parse(raw.toString("utf8")) as unknown;
      const manifest = asObject(parsed, "manifest");
      if (manifest.schema !== "onelayer.live-demo.fallback-artifact.v1") continue;
      candidates.push({ dir, manifest });
    } catch {
      continue;
    }
  }
  candidates.sort((left, right) => (left.dir < right.dir ? 1 : -1));
  return candidates;
}

async function verifyPackage(
  verifier: LoopbackClient,
  packageBase64url: string,
): Promise<FallbackVerification> {
  const response = await verifier.call("POST", "/v1/verify", {
    certificatePackage: packageBase64url,
    requiredCommitment: "finalized",
  });
  if (response.status !== 200) return { status: "INVALID", code: "VERIFIER_UNAVAILABLE" };
  const payload = asObject(response.payload, "verify");
  const status = asString(payload.status, "status", 64);
  const code = asOptionalString(payload.code, 64);
  return { status, code: code === "" ? null : code };
}

function isVerified(verification: FallbackVerification | null): boolean {
  return verification !== null && VERIFIED_STATUSES.has(verification.status);
}

/**
 * Reuses a still-finalized fallback certificate when its artifact re-verifies,
 * otherwise publishes a fresh one through the real flow. Requires the explicit
 * `--approve-fallback` confirmation; without it nothing is signed or sent.
 */
export async function runFallbackCertificate(options: FallbackOptions): Promise<FallbackReport> {
  if (options.approveFallback !== true) throw new SeedRefusal("APPROVAL_REQUIRED");
  const recordId = options.recordId ?? FALLBACK_RECORD_ID;
  if (!/^SYNTHETIC-[1-9][0-9]*$/.test(recordId)) throw new SeedRefusal("REQUEST_INVALID");
  const now = options.now ?? new Date();
  const request = options.request ?? fetch;
  const root = artifactsRoot(options.artifactsDir);
  const verifier = new LoopbackClient(options.verifierUrl, request);
  const api = new LoopbackClient(options.demoApiUrl, request);

  for (const candidate of await reuseCandidates(root)) {
    const manifest = candidate.manifest;
    // Only the requested record's artifact is ever reused: `--fallback-record`
    // names the record this run must end up with.
    if (asOptionalString(manifest.recordId, 32) !== recordId) continue;
    const certificateId = asOptionalString(manifest.certificateId, 32);
    const packageBase64url = await readPackageDocument(candidate.dir, manifest);
    if (certificateId === "" || packageBase64url === "") continue;
    const status = await api.call("GET", `/v1/certificates/${certificateId}/status`);
    const certificateStatus =
      status.status === 200 ? asOptionalString((status.payload as { status?: unknown })?.status, 32) : "";
    const verification = await verifyPackage(verifier, packageBase64url);
    if (!LIVE_CERTIFICATE_STATUSES.has(certificateStatus) || !isVerified(verification)) continue;
    return {
      schema: "onelayer.live-demo.fallback.v1",
      mode: "reused",
      recordId,
      certificateId,
      certificateHash: asOptionalString(manifest.certificateHash, 64),
      qrUrl: asOptionalString(manifest.qrUrl, 2048),
      transactionSignature: asOptionalString(manifest.transactionSignature, 128),
      anchorSlot: asOptionalString(manifest.anchorSlot, 20),
      disclosureMode: asOptionalString(manifest.disclosureMode, 32),
      disclosedPaths: Array.isArray(manifest.disclosedPaths)
        ? manifest.disclosedPaths.filter((value): value is string => typeof value === "string")
        : [],
      verified: verification,
      certificateStatus,
      artifacts: {
        dir: candidate.dir,
        manifest: path.join(candidate.dir, "fallback.json"),
        packageFile: path.join(candidate.dir, "fallback-package.json"),
        qrFile: path.join(candidate.dir, "fallback-qr.png"),
      },
      detail: "an earlier finalized fallback certificate re-verified and was reused",
      ok: true,
    };
  }

  const password = await loadOperatorPassword(options.credentialPath ?? DEFAULT_CREDENTIAL_PATH, options.privateRoot ?? "/dev/shm");
  try {
    const login = await api.call("POST", "/v1/admin/session", {
      username: "operator",
      password,
    });
    if (login.status !== 201) throw new SeedRefusal("SIGN_IN_REFUSED");
    api.adoptSession(login.payload);

    await ensureRecord(api, recordId);
    const created = await publishFallback(api, options, recordId);
    const written = await writeArtifacts(api, root, now, created, recordId);
    const verification = await verifyPackage(verifier, written.packageBase64url);
    return {
      schema: "onelayer.live-demo.fallback.v1",
      mode: "created",
      recordId,
      certificateId: created.certificateId,
      certificateHash: created.certificateHash,
      qrUrl: created.qrUrl,
      transactionSignature: created.transactionSignature,
      anchorSlot: created.anchorSlot,
      disclosureMode: created.disclosureMode,
      disclosedPaths: [...FALLBACK_DISCLOSED_PATHS],
      verified: verification,
      certificateStatus: "ACTIVE",
      artifacts: written.artifacts,
      detail: isVerified(verification)
        ? "a fresh finalized fallback certificate was published and verified"
        : `the fresh fallback certificate did not verify (${verification.status})`,
      ok: isVerified(verification),
    };
  } finally {
    try {
      await api.call("DELETE", "/v1/admin/session");
    } finally {
      api.clearSession();
    }
  }
}

async function readPackageDocument(dir: string, manifest: Record<string, unknown>): Promise<string> {
  const name = asOptionalString(manifest.packageFile, 64);
  if (name === "" || name.includes("/") || name.includes("\\")) return "";
  const raw = await readFile(path.join(dir, name)).catch(() => null);
  if (raw === null || raw.length === 0 || raw.length > MAX_FALLBACK_BODY_BYTES) return "";
  try {
    const parsed = asObject(JSON.parse(raw.toString("utf8")), "package");
    const value = parsed.package_base64url;
    return typeof value === "string" && value.length > 0 && value.length <= MAX_FALLBACK_BODY_BYTES ? value : "";
  } catch {
    return "";
  }
}

async function ensureRecord(api: LoopbackClient, recordId: string): Promise<void> {
  const listed = await api.call("GET", "/v1/admin/records");
  if (listed.status !== 200) throw new SeedRefusal("SERVICE_REFUSED");
  const payload = asObject(listed.payload, "records");
  const records = Array.isArray(payload.records) ? payload.records : [];
  for (const entry of records) {
    const item = entry as { internalRecordId?: unknown };
    if (item.internalRecordId === recordId) return;
  }
  const created = await api.call("POST", "/v1/admin/records", {
    internalRecordId: recordId,
    status: "ACTIVE",
    fields: {
      status: "ACTIVE",
      cadastralNumber: "01-004-0123-045",
      areaSquareMeters: "1250.50",
      encumbered: false,
    },
  });
  if (created.status !== 200 && created.status !== 201) throw new SeedRefusal("SERVICE_REFUSED");
}

interface PublishedFallback {
  certificateId: string;
  certificateHash: string;
  qrUrl: string;
  transactionSignature: string;
  anchorSlot: string;
  disclosureMode: string;
}

async function publishFallback(
  api: LoopbackClient,
  options: FallbackOptions,
  recordId: string,
): Promise<PublishedFallback> {
  const signer = options.signer;
  const prepared = await api.call(
    "POST",
    "/v1/admin/publish-intents",
    { operator: signer.address, cluster: "solana:devnet" },
    { "idempotency-key": randomIdempotencyKey() },
  );
  if (prepared.status !== 201 && prepared.status !== 422 && prepared.status !== 200) {
    throw new SeedRefusal("SERVICE_REFUSED");
  }
  const intent = parseIntent(prepared.payload);
  if (intent.state !== "SIMULATED") throw new SeedRefusal("SIMULATION_FAILED");
  if (intent.plan.feePayer !== signer.address) throw new SeedRefusal("OPERATOR_MISMATCH");

  const signedTransactionBase64 = await signApprovedFallback(intent, options.keyFile, options.keyStore);
  const submitted = await api.call("POST", `/v1/admin/publish-intents/${intent.intentId}/signature`, {
    signedTransactionBase64,
  });
  if (submitted.status !== 200) throw new SeedRefusal("SERVICE_REFUSED");
  const submittedIntent = parseIntent(submitted.payload);

  const attempts = options.reconcileAttempts ?? 30;
  const delayMs = options.reconcileDelayMs ?? 2_000;
  let finalized = submittedIntent;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (finalized.state === "FINALIZED") break;
    if (finalized.state !== "SUBMITTED" && finalized.state !== "SIGNED" && finalized.state !== "SIMULATED") {
      throw new SeedRefusal("PUBLISH_FAILED");
    }
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    const reconciled = await api.call("POST", `/v1/admin/publish-intents/${intent.intentId}/reconciliation`);
    if (reconciled.status !== 200) throw new SeedRefusal("SERVICE_REFUSED");
    finalized = parseIntent(reconciled.payload);
  }
  if (finalized.state !== "FINALIZED") throw new SeedRefusal("NOT_FINALIZED");

  const issued = await api.call("POST", `/v1/admin/publish-intents/${intent.intentId}/certificate`, {
    internalRecordId: recordId,
    disclosedPaths: [...FALLBACK_DISCLOSED_PATHS],
  });
  if (issued.status !== 200 && issued.status !== 201) throw new SeedRefusal("SERVICE_REFUSED");
  const certificate = asObject(issued.payload, "certificate");
  return {
    certificateId: assertCertificateId(asString(certificate.certificateId, "certificateId", 32)),
    certificateHash: asString(certificate.certificateHash, "certificateHash", 64),
    qrUrl: asString(certificate.qrUrl, "qrUrl", 2048),
    transactionSignature: asString(certificate.transactionSignature, "transactionSignature", 128),
    anchorSlot: asDecimal(certificate.anchorSlot),
    disclosureMode: asString(certificate.disclosureMode, "disclosureMode", 32),
  };
}

async function writeArtifacts(
  api: LoopbackClient,
  root: string,
  now: Date,
  created: PublishedFallback,
  recordId: string,
): Promise<{ artifacts: FallbackArtifacts; packageBase64url: string }> {
  const packaged = await api.call("GET", `/v1/certificates/${created.certificateId}/package`);
  if (packaged.status !== 200) throw new SeedRefusal("SERVICE_REFUSED");
  const packageDocument = asObject(packaged.payload, "package");
  const packageBase64url = asString(packageDocument.package_base64url, "package_base64url", MAX_FALLBACK_BODY_BYTES);
  const qr = await api.call("GET", `/v1/qr/${created.certificateId}.png`);
  if (qr.status !== 200 || qr.raw.length === 0 || qr.raw.length > MAX_FALLBACK_BODY_BYTES) {
    throw new SeedRefusal("SERVICE_REFUSED");
  }
  if (!qr.raw.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    throw new SeedRefusal("SERVICE_REFUSED");
  }
  const artifacts = await createRunArtifacts(root, now);
  await writeFreshFile(artifacts.packageFile, Buffer.from(JSON.stringify(packaged.payload, null, 2) + "\n", "utf8"));
  await writeFreshFile(artifacts.qrFile, qr.raw);
  const manifest = {
    schema: "onelayer.live-demo.fallback-artifact.v1",
    createdAt: now.toISOString(),
    recordId,
    certificateId: created.certificateId,
    certificateHash: created.certificateHash,
    qrUrl: created.qrUrl,
    transactionSignature: created.transactionSignature,
    anchorSlot: created.anchorSlot,
    disclosureMode: created.disclosureMode,
    disclosedPaths: [...FALLBACK_DISCLOSED_PATHS],
    packageFile: path.basename(artifacts.packageFile),
    qrFile: path.basename(artifacts.qrFile),
  };
  await writeFreshFile(artifacts.manifest, Buffer.from(JSON.stringify(manifest, null, 2) + "\n", "utf8"));
  return { artifacts, packageBase64url };
}
