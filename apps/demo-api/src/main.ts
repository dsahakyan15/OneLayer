import { createHash, generateKeyPairSync, randomUUID, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { Pool } from "pg";
import QRCode from "qrcode";
import { registryIdHash } from "../../../packages/canonical-ts/src/index.ts";
import { findRegistryConfigPda } from "../../../packages/onchain-client/src/index.ts";
import { getAddressEncoder, type Address } from "@solana/kit";
import { fixtureRoot, type SyntheticFixtureRow } from "./reconcile.ts";
import { qrHashHex } from "./qr.ts";
import { refreshIncidentIndex, type RegistryBinding } from "./incident-index.ts";
import { PostgresIncidentStore } from "./incident-store.ts";
import { incidentsRoute } from "./incident-route.ts";
import { SolanaPublisherRpc } from "./solana-rpc.ts";
import { parseCredentials, SessionStore, CSRF_HEADER, authorizeRequest, requirePermission, AuthorizationError, IdentityUnavailableError } from "./admin-session.ts";
import { requireUnrestrictedResourceAccess } from "./resource-access.ts";
import { routeAdmin, type AdminContext } from "./admin.ts";
import { PostgresSessionStore } from "./postgres-session.ts";
import { OidcClient, parseOidcConfig } from "./oidc.ts";
import {
  carriesHumanSession, carriesServiceBearer, parseServiceBearer, ServicePrincipalStore, ServiceRequestGate,
  SERVICE_CREDENTIAL_REQUIRED, type ServiceAction, type ServicePrincipal,
} from "./service-principal.ts";
import { authorizeServiceRead, matchServiceRead, type ServiceReadRoute } from "./service-read-routes.ts";
import { workingRegistryStatus } from "./registry-status.ts";
import { loadSnapshotKeyConfig } from "./snapshot-key-config.ts";
import { bindSnapshotKeyVersion } from "./snapshot-key-store.ts";
import { PublicationRpc } from "./publication-rpc.ts";
import { loadPublicationConfig } from "./publication-config.ts";
import { loadPublicationApproval } from "./publication-approval.ts";
import { LocalKeyPublicationSigner } from "./publication-signer.ts";
import { WorkflowPublicationRuntime } from "./workflow-runtime.ts";

const MAX_BODY = 1_048_576;
// The deployment registry is explicit. Default stays the legacy synthetic id;
// an isolated devnet demo configures its own namespace (never silently).
const REGISTRY_ID = process.env.ONELAYER_REGISTRY_ID ?? "gov.registry.land";
if (!/^[A-Za-z0-9._:-]{1,128}$/.test(REGISTRY_ID)) throw new Error("ONELAYER_REGISTRY_ID is invalid");
const REGISTRY_ID_PATTERN = new RegExp(`^${REGISTRY_ID.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`);
const MARKER = "ONELAYER_SYNTHETIC_DEVNET_DEMO_V1";
// Deployment contract version surfaced on /v1/health so a launcher or session
// can compare the LIVE service identity to its configured profile and fail
// closed on a mismatch (M6). It names the demo API/registry contract, not a
// production release. Bump only on a breaking change to the health identity.
const DEPLOYMENT_CONTRACT_VERSION = "onelayer.demo-api.health.v1";
// The publication deployment cluster and its pinned chain identity come only
// from the explicit publication configuration (ONELAYER_PUBLICATION_CLUSTER,
// optionally ONELAYER_RPC_GENESIS_HASH). The runtime never falls back to a
// solana:local default: the cluster is baked into the reserved attempt's plan
// hash, the signer enforces it, and the publisher compares the connected RPC's
// getGenesisHash against the pinned expected identity before reserving/signing.
// Upper bound (lamports) on the quoted publish fee. A single publish_anchor is
// ~5000 lamports; a quote above this bound fails closed
// (PUBLICATION_FEE_EXCEEDS_LIMIT) instead of silently overpaying.
const MAX_PUBLISH_FEE_LAMPORTS = 1_000_000n;
/** Verifier batch sequences are u64; the demo stores them in a BIGINT column. */
const U64_MAX = 0xffff_ffff_ffff_ffffn;
const INT8_MAX = 0x7fff_ffff_ffff_ffffn;

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function secret(pathName: string): string {
  return readFileSync(required(pathName), "utf8").trim();
}

const databaseUrl = secret("ONELAYER_DATABASE_URL_FILE");
const rpcUrl = required("ONELAYER_RPC_URL");
const verifierUrl = required("ONELAYER_VERIFIER_URL");
const publicBaseUrl = required("ONELAYER_PUBLIC_BASE_URL");
const programId = required("ONELAYER_PROGRAM_ID");
const publicWebBaseUrl = required("ONELAYER_PUBLIC_WEB_URL");
if (!/^http:\/\/(?:127\.0\.0\.1|localhost):[0-9]{2,5}$/.test(publicWebBaseUrl)) {
  throw new Error("ONELAYER_PUBLIC_WEB_URL must be the exact loopback demo origin");
}
const issuerSecretKey = Uint8Array.from(Buffer.from(secret("ONELAYER_ISSUER_SECRET_FILE"), "hex"));
if (issuerSecretKey.length !== 32) throw new Error("ONELAYER_ISSUER_SECRET_FILE must hold 32 hex-encoded bytes");
const oidcConfig = process.env.ONELAYER_OIDC_CONFIG_FILE
  ? parseOidcConfig(JSON.parse(secret("ONELAYER_OIDC_CONFIG_FILE"))) : undefined;
const adminCredentials = oidcConfig ? [] : parseCredentials(secret("ONELAYER_ADMIN_CREDENTIALS_FILE"));
const localValidatorProfile = process.env.ONELAYER_SYNTHETIC_PROFILE === "local-validator" &&
  process.env.ONELAYER_ADMIN_ACCESS_LAB === "1" &&
  process.env.ONELAYER_PUBLICATION_CLUSTER === "solana:local" &&
  REGISTRY_ID !== "gov.registry.land" && /^http:\/\/127\.0\.0\.1:[0-9]{2,5}$/.test(rpcUrl) &&
  Boolean(process.env.ONELAYER_RPC_GENESIS_HASH);
if (rpcUrl !== "https://api.devnet.solana.com" && !localValidatorProfile) throw new Error("demo API requires devnet or an explicit isolated local-validator lab profile");
if (localValidatorProfile && await new PublicationRpc(rpcUrl, programId).genesisHash() !== process.env.ONELAYER_RPC_GENESIS_HASH) {
  throw new Error("LOCAL_DEMO_GENESIS_MISMATCH");
}
const pool = new Pool({ connectionString: databaseUrl, max: 5, connectionTimeoutMillis: 5_000 });
// The snapshot writer key is explicit, restart-stable configuration. It is
// never generated, split or persisted here: without configuration the API
// still starts and snapshot creation fails closed (SNAPSHOT_KEY_UNAVAILABLE),
// and a partial or invalid pair refuses startup instead of substituting a
// process-random or issuer key.
const snapshotKeyConfig = loadSnapshotKeyConfig();
const recoveryKeys = new Map<string, Uint8Array>();
const restoreApprovalPrivateKey = generateKeyPairSync("ed25519").privateKey;

const [configAddress] = await findRegistryConfigPda(registryIdHash(REGISTRY_ID), {
  programAddress: programId as Address,
});
const registryBinding: RegistryBinding = {
  registryId: REGISTRY_ID,
  programId,
  configAddress,
  configBytes: new Uint8Array(getAddressEncoder().encode(configAddress)),
};
const incidentRpc = new SolanaPublisherRpc(rpcUrl, programId);
const incidentStore = new PostgresIncidentStore(pool, configAddress);

const sessionBackend = process.env.ONELAYER_SESSION_BACKEND ?? "postgres";
if (sessionBackend !== "postgres" && sessionBackend !== "memory") throw new Error("invalid ONELAYER_SESSION_BACKEND");
if (oidcConfig && sessionBackend !== 'postgres') throw new Error('OIDC requires durable PostgreSQL sessions');
// Internal routes use durable scoped service principals by default. The isolated
// in-memory test backend defaults to `disabled` (internal routes refused, no DB
// dependency). The synthetic shared bearer survives only as an explicit
// password-demo opt-in and is refused at startup in OIDC mode. No silent fallback.
const internalAuth = process.env.ONELAYER_INTERNAL_AUTH ?? (sessionBackend === "memory" ? "disabled" : "service-principal");
if (!["service-principal", "legacy-demo-token", "disabled"].includes(internalAuth)) throw new Error("invalid ONELAYER_INTERNAL_AUTH");
if (oidcConfig && internalAuth !== "service-principal") throw new Error("OIDC mode requires service principals for internal routes");
const legacyInternalToken = internalAuth === "legacy-demo-token" ? secret("ONELAYER_INTERNAL_TOKEN_FILE") : undefined;
if (legacyInternalToken !== undefined && !/^[\x21-\x7e]{32,512}$/.test(legacyInternalToken)) throw new Error("legacy internal token must be 32-512 printable characters");
if (oidcConfig && (!/^http:\/\/(?:127\.0\.0\.1|localhost):[0-9]{2,5}$/.test(publicBaseUrl) || new URL(publicBaseUrl).hostname !== new URL(publicWebBaseUrl).hostname)) {
  throw new Error('OIDC lab API and web must use the same exact loopback hostname for host-only cookies');
}
if (oidcConfig && oidcConfig.redirectUri !== `${publicBaseUrl}/v2/admin/oidc/callback`) throw new Error('OIDC redirectUri must match the API callback');
const sessions = sessionBackend === "postgres"
  ? new PostgresSessionStore(pool, adminCredentials, { oidcOnly: Boolean(oidcConfig) })
  : new SessionStore(adminCredentials);
if (sessions instanceof PostgresSessionStore) await sessions.initialize();
// Separate small pool: internal authentication cannot exhaust the pool used by
// human sessions and admin data (M1). The gate below bounds it further.
const servicePool = new Pool({ connectionString: databaseUrl, max: 2, connectionTimeoutMillis: 2_000 });
const servicePrincipals = new ServicePrincipalStore(servicePool);
// Any backend: service-principal mode refuses to start without schema 0012.
if (internalAuth === "service-principal") await servicePrincipals.initialize();
const serviceGate = new ServiceRequestGate();

// Workflow publication runtime: enabled only with explicit deployment keys and
// an allow-listed lab signer key. Without configuration the API still starts
// and the publication routes answer PUBLICATION_UNAVAILABLE (fail closed).
const publicationConfig = await loadPublicationConfig();
let publication: AdminContext["publication"];
if (publicationConfig !== undefined) {
  // Load the distinct approval issuer key from the hardened key store. It is
  // used only to mint signed approval receipts for the exact reserved plan at
  // the authorized HTTP boundary; the private key never reaches the publisher
  // or the signer, which only receive the pinned public key.
  const approvals = await loadPublicationApproval(publicationConfig);
  const signer = await LocalKeyPublicationSigner.create(publicationConfig.signerKeyFile, {
    registryId: REGISTRY_ID, programId, configPda: configAddress,
    // Explicit deployment cluster + pinned genesis identity, never a default.
    cluster: publicationConfig.cluster,
    ...(publicationConfig.genesisHash === undefined ? {} : { genesisHash: publicationConfig.genesisHash }),
    // The signer verifies the approval receipt against this pinned key (H5).
    approvalPublicKey: approvals.publicKey,
  });
  publication = {
    runtime: new WorkflowPublicationRuntime(pool, new PublicationRpc(rpcUrl, programId), signer, {
      registryId: REGISTRY_ID, programId: programId as Address, configPda: configAddress,
      operatorKeyId: publicationConfig.operatorKeyId, keys: publicationConfig.keys,
      cluster: publicationConfig.cluster,
      ...(publicationConfig.genesisHash === undefined ? {} : { genesisHash: publicationConfig.genesisHash }),
      maxFeeLamports: MAX_PUBLISH_FEE_LAMPORTS,
    }, approvals.service),
    keys: publicationConfig.keys,
    operatorKeyId: publicationConfig.operatorKeyId,
  };
}

const adminContext: AdminContext = {
  ...(oidcConfig && sessions instanceof PostgresSessionStore ? { oidc: {
    client: new OidcClient(oidcConfig), login: identity => sessions.loginOidc(identity),
    browserOrigin: publicWebBaseUrl, secureCookies: new URL(publicBaseUrl).protocol === 'https:',
    successRedirect: `${publicWebBaseUrl}/admin`,
  } } : {}),
  pool,
  sessions,
  rpc: incidentRpc,
  registryId: REGISTRY_ID,
  programId: programId as Address,
  configPda: configAddress,
  issuerSecretKey,
  // The bounded MVP writer holds only the explicitly provisioned key material
  // for the life of the process; it is never returned to the browser, written
  // to the database, or included in the timeline. Recovery shares are not
  // generated or stored by the ordinary API process.
  ...(snapshotKeyConfig === undefined ? {} : {
    snapshotKek: snapshotKeyConfig.kek,
    snapshotKeyEncryptionVersion: snapshotKeyConfig.keyEncryptionVersion,
  }),
  recoveryKeys,
  restoreApprovalPrivateKey,
  ...(publication === undefined ? {} : { publication }),
  snapshotFullState: process.env.ONELAYER_SNAPSHOT_FULL_STATE === "1",
  publicWebBaseUrl,
  now: () => new Date(),
};

const INDEX_REFRESH_INTERVAL_MS = 2_000;
let lastIndexRefresh = 0;
let indexRefresh: Promise<void> | null = null;

/**
 * Refreshes the event-backed index at most every {@link INDEX_REFRESH_INTERVAL_MS}.
 * A failed scan is swallowed: the stale watermark then downgrades the verifier
 * to `STALE`/`UNAVAILABLE`, which is the honest answer (§2.3).
 */
async function refreshIndex(): Promise<void> {
  const now = Date.now();
  if (indexRefresh === null && now - lastIndexRefresh >= INDEX_REFRESH_INTERVAL_MS) {
    lastIndexRefresh = now;
    indexRefresh = refreshIncidentIndex(registryBinding, incidentRpc, incidentStore)
      .then(() => undefined)
      .catch((error: unknown) => {
        process.stderr.write(`incident index refresh failed: ${error instanceof Error ? error.message : "unknown"}\n`);
      })
      .finally(() => { indexRefresh = null; });
  }
  await indexRefresh;
}

// Recovery-anchor and snapshot-anchor selection (admin.ts) accept the index
// only after a recent complete refresh, so keep refreshing in the background.
setInterval(() => { void refreshIndex(); }, 30_000).unref();

function json(response: ServerResponse, status: number, body: unknown): void {
  const encoded = JSON.stringify(body, (_key, value) => typeof value === "bigint" ? value.toString() : value);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(encoded),
    "cache-control": "no-store",
  });
  response.end(encoded);
}

async function body(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    length += bytes.length;
    if (length > MAX_BODY) throw new RangeError("request too large");
    chunks.push(bytes);
  }
  const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new TypeError("JSON object required");
  return parsed as Record<string, unknown>;
}

class InternalRefusal extends Error {
  constructor(readonly status: number, readonly code: string) { super(code); }
}

/**
 * Admission for internal routes, before any body read or DB access: exact
 * credential syntax, no human cookie, then the in-process rate/concurrency gate.
 * Returns the gate key's release function.
 */
function admitInternal(request: IncomingMessage): () => void {
  if (internalAuth === "disabled") throw new InternalRefusal(503, "SERVICE_AUTH_DISABLED");
  if (carriesHumanSession(request.headers.cookie)) throw new AuthorizationError(401, SERVICE_CREDENTIAL_REQUIRED);
  let key: string;
  if (legacyInternalToken === undefined) {
    const parsed = parseServiceBearer(request.headers.authorization);
    if (!parsed) throw new AuthorizationError(401, SERVICE_CREDENTIAL_REQUIRED);
    key = parsed.credentialId;
  } else {
    // Explicit synthetic demo mode: one shared bearer, digest + constant-time compare.
    const header = request.headers.authorization ?? "";
    const supplied = createHash("sha256").update(header.startsWith("Bearer ") ? header.slice(7) : "").digest();
    const expected = createHash("sha256").update(legacyInternalToken).digest();
    if (!timingSafeEqual(supplied, expected) || !header.startsWith("Bearer ")) throw new AuthorizationError(401, "UNAUTHORIZED");
    key = "legacy";
  }
  const admitted = serviceGate.enter(key);
  if (admitted === "BUSY") throw new InternalRefusal(429, "SERVICE_BUSY");
  if (admitted === "RATE_LIMITED") throw new InternalRefusal(429, "SERVICE_RATE_LIMITED");
  return admitted;
}

/**
 * Identity, action and registry scope come from PostgreSQL only; forwarded
 * headers, body fields and human cookies never contribute. `precheck`
 * authorizes against the deployment registry without recording success; it
 * runs before a request body is read.
 */
async function authorizeInternal(request: IncomingMessage, action: ServiceAction, registryId: unknown, precheck = false): Promise<ServicePrincipal | null> {
  if (legacyInternalToken === undefined) {
    return servicePrincipals.authorize(request.headers.authorization, action, registryId, { recordSuccess: !precheck });
  }
  if (registryId !== REGISTRY_ID) throw new AuthorizationError(403, "SERVICE_PERMISSION_FORBIDDEN");
  return null;
}

/** Internal bodies must arrive within this bound; a slow body cannot pin a gate slot (N2). */
const INTERNAL_BODY_TIMEOUT_MS = Number(process.env.ONELAYER_INTERNAL_BODY_TIMEOUT_MS ?? "10000");
if (!Number.isSafeInteger(INTERNAL_BODY_TIMEOUT_MS) || INTERNAL_BODY_TIMEOUT_MS < 100 || INTERNAL_BODY_TIMEOUT_MS > 10_000) {
  throw new Error("ONELAYER_INTERNAL_BODY_TIMEOUT_MS must be 100-10000");
}

async function internalBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; request.destroy(); }, INTERNAL_BODY_TIMEOUT_MS);
  try { return await body(request); }
  catch (error) {
    if (timedOut) throw new InternalRefusal(408, "REQUEST_TIMEOUT");
    if (error instanceof RangeError) throw new InternalRefusal(413, "REQUEST_TOO_LARGE");
    if (error instanceof SyntaxError || error instanceof TypeError) throw new InternalRefusal(400, "REQUEST_INVALID");
    throw error;
  } finally { clearTimeout(timer); }
}

function text(value: unknown, name: string, pattern: RegExp): string {
  if (typeof value !== "string" || !pattern.test(value)) throw new TypeError(`${name} is invalid`);
  return value;
}

function unsigned(value: unknown, name: string): string {
  return text(String(value), name, /^(?:0|[1-9][0-9]*)$/);
}

async function ensureFixture(): Promise<void> {
  const result = await pool.query("SELECT marker FROM demo_fixture_marker");
  if (result.rows.length !== 1 || result.rows[0].marker !== MARKER) throw new Error("synthetic fixture marker missing");
}

async function requireWorkingRegistry(response: ServerResponse): Promise<boolean> {
  const status = await workingRegistryStatus(incidentRpc, configAddress);
  if (status === "WORKING") return true;
  if (status === "PAUSED") json(response, 409, { code: "REGISTRY_PAUSED" });
  else json(response, 503, { code: "REGISTRY_STATUS_UNAVAILABLE" });
  return false;
}

function registrationFields(input: Record<string, unknown>) {
  const registryId = text(input.registryId, "registryId", REGISTRY_ID_PATTERN);
  const batchSequence = unsigned(input.batchSequence, "batchSequence");
  const registryVersion = unsigned(input.registryVersion, "registryVersion");
  const merkleRoot = text(input.merkleRoot, "merkleRoot", /^[0-9a-f]{64}$/);
  const manifestHash = text(input.manifestHash, "manifestHash", /^[0-9a-f]{64}$/);
  const anchorHash = text(input.anchorHash, "anchorHash", /^[0-9a-f]{64}$/);
  const programId = text(input.programId, "programId", /^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
  const segmentPda = text(input.segmentPda, "segmentPda", /^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
  const transactionSignature = text(input.transactionSignature, "transactionSignature", /^[1-9A-HJ-NP-Za-km-z]{80,90}$/);
  const anchorSlot = unsigned(input.anchorSlot, "anchorSlot");
  const certificateId = text(input.certificateId, "certificateId", /^[0-9a-f]{32}$/);
  const certificateHash = text(input.certificateHash, "certificateHash", /^[0-9a-f]{64}$/);
  const certificatePackage = text(input.certificatePackage, "certificatePackage", /^[A-Za-z0-9_-]+$/);
  const qrUrl = text(input.qrUrl, "qrUrl", /^http:\/\/127\.0\.0\.1:8090\/c\/[0-9a-f]{32}\?h=[A-Za-z0-9_-]{43}$/);
  if (qrHashHex(new URL(qrUrl).searchParams.get("h")) !== certificateHash) throw new TypeError("QR hash does not match certificate hash");
  const issuedAt = text(input.issuedAt, "issuedAt", /^20[0-9]{2}-[0-9]{2}-[0-9]{2}T/);
  const internalRecordId = input.internalRecordId === undefined
    ? null
    : text(input.internalRecordId, "internalRecordId", /^SYNTHETIC-[1-9][0-9]*$/);
  const recordVersion = input.recordVersion === undefined
    ? null
    : unsigned(input.recordVersion, "recordVersion");
  return { registryId, batchSequence, registryVersion, merkleRoot, manifestHash, anchorHash, programId, segmentPda,
    transactionSignature, anchorSlot, certificateId, certificateHash, certificatePackage, qrUrl, issuedAt, internalRecordId, recordVersion };
}

async function registerArtifact(input: Record<string, unknown>, principal: ServicePrincipal | null): Promise<void> {
  // Field validation happens before any fixture or RPC work (N6): a malformed
  // registration is a 400 client error, not a 500 after a chain call.
  let fields: ReturnType<typeof registrationFields>;
  try { fields = registrationFields(input); }
  catch (error) {
    if (error instanceof TypeError || error instanceof RangeError) throw new InternalRefusal(400, "REQUEST_INVALID");
    throw error;
  }
  const { registryId, batchSequence, registryVersion, merkleRoot, manifestHash, anchorHash, programId, segmentPda,
    transactionSignature, anchorSlot, certificateId, certificateHash, certificatePackage, qrUrl, issuedAt, internalRecordId, recordVersion } = fields;
  await ensureFixture();
  const registryStatus = await workingRegistryStatus(incidentRpc, configAddress);
  if (registryStatus === "PAUSED") throw new Error("REGISTRY_PAUSED");
  if (registryStatus === "UNAVAILABLE") throw new Error("REGISTRY_STATUS_UNAVAILABLE");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // A revoke/rotation committed after authorization (e.g. during the RPC
    // status call above) rolls this write back instead of racing it (m2).
    if (principal) await servicePrincipals.revalidate(client, principal);
    await client.query(
      `INSERT INTO demo_anchor (
        registry_id, batch_sequence, registry_version, merkle_root, manifest_hash, anchor_hash,
        program_id, segment_pda, transaction_signature, anchor_slot, commitment, finalized_at
      ) VALUES ($1,$2,$3,decode($4,'hex'),decode($5,'hex'),decode($6,'hex'),$7,$8,$9,$10,'finalized',now())
      ON CONFLICT (registry_id, batch_sequence) DO UPDATE SET
        registry_version=EXCLUDED.registry_version, merkle_root=EXCLUDED.merkle_root,
        manifest_hash=EXCLUDED.manifest_hash, anchor_hash=EXCLUDED.anchor_hash, program_id=EXCLUDED.program_id,
        segment_pda=EXCLUDED.segment_pda, transaction_signature=EXCLUDED.transaction_signature,
        anchor_slot=EXCLUDED.anchor_slot, commitment='finalized', finalized_at=now()`,
      [registryId, batchSequence, registryVersion, merkleRoot, manifestHash, anchorHash, programId, segmentPda, transactionSignature, anchorSlot],
    );
    await client.query(
      `INSERT INTO anchor_batch (
        registry_id, batch_sequence, registry_version, cursor_start, cursor_end, leaf_count,
        merkle_root, manifest_hash, previous_anchor_hash, anchor_hash, status,
        solana_signature, solana_slot, prepared_at, finalized_at
      ) VALUES ($1,$2,$3,1,2,2,decode($4,'hex'),decode($5,'hex'),decode(repeat('00',32),'hex'),decode($6,'hex'),'FINALIZED',$7,$8,now(),now())
      ON CONFLICT (registry_id, batch_sequence) DO UPDATE SET
        registry_version=EXCLUDED.registry_version, merkle_root=EXCLUDED.merkle_root,
        manifest_hash=EXCLUDED.manifest_hash, anchor_hash=EXCLUDED.anchor_hash,
        status='FINALIZED', solana_signature=EXCLUDED.solana_signature,
        solana_slot=EXCLUDED.solana_slot, finalized_at=now()`,
      [registryId, batchSequence, registryVersion, merkleRoot, manifestHash, anchorHash, transactionSignature, anchorSlot],
    );
    await client.query(
      `INSERT INTO demo_certificate (
        certificate_id, registry_id, batch_sequence, certificate_hash, package_base64url, qr_url, status, issued_at,
        internal_record_id, record_version
      ) VALUES ($1,$2,$3,decode($4,'hex'),$5,$6,'ACTIVE',$7,$8,$9)
      ON CONFLICT (certificate_id) DO UPDATE SET
        certificate_hash=EXCLUDED.certificate_hash, package_base64url=EXCLUDED.package_base64url, qr_url=EXCLUDED.qr_url,
        status='ACTIVE', issued_at=EXCLUDED.issued_at,
        internal_record_id=EXCLUDED.internal_record_id, record_version=EXCLUDED.record_version`,
      [certificateId, registryId, batchSequence, certificateHash, certificatePackage, qrUrl, issuedAt, internalRecordId, recordVersion],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function reconcile(): Promise<{ status: "CLEAN" | "DISPUTED"; expectedRoot: string; actualRoot: string }> {
  await ensureFixture();
  const [anchor, records] = await Promise.all([
    pool.query("SELECT encode(merkle_root, 'hex') AS root, batch_sequence FROM demo_anchor WHERE registry_id=$1 ORDER BY batch_sequence DESC LIMIT 1", [REGISTRY_ID]),
    // The reconcile root must be built from the same field set as the batch:
    // the imported paths belong to the commitment just like `status` does.
    pool.query(
      `SELECT r.internal_record_id, r.record_version::text, r.status, r.record_field_key_hex,
              COALESCE(
                json_agg(json_build_object('path', f.path, 'type', f.value_type, 'value', f.value_text)
                         ORDER BY f.path) FILTER (WHERE f.path IS NOT NULL),
                '[]'
              ) AS fields
         FROM synthetic_registry_record r
         LEFT JOIN synthetic_record_field f ON f.internal_record_id = r.internal_record_id
        GROUP BY r.internal_record_id
        ORDER BY r.source_cursor`,
    ),
  ]);
  if (anchor.rows.length !== 1) throw new Error("finalized demo anchor missing");
  const rows: SyntheticFixtureRow[] = records.rows.map((row) => ({
    internalRecordId: row.internal_record_id,
    recordVersion: row.record_version,
    status: row.status,
    recordFieldKeyHex: row.record_field_key_hex,
    fields: row.fields,
  }));
  const expectedRoot: string = anchor.rows[0].root;
  const actualRoot = fixtureRoot(rows);
  if (actualRoot === expectedRoot) return { status: "CLEAN", expectedRoot, actualRoot };
  const batchSequence = String(anchor.rows[0].batch_sequence);
  const evidence = JSON.stringify({ registryId: REGISTRY_ID, batchSequence, expectedRoot, actualRoot });
  const evidenceHash = createHash("sha256").update(evidence).digest("hex");
  await pool.query(
    `INSERT INTO integrity_incident (
      incident_id, registry_id, incident_sequence, incident_type, severity,
      expected_leaf_hash, observed_leaf_hash, first_suspect_batch, last_suspect_batch,
      status, evidence_object_key, opened_at
    ) VALUES ($1,$2,1,'DIRECT_DB_TAMPERING','CRITICAL',decode($3,'hex'),decode($4,'hex'),$5,$5,'OPEN',$6,now())
    ON CONFLICT (registry_id, incident_sequence) DO UPDATE SET
      expected_leaf_hash=EXCLUDED.expected_leaf_hash, observed_leaf_hash=EXCLUDED.observed_leaf_hash,
      first_suspect_batch=EXCLUDED.first_suspect_batch, last_suspect_batch=EXCLUDED.last_suspect_batch,
      status='OPEN', evidence_object_key=EXCLUDED.evidence_object_key, opened_at=now(),
      resolved_at=NULL, resolution=NULL`,
    [randomUUID(), REGISTRY_ID, expectedRoot, actualRoot, batchSequence, `synthetic://incident/${evidenceHash}`],
  );
  await pool.query("UPDATE demo_certificate SET status='DISPUTED' WHERE registry_id=$1 AND batch_sequence=$2", [REGISTRY_ID, batchSequence]);
  await pool.query("UPDATE anchor_batch SET status='DISPUTED' WHERE registry_id=$1 AND batch_sequence=$2", [REGISTRY_ID, batchSequence]);
  return { status: "DISPUTED", expectedRoot, actualRoot };
}

async function handleAdmin(
  request: IncomingMessage,
  response: ServerResponse,
  url: URL,
): Promise<void> {
  // Several admin actions are bodyless POSTs (reconciliation, rejection), so an
  // absent body is normal rather than a parse error.
  const declaredLength = Number(request.headers["content-length"] ?? "0");
  const hasBody = Number.isSafeInteger(declaredLength) && declaredLength > 0;
  const result = await routeAdmin(adminContext, {
    method: request.method ?? "GET",
    path: url.pathname,
    query: url.searchParams,
    body: hasBody ? await body(request) : null,
    cookieHeader: request.headers.cookie,
    csrfHeader: firstHeader(request.headers[CSRF_HEADER]),
    idempotencyKey: firstHeader(request.headers["idempotency-key"]),
    originHeader: request.headers.origin,
  });
  if (result.setCookie !== undefined) response.setHeader("set-cookie", result.setCookie);
  if (result.location !== undefined) response.setHeader('location', result.location);
  if (result.status === 204) {
    response.writeHead(204, { "cache-control": "no-store" });
    response.end();
    return;
  }
  json(response, result.status, result.body);
}

function firstHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
  const url = new URL(request.url ?? "/", publicBaseUrl);
  const internalRoute = url.pathname === "/internal/register" || url.pathname === "/internal/reconcile";
  // A service principal is never a human identity: its bearer is refused on
  // every non-internal route, even alongside a valid admin cookie, except the
  // exact verifier GET surface whitelisted in service-read-routes.ts. That
  // surface exists only where durable service principals are configured; the
  // legacy demo token never unlocks it.
  const serviceBearer = carriesServiceBearer(request.headers.authorization);
  const serviceRead = serviceBearer && internalAuth === "service-principal" && !internalRoute
    ? matchServiceRead(request.method, url.pathname)
    : null;
  if (!internalRoute && serviceBearer && serviceRead === null) {
    json(response, 401, { code: "SERVICE_PRINCIPAL_NOT_ALLOWED" });
    return;
  }
  if (url.pathname.startsWith("/v1/admin/") || url.pathname.startsWith("/v2/admin/")) {
    await handleAdmin(request, response, url);
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/health") {
    await ensureFixture();
    // Live deployment identity (M6): the running service reports the registry
    // namespace, the actual deployment cluster, the pinned chain genesis, the
    // program, config PDA and contract version it actually serves. The cluster
    // and genesis come from the explicit publication configuration (never a
    // hardcoded devnet): an isolated local-validator profile reports
    // `solana:local` and its real genesis, while a legacy deployment reports
    // `solana:devnet`. Callers compare this to their configured profile and
    // refuse on a mismatch; a missing field is unknown and fails closed. This is
    // read from server configuration, never from a mutable client assertion.
    json(response, 200, {
      status: "ok",
      fixture: MARKER,
      cluster: publicationConfig?.cluster ?? "solana:devnet",
      genesisHash: publicationConfig?.genesisHash ?? null,
      registryId: REGISTRY_ID,
      programId,
      configPda: configAddress,
      contractVersion: DEPLOYMENT_CONTRACT_VERSION,
    });
    return;
  }
  if (request.method === "POST" && internalRoute) {
    const release = admitInternal(request);
    try {
      if (url.pathname === "/internal/register") {
        // Credential + action are checked before the body is read; the registry
        // scope is checked (and audited) once the body names it.
        await authorizeInternal(request, "artifacts.register", REGISTRY_ID, true);
        const input = await internalBody(request);
        const principal = await authorizeInternal(request, "artifacts.register", input.registryId);
        await registerArtifact(input, principal);
        json(response, 201, { status: "registered" });
      } else {
        await authorizeInternal(request, "integrity.reconcile", REGISTRY_ID);
        json(response, 200, await reconcile());
      }
    } finally { release(); }
    return;
  }
  // Admission for a whitelisted read, in the same order as the internal routes
  // (human cookie, strict bearer syntax, in-process gate). The slot is held for
  // the whole response-producing operation below, not only for the authorization
  // call: the concurrency cap must bound in-flight read work (resource queries,
  // the incident index refresh) and the pool connections that work holds.
  const releaseServiceRead = serviceRead === null ? null : admitInternal(request);
  try {
    await handlePublicReads(request, response, url, serviceRead);
  } finally { releaseServiceRead?.(); }
}

/**
 * Everything after admission on the public surface: the legacy lookup routes
 * and, for the whitelisted GETs, the live service-principal decision. A human
 * request keeps the OIDC admission and export gate; an authorized service read
 * bypasses that gate for the whitelisted path only.
 */
async function handlePublicReads(
  request: IncomingMessage,
  response: ServerResponse,
  url: URL,
  serviceRead: ServiceReadRoute | null,
): Promise<void> {
  if (serviceRead !== null) {
    await authorizeServiceRead(servicePrincipals, request.headers.authorization, serviceRead, url, REGISTRY_ID);
  }
  if (oidcConfig && serviceRead === null) {
    // Legacy QR/lookup routes must not bypass corporate session admission.
    const session = await authorizeRequest(sessions, {
      method: request.method ?? 'GET', cookieHeader: request.headers.cookie,
      csrfHeader: firstHeader(request.headers[CSRF_HEADER]),
    });
    requirePermission(session, REGISTRY_ID, 'certificates.read');
    requireUnrestrictedResourceAccess(session.resourcePolicy, REGISTRY_ID, 'certificates.read');
    requirePermission(session, REGISTRY_ID, 'certificates.export');
    requireUnrestrictedResourceAccess(session.resourcePolicy, REGISTRY_ID, 'certificates.export');
  }
  if (request.method === "GET" && url.pathname.startsWith("/v1/anchors/")) {
    const batchSequence = unsigned(url.pathname.slice("/v1/anchors/".length), "batchSequence");
    // The verifier domain is u64, not the storage width: a value above u64 is
    // not a batch sequence at all (400), and a valid u64 above INT8_MAX cannot
    // exist in the BIGINT column (404). Both decisions are made before the
    // query, and the 20-digit bound stops BigInt from ever parsing an unbounded
    // number (a canonical u64 is at most 20 digits).
    if (batchSequence.length > 20) { json(response, 400, { code: "BATCH_SEQUENCE_INVALID" }); return; }
    const sequence = BigInt(batchSequence);
    if (sequence > U64_MAX) { json(response, 400, { code: "BATCH_SEQUENCE_INVALID" }); return; }
    if (sequence > INT8_MAX) { json(response, 404, { code: "ANCHOR_NOT_FOUND" }); return; }
    const result = await pool.query(
      "SELECT registry_id, batch_sequence::text, registry_version::text, encode(merkle_root,'hex') merkle_root, encode(manifest_hash,'hex') manifest_hash, program_id, segment_pda, transaction_signature, anchor_slot::text, commitment FROM demo_anchor WHERE registry_id=$1 AND batch_sequence=$2",
      [REGISTRY_ID, batchSequence],
    );
    json(response, result.rows.length ? 200 : 404, result.rows[0] ?? { code: "ANCHOR_NOT_FOUND" });
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/incidents") {
    // Status mapping, u64 strings and the numeric batch comparison live in
    // incident-route.ts (tested in tests/incident-route.test.ts).
    json(response, 200, await incidentsRoute({
      registryId: REGISTRY_ID,
      refresh: refreshIndex,
      store: incidentStore,
      queryLocal: (sql, values) => pool.query(sql, values),
    }, url));
    return;
  }
  const certificateLifecycle = url.pathname.match(/^\/v1\/certificates\/([0-9a-f]{32})\/lifecycle$/);
  if (request.method === "GET" && certificateLifecycle) {
    if (url.searchParams.get("registryId") !== REGISTRY_ID) throw new TypeError("registryId is invalid");
    const result = await pool.query(
      `SELECT c.status,
              COALESCE(
                (SELECT max(r.record_version) FROM synthetic_registry_record r
                  WHERE r.internal_record_id = c.internal_record_id),
                c.record_version,
                1
              )::text AS current_record_version
         FROM demo_certificate c
        WHERE c.certificate_id = $1 AND c.registry_id = $2`,
      [certificateLifecycle[1], REGISTRY_ID],
    );
    if (result.rows.length === 0) { json(response, 404, { code: "CERTIFICATE_NOT_FOUND" }); return; }
    const status: string = result.rows[0].status;
    json(response, 200, {
      registryId: REGISTRY_ID,
      certificateId: certificateLifecycle[1],
      currentRecordVersion: result.rows[0].current_record_version,
      // DISPUTED is an incident state, not a lifecycle state: the certificate
      // itself has not been replaced.
      certificateStatus: status === "SUPERSEDED" || status === "REVOKED" ? status : "ACTIVE",
    });
    return;
  }
  const certificateStatus = url.pathname.match(/^\/v1\/certificates\/([0-9a-f]{32})\/status$/);
  if (request.method === "GET" && certificateStatus) {
    // The registry filter keeps a foreign registry's certificate unreadable
    // through its ID, like the lifecycle and metadata queries already do.
    const result = await pool.query(
      "SELECT certificate_id, status, batch_sequence::text FROM demo_certificate WHERE certificate_id=$1 AND registry_id=$2",
      [certificateStatus[1], REGISTRY_ID],
    );
    json(response, result.rows.length ? 200 : 404, result.rows[0] ?? { code: "CERTIFICATE_NOT_FOUND" });
    return;
  }
  const certificatePackage = url.pathname.match(/^\/v1\/certificates\/([0-9a-f]{32})\/package$/);
  if (request.method === "GET" && certificatePackage) {
    if (!(await requireWorkingRegistry(response))) return;
    const result = await pool.query(
      "SELECT package_base64url, encode(certificate_hash,'hex') AS certificate_hash, qr_url FROM demo_certificate WHERE certificate_id=$1",
      [certificatePackage[1]],
    );
    if (!result.rows.length) { json(response, 404, { code: "CERTIFICATE_NOT_FOUND" }); return; }
    // When the caller arrived from a QR code it must present the hash the code
    // carried; a swapped package fails here, before any chain lookup.
    const qrHash = url.searchParams.get("h");
    if (qrHash !== null && qrHashHex(qrHash) !== result.rows[0].certificate_hash) {
      json(response, 422, { code: "QR_HASH_MISMATCH" });
      return;
    }
    json(response, 200, {
      package_base64url: result.rows[0].package_base64url,
      certificateHash: result.rows[0].certificate_hash,
      qrUrl: result.rows[0].qr_url,
    });
    return;
  }
  // Public metadata about the certificate as an artifact: how much of the
  // record it discloses and which anchor it points at. The field values are
  // not served here — they come from the package the verifier checked.
  const certificateMetadata = url.pathname.match(/^\/v1\/certificates\/([0-9a-f]{32})\/metadata$/);
  if (request.method === "GET" && certificateMetadata) {
    if (!(await requireWorkingRegistry(response))) return;
    const result = await pool.query(
      `SELECT c.certificate_id, c.batch_sequence::text, c.status, c.issued_at, c.qr_url,
              c.disclosure_mode, c.disclosed_paths, c.record_version::text,
              encode(c.certificate_hash,'hex') AS certificate_hash,
              a.anchor_slot::text, a.transaction_signature, encode(a.merkle_root,'hex') AS merkle_root,
              encode(a.manifest_hash,'hex') AS manifest_hash
         FROM demo_certificate c
         JOIN demo_anchor a ON a.registry_id = c.registry_id AND a.batch_sequence = c.batch_sequence
        WHERE c.certificate_id = $1 AND c.registry_id = $2`,
      [certificateMetadata[1], REGISTRY_ID],
    );
    if (!result.rows.length) { json(response, 404, { code: "CERTIFICATE_NOT_FOUND" }); return; }
    const row = result.rows[0];
    json(response, 200, {
      certificateId: row.certificate_id,
      registryId: REGISTRY_ID,
      cluster: "solana:devnet",
      status: row.status,
      issuedAt: row.issued_at,
      recordVersion: row.record_version,
      certificateHash: row.certificate_hash,
      qrUrl: row.qr_url,
      disclosureMode: row.disclosure_mode,
      disclosedPaths: row.disclosed_paths,
      batchSequence: row.batch_sequence,
      anchorSlot: row.anchor_slot,
      transactionSignature: row.transaction_signature,
      merkleRoot: row.merkle_root,
      manifestHash: row.manifest_hash,
      explorerUrl: `https://explorer.solana.com/tx/${row.transaction_signature}?cluster=devnet`,
    });
    return;
  }
  const qr = url.pathname.match(/^\/v1\/qr\/([0-9a-f]{32})\.(svg|png)$/);
  if (request.method === "GET" && qr) {
    if (!(await requireWorkingRegistry(response))) return;
    const result = await pool.query("SELECT qr_url FROM demo_certificate WHERE certificate_id=$1", [qr[1]]);
    if (!result.rows.length) { json(response, 404, { code: "CERTIFICATE_NOT_FOUND" }); return; }
    const qrUrl: string = result.rows[0].qr_url;
    if (qr[2] === "png") {
      // PNG exists for printing and slides; the payload is the same URL.
      const png = await QRCode.toBuffer(qrUrl, { type: "png", errorCorrectionLevel: "M", margin: 2, width: 512 });
      response.writeHead(200, { "content-type": "image/png", "cache-control": "no-store", "content-length": png.length });
      response.end(png);
      return;
    }
    const svg = await QRCode.toString(qrUrl, { type: "svg", errorCorrectionLevel: "M", margin: 2 });
    response.writeHead(200, { "content-type": "image/svg+xml", "cache-control": "no-store", "content-length": Buffer.byteLength(svg) });
    response.end(svg);
    return;
  }
  const page = url.pathname.match(/^\/c\/([0-9a-f]{32})$/);
  if (request.method === "GET" && page) {
    if (!(await requireWorkingRegistry(response))) return;
    const certificateId = page[1];
    const certificate = await pool.query("SELECT encode(certificate_hash,'hex') AS certificate_hash FROM demo_certificate WHERE certificate_id=$1", [certificateId]);
    if (!certificate.rows.length || qrHashHex(url.searchParams.get("h")) !== certificate.rows[0].certificate_hash) {
      json(response, 422, { code: "QR_HASH_MISMATCH" });
      return;
    }
    const html = `<!doctype html><meta charset="utf-8"><title>OneLayer verification</title><style>body{font:18px system-ui;max-width:760px;margin:8vh auto;padding:24px;background:#0b1020;color:#eaf2ff}pre{white-space:pre-wrap;background:#151d35;padding:20px;border-radius:12px}.ok{color:#58e6a9}.bad{color:#ff6b86}</style><h1>OneLayer synthetic devnet certificate</h1><p>Certificate <code>${certificateId}</code></p><pre id="result">Checking finalized Solana anchor…</pre><script>Promise.all([fetch('/v1/certificates/${certificateId}/package').then(r=>r.json())]).then(async([p])=>{const r=await fetch('${verifierUrl}/v1/verify',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({certificatePackage:p.package_base64url,requiredCommitment:'finalized'})});const v=await r.json();const el=document.querySelector('#result');el.className=v.status==='VERIFIED'?'ok':'bad';el.textContent=JSON.stringify(v,null,2)}).catch(e=>document.querySelector('#result').textContent=e.message)</script>`;
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-length": Buffer.byteLength(html) });
    response.end(html);
    return;
  }
  json(response, 404, { code: "NOT_FOUND" });
}

const port = Number(process.env.PORT ?? "8090");
if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("PORT is invalid");
// Startup binding: a configured version identifier must never be reused with
// different key material across restarts. Registration is awaited before the
// listener starts, so a conflicting restart refuses to serve. Only a
// domain-separated digest reaches PostgreSQL; the KEK is never persisted.
if (snapshotKeyConfig !== undefined) {
  await bindSnapshotKeyVersion(pool, REGISTRY_ID, snapshotKeyConfig);
}
const server = createServer((request, response) => {
  handle(request, response).catch((error: unknown) => {
    if (error instanceof AuthorizationError) { json(response, error.status, { code: error.code }); return; }
    if (error instanceof InternalRefusal) {
      if (error.status === 429) response.setHeader("retry-after", "1");
      json(response, error.status, { code: error.code });
      return;
    }
    if (error instanceof IdentityUnavailableError) { json(response, 503, { code: 'IDENTITY_UNAVAILABLE' }); return; }
    json(response, 500, { code: "DEMO_API_ERROR" });
  });
});
server.listen(port, "127.0.0.1", () => process.stdout.write(`demo API listening on 127.0.0.1:${port}\n`));
