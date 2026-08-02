import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
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
import { SolanaPublisherRpc } from "./solana-rpc.ts";
import { parseCredentials, SessionStore, CSRF_HEADER } from "./admin-session.ts";
import { routeAdmin, type AdminContext } from "./admin.ts";

const MAX_BODY = 1_048_576;
const REGISTRY_ID = "gov.registry.land";
const MARKER = "ONELAYER_SYNTHETIC_DEVNET_DEMO_V1";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function secret(pathName: string): string {
  return readFileSync(required(pathName), "utf8").trim();
}

const databaseUrl = secret("ONELAYER_DATABASE_URL_FILE");
const internalToken = secret("ONELAYER_INTERNAL_TOKEN_FILE");
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
const adminCredentials = parseCredentials(secret("ONELAYER_ADMIN_CREDENTIALS_FILE"));
if (rpcUrl !== "https://api.devnet.solana.com") throw new Error("demo API is devnet-only");
const pool = new Pool({ connectionString: databaseUrl, max: 5 });

const [configAddress] = await findRegistryConfigPda(registryIdHash(REGISTRY_ID), {
  programAddress: programId as Address,
});
const registryBinding: RegistryBinding = {
  registryId: REGISTRY_ID,
  configAddress,
  configBytes: new Uint8Array(getAddressEncoder().encode(configAddress)),
};
const incidentRpc = new SolanaPublisherRpc(rpcUrl, programId);
const incidentStore = new PostgresIncidentStore(pool, configAddress);

const adminContext: AdminContext = {
  pool,
  sessions: new SessionStore(adminCredentials),
  rpc: incidentRpc,
  registryId: REGISTRY_ID,
  programId: programId as Address,
  configPda: configAddress,
  issuerSecretKey,
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

function authorized(request: IncomingMessage): boolean {
  const supplied = request.headers.authorization?.replace(/^Bearer /, "") ?? "";
  const left = Buffer.from(supplied);
  const right = Buffer.from(internalToken);
  return left.length === right.length && timingSafeEqual(left, right);
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

async function registerArtifact(input: Record<string, unknown>): Promise<void> {
  await ensureFixture();
  const registryId = text(input.registryId, "registryId", /^gov\.registry\.land$/);
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
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
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
  });
  if (result.setCookie !== undefined) response.setHeader("set-cookie", result.setCookie);
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
  if (url.pathname.startsWith("/v1/admin/")) {
    await handleAdmin(request, response, url);
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/health") {
    await ensureFixture();
    json(response, 200, { status: "ok", fixture: MARKER, cluster: "devnet" });
    return;
  }
  if (request.method === "POST" && url.pathname === "/internal/register") {
    if (!authorized(request)) { json(response, 401, { code: "UNAUTHORIZED" }); return; }
    await registerArtifact(await body(request));
    json(response, 201, { status: "registered" });
    return;
  }
  if (request.method === "POST" && url.pathname === "/internal/reconcile") {
    if (!authorized(request)) { json(response, 401, { code: "UNAUTHORIZED" }); return; }
    json(response, 200, await reconcile());
    return;
  }
  if (request.method === "GET" && url.pathname.startsWith("/v1/anchors/")) {
    const batchSequence = unsigned(url.pathname.slice("/v1/anchors/".length), "batchSequence");
    const result = await pool.query(
      "SELECT registry_id, batch_sequence::text, registry_version::text, encode(merkle_root,'hex') merkle_root, encode(manifest_hash,'hex') manifest_hash, program_id, segment_pda, transaction_signature, anchor_slot::text, commitment FROM demo_anchor WHERE registry_id=$1 AND batch_sequence=$2",
      [REGISTRY_ID, batchSequence],
    );
    json(response, result.rows.length ? 200 : 404, result.rows[0] ?? { code: "ANCHOR_NOT_FOUND" });
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/incidents") {
    if (url.searchParams.get("registryId") !== REGISTRY_ID) throw new TypeError("registryId is invalid");
    const batchSequence = BigInt(unsigned(url.searchParams.get("batchSequence"), "batchSequence"));
    await refreshIndex();
    const [state, onchain, local] = await Promise.all([
      incidentStore.loadState(REGISTRY_ID),
      incidentStore.listNotices(REGISTRY_ID, batchSequence),
      // Local monitor findings (direct-DB tampering) are not on-chain events and
      // are reported as a separate source; they never set the watermark.
      pool.query(
        "SELECT first_suspect_batch::text, last_suspect_batch::text, status FROM integrity_incident WHERE registry_id=$1 AND first_suspect_batch <= $2 AND last_suspect_batch >= $2",
        [REGISTRY_ID, batchSequence.toString()],
      ),
    ]);
    const incidents = [
      ...onchain.map((notice) => ({
        firstBatchSequence: notice.firstSuspectBatch.toString(),
        lastBatchSequence: notice.lastSuspectBatch.toString(),
        status: notice.status,
        source: "ONCHAIN" as const,
        openedSlot: notice.openedSlot.toString(),
        resolvedSlot: notice.resolvedSlot === null ? undefined : notice.resolvedSlot.toString(),
      })),
      ...local.rows.map((row) => ({
        firstBatchSequence: row.first_suspect_batch,
        lastBatchSequence: row.last_suspect_batch,
        status: row.status === "OPEN" ? "OPEN" as const : "RESOLVED" as const,
        source: "LOCAL_MONITOR" as const,
      })),
    ];
    const body: Record<string, unknown> = { registryId: REGISTRY_ID, incidents };
    // No watermark means "never indexed", which the verifier must read as
    // UNAVAILABLE rather than as a complete empty answer.
    if (state.indexedThroughSlot > 0n) body.indexedThroughSlot = state.indexedThroughSlot.toString();
    json(response, 200, body);
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
      currentRecordVersion: result.rows[0].current_record_version,
      // DISPUTED is an incident state, not a lifecycle state: the certificate
      // itself has not been replaced.
      certificateStatus: status === "SUPERSEDED" || status === "REVOKED" ? status : "ACTIVE",
    });
    return;
  }
  const certificateStatus = url.pathname.match(/^\/v1\/certificates\/([0-9a-f]{32})\/status$/);
  if (request.method === "GET" && certificateStatus) {
    const result = await pool.query("SELECT certificate_id, status, batch_sequence::text FROM demo_certificate WHERE certificate_id=$1", [certificateStatus[1]]);
    json(response, result.rows.length ? 200 : 404, result.rows[0] ?? { code: "CERTIFICATE_NOT_FOUND" });
    return;
  }
  const certificatePackage = url.pathname.match(/^\/v1\/certificates\/([0-9a-f]{32})\/package$/);
  if (request.method === "GET" && certificatePackage) {
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
const server = createServer((request, response) => {
  handle(request, response).catch((error: unknown) => json(response, 500, { code: "DEMO_API_ERROR", message: error instanceof Error ? error.message : "unknown error" }));
});
server.listen(port, "0.0.0.0", () => process.stdout.write(`demo API listening on 0.0.0.0:${port}\n`));
