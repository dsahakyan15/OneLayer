import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { Pool } from "pg";
import QRCode from "qrcode";
import { fixtureRoot, type SyntheticFixtureRow } from "./reconcile.ts";

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
if (rpcUrl !== "https://api.devnet.solana.com") throw new Error("demo API is devnet-only");
const pool = new Pool({ connectionString: databaseUrl, max: 5 });

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

async function finalizedSlot(): Promise<string> {
  const rpcResponse = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getSlot", params: [{ commitment: "finalized" }] }),
  });
  if (!rpcResponse.ok) throw new Error(`devnet RPC HTTP ${rpcResponse.status}`);
  const rpcBody: any = await rpcResponse.json();
  return unsigned(rpcBody.result, "finalized slot");
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
  const qrUrl = text(input.qrUrl, "qrUrl", /^http:\/\/127\.0\.0\.1:8090\/c\/[0-9a-f]{32}\?h=[0-9a-f]{64}$/);
  if (new URL(qrUrl).searchParams.get("h") !== certificateHash) throw new TypeError("QR hash does not match certificate hash");
  const issuedAt = text(input.issuedAt, "issuedAt", /^20[0-9]{2}-[0-9]{2}-[0-9]{2}T/);
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
        certificate_id, registry_id, batch_sequence, certificate_hash, package_base64url, qr_url, status, issued_at
      ) VALUES ($1,$2,$3,decode($4,'hex'),$5,$6,'ACTIVE',$7)
      ON CONFLICT (certificate_id) DO UPDATE SET
        certificate_hash=EXCLUDED.certificate_hash, package_base64url=EXCLUDED.package_base64url, qr_url=EXCLUDED.qr_url,
        status='ACTIVE', issued_at=EXCLUDED.issued_at`,
      [certificateId, registryId, batchSequence, certificateHash, certificatePackage, qrUrl, issuedAt],
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
    pool.query("SELECT internal_record_id, record_version::text, status, record_field_key_hex FROM synthetic_registry_record ORDER BY source_cursor"),
  ]);
  if (anchor.rows.length !== 1) throw new Error("finalized demo anchor missing");
  const rows: SyntheticFixtureRow[] = records.rows.map((row) => ({
    internalRecordId: row.internal_record_id,
    recordVersion: row.record_version,
    status: row.status,
    recordFieldKeyHex: row.record_field_key_hex,
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

async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
  const url = new URL(request.url ?? "/", publicBaseUrl);
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
    const batchSequence = unsigned(url.searchParams.get("batchSequence"), "batchSequence");
    const result = await pool.query(
      "SELECT first_suspect_batch::text, last_suspect_batch::text, status FROM integrity_incident WHERE registry_id=$1 AND first_suspect_batch <= $2 AND last_suspect_batch >= $2",
      [REGISTRY_ID, batchSequence],
    );
    json(response, 200, {
      registryId: REGISTRY_ID,
      indexedThroughSlot: await finalizedSlot(),
      incidents: result.rows.map((row) => ({ firstBatchSequence: row.first_suspect_batch, lastBatchSequence: row.last_suspect_batch, status: row.status })),
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
    const result = await pool.query("SELECT package_base64url FROM demo_certificate WHERE certificate_id=$1", [certificatePackage[1]]);
    json(response, result.rows.length ? 200 : 404, result.rows[0] ?? { code: "CERTIFICATE_NOT_FOUND" });
    return;
  }
  const qr = url.pathname.match(/^\/v1\/qr\/([0-9a-f]{32})\.svg$/);
  if (request.method === "GET" && qr) {
    const result = await pool.query("SELECT qr_url FROM demo_certificate WHERE certificate_id=$1", [qr[1]]);
    if (!result.rows.length) { json(response, 404, { code: "CERTIFICATE_NOT_FOUND" }); return; }
    const svg = await QRCode.toString(result.rows[0].qr_url, { type: "svg", errorCorrectionLevel: "M", margin: 2 });
    response.writeHead(200, { "content-type": "image/svg+xml", "cache-control": "no-store", "content-length": Buffer.byteLength(svg) });
    response.end(svg);
    return;
  }
  const page = url.pathname.match(/^\/c\/([0-9a-f]{32})$/);
  if (request.method === "GET" && page) {
    const certificateId = page[1];
    const certificate = await pool.query("SELECT encode(certificate_hash,'hex') AS certificate_hash FROM demo_certificate WHERE certificate_id=$1", [certificateId]);
    if (!certificate.rows.length || url.searchParams.get("h") !== certificate.rows[0].certificate_hash) {
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
