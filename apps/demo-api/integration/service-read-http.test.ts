// HTTP matrix for the scoped verifier read surface (ticket 07 slice): live
// action and registry scope, the route's own registry selector, expiry and
// revoke, exact method/path refusals, cookie-bearer separation and the modes in
// which the surface does not exist at all. The happy-path composition with the
// verifier adapters lives in tests/e2e/service-verifier-read.test.ts.
//
// No incident request here reaches an authorized handler: /v1/incidents makes
// the API refresh its event index against devnet RPC. Refusals are asserted
// instead, and the incident index table must stay untouched.
//
// The last block of the first test pins the gate: a slot covers the whole
// response-producing operation, so with two reads blocked inside the handler a
// third is refused (not queued) and every blocked, failed or aborted read
// returns its slot.
import assert from "node:assert/strict";
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { connect, createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { promisify } from "node:util";
import type { Pool } from "pg";
import { isolatedPostgres } from "./support/postgres.ts";
import { startTestIdp } from "./support/test-idp.ts";

const exec = promisify(execFile);
const cwd = new URL("../", import.meta.url);
const REGISTRY = "gov.registry.land";
const FOREIGN_REGISTRY = "other.registry";
const CERTIFICATE = "aa".repeat(16);
const FOREIGN_CERTIFICATE = "bb".repeat(16);
const LEGACY_TOKEN = "synthetic-legacy-internal-token-0123456789";
const PUBLIC_WEB_URL = "http://127.0.0.1:8091";

/** Reads blocked on a lock, i.e. requests currently inside the read handler. */
async function blockedReads(pool: Pool): Promise<number> {
  return (await pool.query(
    "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%demo_certificate%'",
  )).rows[0].n as number;
}

async function waitForBlockedReads(pool: Pool, accept: (n: number) => boolean, expectation: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  for (;;) {
    const seen = await blockedReads(pool);
    if (accept(seen)) return;
    if (Date.now() > deadline) throw new Error(`waited for ${expectation}, saw ${seen}`);
    await new Promise(resolve => setTimeout(resolve, 50));
  }
}

async function freePort(): Promise<number> {
  const listener = createServer();
  listener.listen(0, "127.0.0.1");
  await once(listener, "listening");
  const address = listener.address();
  assert.ok(address && typeof address !== "string");
  await new Promise<void>((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
  return address.port;
}

function baseEnv(dir: string, port: number): NodeJS.ProcessEnv {
  return {
    ...process.env, PORT: String(port),
    ONELAYER_DATABASE_URL_FILE: join(dir, "database"), ONELAYER_INTERNAL_TOKEN_FILE: join(dir, "token"),
    ONELAYER_ISSUER_SECRET_FILE: join(dir, "issuer"), ONELAYER_ADMIN_CREDENTIALS_FILE: join(dir, "credentials"),
    ONELAYER_RPC_URL: "https://api.devnet.solana.com", ONELAYER_VERIFIER_URL: "http://127.0.0.1:1",
    ONELAYER_PUBLIC_BASE_URL: `http://127.0.0.1:${port}`, ONELAYER_PUBLIC_WEB_URL: PUBLIC_WEB_URL,
    ONELAYER_PROGRAM_ID: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo",
  };
}

async function writeCommon(dir: string, database: string): Promise<void> {
  await Promise.all([
    writeFile(join(dir, "database"), database),
    writeFile(join(dir, "token"), LEGACY_TOKEN),
    writeFile(join(dir, "issuer"), "09".repeat(32)),
    writeFile(join(dir, "credentials"), JSON.stringify({ operator: "synthetic-operator-password", auditor: "synthetic-auditor-password" })),
  ]);
}

/** Starts real main.ts; resolves when listening, rejects with its output if it exits. */
async function startApi(context: TestContext, env: NodeJS.ProcessEnv): Promise<void> {
  const child: ChildProcess = spawn(process.execPath, ["--experimental-transform-types", "src/main.ts"], { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
  context.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const closed = once(child, "close");
      child.kill("SIGKILL");
      await closed;
    }
  });
  await new Promise<void>((resolve, reject) => {
    let output = "";
    // Real main.ts startup (module graph plus transforms) is seconds long on a
    // loaded machine; the bound is generous so a slow start is not a failure.
    const timer = setTimeout(() => reject(new Error(`startup timed out: ${output}`)), 30_000);
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.once("exit", code => { clearTimeout(timer); reject(new Error(`API exited ${code}: ${output}`)); });
    child.stderr!.on("data", data => { output += String(data); });
    child.stdout!.on("data", data => {
      output += String(data);
      if (output.includes("demo API listening")) { clearTimeout(timer); resolve(); }
    });
  });
}

test("real OIDC API: service reads are scoped, audited and refused outside the exact whitelist", { timeout: 180_000 }, async context => {
  const { pool, connectionString, dir } = await isolatedPostgres(context);
  await writeCommon(dir, connectionString);
  const port = await freePort();
  const idp = await startTestIdp(); context.after(() => idp.close());
  await writeFile(join(dir, "oidc.json"), JSON.stringify(idp.config(`http://127.0.0.1:${port}/v2/admin/oidc/callback`)));
  const env: NodeJS.ProcessEnv = { ...baseEnv(dir, port), ONELAYER_OIDC_CONFIG_FILE: join(dir, "oidc.json"), ONELAYER_SESSION_BACKEND: "postgres" };
  const manage = (...args: string[]) => exec(process.execPath, ["--experimental-transform-types", "scripts/manage-admin-access.ts", ...args], { cwd, env });
  const scope = async (name: string, value: unknown) => { await writeFile(join(dir, name), JSON.stringify(value)); return join(dir, name); };

  // One human account with a narrowed resource policy: corporate admission and
  // the export gate must keep denying it on the same paths the service surface
  // reads, and a service bearer must never become that human identity.
  await writeFile(join(dir, "alice.json"), JSON.stringify({ issuer: idp.issuer, subject: "test-user", access: { role: "registry_worker" }, resourcePolicy: { version: 1, grants: [] } }));
  await manage("oidc-provision", "alice", "maintainer", join(dir, "alice.json"));
  await manage("device-enroll", "alice", "maintainer", "test-device");
  await manage("service-provision", "svc.reader", "maintainer", await scope("reader.json", { actions: ["anchors.read", "certificates.read", "incidents.read"], registryIds: [REGISTRY] }), join(dir, "reader.token"), "30");
  await manage("service-provision", "svc.anchors", "maintainer", await scope("anchors.json", { actions: ["anchors.read"], registryIds: [REGISTRY] }), join(dir, "anchors.token"), "30");
  await manage("service-provision", "svc.foreign", "maintainer", await scope("foreign.json", { actions: ["anchors.read", "certificates.read", "incidents.read"], registryIds: [FOREIGN_REGISTRY] }), join(dir, "foreign.token"), "30");
  await manage("service-provision", "svc.expired", "maintainer", await scope("expired.json", { actions: ["anchors.read", "incidents.read"], registryIds: [REGISTRY] }), join(dir, "expired.token"), "30");
  await manage("service-provision", "svc.gate", "maintainer", await scope("gate.json", { actions: ["certificates.read", "incidents.read"], registryIds: [REGISTRY] }), join(dir, "gate.token"), "30");
  const read = async (name: string) => (await readFile(join(dir, name), "utf8")).trim();
  const [readerToken, anchorsToken, foreignToken, expiredToken, gateToken] = await Promise.all([read("reader.token"), read("anchors.token"), read("foreign.token"), read("expired.token"), read("gate.token")]);

  await pool.query(await readFile(new URL("../../../db/fixtures/devnet-demo.sql", import.meta.url), "utf8"));
  const insertAnchor = (registryId: string) => pool.query(
    `INSERT INTO demo_anchor (registry_id,batch_sequence,registry_version,merkle_root,manifest_hash,anchor_hash,program_id,segment_pda,transaction_signature,anchor_slot,commitment,finalized_at)
     VALUES ($1,1,1,decode(repeat('33',32),'hex'),decode(repeat('11',32),'hex'),decode(repeat('22',32),'hex'),'p','s','t',1,'finalized',now())`, [registryId]);
  await insertAnchor(REGISTRY); await insertAnchor(FOREIGN_REGISTRY);
  const insertCertificate = (certificateId: string, registryId: string) => pool.query(
    `INSERT INTO demo_certificate (certificate_id,registry_id,batch_sequence,certificate_hash,package_base64url,qr_url,status,issued_at,internal_record_id,record_version)
     VALUES ($1,$2,1,decode(repeat('44',32),'hex'),'cGFja2FnZQ',$3,'ACTIVE',now(),'SYNTHETIC-1',1)`,
    [certificateId, registryId, `http://127.0.0.1:8090/c/${certificateId}?h=${"A".repeat(43)}`]);
  await insertCertificate(CERTIFICATE, REGISTRY);
  await insertCertificate(FOREIGN_CERTIFICATE, FOREIGN_REGISTRY);

  await startApi(context, env);
  const base = `http://127.0.0.1:${port}`;
  const expectResponse = async (response: Promise<Response>, status: number, code?: string): Promise<string> => {
    const result = await response;
    const text = await result.text();
    assert.equal(result.status, status, text);
    if (code !== undefined) assert.equal(JSON.parse(text).code, code, text);
    return text;
  };
  const expectJson = async (response: Promise<Response>, status: number): Promise<Record<string, any>> =>
    JSON.parse(await expectResponse(response, status));
  const auth = (token: string) => ({ authorization: `Bearer ${token}` });
  const start = await fetch(`${base}/v2/admin/oidc/start`, { method: "POST", headers: { origin: PUBLIC_WEB_URL } });
  assert.equal(start.status, 200);
  const binding = start.headers.get("set-cookie")!.split(";")[0]!;
  const callback = await idp.authorize((await start.json() as { authorizationUrl: string }).authorizationUrl);
  const logged = await fetch(`${base}/v2/admin/oidc/callback?${new URLSearchParams(callback)}`, { headers: { cookie: binding }, redirect: "manual" });
  assert.equal(logged.status, 303);
  const aliceCookie = logged.headers.get("set-cookie")!.split(";")[0]!;
  assert.equal((await fetch(`${base}/v1/admin/session`, { headers: { cookie: aliceCookie } })).status, 200);

  // Refused incident reads first, and the only incident requests in this test.
  // Wrong action, foreign scope, foreign selector and an absent selector are all
  // decided before the handler, so no index refresh (devnet RPC) can run.
  await expectResponse(fetch(`${base}/v1/incidents?registryId=${REGISTRY}&batchSequence=1`, { headers: auth(anchorsToken) }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expectResponse(fetch(`${base}/v1/incidents?registryId=${REGISTRY}&batchSequence=1`, { headers: auth(foreignToken) }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expectResponse(fetch(`${base}/v1/incidents?registryId=${FOREIGN_REGISTRY}&batchSequence=1`, { headers: auth(foreignToken) }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expectResponse(fetch(`${base}/v1/incidents?registryId=${FOREIGN_REGISTRY}&batchSequence=1`, { headers: auth(readerToken) }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expectResponse(fetch(`${base}/v1/incidents?batchSequence=1`, { headers: auth(readerToken) }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  // The human gate still owns the path without a service bearer.
  await expectResponse(fetch(`${base}/v1/incidents?registryId=${REGISTRY}&batchSequence=1`), 401, "SESSION_REQUIRED");
  await expectResponse(fetch(`${base}/v1/incidents?registryId=${REGISTRY}&batchSequence=1`, { headers: { cookie: aliceCookie } }), 403, "RESOURCE_FORBIDDEN");
  // No incident work happened: the handler would insert the index state row
  // before its refresh, and a selector-refused request records no authorization.
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM incident_index_state")).rows[0].n, 0);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM service_principal_event WHERE principal_id='svc.reader' AND event='REQUEST_AUTHORIZED' AND service_action='incidents.read'")).rows[0].n, 0);

  // Authorized reads on the deployment registry, with no human session: the
  // same URLs without a service credential are a human OIDC surface.
  const anchor = await expectJson(fetch(`${base}/v1/anchors/1`, { headers: auth(readerToken) }), 200);
  assert.equal(anchor.registry_id, REGISTRY);
  assert.equal(anchor.batch_sequence, "1");
  assert.deepEqual(await expectJson(fetch(`${base}/v1/certificates/${CERTIFICATE}/status`, { headers: auth(readerToken) }), 200),
    { certificate_id: CERTIFICATE, status: "ACTIVE", batch_sequence: "1" });
  assert.deepEqual(await expectJson(fetch(`${base}/v1/certificates/${CERTIFICATE}/lifecycle?registryId=${REGISTRY}`, { headers: auth(readerToken) }), 200),
    { registryId: REGISTRY, certificateId: CERTIFICATE, currentRecordVersion: "1", certificateStatus: "ACTIVE" });
  await expectResponse(fetch(`${base}/v1/anchors/1`), 401, "SESSION_REQUIRED");
  await expectResponse(fetch(`${base}/v1/anchors/1`, { headers: { cookie: aliceCookie } }), 403, "RESOURCE_FORBIDDEN");
  await expectResponse(fetch(`${base}/v1/anchors/1`, { headers: { cookie: aliceCookie, ...auth(readerToken) } }), 401, "SERVICE_CREDENTIAL_REQUIRED");

  // A foreign registry row is unreadable through its ID, for every caller.
  await expectResponse(fetch(`${base}/v1/certificates/${FOREIGN_CERTIFICATE}/status`, { headers: auth(readerToken) }), 404, "CERTIFICATE_NOT_FOUND");
  await expectResponse(fetch(`${base}/v1/certificates/${FOREIGN_CERTIFICATE}/lifecycle?registryId=${REGISTRY}`, { headers: auth(readerToken) }), 404, "CERTIFICATE_NOT_FOUND");

  // Scope and action come from PostgreSQL only; a registry selector outside the
  // deployment is refused after the credential is proven and before any lookup.
  await expectResponse(fetch(`${base}/v1/certificates/${CERTIFICATE}/status`, { headers: auth(anchorsToken) }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expectResponse(fetch(`${base}/v1/certificates/${CERTIFICATE}/lifecycle?registryId=${REGISTRY}`, { headers: auth(anchorsToken) }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expectResponse(fetch(`${base}/v1/anchors/1`, { headers: auth(foreignToken) }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expectResponse(fetch(`${base}/v1/certificates/${CERTIFICATE}/status`, { headers: auth(foreignToken) }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expectResponse(fetch(`${base}/v1/certificates/${CERTIFICATE}/lifecycle?registryId=${FOREIGN_REGISTRY}`, { headers: auth(readerToken) }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expectResponse(fetch(`${base}/v1/certificates/${CERTIFICATE}/lifecycle`, { headers: auth(readerToken) }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  // The selector is strict: a repeated `registryId` is refused even when its
  // first value names this deployment, so first-value handlers are unreachable.
  await expectResponse(fetch(`${base}/v1/incidents?registryId=${REGISTRY}&registryId=${REGISTRY}&batchSequence=1`, { headers: auth(readerToken) }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expectResponse(fetch(`${base}/v1/incidents?registryId=${REGISTRY}&registryId=${FOREIGN_REGISTRY}&batchSequence=1`, { headers: auth(readerToken) }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expectResponse(fetch(`${base}/v1/certificates/${CERTIFICATE}/lifecycle?registryId=${REGISTRY}&registryId=${REGISTRY}`, { headers: auth(readerToken) }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expectResponse(fetch(`${base}/v1/anchors/1`, { headers: auth(`olsp_${"A".repeat(22)}.${"B".repeat(43)}`) }), 401, "SERVICE_CREDENTIAL_REQUIRED");

  // Exact whitelist: everything else keeps the route-refusal error, with or
  // without a valid human cookie, including non-GET methods on the same paths.
  for (const path of [
    `/v1/certificates/${CERTIFICATE}/package`, `/v1/certificates/${CERTIFICATE}/metadata`,
    `/v1/qr/${CERTIFICATE}.svg`, `/v1/qr/${CERTIFICATE}.png`, `/c/${CERTIFICATE}`,
    "/v1/anchors", "/v1/anchors/1/", "/v1/anchors/1/extra", "/v1/anchors/01",
    `/v1/certificates/${CERTIFICATE.toUpperCase()}/status`, "/v1/health", "/v1/admin/session",
  ]) {
    await expectResponse(fetch(`${base}${path}`, { headers: auth(readerToken) }), 401, "SERVICE_PRINCIPAL_NOT_ALLOWED");
    await expectResponse(fetch(`${base}${path}`, { headers: { cookie: aliceCookie, ...auth(readerToken) } }), 401, "SERVICE_PRINCIPAL_NOT_ALLOWED");
  }
  // Internal routes stay POST-only: a GET there never becomes a service read.
  await expectResponse(fetch(`${base}/internal/register`, { headers: auth(readerToken) }), 401, "SESSION_REQUIRED");
  for (const method of ["POST", "PUT", "DELETE"]) {
    await expectResponse(fetch(`${base}/v1/anchors/1`, { method, headers: auth(readerToken) }), 401, "SERVICE_PRINCIPAL_NOT_ALLOWED");
    await expectResponse(fetch(`${base}/v1/incidents?registryId=${REGISTRY}&batchSequence=1`, { method, headers: auth(readerToken) }), 401, "SERVICE_PRINCIPAL_NOT_ALLOWED");
    await expectResponse(fetch(`${base}/v1/certificates/${CERTIFICATE}/status`, { method, headers: auth(readerToken) }), 401, "SERVICE_PRINCIPAL_NOT_ALLOWED");
  }

  // Expiry and revoke fail the read before any selector or resource work; the
  // credential is proven even when the selector itself is invalid.
  await pool.query("UPDATE service_principal_credential SET created_at = clock_timestamp() - interval '2 days', expires_at = clock_timestamp() - interval '1 day' WHERE principal_id='svc.expired'");
  await expectResponse(fetch(`${base}/v1/anchors/1`, { headers: auth(expiredToken) }), 401, "SERVICE_CREDENTIAL_REQUIRED");
  await expectResponse(fetch(`${base}/v1/incidents?registryId=${FOREIGN_REGISTRY}&batchSequence=1`, { headers: auth(expiredToken) }), 401, "SERVICE_CREDENTIAL_REQUIRED");
  await manage("service-revoke", "svc.anchors", "maintainer");
  await expectResponse(fetch(`${base}/v1/anchors/1`, { headers: auth(anchorsToken) }), 401, "SERVICE_CREDENTIAL_REQUIRED");

  // The legacy shared token is not a service identity and gains nothing here:
  // only the human gate ever sees it, exactly as without it.
  await expectResponse(fetch(`${base}/v1/anchors/1`, { headers: auth(LEGACY_TOKEN) }), 401, "SESSION_REQUIRED");
  await expectResponse(fetch(`${base}/v1/anchors/1`, { headers: { cookie: aliceCookie, ...auth(LEGACY_TOKEN) } }), 403, "RESOURCE_FORBIDDEN");

  // One denial window per credential/reason/action/minute: identical adjacent
  // rows are collapsed. Repeats only bump the counter, so no success is ever
  // recorded for a refused request and the legacy token records nothing at all.
  const rows = (await pool.query(
    "SELECT principal_id, event, reason, service_action, registry_id FROM service_principal_event WHERE event LIKE 'REQUEST_%' ORDER BY event_id",
  )).rows.map(row => `${row.principal_id}:${row.reason ?? row.event}:${row.service_action}:${row.registry_id}`);
  const events = rows.filter((row, index) => index === 0 || row !== rows[index - 1]);
  assert.deepEqual(events, [
    "svc.anchors:ACTION_NOT_ALLOWED:incidents.read:gov.registry.land",
    "svc.foreign:REGISTRY_OUT_OF_SCOPE:incidents.read:gov.registry.land",
    "svc.reader:REQUEST_AUTHORIZED:anchors.read:gov.registry.land",
    "svc.reader:REQUEST_AUTHORIZED:certificates.read:gov.registry.land",
    "svc.anchors:ACTION_NOT_ALLOWED:certificates.read:gov.registry.land",
    "svc.foreign:REGISTRY_OUT_OF_SCOPE:anchors.read:gov.registry.land",
    "svc.foreign:REGISTRY_OUT_OF_SCOPE:certificates.read:gov.registry.land",
    "svc.expired:CREDENTIAL_EXPIRED:anchors.read:gov.registry.land",
    "svc.expired:CREDENTIAL_EXPIRED:incidents.read:gov.registry.land",
    "svc.anchors:CREDENTIAL_REVOKED:anchors.read:gov.registry.land",
  ]);

  // Anchors domain and storage bounds, decided before any query: a valid u64
  // above INT8_MAX cannot exist in the BIGINT column (404), and anything above
  // u64 is not a batch sequence at all (400). Reaching PostgreSQL with either
  // would be a 22003 and surface as a 500. More than 20 digits never matches
  // the allowlist, so no code path parses an unbounded number. These requests
  // come after the audit snapshot above, so its rows stay unchanged.
  const anchorBounds: Array<[string, number, string]> = [
    ["9223372036854775808", 404, "ANCHOR_NOT_FOUND"],
    ["18446744073709551615", 404, "ANCHOR_NOT_FOUND"],
    ["18446744073709551616", 400, "BATCH_SEQUENCE_INVALID"],
  ];
  for (const [batchSequence, status, code] of anchorBounds) {
    await expectResponse(fetch(`${base}/v1/anchors/${batchSequence}`, { headers: auth(readerToken) }), status, code);
  }
  await expectResponse(fetch(`${base}/v1/anchors/${"9".repeat(21)}`, { headers: auth(readerToken) }), 401, "SERVICE_PRINCIPAL_NOT_ALLOWED");

  // The gate slot covers the whole read operation, not only its authorization.
  // A table lock stands in for any slow SQL or index refresh: while two reads
  // are blocked inside the handler a third is refused with 429 instead of
  // queueing after a short authorization, and both blocked reads still complete
  // and return their slots once the lock lifts.
  const statusUrl = `${base}/v1/certificates/${CERTIFICATE}/status`;
  const blocker = await pool.connect();
  const blocked: Array<Promise<Response>> = [];
  try {
    await blocker.query("BEGIN");
    await blocker.query("LOCK TABLE demo_certificate IN ACCESS EXCLUSIVE MODE");
    blocked.push(fetch(statusUrl, { headers: auth(gateToken) }), fetch(statusUrl, { headers: auth(gateToken) }));
    await waitForBlockedReads(pool, seen => seen >= 2, "two blocked reads");
    // Bounded: a regression that lets the read past the gate must fail here
    // instead of hanging until the fetch timeout.
    const busy = await fetch(statusUrl, { headers: auth(gateToken), signal: AbortSignal.timeout(2_000) });
    assert.equal(busy.status, 429);
    assert.deepEqual(await busy.json(), { code: "SERVICE_BUSY" });
    await blocker.query("COMMIT");
    assert.deepEqual((await Promise.all(blocked)).map(response => response.status), [200, 200]);
  } finally {
    await blocker.query("ROLLBACK").catch(() => undefined);
    blocker.release();
    await Promise.allSettled(blocked);
  }

  // A read that fails inside the handler returns its slot: two such errors must
  // not leave the next two concurrent reads without a slot. The route rejects a
  // non-canonical batch number before any refresh (pre-existing gap in the
  // handler's own validation, unchanged by this slice).
  for (const batchSequence of ["x", "1.5"]) {
    await expectResponse(fetch(`${base}/v1/incidents?registryId=${REGISTRY}&batchSequence=${batchSequence}`, { headers: auth(gateToken) }), 500, "DEMO_API_ERROR");
  }
  const afterErrors = await Promise.all([fetch(statusUrl, { headers: auth(gateToken) }), fetch(statusUrl, { headers: auth(gateToken) })]);
  assert.deepEqual(afterErrors.map(response => response.status), [200, 200]);

  // An aborted connection must not leak a slot either: the client disappears
  // while the handler is still waiting, the handler then finishes and returns
  // its slot, so two concurrent reads still fit under the cap of two.
  const aborted = await pool.connect();
  try {
    await aborted.query("BEGIN");
    await aborted.query("LOCK TABLE demo_certificate IN ACCESS EXCLUSIVE MODE");
    const socket = connect(port, "127.0.0.1");
    await once(socket, "connect");
    socket.on("error", () => undefined);
    socket.write(`GET /v1/certificates/${CERTIFICATE}/status HTTP/1.1\r\nhost: 127.0.0.1\r\nauthorization: Bearer ${gateToken}\r\n\r\n`);
    await waitForBlockedReads(pool, seen => seen >= 1, "the aborted read inside the handler");
    socket.destroy();
    await aborted.query("COMMIT");
    await waitForBlockedReads(pool, seen => seen === 0, "the aborted read to finish");
    const afterAbort = await Promise.all([fetch(statusUrl, { headers: auth(gateToken) }), fetch(statusUrl, { headers: auth(gateToken) })]);
    assert.deepEqual(afterAbort.map(response => response.status), [200, 200]);
  } finally {
    await aborted.query("ROLLBACK").catch(() => undefined);
    aborted.release();
  }
});

test("service reads exist only where durable service principals are configured", { timeout: 120_000 }, async context => {
  const dir = await mkdtemp(join(tmpdir(), "onelayer-service-reads-"));
  context.after(() => rm(dir, { recursive: true, force: true }));
  await writeCommon(dir, "postgresql://fixture:fixture@127.0.0.1:1/unused");
  const serviceBearer = `Bearer olsp_${"A".repeat(22)}.${"B".repeat(43)}`;
  const paths = ["/v1/anchors/1", `/v1/incidents?registryId=${REGISTRY}&batchSequence=1`, `/v1/certificates/${CERTIFICATE}/status`, `/v1/certificates/${CERTIFICATE}/lifecycle?registryId=${REGISTRY}`];
  for (const mode of [{ name: "legacy", env: { ONELAYER_SESSION_BACKEND: "memory", ONELAYER_INTERNAL_AUTH: "legacy-demo-token" } },
    { name: "disabled", env: { ONELAYER_SESSION_BACKEND: "memory" } }]) {
    const port = await freePort();
    await startApi(context, { ...baseEnv(dir, port), ...mode.env });
    for (const path of paths) {
      const refused = await fetch(`http://127.0.0.1:${port}${path}`, { headers: { authorization: serviceBearer } });
      assert.equal(refused.status, 401, `${mode.name} ${path}`);
      assert.deepEqual(await refused.json(), { code: "SERVICE_PRINCIPAL_NOT_ALLOWED" }, `${mode.name} ${path}`);
    }
    // Same bounds on the credential-free path with an unreachable database: a
    // missing bound would reach the pool and answer 500, so these answers prove
    // both decisions happen before any query.
    for (const [batchSequence, status, code] of [["9223372036854775808", 404, "ANCHOR_NOT_FOUND"], ["18446744073709551615", 404, "ANCHOR_NOT_FOUND"],
      ["18446744073709551616", 400, "BATCH_SEQUENCE_INVALID"], [`${"9".repeat(21)}`, 400, "BATCH_SEQUENCE_INVALID"]] as Array<[string, number, string]>) {
      const bounded = await fetch(`http://127.0.0.1:${port}/v1/anchors/${batchSequence}`);
      assert.equal(bounded.status, status, `${mode.name} ${batchSequence}`);
      assert.deepEqual(await bounded.json(), { code }, `${mode.name} ${batchSequence}`);
    }
  }
});
