import assert from "node:assert/strict";
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { connect, createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { promisify } from "node:util";
import { isolatedPostgres } from "./support/postgres.ts";
import { startTestIdp } from "./support/test-idp.ts";

const exec = promisify(execFile);
const cwd = new URL("../", import.meta.url);

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
    ONELAYER_PUBLIC_BASE_URL: `http://127.0.0.1:${port}`, ONELAYER_PUBLIC_WEB_URL: "http://127.0.0.1:8091",
    ONELAYER_PROGRAM_ID: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo",
  };
}

async function writeCommon(dir: string, database: string): Promise<void> {
  await Promise.all([
    writeFile(join(dir, "database"), database),
    writeFile(join(dir, "token"), "synthetic-legacy-internal-token-0123456789"),
    writeFile(join(dir, "issuer"), "09".repeat(32)),
    writeFile(join(dir, "credentials"), JSON.stringify({ operator: "synthetic-operator-password", auditor: "synthetic-auditor-password" })),
  ]);
}

/** Starts real main.ts; resolves when listening, rejects with its output if it exits. */
async function startApi(context: TestContext, env: NodeJS.ProcessEnv): Promise<ChildProcess> {
  const child = spawn(process.execPath, ["--experimental-transform-types", "src/main.ts"], { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
  context.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const closed = once(child, "close");
      child.kill("SIGKILL");
      await closed;
    }
  });
  await new Promise<void>((resolve, reject) => {
    let output = "";
    const timer = setTimeout(() => reject(new Error(`startup timed out: ${output}`)), 15_000);
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.once("exit", code => { clearTimeout(timer); reject(new Error(`API exited ${code}: ${output}`)); });
    child.stderr!.on("data", data => { output += String(data); });
    child.stdout!.on("data", data => {
      output += String(data);
      if (output.includes("demo API listening")) { clearTimeout(timer); resolve(); }
    });
  });
  return child;
}

test("real API processes enforce durable scoped service principals and keep human and service identities apart", { timeout: 120_000 }, async context => {
  const { pool, connectionString, dir } = await isolatedPostgres(context);
  await writeCommon(dir, connectionString);
  const [portA, portB] = [await freePort(), await freePort()];
  const idp = await startTestIdp(); context.after(() => idp.close());
  await writeFile(join(dir, "oidc.json"), JSON.stringify(idp.config(`http://127.0.0.1:${portA}/v2/admin/oidc/callback`)));
  const envA = { ...baseEnv(dir, portA), ONELAYER_OIDC_CONFIG_FILE: join(dir, "oidc.json"), ONELAYER_SESSION_BACKEND: "postgres" };
  await writeFile(join(dir, "oidc-b.json"), JSON.stringify(idp.config(`http://127.0.0.1:${portB}/v2/admin/oidc/callback`)));
  const envB = { ...baseEnv(dir, portB), ONELAYER_OIDC_CONFIG_FILE: join(dir, "oidc-b.json"), ONELAYER_SESSION_BACKEND: "postgres",
    ONELAYER_INTERNAL_BODY_TIMEOUT_MS: "1000" };
  const manage = (...args: string[]) => exec(process.execPath, ["--experimental-transform-types", "scripts/manage-admin-access.ts", ...args], { cwd, env: envA });
  const scope = async (name: string, value: unknown) => { await writeFile(join(dir, name), JSON.stringify(value)); return join(dir, name); };

  await writeFile(join(dir, "provision.json"), JSON.stringify({ issuer: idp.issuer, subject: "test-user", access: { role: "registry_worker" }, resourcePolicy: { version: 1, grants: [] } }));
  await manage("oidc-provision", "alice", "maintainer", join(dir, "provision.json"));
  await manage("device-enroll", "alice", "maintainer", "test-device");
  await manage("service-provision", "svc.reconciler", "maintainer", await scope("reconcile.json", { actions: ["integrity.reconcile"], registryIds: ["gov.registry.land"] }), join(dir, "reconciler.token"), "30");
  await manage("service-provision", "svc.register", "maintainer", await scope("register.json", { actions: ["artifacts.register"], registryIds: ["gov.registry.land"] }), join(dir, "register.token"), "30");
  await manage("service-provision", "svc.foreignonly", "maintainer", await scope("foreignonly.json", { actions: ["artifacts.register"], registryIds: ["other.registry"] }), join(dir, "foreignonly.token"), "30");
  await manage("service-provision", "svc.foreign", "maintainer", await scope("foreign.json", { actions: ["artifacts.register", "integrity.reconcile"], registryIds: ["other.registry"] }), join(dir, "foreign.token"), "30");
  assert.equal((await stat(join(dir, "reconciler.token"))).mode & 0o777, 0o600);
  // The CLI never overwrites an existing secret file and does not provision on refusal.
  await assert.rejects(manage("service-provision", "svc.clobber", "maintainer", join(dir, "reconcile.json"), join(dir, "reconciler.token"), "30"));
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM service_principal WHERE principal_id='svc.clobber'")).rows[0].n, 0);
  const read = async (name: string) => (await readFile(join(dir, name), "utf8")).trim();
  const reconcilerToken = await read("reconciler.token"), registerToken = await read("register.token"), foreignToken = await read("foreign.token");

  // Synthetic fixture so an authorized reconcile reaches a real 200 without RPC;
  // the anchor root is fixtureRoot() of db/fixtures/devnet-demo.sql (CLEAN).
  await pool.query(await readFile(new URL("../../../db/fixtures/devnet-demo.sql", import.meta.url), "utf8"));
  await pool.query(`INSERT INTO demo_anchor (registry_id,batch_sequence,registry_version,merkle_root,manifest_hash,anchor_hash,program_id,segment_pda,transaction_signature,anchor_slot,commitment,finalized_at)
    VALUES ('gov.registry.land',1,1,decode('25b8f850d9bf4885f6f84f1ee5c887e814e92d199fcc58d24deba1d24314891f','hex'),decode(repeat('11',32),'hex'),decode(repeat('22',32),'hex'),'p','s','t',1,'finalized',now())`);

  // m9: a reachable database without migration 0012 refuses startup even on the memory backend.
  await pool.query("CREATE DATABASE no_service_schema");
  await writeFile(join(dir, "database-empty"), connectionString.replace("/postgres?", "/no_service_schema?"));
  await assert.rejects(startApi(context, { ...baseEnv(dir, await freePort()), ONELAYER_DATABASE_URL_FILE: join(dir, "database-empty"),
    ONELAYER_SESSION_BACKEND: "memory", ONELAYER_INTERNAL_AUTH: "service-principal" }), /IDENTITY_UNAVAILABLE/);

  await startApi(context, envA);
  await startApi(context, envB);
  const [a, b] = [`http://127.0.0.1:${portA}`, `http://127.0.0.1:${portB}`];
  const post = (base: string, path: string, headers: Record<string, string> = {}, body?: unknown) => fetch(`${base}${path}`, {
    method: "POST", headers: { ...(body === undefined ? {} : { "content-type": "application/json" }), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const auth = (token: string) => ({ authorization: `Bearer ${token}` });
  const spoof = {
    "x-forwarded-user": "svc.reconciler", "x-forwarded-for": "127.0.0.1", "x-forwarded-host": "127.0.0.1",
    "x-onelayer-service-principal": "svc.reconciler", "x-onelayer-role": "chief_admin", "x-real-ip": "127.0.0.1",
  };
  const expect = async (response: Promise<Response>, status: number, code?: string) => {
    const result = await response;
    const text = await result.text();
    assert.equal(result.status, status, text);
    if (code) assert.equal(JSON.parse(text).code, code);
    return text;
  };

  // Absent, spoofed and legacy shared-token credentials.
  await expect(post(a, "/internal/reconcile"), 401, "SERVICE_CREDENTIAL_REQUIRED");
  await expect(post(a, "/internal/reconcile", spoof), 401, "SERVICE_CREDENTIAL_REQUIRED");
  await expect(post(a, "/internal/reconcile", { ...spoof, authorization: "Bearer synthetic-legacy-internal-token-0123456789" }), 401, "SERVICE_CREDENTIAL_REQUIRED");
  await expect(post(a, "/internal/register", { ...spoof }, { registryId: "gov.registry.land" }), 401, "SERVICE_CREDENTIAL_REQUIRED");
  // Credential is checked before the body is parsed: malformed bearer + invalid JSON is 401, not 400/500.
  const raw = (base: string, headers: Record<string, string>, text: string) => fetch(`${base}/internal/register`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: text });
  await expect(raw(a, { authorization: "Bearer olsp_short" }, "{not json"), 401, "SERVICE_CREDENTIAL_REQUIRED");
  await expect(raw(a, { authorization: "Bearer  olsp_" + "A".repeat(22) + "." + "B".repeat(43) }, "{not json"), 401, "SERVICE_CREDENTIAL_REQUIRED");

  // Scope comes only from PostgreSQL, whatever headers or body fields claim.
  assert.match(await expect(post(a, "/internal/reconcile", { ...spoof, ...auth(reconcilerToken) }), 200), /"status":"CLEAN"/);
  await expect(post(b, "/internal/reconcile", { ...spoof, ...auth(registerToken) }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expect(post(b, "/internal/reconcile", auth(foreignToken)), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expect(post(a, "/internal/register", { ...spoof, ...auth(foreignToken) }, { registryId: "gov.registry.land", actions: ["artifacts.register"] }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expect(post(a, "/internal/register", auth(registerToken), { registryId: "other.registry" }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expect(post(a, "/internal/register", auth(reconcilerToken), { registryId: "gov.registry.land" }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  // Authenticated but malformed body: a client error, not a server fault.
  await expect(raw(a, auth(registerToken), "{not json"), 400, "REQUEST_INVALID");
  await expect(raw(a, auth(registerToken), "[]"), 400, "REQUEST_INVALID");
  // N6: field validation precedes fixture/RPC work: 400, not 500 after a chain call.
  await expect(post(a, "/internal/register", auth(registerToken), { registryId: "gov.registry.land", batchSequence: "x" }), 400, "REQUEST_INVALID");

  // N2: a slow or absent body cannot pin gate slots. A principal whose scope has no
  // registry served here is refused before any body byte; a slow body times out.
  const rawRequest = (port: number, headers: string, bodyPart: string) => new Promise<{ text: string; ms: number }>((resolve, reject) => {
    const started = Date.now();
    const socket = connect(port, "127.0.0.1");
    let text = "";
    socket.on("data", data => { text += String(data); if (/\r\n\r\n/.test(text) && text.startsWith("HTTP/1.1 4")) socket.end(); });
    socket.on("error", reject);
    socket.on("close", () => resolve({ text, ms: Date.now() - started }));
    socket.write(`POST /internal/register HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\ncontent-length: 1000\r\n${headers}\r\n${bodyPart}`);
  });
  const foreignOnlyToken = await read("foreignonly.token");
  const refused = await rawRequest(portB, `authorization: Bearer ${foreignOnlyToken}\r\n`, "");
  assert.match(refused.text, /^HTTP\/1\.1 403 /);
  assert.match(refused.text, /SERVICE_PERMISSION_FORBIDDEN/);
  const slow = await Promise.all([1, 2].map(() => rawRequest(portB, `authorization: Bearer ${registerToken}\r\n`, '{"registryId":')));
  for (const result of slow) assert.ok(result.ms >= 900 && result.ms < 8000, String(result.ms));
  await expect(post(b, "/internal/reconcile", auth(reconcilerToken)), 200);

  // Human session: works on admin routes, never on internal routes (alone or with a valid bearer).
  const begin = await fetch(`${a}/v2/admin/oidc/start`, { method: "POST", headers: { origin: "http://127.0.0.1:8091" } });
  const binding = begin.headers.get("set-cookie")!.split(";")[0]!;
  const callback = await idp.authorize((await begin.json() as { authorizationUrl: string }).authorizationUrl);
  const logged = await fetch(`${a}/v2/admin/oidc/callback?${new URLSearchParams(callback)}`, { headers: { cookie: binding }, redirect: "manual" });
  const cookie = logged.headers.get("set-cookie")!.split(";")[0]!;
  const sessionId = cookie.split("=")[1]!;
  await expect(fetch(`${b}/v1/admin/session`, { headers: { cookie } }), 200);
  await expect(post(b, "/internal/reconcile", { cookie }), 401, "SERVICE_CREDENTIAL_REQUIRED");
  await expect(post(b, "/internal/reconcile", { cookie, ...auth(reconcilerToken) }), 401, "SERVICE_CREDENTIAL_REQUIRED");
  await expect(post(b, "/internal/reconcile", auth(sessionId)), 401, "SERVICE_CREDENTIAL_REQUIRED");

  // Service bearer: refused on human admin and legacy resource routes, even with a valid cookie.
  for (const path of ["/v1/admin/session", "/v1/admin/schema", "/v2/admin/accounts/alice/revoke", "/v1/certificates/abababababababababababababababab/package"]) {
    await expect(fetch(`${a}${path}`, { headers: auth(reconcilerToken) }), 401, "SERVICE_PRINCIPAL_NOT_ALLOWED");
    await expect(fetch(`${a}${path}`, { headers: { cookie, ...auth(reconcilerToken) } }), 401, "SERVICE_PRINCIPAL_NOT_ALLOWED");
  }
  // The verifier read whitelist is exact and live: this credential is evaluated
  // there (wrong action is a scope error), a cookie never travels with a bearer,
  // and a non-GET method or a non-whitelisted path keeps the route refusal.
  await expect(fetch(`${a}/v1/anchors/1`, { headers: auth(reconcilerToken) }), 403, "SERVICE_PERMISSION_FORBIDDEN");
  await expect(fetch(`${a}/v1/anchors/1`, { headers: { cookie, ...auth(reconcilerToken) } }), 401, "SERVICE_CREDENTIAL_REQUIRED");
  await expect(fetch(`${a}/v1/anchors/1`, { method: "POST", headers: auth(reconcilerToken) }), 401, "SERVICE_PRINCIPAL_NOT_ALLOWED");
  await expect(fetch(`${a}/v1/admin/session`, { headers: { cookie } }), 200);

  // Rotation on the host: old secret fails on both processes, new works on the other one.
  await manage("service-rotate", "svc.reconciler", "maintainer", join(dir, "reconciler-2.token"), "30");
  const rotated = await read("reconciler-2.token");
  await expect(post(a, "/internal/reconcile", auth(reconcilerToken)), 401, "SERVICE_CREDENTIAL_REQUIRED");
  await expect(post(b, "/internal/reconcile", auth(reconcilerToken)), 401, "SERVICE_CREDENTIAL_REQUIRED");
  await expect(post(b, "/internal/reconcile", auth(rotated)), 200);
  await manage("service-revoke", "svc.reconciler", "maintainer");
  await expect(post(a, "/internal/reconcile", auth(rotated)), 401, "SERVICE_CREDENTIAL_REQUIRED");
  await expect(post(b, "/internal/reconcile", auth(rotated)), 401, "SERVICE_CREDENTIAL_REQUIRED");

  // M1: a flood with a revoked credential is refused by the in-process gate before
  // the DB (429) or with a counted denial (401); human sessions keep working and
  // the append-only log does not grow per request.
  const flood = await Promise.all([
    ...Array.from({ length: 80 }, () => post(a, "/internal/reconcile", auth(rotated)).then(async r => { await r.arrayBuffer(); return r.status; })),
    ...Array.from({ length: 10 }, () => fetch(`${a}/v1/admin/session`, { headers: { cookie } }).then(async r => { await r.arrayBuffer(); return -r.status; })),
  ]);
  const floodStatuses = flood.filter(status => status > 0);
  assert.ok(floodStatuses.every(status => status === 401 || status === 429), String(floodStatuses));
  assert.ok(floodStatuses.filter(status => status === 429).length >= 20, String(floodStatuses));
  assert.deepEqual(flood.filter(status => status < 0), Array(10).fill(-200));
  const counted = (await pool.query(
    `SELECT sum(w.denials)::int AS n FROM service_principal_denial_window w JOIN service_principal_credential c USING (credential_id)
      WHERE c.principal_id='svc.reconciler' AND w.reason='CREDENTIAL_REVOKED'`)).rows[0].n;
  // 2 earlier denials of the first secret + 2 of the rotated one + every flood 401.
  assert.equal(counted, 4 + floodStatuses.filter(status => status === 401).length);
  const revokedEvents = (await pool.query(
    "SELECT count(*)::int AS n FROM service_principal_event WHERE principal_id='svc.reconciler' AND reason='CREDENTIAL_REVOKED'")).rows[0].n;
  assert.ok(revokedEvents >= 2 && revokedEvents <= 4, String(revokedEvents)); // one per credential per minute window
  await expect(fetch(`${a}/v1/admin/session`, { headers: { cookie } }), 200);

  const rows = (await pool.query(
    "SELECT principal_id, event, reason, service_action, registry_id FROM service_principal_event WHERE event LIKE 'REQUEST_%' ORDER BY event_id",
  )).rows.map(row => `${row.principal_id}:${row.reason ?? row.event}:${row.service_action}:${row.registry_id}`);
  // Collapse repeats that a minute boundary may split out of one denial window.
  const events = rows.filter((row, index) => index === 0 || row !== rows[index - 1]);
  assert.deepEqual(events, [
    "svc.reconciler:REQUEST_AUTHORIZED:integrity.reconcile:gov.registry.land",
    "svc.register:ACTION_NOT_ALLOWED:integrity.reconcile:gov.registry.land",
    "svc.foreign:REGISTRY_OUT_OF_SCOPE:integrity.reconcile:gov.registry.land",
    "svc.foreign:REGISTRY_OUT_OF_SCOPE:artifacts.register:gov.registry.land",
    "svc.register:REGISTRY_OUT_OF_SCOPE:artifacts.register:other.registry",
    "svc.reconciler:ACTION_NOT_ALLOWED:artifacts.register:gov.registry.land",
    "svc.register:REQUEST_AUTHORIZED:artifacts.register:gov.registry.land",
    "svc.foreignonly:REGISTRY_OUT_OF_SCOPE:artifacts.register:gov.registry.land",
    "svc.reconciler:REQUEST_AUTHORIZED:integrity.reconcile:gov.registry.land",
    "svc.reconciler:ACTION_NOT_ALLOWED:anchors.read:gov.registry.land",
    "svc.reconciler:CREDENTIAL_REVOKED:integrity.reconcile:gov.registry.land",
    "svc.reconciler:REQUEST_AUTHORIZED:integrity.reconcile:gov.registry.land",
    "svc.reconciler:CREDENTIAL_REVOKED:integrity.reconcile:gov.registry.land",
  ]);
  const actors = (await pool.query("SELECT DISTINCT actor FROM service_principal_event WHERE event IN ('PROVISIONED','ROTATED','REVOKED')")).rows;
  assert.deepEqual(actors, [{ actor: "maintainer" }]);
});

test("legacy shared token is an explicit demo-only opt-in and OIDC mode refuses it at startup", { timeout: 60_000 }, async context => {
  const dir = await mkdtemp(join(tmpdir(), "onelayer-service-legacy-"));
  context.after(() => rm(dir, { recursive: true, force: true }));
  await writeCommon(dir, "postgresql://fixture:fixture@127.0.0.1:1/unused");
  const idp = await startTestIdp(); context.after(() => idp.close());
  const refusedPort = await freePort();
  await writeFile(join(dir, "oidc.json"), JSON.stringify(idp.config(`http://127.0.0.1:${refusedPort}/v2/admin/oidc/callback`)));
  await assert.rejects(startApi(context, { ...baseEnv(dir, refusedPort), ONELAYER_OIDC_CONFIG_FILE: join(dir, "oidc.json"), ONELAYER_INTERNAL_AUTH: "legacy-demo-token" }),
    /OIDC mode requires service principals/);
  await assert.rejects(startApi(context, { ...baseEnv(dir, refusedPort), ONELAYER_SESSION_BACKEND: "memory", ONELAYER_INTERNAL_AUTH: "shared" }), /invalid ONELAYER_INTERNAL_AUTH/);

  // m7: when the DB outcome is unknown the CLI says so and leaves no token file.
  await writeFile(join(dir, "scope.json"), JSON.stringify({ actions: ["integrity.reconcile"], registryIds: ["gov.registry.land"] }));
  const cli = await exec(process.execPath, ["--experimental-transform-types", "scripts/manage-admin-access.ts", "service-provision", "svc.unknown", "maintainer", join(dir, "scope.json"), join(dir, "unknown.token"), "30"],
    { cwd, env: baseEnv(dir, refusedPort) }).then(() => null, (error: { code: number; stderr: string }) => error);
  assert.equal(cli?.code, 1);
  assert.match(cli!.stderr, /OUTCOME_UNKNOWN/);
  await assert.rejects(stat(join(dir, "unknown.token")), { code: "ENOENT" });

  // N5: a missing DB URL fails before any token file is created.
  const noDb = { ...baseEnv(dir, refusedPort) }; delete noDb.ONELAYER_DATABASE_URL_FILE;
  const early = await exec(process.execPath, ["--experimental-transform-types", "scripts/manage-admin-access.ts", "service-provision", "svc.early", "maintainer", join(dir, "scope.json"), join(dir, "early.token"), "30"],
    { cwd, env: noDb }).then(() => null, (error: { code: number; stderr: string }) => error);
  assert.equal(early?.code, 1);
  await assert.rejects(stat(join(dir, "early.token")), { code: "ENOENT" });

  // m9: service-principal mode checks schema 0012 at startup on every backend.
  await assert.rejects(startApi(context, { ...baseEnv(dir, refusedPort), ONELAYER_SESSION_BACKEND: "memory", ONELAYER_INTERNAL_AUTH: "service-principal" }), /IDENTITY_UNAVAILABLE/);

  // The isolated memory backend defaults to disabled internal routes: refused, never open.
  const defaultPort = await freePort();
  await startApi(context, { ...baseEnv(dir, defaultPort), ONELAYER_SESSION_BACKEND: "memory" });
  const wellFormed = `Bearer olsp_${"A".repeat(22)}.${"B".repeat(43)}`;
  for (const authorization of [wellFormed, "Bearer synthetic-legacy-internal-token-0123456789"]) {
    const disabled = await fetch(`http://127.0.0.1:${defaultPort}/internal/reconcile`, { method: "POST", headers: { authorization } });
    assert.equal(disabled.status, 503);
    assert.deepEqual(await disabled.json(), { code: "SERVICE_AUTH_DISABLED" });
  }

  // Explicit password-demo legacy mode keeps the old bearer, bounded to the deployment registry.
  const legacyPort = await freePort();
  await startApi(context, { ...baseEnv(dir, legacyPort), ONELAYER_SESSION_BACKEND: "memory", ONELAYER_INTERNAL_AUTH: "legacy-demo-token" });
  const legacy = `http://127.0.0.1:${legacyPort}`;
  const good = { authorization: "Bearer synthetic-legacy-internal-token-0123456789", "content-type": "application/json" };
  assert.equal((await fetch(`${legacy}/internal/reconcile`, { method: "POST", headers: { authorization: "Bearer wrong" } })).status, 401);
  assert.equal((await fetch(`${legacy}/internal/reconcile`, { method: "POST", headers: { authorization: "synthetic-legacy-internal-token-0123456789" } })).status, 401);
  assert.equal((await fetch(`${legacy}/internal/reconcile`, { method: "POST", headers: { ...good, cookie: "onelayer_admin_session=x" } })).status, 401);
  assert.equal((await fetch(`${legacy}/internal/register`, { method: "POST", headers: good, body: JSON.stringify({ registryId: "other.registry" }) })).status, 403);
  // Legacy mode also checks the token before reading the body.
  assert.equal((await fetch(`${legacy}/internal/register`, { method: "POST", headers: { ...good, authorization: "Bearer wrong" }, body: "{not json" })).status, 401);
  assert.equal((await fetch(`${legacy}/internal/register`, { method: "POST", headers: good, body: "{not json" })).status, 400);
  assert.equal((await fetch(`${legacy}/v1/admin/schema`, { headers: { authorization: wellFormed } })).status, 401);
});
