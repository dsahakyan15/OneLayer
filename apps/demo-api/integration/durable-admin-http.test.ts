import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { isolatedPostgres } from "./support/postgres.ts";

const exec = promisify(execFile);

test("real API restarts preserve grants, session logout and durable local account revoke", { timeout: 60_000 }, async context => {
  const { pool, connectionString, dir } = await isolatedPostgres(context);
  await Promise.all([
    writeFile(join(dir, "database"), connectionString),
    writeFile(join(dir, "token"), "synthetic-internal-token"),
    writeFile(join(dir, "issuer"), "09".repeat(32)),
    writeFile(join(dir, "credentials"), JSON.stringify({ operator: "synthetic-operator-password", auditor: "synthetic-auditor-password" })),
    writeFile(join(dir, "access.json"), JSON.stringify({ role: "auditor", permissions: ["records.read"], registryIds: ["gov.registry.land"] })),
  ]);
  const listener = createServer();
  listener.listen(0, "127.0.0.1");
  await once(listener, "listening");
  const address = listener.address();
  assert.ok(address && typeof address !== "string");
  const port = address.port;
  await new Promise<void>((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
  const cwd = new URL("../", import.meta.url);
  const env = {
    ...process.env, PORT: String(port), ONELAYER_SESSION_BACKEND: "postgres",
    ONELAYER_DATABASE_URL_FILE: join(dir, "database"), ONELAYER_INTERNAL_TOKEN_FILE: join(dir, "token"),
    ONELAYER_ISSUER_SECRET_FILE: join(dir, "issuer"), ONELAYER_ADMIN_CREDENTIALS_FILE: join(dir, "credentials"),
    ONELAYER_RPC_URL: "https://api.devnet.solana.com", ONELAYER_VERIFIER_URL: "http://127.0.0.1:1",
    ONELAYER_PUBLIC_BASE_URL: `http://127.0.0.1:${port}`, ONELAYER_PUBLIC_WEB_URL: "http://127.0.0.1:8091",
    ONELAYER_PROGRAM_ID: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo",
  };
  let child: ReturnType<typeof spawn> | undefined;
  async function stop() {
    if (child && child.exitCode === null && child.signalCode === null) {
      const closed = once(child, "close");
      child.kill("SIGKILL");
      await closed;
    }
  }
  async function start() {
    child = spawn(process.execPath, ["--experimental-transform-types", "src/main.ts"], { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    const processUnderTest = child;
    await new Promise<void>((resolve, reject) => {
      let output = "";
      const timer = setTimeout(() => reject(new Error(`startup timed out: ${output}`)), 10_000);
      processUnderTest.once("error", error => { clearTimeout(timer); reject(error); });
      processUnderTest.once("exit", code => { clearTimeout(timer); reject(new Error(`API exited ${code}: ${output}`)); });
      processUnderTest.stderr!.on("data", data => { output += String(data); });
      processUnderTest.stdout!.on("data", data => {
        output += String(data);
        if (output.includes("demo API listening")) { clearTimeout(timer); resolve(); }
      });
    });
  }
  const url = `http://127.0.0.1:${port}/v1/admin`;
  const read = (cookie: string) => fetch(`${url}/session`, { headers: { cookie, connection: "close" } });
  async function login(username = "operator") {
    const response = await fetch(`${url}/session`, { method: "POST", headers: { "content-type": "application/json", connection: "close" },
      body: JSON.stringify({ username, password: `synthetic-${username}-password` }) });
    assert.equal(response.status, 201);
    const body = await response.json() as { role: string; csrfToken: string };
    return { cookie: response.headers.get("set-cookie")!.split(";")[0], ...body };
  }
  const manage = (...args: string[]) => exec(process.execPath, ["--experimental-transform-types", "scripts/manage-admin-access.ts", ...args], { cwd, env });
  try {
    await start();
    const original = await login();
    await stop();
    await start();
    assert.equal((await read(original.cookie)).status, 200, "session must survive an actual API process restart");

    await manage("access", "operator", "synthetic-maintainer", join(dir, "access.json"));
    assert.equal((await read(original.cookie)).status, 401);
    const narrowed = await login();
    assert.equal(narrowed.role, "auditor");
    assert.equal((await fetch(`${url}/certificates`, { headers: { cookie: narrowed.cookie } })).status, 403);
    await stop();
    await start();
    assert.equal((await read(narrowed.cookie)).status, 200);
    assert.equal((await login()).role, "auditor", "boot cannot reset narrowed grants from the original file");

    const logout = await fetch(`${url}/session`, { method: "DELETE", headers: { cookie: narrowed.cookie, "x-onelayer-csrf": narrowed.csrfToken } });
    assert.equal(logout.status, 204);
    assert.equal((await read(narrowed.cookie)).status, 401);
    const beforeRevoke = await login();
    await manage("revoke", "operator", "synthetic-maintainer");
    assert.equal((await read(beforeRevoke.cookie)).status, 401);
    await stop();
    await start();
    const revoked = await fetch(`${url}/session`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username: "operator", password: "synthetic-operator-password" }) });
    assert.equal(revoked.status, 401);
    assert.equal((await read(beforeRevoke.cookie)).status, 401);
    assert.equal((await read(narrowed.cookie)).status, 401, "logout must survive restart");
    const auditor = await login("auditor");
    assert.equal((await read(auditor.cookie)).status, 200);

    // Make the identity relation unavailable without stopping unrelated APIs.
    await pool.query("ALTER TABLE demo_admin_session RENAME TO unavailable_test_sessions");
    const unavailable = await read(auditor.cookie);
    assert.equal(unavailable.status, 503);
    assert.deepEqual(await unavailable.json(), { code: "IDENTITY_UNAVAILABLE" });
    const failedLogout = await fetch(`${url}/session`, { method: "DELETE", headers: { cookie: auditor.cookie, "x-onelayer-csrf": auditor.csrfToken } });
    assert.equal(failedLogout.status, 503, "failed logout must not report success");
    await pool.query("ALTER TABLE unavailable_test_sessions RENAME TO demo_admin_session");
    assert.equal((await read(auditor.cookie)).status, 200);
    const events = (await pool.query("SELECT action, actor FROM demo_admin_access_event WHERE username='operator' ORDER BY event_id")).rows;
    assert.deepEqual(events, [
      { action: "BOOTSTRAP", actor: "deployment-bootstrap" },
      { action: "ACCESS_CHANGED", actor: "synthetic-maintainer" },
      { action: "REVOKE", actor: "synthetic-maintainer" },
    ]);
  } finally { await stop(); }
});
