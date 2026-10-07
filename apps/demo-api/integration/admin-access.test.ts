import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

// Real main.ts process and HTTP adapter. No working database or live RPC is
// needed: forbidden requests must fail before either dependency is reached.
test("HTTP admin permissions ignore supplied roles and forwarded identity; logout revokes the cookie", { timeout: 20_000 }, async context => {
  const dir = await mkdtemp(join(tmpdir(), "onelayer-admin-access-"));
  context.after(() => rm(dir, { recursive: true, force: true }));
  const listener = createServer();
  listener.listen(0, "127.0.0.1");
  await once(listener, "listening");
  const address = listener.address();
  assert.ok(address && typeof address !== "string");
  const port = address.port;
  await new Promise<void>((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
  await Promise.all([
    writeFile(join(dir, "database"), "postgresql://fixture:fixture@127.0.0.1:1/unused"),
    writeFile(join(dir, "token"), "synthetic-internal-token"),
    writeFile(join(dir, "issuer"), "09".repeat(32)),
    writeFile(join(dir, "credentials"), JSON.stringify({
      operator: { password: "synthetic-operator-password", permissions: ["records.read"], registryIds: ["gov.registry.land"] },
      auditor: { password: "synthetic-auditor-password", registryIds: ["other.registry"] },
    })),
  ]);
  const child = spawn(process.execPath, ["--experimental-transform-types", "src/main.ts"], {
    cwd: new URL("../", import.meta.url),
    env: {
      ...process.env, PORT: String(port),
      ONELAYER_SESSION_BACKEND: "memory",
      ONELAYER_DATABASE_URL_FILE: join(dir, "database"), ONELAYER_INTERNAL_TOKEN_FILE: join(dir, "token"),
      ONELAYER_ISSUER_SECRET_FILE: join(dir, "issuer"), ONELAYER_ADMIN_CREDENTIALS_FILE: join(dir, "credentials"),
      ONELAYER_RPC_URL: "https://api.devnet.solana.com", ONELAYER_VERIFIER_URL: "http://127.0.0.1:1",
      ONELAYER_PUBLIC_BASE_URL: `http://127.0.0.1:${port}`, ONELAYER_PUBLIC_WEB_URL: "http://127.0.0.1:8091",
      ONELAYER_PROGRAM_ID: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo",
    }, stdio: ["ignore", "pipe", "pipe"],
  });
  context.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const closed = once(child, "close");
      child.kill("SIGKILL");
      await closed;
    }
  });
  await new Promise<void>((resolve, reject) => {
    let output = "";
    const timer = setTimeout(() => reject(new Error(`API startup timeout: ${output}`)), 10_000);
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.once("exit", code => { clearTimeout(timer); reject(new Error(`API exited ${code}: ${output}`)); });
    child.stderr.on("data", data => { output += String(data); });
    child.stdout.on("data", data => {
      output += String(data);
      if (output.includes("demo API listening")) { clearTimeout(timer); resolve(); }
    });
  });
  const url = `http://127.0.0.1:${port}/v1/admin`;
  const forged = { "x-forwarded-user": "chief_admin", "x-forwarded-role": "operator", "x-forwarded-for": "127.0.0.1", authorization: "Bearer synthetic-internal-token" };
  assert.equal((await fetch(`${url}/schema`, { headers: forged })).status, 401);
  for (const username of ["operator", "auditor"]) {
    const login = await fetch(`${url}/session`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ username, password: `synthetic-${username}-password`, role: "chief_admin", permissions: ["recovery.approve"] }),
    });
    assert.equal(login.status, 201);
    const cookie = login.headers.get("set-cookie")!.split(";")[0];
    const session = await login.json() as { role: string; csrfToken: string };
    assert.equal(session.role, username);
    const headers = { ...forged, cookie, "x-onelayer-csrf": session.csrfToken, "content-type": "application/json" };
    assert.equal((await fetch(`${url}/schema`, { headers })).status, username === "operator" ? 200 : 403);
    for (const path of ["dashboard", "certificates", "timeline", "backup-centers", "recovery/operations"]) {
      const response = await fetch(`${url}/${path}`, { headers });
      assert.equal(response.status, 403, `${username}: ${path}`);
      assert.deepEqual(await response.json(), { code: "PERMISSION_FORBIDDEN" });
    }
    const denied = await fetch(`${url}/records`, { method: "POST", headers, body: JSON.stringify({ role: "operator", permissions: ["records.draft"] }) });
    assert.equal(denied.status, 403);
    const noCsrf = await fetch(`${url}/session`, { method: "DELETE", headers: { cookie } });
    assert.equal(noCsrf.status, 403);
    assert.equal((await fetch(`${url}/session`, { method: "DELETE", headers })).status, 204);
    assert.equal((await fetch(`${url}/schema`, { headers })).status, 401);
  }
});
