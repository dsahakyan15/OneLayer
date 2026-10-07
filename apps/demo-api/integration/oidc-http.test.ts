import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { isolatedPostgres } from "./support/postgres.ts";

import { startTestIdp } from './support/test-idp.ts';
const exec = promisify(execFile);

test("real main OIDC callback admits durable sessions and closes legacy resource bypass", {timeout:60000}, async context => {
  const { pool, connectionString, dir } = await isolatedPostgres(context);
  await Promise.all([
    writeFile(join(dir, "database"), connectionString),
    writeFile(join(dir, "token"), "synthetic-internal-token"),
    writeFile(join(dir, "issuer"), "09".repeat(32)),
    writeFile(join(dir, "credentials"), JSON.stringify({ operator: "synthetic-operator-password", auditor: "synthetic-auditor-password" })),
  ]);
  const listener = createServer();
  listener.listen(0, "127.0.0.1");
  await once(listener, "listening");
  const address = listener.address();
  assert.ok(address && typeof address !== "string");
  const port = address.port;
  await new Promise<void>((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
  const idp = await startTestIdp(); context.after(() => idp.close());
  await writeFile(join(dir,"oidc.json"),JSON.stringify(idp.config(`http://127.0.0.1:${port}/v2/admin/oidc/callback`)));
  await writeFile(join(dir,'provision.json'),JSON.stringify({issuer:idp.issuer,subject:'test-user',access:{role:'registry_worker'},resourcePolicy:{version:1,grants:[]}}));
  const cwd = new URL("../", import.meta.url);
  const env = {
    ...process.env, ONELAYER_OIDC_CONFIG_FILE: join(dir,"oidc.json"), PORT: String(port), ONELAYER_SESSION_BACKEND: "postgres",
    ONELAYER_DATABASE_URL_FILE: join(dir, "database"), ONELAYER_INTERNAL_TOKEN_FILE: join(dir, "token"),
    ONELAYER_ISSUER_SECRET_FILE: join(dir, "issuer"), ONELAYER_ADMIN_CREDENTIALS_FILE: join(dir, "credentials"),
    ONELAYER_RPC_URL: "https://api.devnet.solana.com", ONELAYER_VERIFIER_URL: "http://127.0.0.1:1",
    ONELAYER_PUBLIC_BASE_URL: `http://127.0.0.1:${port}`, ONELAYER_PUBLIC_WEB_URL: "http://127.0.0.1:8091",
    ONELAYER_PROGRAM_ID: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo",
  };
  const manage=(...args:string[])=>exec(process.execPath,['--experimental-transform-types','scripts/manage-admin-access.ts',...args],{cwd,env});
  await manage('oidc-provision','alice','maintainer',join(dir,'provision.json'));
  await manage('device-enroll','alice','maintainer','test-device');
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
  const base=`http://127.0.0.1:${port}`;
  async function login() {
    const begin=await fetch(`${base}/v2/admin/oidc/start`,{method:'POST',headers:{origin:env.ONELAYER_PUBLIC_WEB_URL}});
    assert.equal(begin.status,200);
    const binding=begin.headers.get('set-cookie')!.split(';')[0];
    assert.ok(begin.headers.get('set-cookie')!.includes('HttpOnly'));
    const details=await begin.json() as {authorizationUrl:string};
    const callback=await idp.authorize(details.authorizationUrl);
    const result=await fetch(`${base}/v2/admin/oidc/callback?${new URLSearchParams(callback)}`,{headers:{cookie:binding},redirect:'manual'});
    assert.equal(result.status,303);
    assert.equal(result.headers.get('location'),`${env.ONELAYER_PUBLIC_WEB_URL}/admin`);
    return result.headers.get('set-cookie')!.split(';')[0];
  }
  try {
    await start();
    const password=await fetch(`${base}/v1/admin/session`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'operator',password:'synthetic-operator-password'})});
    assert.equal(password.status,403);
    assert.equal((await fetch(`${base}/v2/admin/oidc/start`,{method:'POST',headers:{origin:'https://evil.example'}})).status,403);
    const cookie=await login();
    assert.equal((await fetch(`${base}/v1/admin/session`,{headers:{cookie}})).status,200);
    for (const path of ['/v1/certificates/fake','/v1/qr/fake','/qr/fake','/c/fake','/v1/anchors/1']) {
      assert.equal((await fetch(base+path)).status,401,path);
      assert.equal((await fetch(base+path,{headers:{cookie}})).status,403,path);
    }
    await stop(); await start();
    assert.equal((await fetch(`${base}/v1/admin/session`,{headers:{cookie}})).status,200);
    await manage('device-revoke','test-device','maintainer');
    assert.equal((await fetch(`${base}/v1/admin/session`,{headers:{cookie}})).status,401);
  } finally { await stop(); }
});
