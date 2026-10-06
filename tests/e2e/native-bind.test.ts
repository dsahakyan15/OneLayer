import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createHash } from "node:crypto";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createConnection, createServer } from "node:net";
import { networkInterfaces, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test, { type TestContext } from "node:test";
import { syntheticTrustPolicy } from "../support/trust-fixtures.ts";

const repo = fileURLToPath(new URL("../../", import.meta.url));

async function unusedPort(): Promise<number> {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const port = address.port;
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

async function connect(host: string, port: number): Promise<void> {
  const socket = createConnection({ host, port });
  try {
    socket.setTimeout(2_000, () => socket.destroy(new Error("TCP connection timed out")));
    await once(socket, "connect");
  } finally { socket.destroy(); }
}

async function assertLoopbackOnly(context: TestContext, app: string, env: NodeJS.ProcessEnv, ready: string) {
  const lan = Object.values(networkInterfaces()).flat().find(address => address?.family === "IPv4" && !address.internal);
  if (!lan) { context.skip("No non-loopback IPv4 interface to exercise network isolation"); return; }
  const port = await unusedPort();
  const appDir = join(repo, "apps", app);
  const manifest = JSON.parse(await readFile(join(appDir, "package.json"), "utf8"));
  // Execute the checked-in startup command, including its runtime flags. Only
  // the test port changes; using different flags can mask real startup errors.
  const [executable, ...args] = manifest.scripts.start.split(" ") as string[];
  if (executable === "next") {
    args.unshift(join(appDir, "node_modules/next/dist/bin/next"));
    assert.ok(args.includes("-p"));
    args[args.indexOf("-p") + 1] = String(port);
  } else { assert.equal(executable, "node"); }
  const child = spawn(process.execPath, args, { cwd: appDir, env: { ...process.env, ...env, PORT: String(port), NEXT_TELEMETRY_DISABLED: "1" }, stdio: ["ignore", "pipe", "pipe"] });
  const stopChild = async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const closed = once(child, "close");
      child.kill("SIGKILL");
      await closed;
    }
  };
  context.after(stopChild);
  let output = "";
  // A cold `next start` on a loaded machine can exceed 10s; the bound is
  // generous but finite, and the failure carries the command, cwd and captured
  // output so a real startup error is diagnosable instead of an opaque timeout.
  const STARTUP_TIMEOUT_MS = 60_000;
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`${app} startup timed out after ${STARTUP_TIMEOUT_MS}ms\n  command: ${process.execPath} ${args.join(" ")}\n  cwd: ${appDir}\n  output:\n${output || "(none)"}`)),
        STARTUP_TIMEOUT_MS,
      );
      const fail = (code: number | null) => {
        clearTimeout(timer);
        reject(new Error(`${app} exited ${code}\n  command: ${process.execPath} ${args.join(" ")}\n  cwd: ${appDir}\n  output:\n${output || "(none)"}`));
      };
      child.once("error", error => { clearTimeout(timer); reject(error); });
      child.once("exit", fail);
      child.stderr.on("data", data => { output += String(data); });
      child.stdout.on("data", data => {
        output += String(data);
        if (output.includes(ready)) { clearTimeout(timer); child.removeListener("exit", fail); resolve(); }
      });
    });
  } catch (error) {
    await stopChild();
    throw error;
  }
  await connect("127.0.0.1", port);
  // Sandbox EPERM or a timeout is NOT evidence of network isolation.
  await assert.rejects(connect(lan.address, port), { code: "ECONNREFUSED" });
}

async function fixture(context: TestContext) {
  const dir = await mkdtemp(join(tmpdir(), "onelayer-bind-"));
  context.after(() => rm(dir, { recursive: true, force: true }));
  // Synthetic credentials; no database or external RPC request is required.
  await Promise.all([
    writeFile(join(dir, "database"), "postgresql://fixture:fixture@127.0.0.1:1/unused"),
    writeFile(join(dir, "token"), "synthetic-internal-token"),
    writeFile(join(dir, "issuer"), "09".repeat(32)),
    writeFile(join(dir, "credentials"), JSON.stringify({ operator: "synthetic-operator-password", auditor: "synthetic-auditor-password", chief_admin: "synthetic-chief-password" })),
    writeFile(join(dir, "policy.json"), JSON.stringify(syntheticTrustPolicy({ programId: new Uint8Array(32).fill(4), issuerSeed: new Uint8Array(32).fill(9) }))),
  ]);
  return dir;
}

test("native demo API accepts loopback but rejects the machine's LAN interface", { timeout: 70_000 }, async context => {
  const dir = await fixture(context);
  await assertLoopbackOnly(context, "demo-api", {
    ONELAYER_SESSION_BACKEND: "memory",
      ONELAYER_DATABASE_URL_FILE: join(dir, "database"), ONELAYER_INTERNAL_TOKEN_FILE: join(dir, "token"),
    ONELAYER_ISSUER_SECRET_FILE: join(dir, "issuer"), ONELAYER_ADMIN_CREDENTIALS_FILE: join(dir, "credentials"),
    ONELAYER_RPC_URL: "https://api.devnet.solana.com", ONELAYER_VERIFIER_URL: "http://127.0.0.1:8080",
    ONELAYER_PUBLIC_BASE_URL: "http://127.0.0.1:8090", ONELAYER_PUBLIC_WEB_URL: "http://127.0.0.1:8091",
    ONELAYER_PROGRAM_ID: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo",
  }, "demo API listening");
});

test("native verifier accepts loopback but rejects the machine's LAN interface", { timeout: 70_000 }, async context => {
  const dir = await fixture(context);
  // Watermark directory must be disjoint from the policy directory and private (mkdtemp: 0700).
  const stateDir = await mkdtemp(join(tmpdir(), "onelayer-bind-state-"));
  context.after(() => rm(stateDir, { recursive: true, force: true }));
  await assertLoopbackOnly(context, "verifier", {
    ONELAYER_TRUST_POLICY_FILE: join(dir, "policy.json"), ONELAYER_TRUST_POLICY_MIN_REVISION: "1", ONELAYER_TRUST_POLICY_UNSIGNED: "1",
    // First-run bootstrap pinned to this exact policy document (policy digest = sha256 of the policy JSON file).
    ONELAYER_TRUST_STATE_FILE: join(stateDir, "accepted.json"),
    ONELAYER_TRUST_STATE_BOOTSTRAP: createHash("sha256").update(await readFile(join(dir, "policy.json"))).digest("hex"),
    ONELAYER_RPC_URL: "http://127.0.0.1:1", ONELAYER_INCIDENT_INDEX_URL: "http://127.0.0.1:1", ONELAYER_LOOKUP_URL: "http://127.0.0.1:1",
  }, "verifier listening");
});

test("built web startup accepts loopback but rejects the machine's LAN interface", { timeout: 70_000 }, async context => {
  try { await access(join(repo, "apps/mvp-web/.next/BUILD_ID")); }
  catch { context.skip("Run the web build before its actual production startup check"); return; }
  await assertLoopbackOnly(context, "mvp-web", {
    ONELAYER_ADMIN_API_URL: "http://127.0.0.1:1", ONELAYER_VERIFIER_URL: "http://127.0.0.1:1",
  }, "Ready in");
});
