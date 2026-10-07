// Actual configured main.ts startup for the publication runtime (H4/H5/M4).
//
// Starts the checked-in `apps/demo-api` startup command with a full publication
// configuration (keys + distinct approval-issuer key + explicit devnet cluster)
// and proves: (1) the API starts and the publication routes are configured
// (an unauthenticated request is 401, not the 503 "PUBLICATION_UNAVAILABLE"
// that an unconfigured runtime returns); (2) a partial configuration refuses
// startup with PUBLICATION_CONFIG_INCOMPLETE instead of silently disabling the
// approval boundary. No network or database connection is required to start.
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test, { type TestContext } from "node:test";
import { ensureKeyPair } from "../../apps/demo-api/scripts/live-demo-key-store.ts";

const repo = fileURLToPath(new URL("../../", import.meta.url));
const appDir = join(repo, "apps", "demo-api");

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

interface Fixture { home: string; env: NodeJS.ProcessEnv; port: number }

async function fixture(context: TestContext, withApprovalKey: boolean): Promise<Fixture> {
  const home = await mkdtemp(join(tmpdir(), "onelayer-pub-startup-"));
  context.after(() => rm(home, { recursive: true, force: true }));
  const keysDir = join(home, ".local", "state", "onelayer-devnet-demo", "keys");
  await mkdir(keysDir, { recursive: true, mode: 0o700 });
  const signerFile = join(keysDir, "demo-operator.json");
  const approvalFile = join(keysDir, "approval-issuer.json");
  await ensureKeyPair({ home, keyFile: signerFile });
  await ensureKeyPair({ home, keyFile: approvalFile });
  const publicationKeys = join(home, "publication-keys.json");
  await writeFile(publicationKeys, JSON.stringify({ idKey: "11".repeat(32), fieldKeyMaster: "22".repeat(32) }), { mode: 0o600 });
  await Promise.all([
    writeFile(join(home, "database"), "postgresql://fixture:fixture@127.0.0.1:1/unused"),
    writeFile(join(home, "token"), "synthetic-internal-token"),
    writeFile(join(home, "issuer"), "09".repeat(32)),
    writeFile(join(home, "credentials"), JSON.stringify({ operator: "synthetic-operator-password", auditor: "synthetic-auditor-password", chief_admin: "synthetic-chief-password" })),
  ]);
  const port = await unusedPort();
  return {
    home, port,
    env: {
      HOME: home,
      PORT: String(port),
      ONELAYER_SESSION_BACKEND: "memory",
      ONELAYER_DATABASE_URL_FILE: join(home, "database"),
      ONELAYER_INTERNAL_TOKEN_FILE: join(home, "token"),
      ONELAYER_ISSUER_SECRET_FILE: join(home, "issuer"),
      ONELAYER_ADMIN_CREDENTIALS_FILE: join(home, "credentials"),
      ONELAYER_RPC_URL: "https://api.devnet.solana.com",
      ONELAYER_VERIFIER_URL: "http://127.0.0.1:8080",
      ONELAYER_PUBLIC_BASE_URL: "http://127.0.0.1:8090",
      ONELAYER_PUBLIC_WEB_URL: "http://127.0.0.1:8091",
      ONELAYER_PROGRAM_ID: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo",
      ONELAYER_PUBLICATION_KEYS_FILE: publicationKeys,
      ONELAYER_PUBLICATION_OPERATOR_KEY_ID: "demo-operator-1",
      ONELAYER_PUBLICATION_SIGNER_FILE: signerFile,
      ...(withApprovalKey ? {
        ONELAYER_PUBLICATION_APPROVAL_KEY_FILE: approvalFile,
        ONELAYER_PUBLICATION_CLUSTER: "solana:devnet",
      } : {}),
    },
  };
}

function start(context: TestContext, env: NodeJS.ProcessEnv): { child: ChildProcess; output: () => string } {
  const child = spawn(process.execPath, ["--experimental-transform-types", "src/main.ts"], {
    cwd: appDir, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"],
  });
  context.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const closed = once(child, "close");
      child.kill("SIGKILL");
      await closed;
    }
  });
  let output = "";
  child.stdout?.on("data", data => { output += String(data); });
  child.stderr?.on("data", data => { output += String(data); });
  return { child, output: () => output };
}

test("configured publication startup wires the approval boundary (401, not 503)", { timeout: 70_000 }, async context => {
  const { port, env } = await fixture(context, true);
  const { child, output } = start(context, env);
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`startup timed out; output:\n${output()}`)), 60_000);
    const check = () => { if (output().includes("demo API listening")) { clearTimeout(timer); resolve(); } };
    child.stdout?.on("data", check);
    child.stderr?.on("data", check);
    child.once("exit", code => { clearTimeout(timer); reject(new Error(`exited ${code}; output:\n${output()}`)); });
  });
  const response = await fetch(`http://127.0.0.1:${port}/v2/admin/workflow/publications`);
  assert.equal(response.status, 401, "publication routes are configured; an unauthenticated call is 401, never the unconfigured 503");
});

test("partial publication configuration refuses startup instead of silently disabling approval", { timeout: 70_000 }, async context => {
  const { env } = await fixture(context, false);
  const { child, output } = start(context, env);
  const [code] = await once(child, "exit") as [number | null];
  assert.notEqual(code, 0, `partial publication config must fail closed; output:\n${output()}`);
  assert.match(output(), /PUBLICATION_CONFIG_INCOMPLETE/);
});
