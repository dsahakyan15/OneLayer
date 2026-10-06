// Lifecycle proof for the explicit snapshot writer key: a real API child loads
// the provisioned pair at startup and commits the configured version into real
// package ciphertext; a rotated deployment still restores an older package
// with its own out-of-band 3-of-5 shares and refuses the wrong key instead of
// regenerating; and an absent pair keeps the API serving while backup creation
// fails closed. The demo fixture anchor and incident watermark are seeded
// directly in the disposable PostgreSQL instance, and every child starts with
// the test-only network preload that refuses non-loopback fetch and redirects,
// so even a slow run whose 30-second background refresh fires cannot dispatch
// public-chain traffic. The preload's marker proves the guard installed before
// the RPC adapter captured fetch.
import assert from "node:assert/strict";
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { chmod, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { promisify } from "node:util";
import type { Pool } from "pg";
import { decodeCanonical } from "../../../packages/canonical-ts/src/index.ts";
import { decodeSnapshotPackage, restoreSnapshot, splitRecoveryKek } from "../../../packages/snapshot-ts/src/index.ts";
import { encodeRecoveryShare } from "../src/backup.ts";
import { loadSnapshotKeyConfig } from "../src/snapshot-key-config.ts";
import { isolatedPostgres } from "./support/postgres.ts";

const exec = promisify(execFile);
const cwd = new URL("../", import.meta.url);
const REGISTRY = "gov.registry.land";
const PUBLIC_WEB_URL = "http://127.0.0.1:8091";
const OPERATOR_PASSWORD = "synthetic-operator-password-012345";
const PROGRAM_ID = "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo";
const networkGuard = new URL("../../../tests/helpers/local-network-only.mjs", import.meta.url).href;
const GUARD_MARKER = "synthetic outbound guard ready";

function keyMaterial(label: string): Uint8Array {
  return createHash("sha256").update("onelayer-lab-" + label).digest();
}

async function tempDir(context: TestContext): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "onelayer-snapshot-key-"));
  context.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function writeKey(dir: string, name: string, bytes: Uint8Array): Promise<string> {
  const path = join(dir, name);
  await writeFile(path, bytes, { mode: 0o600 });
  await chmod(path, 0o600);
  return path;
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
    ...process.env, PORT: String(port), ONELAYER_SESSION_BACKEND: "memory",
    ONELAYER_DATABASE_URL_FILE: join(dir, "database"), ONELAYER_INTERNAL_TOKEN_FILE: join(dir, "token"),
    ONELAYER_ISSUER_SECRET_FILE: join(dir, "issuer"), ONELAYER_ADMIN_CREDENTIALS_FILE: join(dir, "credentials"),
    ONELAYER_RPC_URL: "https://api.devnet.solana.com", ONELAYER_VERIFIER_URL: "http://127.0.0.1:1",
    ONELAYER_PUBLIC_BASE_URL: `http://127.0.0.1:${port}`, ONELAYER_PUBLIC_WEB_URL: PUBLIC_WEB_URL,
    ONELAYER_PROGRAM_ID: PROGRAM_ID,
  };
}

async function writeCommon(dir: string, database: string): Promise<void> {
  await Promise.all([
    writeFile(join(dir, "database"), database),
    writeFile(join(dir, "token"), "synthetic-internal-token-0123456789"),
    writeFile(join(dir, "issuer"), "09".repeat(32)),
    writeFile(join(dir, "credentials"), JSON.stringify({
      operator: OPERATOR_PASSWORD,
      auditor: "synthetic-auditor-password-012345",
    })),
  ]);
}

/** Seeds the synthetic marker, one finalized anchor and a fresh incident watermark. */
async function seedSnapshotFixture(pool: Pool): Promise<void> {
  await pool.query("INSERT INTO demo_fixture_marker (marker) VALUES ('ONELAYER_SYNTHETIC_DEVNET_DEMO_V1') ON CONFLICT DO NOTHING");
  const root = Buffer.alloc(32, 1);
  await pool.query(
    `INSERT INTO demo_anchor (registry_id, batch_sequence, registry_version, merkle_root, manifest_hash, anchor_hash,
       program_id, segment_pda, transaction_signature, anchor_slot, commitment, finalized_at)
     VALUES ($1, 1, 1, $2, $2, $2, 'program', 'segment', 'synthetic-signature-1', 100, 'finalized', now())`,
    [REGISTRY, root],
  );
  await touchIncidentIndex(pool);
}

async function touchIncidentIndex(pool: Pool): Promise<void> {
  await pool.query(
    `INSERT INTO incident_index_state (registry_id, registry_config, indexed_through_slot, updated_at)
     VALUES ($1, 'synthetic-config', 200, now())
     ON CONFLICT (registry_id) DO UPDATE SET indexed_through_slot = EXCLUDED.indexed_through_slot, updated_at = now()`,
    [REGISTRY],
  );
}

interface ApiProcess {
  origin: string;
  child: ChildProcess;
  stop: () => Promise<void>;
}

/** Starts real main.ts; resolves when it listens, rejects with its output if it exits. */
async function startApi(context: TestContext, env: NodeJS.ProcessEnv): Promise<ApiProcess> {
  // The preload installs before main.ts captures fetch for the RPC adapter, so
  // the periodic incident refresh cannot reach the public chain on slow runs.
  const child = spawn(process.execPath, ["--import", networkGuard, "--experimental-transform-types", "src/main.ts"], { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout!.on("data", data => { output += String(data); });
  child.stderr!.on("data", data => { output += String(data); });
  const stop = async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const closed = once(child, "close");
      child.kill("SIGKILL");
      await closed;
    }
  };
  context.after(stop);
  await new Promise<void>((resolve, reject) => {
    // Real main.ts startup (module graph plus transforms) is seconds long on a
    // loaded machine; the bound is generous so a slow start is not a failure.
    const timer = setTimeout(() => reject(new Error("startup timed out: " + output)), 60_000);
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.once("exit", code => { clearTimeout(timer); reject(new Error("API exited " + code + ": " + output)); });
    child.stdout!.on("data", data => {
      if (String(data).includes("demo API listening")) { clearTimeout(timer); resolve(); }
    });
  });
  assert.ok(output.includes(GUARD_MARKER), "the synthetic outbound guard must install before the API's RPC adapter");
  return { origin: "http://127.0.0.1:" + env.PORT, child, stop };
}

/** Runs real main.ts with a configuration that must refuse startup before listening. */
async function startApiExpectingRefusal(env: NodeJS.ProcessEnv): Promise<string> {
  const child = spawn(process.execPath, ["--import", networkGuard, "--experimental-transform-types", "src/main.ts"], { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout!.on("data", data => { output += String(data); });
  child.stderr!.on("data", data => { output += String(data); });
  const code = await new Promise<number | null>((resolve, reject) => {
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("refusal run kept running: " + output)); }, 60_000);
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.once("exit", exitCode => { clearTimeout(timer); resolve(exitCode); });
  });
  assert.notEqual(code, 0, "an invalid pair must refuse startup");
  assert.ok(!output.includes("demo API listening"), "the API must not listen with an invalid pair");
  assert.ok(output.includes(GUARD_MARKER), "the synthetic outbound guard must install before the API's RPC adapter");
  return output;
}

interface AdminSessionHeaders { cookie: string; csrf: string; }

async function login(origin: string): Promise<AdminSessionHeaders> {
  const response = await fetch(origin + "/v1/admin/session", {
    method: "POST",
    headers: { "content-type": "application/json", origin: PUBLIC_WEB_URL },
    body: JSON.stringify({ username: "operator", password: OPERATOR_PASSWORD }),
  });
  assert.equal(response.status, 201);
  const body = await response.json() as { csrfToken: string };
  const cookie = response.headers.getSetCookie()[0]!.split(";")[0]!;
  return { cookie, csrf: body.csrfToken };
}

async function postAdmin(
  origin: string,
  path: string,
  body: unknown,
  session: AdminSessionHeaders,
  idempotencyKey?: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await fetch(origin + path, {
    method: "POST",
    headers: {
      "content-type": "application/json", origin: PUBLIC_WEB_URL,
      cookie: session.cookie, "x-onelayer-csrf": session.csrf,
      ...(idempotencyKey === undefined ? {} : { "idempotency-key": idempotencyKey }),
    },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() as Record<string, unknown> };
}

test("configured snapshot key survives restart and rotation; absent configuration fails closed", { timeout: 180_000 }, async context => {
  const { pool, connectionString, dir } = await isolatedPostgres(context);
  await writeCommon(dir, connectionString);
  await seedSnapshotFixture(pool);
  const materialV1 = keyMaterial("v1");
  const materialV2 = keyMaterial("v2");
  const keyV1 = await writeKey(dir, "kek-v1", materialV1);
  const keyV2 = await writeKey(dir, "kek-v2", materialV2);
  const snapshotCount = async () => (await pool.query("SELECT count(*)::int AS n FROM snapshot WHERE registry_id = $1", [REGISTRY])).rows[0].n as number;

  // 1. The pre-rotation deployment writes a package bound to its explicit version.
  const first = await startApi(context, { ...baseEnv(dir, await freePort()), ONELAYER_SNAPSHOT_KEK_FILE: keyV1, ONELAYER_SNAPSHOT_KEY_VERSION: "lab-kek-v1" });
  const firstSession = await login(first.origin);
  const created = await postAdmin(first.origin, "/v1/admin/snapshots/refresh", {}, firstSession, "snapshot-before-rotation-01");
  assert.equal(created.status, 201);
  assert.equal(created.body.keyEncryptionVersion, "lab-kek-v1");
  const firstSnapshotId = created.body.snapshotId as string;
  assert.equal(await snapshotCount(), 1);
  await first.stop();

  // 2. Rotation to a new key file and version; the older package is untouched.
  await touchIncidentIndex(pool);
  const second = await startApi(context, { ...baseEnv(dir, await freePort()), ONELAYER_SNAPSHOT_KEK_FILE: keyV2, ONELAYER_SNAPSHOT_KEY_VERSION: "lab-kek-v2" });
  const secondSession = await login(second.origin);
  const rotated = await postAdmin(second.origin, "/v1/admin/snapshots/refresh", {}, secondSession, "snapshot-after-rotation-01");
  assert.equal(rotated.status, 201);
  assert.equal(rotated.body.keyEncryptionVersion, "lab-kek-v2");

  const versions = await pool.query(
    "SELECT snapshot_version::text, key_encryption_version FROM snapshot WHERE registry_id = $1 ORDER BY snapshot_version",
    [REGISTRY],
  );
  assert.deepEqual(versions.rows, [
    { snapshot_version: "1", key_encryption_version: "lab-kek-v1" },
    { snapshot_version: "2", key_encryption_version: "lab-kek-v2" },
  ]);

  // 3. Cross-process reload: this process loads the provisioned file itself and
  // decrypts the package the child wrote.
  const parentConfig = loadSnapshotKeyConfig({ ONELAYER_SNAPSHOT_KEK_FILE: keyV2, ONELAYER_SNAPSHOT_KEY_VERSION: "lab-kek-v2" });
  assert.ok(parentConfig);
  const stored = await pool.query(
    "SELECT encrypted_package FROM snapshot WHERE registry_id = $1 AND snapshot_version = 2",
    [REGISTRY],
  );
  const decoded = decodeSnapshotPackage(Buffer.from(stored.rows[0].encrypted_package));
  assert.equal(decoded.keyEncryptionVersion, "lab-kek-v2");
  const state = decodeCanonical(restoreSnapshot(decoded, parentConfig.kek));
  assert.equal(state.type, "map");
  if (state.type === "map") {
    assert.equal(state.entries.format.type === "text" ? state.entries.format.value : null, "ONELAYER_SNAPSHOT_STATE_V1");
    assert.equal(state.entries.registryId.type === "text" ? state.entries.registryId.value : null, REGISTRY);
  }

  // 4. The rotated deployment still restores the v1 package through the HTTP
  // recovery flow using the v1 key's own supplied 3-of-5 shares.
  const centerId = (rotated.body.centers as Array<{ centerId: string }>)[0]!.centerId;
  const sharesV1 = splitRecoveryKek(materialV1);
  const sharesV2 = splitRecoveryKek(materialV2);
  const supplied = (shares: ReadonlyArray<{ index: number; bytes: Uint8Array }>) =>
    [1, 3, 5].map(index => encodeRecoveryShare(shares[index - 1]!));
  await touchIncidentIndex(pool);
  const prepared = await postAdmin(second.origin, "/v1/admin/recovery/prepare", {
    centerId, snapshotId: firstSnapshotId, target: "local-demo-target", recoveryShares: supplied(sharesV1),
  }, secondSession, "recovery-old-package-01");
  assert.equal(prepared.status, 201);
  assert.equal(prepared.body.state, "AWAITING_APPROVAL");

  // The wrong key material (here the rotated v2 key) is an honest failure, not a
  // regeneration: nothing re-encrypts or reissues the stored package.
  const wrongKey = await postAdmin(second.origin, "/v1/admin/recovery/prepare", {
    centerId, snapshotId: firstSnapshotId, target: "local-demo-target", recoveryShares: supplied(sharesV2),
  }, secondSession, "recovery-old-package-wrong-01");
  assert.equal(wrongKey.status, 422);
  assert.equal(wrongKey.body.code, "DECRYPTION_FAILED");

  // Two shares are never enough, regardless of which key version they belong to.
  const insufficient = await postAdmin(second.origin, "/v1/admin/recovery/prepare", {
    centerId, snapshotId: firstSnapshotId, target: "local-demo-target",
    recoveryShares: supplied(sharesV1).slice(0, 2),
  }, secondSession, "recovery-old-package-short-01");
  assert.equal(insufficient.status, 422);
  assert.equal(insufficient.body.code, "RECOVERY_SHARES_INSUFFICIENT");
  await second.stop();

  // 5. Without the pair the API still starts and serves, while backup creation
  // refuses before any fixture, center or state work: the fixture marker is
  // removed first, so a marker failure would otherwise answer instead.
  await pool.query("DELETE FROM demo_fixture_marker");
  const third = await startApi(context, baseEnv(dir, await freePort()));
  const thirdSession = await login(third.origin);
  const refused = await postAdmin(third.origin, "/v1/admin/snapshots/refresh", {}, thirdSession, "snapshot-without-key-01");
  assert.equal(refused.status, 503);
  assert.equal(refused.body.code, "SNAPSHOT_KEY_UNAVAILABLE");
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM demo_fixture_marker")).rows[0].n, 0);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM backup_center WHERE registry_id = $1", [REGISTRY])).rows[0].n, 5);
  assert.equal(await snapshotCount(), 2);
  await third.stop();

  // 6. A partial pair refuses startup with a generic error and generates nothing.
  const partial = await startApiExpectingRefusal({
    ...baseEnv(dir, await freePort()), ONELAYER_SNAPSHOT_KEY_VERSION: "lab-kek-v2",
  });
  assert.match(partial, /ONELAYER_SNAPSHOT_KEK_FILE and ONELAYER_SNAPSHOT_KEY_VERSION must be configured together/);
  assert.ok(!partial.includes(keyV2), "the refusal must not echo the configured path");
  const missingPath = join(dir, "never-provisioned-kek");
  const missing = await startApiExpectingRefusal({
    ...baseEnv(dir, await freePort()), ONELAYER_SNAPSHOT_KEK_FILE: missingPath, ONELAYER_SNAPSHOT_KEY_VERSION: "lab-kek-v2",
  });
  assert.match(missing, /ONELAYER_SNAPSHOT_KEK_FILE is invalid/);
  assert.ok(!missing.includes(missingPath), "the refusal must not echo the configured path");
  await assert.rejects(stat(missingPath), "a missing key file must never be generated");
  const blank = await startApiExpectingRefusal({
    ...baseEnv(dir, await freePort()), ONELAYER_SNAPSHOT_KEK_FILE: "", ONELAYER_SNAPSHOT_KEY_VERSION: "",
  });
  assert.match(blank, /ONELAYER_SNAPSHOT_KEK_FILE is invalid/);
});

test("the provisioned key reloads identically in separate processes", { timeout: 60_000 }, async context => {
  const dir = await tempDir(context);
  const material = keyMaterial("reload");
  const keyPath = await writeKey(dir, "kek", material);
  const loader = new URL("../src/snapshot-key-config.ts", import.meta.url).href;
  const script = join(dir, "reload-check.ts");
  await writeFile(script, [
    'import { createHash } from "node:crypto";',
    "import { loadSnapshotKeyConfig } from " + JSON.stringify(loader) + ";",
    "const config = loadSnapshotKeyConfig();",
    'if (config === undefined) throw new Error("writer key is not configured");',
    'process.stdout.write(JSON.stringify({ digest: createHash("sha256").update(config.kek).digest("hex"), version: config.keyEncryptionVersion }));',
  ].join("\n"));
  const env = {
    PATH: process.env.PATH ?? "",
    ONELAYER_SNAPSHOT_KEK_FILE: keyPath,
    ONELAYER_SNAPSHOT_KEY_VERSION: "lab-kek-v1",
  };
  const run = async () => JSON.parse((await exec(process.execPath, ["--experimental-transform-types", script], { env })).stdout) as { digest: string; version: string };
  const first = await run();
  const second = await run();
  const parentDigest = createHash("sha256").update(material).digest("hex");
  assert.equal(first.digest, parentDigest);
  assert.equal(second.digest, parentDigest);
  assert.equal(first.version, "lab-kek-v1");
});
