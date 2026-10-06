// Explicit writer-key configuration: the pair is either fully absent (backup
// creation fails closed) or fully valid (a private 32-byte file plus a stable
// version). Every unsafe file shape, partial pair and unstable version must
// refuse startup with a generic error that carries no path or key material.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import {
  loadSnapshotKeyConfig,
  SNAPSHOT_KEK_BYTES,
  SNAPSHOT_KEK_FILE_ENV,
  SNAPSHOT_KEK_FILE_INVALID,
  SNAPSHOT_KEY_CONFIG_INCOMPLETE,
  SNAPSHOT_KEY_VERSION_ENV,
  SNAPSHOT_KEY_VERSION_INVALID,
} from "../src/snapshot-key-config.ts";

/** Exactly 32 bytes of obviously synthetic key material used as a leak canary. */
const CANARY = Buffer.from("snapshot-canary-material-32bytes");
assert.equal(CANARY.length, SNAPSHOT_KEK_BYTES);

async function tempDir(context: TestContext): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "onelayer-snapshot-key-"));
  context.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function keyFile(dir: string, name: string, bytes: Uint8Array = CANARY, mode = 0o600): Promise<string> {
  const path = join(dir, name);
  await writeFile(path, bytes, { mode });
  await chmod(path, mode);
  return path;
}

function env(kekFile: string | undefined, version: string | undefined): NodeJS.ProcessEnv {
  return {
    ...(kekFile === undefined ? {} : { [SNAPSHOT_KEK_FILE_ENV]: kekFile }),
    ...(version === undefined ? {} : { [SNAPSHOT_KEY_VERSION_ENV]: version }),
  };
}

test("an absent pair leaves the writer unconfigured", () => {
  assert.equal(loadSnapshotKeyConfig({}), undefined);
  assert.equal(loadSnapshotKeyConfig({ PATH: "/usr/bin" }), undefined);
});

test("explicitly empty values fail startup instead of disabling the writer", async context => {
  const dir = await tempDir(context);
  const path = await keyFile(dir, "writer-kek");
  assert.throws(() => loadSnapshotKeyConfig(env("", "")), { message: SNAPSHOT_KEK_FILE_INVALID });
  assert.throws(() => loadSnapshotKeyConfig(env("", "lab-kek-v2")), { message: SNAPSHOT_KEK_FILE_INVALID });
  assert.throws(() => loadSnapshotKeyConfig(env(path, "")), { message: SNAPSHOT_KEY_VERSION_INVALID });
  assert.throws(() => loadSnapshotKeyConfig(env(undefined, "")), { message: SNAPSHOT_KEY_CONFIG_INCOMPLETE });
});

test("a valid private file loads its exact bytes on every reload", async context => {
  const dir = await tempDir(context);
  const bytes = Buffer.from(Array.from({ length: SNAPSHOT_KEK_BYTES }, (_unused, index) => (index * 7) % 256));
  bytes[0] = 0;
  bytes[SNAPSHOT_KEK_BYTES - 1] = 255;
  const path = await keyFile(dir, "writer-kek", bytes);

  const first = loadSnapshotKeyConfig(env(path, "lab-kek-v2"));
  assert.ok(first);
  assert.deepEqual([...first.kek], [...bytes]);
  assert.equal(first.keyEncryptionVersion, "lab-kek-v2");

  // A restart reloads the same persisted bytes: nothing is generated in process.
  const second = loadSnapshotKeyConfig(env(path, "lab-kek-v2"));
  assert.ok(second);
  assert.deepEqual([...second.kek], [...bytes]);

  // The caller owns a copy: mutating it cannot change the provisioned material.
  first.kek.fill(0xa5);
  const third = loadSnapshotKeyConfig(env(path, "lab-kek-v2"));
  assert.ok(third);
  assert.deepEqual([...third.kek], [...bytes]);

  // A read-only private file is still a valid carrier for the provisioned key.
  const readOnly = await keyFile(dir, "read-only-kek", bytes, 0o400);
  assert.deepEqual([...loadSnapshotKeyConfig(env(readOnly, "lab-kek-v1"))!.kek], [...bytes]);
});

test("a partial configuration refuses startup without generating material", async context => {
  const dir = await tempDir(context);
  const path = await keyFile(dir, "writer-kek");
  assert.throws(() => loadSnapshotKeyConfig(env(path, undefined)), { message: SNAPSHOT_KEY_CONFIG_INCOMPLETE });
  assert.throws(() => loadSnapshotKeyConfig(env(undefined, "lab-kek-v2")), { message: SNAPSHOT_KEY_CONFIG_INCOMPLETE });

  const missing = join(dir, "not-provisioned");
  assert.throws(() => loadSnapshotKeyConfig(env(missing, undefined)), { message: SNAPSHOT_KEY_CONFIG_INCOMPLETE });
  await assert.rejects(stat(missing), "an absent key must never be generated");
});

test("version identifiers must be stable lowercase labels", async context => {
  const dir = await tempDir(context);
  const path = await keyFile(dir, "writer-kek");
  for (const valid of ["v1", "v2", "lab-kek-v1", "mvp-memory-kek-v1", "a".repeat(64)]) {
    assert.equal(loadSnapshotKeyConfig(env(path, valid))?.keyEncryptionVersion, valid);
  }
  for (const invalid of ["V1", "Lab-Kek-V2", "kek v2", "kek/v2", "kek\\v2", "kek:v2", "kek\nv2", "-v1", ".v1", "_v1", " ", "a".repeat(65)]) {
    assert.throws(
      () => loadSnapshotKeyConfig(env(path, invalid)),
      { message: SNAPSHOT_KEY_VERSION_INVALID },
      JSON.stringify(invalid) + " must be refused",
    );
  }
});

test("unsafe key files are refused generically before any byte is returned", async context => {
  const dir = await tempDir(context);
  const valid = await keyFile(dir, "valid-kek");
  const cases: Array<[string, string]> = [["missing file", join(dir, "missing-kek")]];

  const directory = join(dir, "kek-directory");
  await mkdir(directory);
  cases.push(["directory", directory]);

  const fifo = join(dir, "kek-fifo");
  execFileSync("mkfifo", [fifo]);
  cases.push(["FIFO", fifo]);

  const link = join(dir, "kek-symlink");
  await symlink(valid, link);
  cases.push(["symlink", link]);

  for (const size of [0, SNAPSHOT_KEK_BYTES - 1, SNAPSHOT_KEK_BYTES + 1, 4096]) {
    cases.push([size + "-byte file", await keyFile(dir, "kek-size-" + size, Buffer.alloc(size, 7))]);
  }
  for (const mode of [0o644, 0o640, 0o666, 0o622, 0o777]) {
    cases.push(["mode " + mode.toString(8), await keyFile(dir, "kek-mode-" + mode.toString(8), CANARY, mode)]);
  }

  for (const [label, path] of cases) {
    const started = Date.now();
    assert.throws(() => loadSnapshotKeyConfig(env(path, "lab-kek-v2")), (error: unknown) => {
      assert.ok(error instanceof Error, label);
      assert.equal(error.message, SNAPSHOT_KEK_FILE_INVALID, label);
      // Generic: neither the configured path nor any key material may appear.
      assert.ok(!error.message.includes(path), label);
      assert.ok(!error.message.includes(CANARY.toString("utf8")), label);
      return true;
    }, label);
    assert.ok(Date.now() - started < 1_000, label + " must refuse without blocking");
  }
});
