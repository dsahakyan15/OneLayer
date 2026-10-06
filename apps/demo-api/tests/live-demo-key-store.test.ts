import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { chmod, lstat, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { after, before, test } from "node:test";
import { getAddressDecoder } from "@solana/kit";
import {
  assertKeyFilePolicy,
  defaultKeyFile,
  demoStateRoot,
  ensureKeyPair,
  ensureKeyStore,
  KeyStoreError,
  loadSigningKey,
  MAX_KEY_FILE_BYTES,
  persistentKeyRoot,
  readKeyFileBytes,
  validateKeyPath,
} from "../scripts/live-demo-key-store.ts";

const SEED = new Uint8Array(32).fill(7);
const OTHER_SEED = new Uint8Array(32).fill(9);

let homeDir = "";
let storeDir = "";

function keysFor(secret: Uint8Array): { address: string; publicKeyBytes: Uint8Array } {
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(secret)]),
    format: "der",
    type: "pkcs8",
  });
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const publicKeyBytes = new Uint8Array(publicDer).slice(-32);
  return { address: String(getAddressDecoder().decode(publicKeyBytes)), publicKeyBytes };
}

function keypairBytesFor(secret: Uint8Array): Uint8Array {
  return new Uint8Array([...secret, ...keysFor(secret).publicKeyBytes]);
}

async function expectStoreError(code: string, run: () => Promise<unknown>): Promise<void> {
  await assert.rejects(run, (error: unknown) => {
    assert.ok(error instanceof KeyStoreError, `expected KeyStoreError, got ${String(error)}`);
    assert.equal((error as KeyStoreError).code, code);
    return true;
  });
}

function expectPolicyRejection(keyFile: string, home?: string): void {
  assert.throws(
    () => assertKeyFilePolicy(keyFile, home === undefined ? undefined : { home }),
    (error: unknown) => {
      assert.ok(error instanceof KeyStoreError);
      assert.equal((error as KeyStoreError).code, "KEYFILE_REJECTED");
      return true;
    },
  );
}

before(async () => {
  homeDir = path.join(tmpdir(), `onelayer-live-demo-key-store-test-${process.pid}`);
  await mkdir(homeDir, { mode: 0o700, recursive: true });
  storeDir = path.join(homeDir, ".local", "state", "onelayer-devnet-demo", "keys");
});

after(async () => {
  await rm(homeDir, { recursive: true, force: true });
});

test("the persistent store layout is fixed below the user state root", () => {
  assert.equal(persistentKeyRoot({ home: homeDir }), storeDir);
  assert.equal(defaultKeyFile({ home: homeDir }), path.join(storeDir, "demo-operator.json"));
  assert.equal(demoStateRoot({ home: homeDir }), path.join(homeDir, ".local", "state", "onelayer-devnet-demo"));
  assert.ok(defaultKeyFile({ home: homeDir }).endsWith(path.join(".local", "state", "onelayer-devnet-demo", "keys", "demo-operator.json")));
});

test("the allow-list accepts the persistent store and the legacy /dev/shm root", () => {
  assert.equal(assertKeyFilePolicy(defaultKeyFile({ home: homeDir }), { home: homeDir }).kind, "persistent");
  assert.equal(assertKeyFilePolicy(path.join(storeDir, "nested", "other.json"), { home: homeDir }).kind, "persistent");
  assert.equal(assertKeyFilePolicy("/dev/shm/onelayer-devnet-demo/demo-operator.json").kind, "shm");
  assert.equal(assertKeyFilePolicy("/dev/shm/onelayer-live-demo-deep/a/b.json").kind, "shm");
});

test("the allow-list refuses every path outside the two roots", () => {
  expectPolicyRejection(path.join(homeDir, "demo-operator.json"), homeDir);
  expectPolicyRejection(path.join(homeDir, ".local", "state", "onelayer-devnet-demo", "demo-operator.json"), homeDir);
  expectPolicyRejection(path.join(homeDir, ".local", "state", "other-app", "keys", "x.json"), homeDir);
  expectPolicyRejection("/dev/shm/demo-operator.json");
  expectPolicyRejection("/tmp/demo-operator.json");
  expectPolicyRejection("/etc/onelayer-demo-operator.json");
  expectPolicyRejection("relative/demo-operator.json", homeDir);
  expectPolicyRejection("/dev/shm/onelayer/../../etc/passwd");
});

test("ensureKeyStore creates the private store once and is idempotent", async () => {
  const root = await ensureKeyStore({ home: homeDir });
  assert.equal(root, storeDir);
  const stats = await lstat(storeDir);
  assert.ok(stats.isDirectory());
  assert.equal(stats.mode & 0o077, 0);
  await ensureKeyStore({ home: homeDir });
  assert.equal((await lstat(storeDir)).mode & 0o077, 0);
});

test("ensureKeyPair installs a validated Solana CLI keypair and returns only its address", async () => {
  const keypair = keypairBytesFor(SEED);
  const result = await ensureKeyPair({ home: homeDir, keypair });
  assert.deepEqual(Object.keys(result).sort(), ["address", "created", "path"]);
  assert.equal(result.created, true);
  assert.equal(result.path, path.join(storeDir, "demo-operator.json"));
  assert.equal(result.address, keysFor(SEED).address);
  const serialized = JSON.stringify(result);
  const seedHex = Buffer.from(SEED).toString("hex");
  const seedBase64 = Buffer.from(SEED).toString("base64");
  const fileText = await readFile(result.path, "utf8");
  assert.ok(!serialized.includes(seedHex), "seed hex leaked");
  assert.ok(!serialized.includes(seedBase64), "seed base64 leaked");
  assert.ok(!serialized.includes(fileText), "keypair file leaked");
  assert.ok(!serialized.includes("302e020100300506032b657004220420"), "pkcs8 prefix leaked");
  const stats = await lstat(result.path);
  assert.ok(stats.isFile());
  assert.equal(stats.mode & 0o077, 0);
  assert.equal(JSON.parse(fileText).length, 64);
});

test("ensureKeyPair never overwrites an existing key file", async () => {
  const keyFile = path.join(storeDir, "demo-operator.json");
  const original = await readFile(keyFile, "utf8");
  const replay = await ensureKeyPair({ home: homeDir, keypair: keypairBytesFor(SEED) });
  assert.equal(replay.created, false);
  assert.equal(replay.address, keysFor(SEED).address);
  assert.equal(await readFile(keyFile, "utf8"), original);
  const different = await ensureKeyPair({ home: homeDir, keypair: keypairBytesFor(OTHER_SEED) });
  assert.equal(different.created, false);
  assert.equal(different.address, keysFor(SEED).address, "existing key must win");
  assert.equal(await readFile(keyFile, "utf8"), original);
});

test("ensureKeyPair generates a development key when none is supplied", async () => {
  const generated = await ensureKeyPair({ home: homeDir, keyFile: path.join(storeDir, "generated.json") });
  assert.equal(generated.created, true);
  const parsed = JSON.parse(await readFile(generated.path, "utf8")) as number[];
  assert.equal(parsed.length, 64);
  const loaded = await loadSigningKey(generated.path, { home: homeDir });
  assert.equal(String(loaded.address), generated.address);
});

test("ensureKeyPair refuses key material that is not the Solana CLI layout", async () => {
  await expectStoreError("KEYPAIR_INVALID", () =>
    ensureKeyPair({ home: homeDir, keyFile: path.join(storeDir, "short.json"), keypair: new Uint8Array(63) }),
  );
  const mismatched = keypairBytesFor(SEED);
  mismatched[32] ^= 0xff;
  await expectStoreError("KEYPAIR_INVALID", () =>
    ensureKeyPair({ home: homeDir, keyFile: path.join(storeDir, "mismatched.json"), keypair: mismatched }),
  );
});

test("ensureKeyPair refuses to bless an existing invalid or unsafe file", async () => {
  const invalid = path.join(storeDir, "invalid.json");
  await writeFile(invalid, JSON.stringify([1, 2, 3]), { mode: 0o600 });
  await expectStoreError("KEYPAIR_INVALID", () => ensureKeyPair({ home: homeDir, keyFile: invalid }));
  const unsafe = path.join(storeDir, "unsafe.json");
  await writeFile(unsafe, JSON.stringify([...keypairBytesFor(SEED)]), { mode: 0o644 });
  await expectStoreError("KEYFILE_REJECTED", () => ensureKeyPair({ home: homeDir, keyFile: unsafe }));
  assert.equal(JSON.parse(await readFile(invalid, "utf8")).length, 3, "invalid file must not be overwritten");
});

test("ensureKeyPair refuses to write into an unsafe store", async () => {
  const looseHome = path.join(tmpdir(), `onelayer-live-demo-key-store-loose-${process.pid}`);
  await mkdir(looseHome, { mode: 0o777, recursive: true });
  try {
    await expectStoreError("KEYFILE_REJECTED", () => ensureKeyPair({ home: looseHome, keypair: keypairBytesFor(SEED) }));
  } finally {
    await rm(looseHome, { recursive: true, force: true });
  }
});

test("loadSigningKey accepts a read-only file and refuses unsafe ones", async () => {
  const readOnly = path.join(storeDir, "read-only.json");
  await writeFile(readOnly, JSON.stringify([...keypairBytesFor(OTHER_SEED)]), { mode: 0o600 });
  await chmod(readOnly, 0o400);
  const loaded = await loadSigningKey(readOnly, { home: homeDir });
  assert.equal(String(loaded.address), keysFor(OTHER_SEED).address);

  const link = path.join(storeDir, "link.json");
  await symlink(readOnly, link);
  await expectStoreError("KEYFILE_REJECTED", () => loadSigningKey(link, { home: homeDir }));

  await expectStoreError("KEYFILE_UNREADABLE", () =>
    loadSigningKey(path.join(storeDir, "absent.json"), { home: homeDir }),
  );

  const broken = path.join(storeDir, "broken.json");
  await writeFile(broken, JSON.stringify([...keypairBytesFor(SEED).slice(0, 32), ...keysFor(OTHER_SEED).publicKeyBytes]), {
    mode: 0o600,
  });
  await expectStoreError("KEYPAIR_INVALID", () => loadSigningKey(broken, { home: homeDir }));
});

test("readKeyFileBytes bounds the key file size", async () => {
  const oversized = path.join(storeDir, "oversized.json");
  await writeFile(oversized, `["${"a".repeat(MAX_KEY_FILE_BYTES + 1)}"]`, { mode: 0o600 });
  await expectStoreError("KEYPAIR_INVALID", () => readKeyFileBytes(oversized, { home: homeDir }));
});

test("validateKeyPath accepts a healthy store and refuses a writable one", async () => {
  await validateKeyPath(defaultKeyFile({ home: homeDir }), { home: homeDir });
  const nested = path.join(storeDir, "nested");
  await mkdir(nested, { mode: 0o700, recursive: true });
  await validateKeyPath(path.join(nested, "other.json"), { home: homeDir });
  await chmod(storeDir, 0o707);
  try {
    await expectStoreError("KEYFILE_REJECTED", () => validateKeyPath(defaultKeyFile({ home: homeDir }), { home: homeDir }));
  } finally {
    await chmod(storeDir, 0o700);
  }
});

test("key store errors carry codes only", async () => {
  const keyFile = path.join(storeDir, "absent.json");
  await assert.rejects(readKeyFileBytes(keyFile, { home: homeDir }), (error: unknown) => {
    assert.ok(error instanceof KeyStoreError);
    assert.equal((error as KeyStoreError).code, "KEYFILE_UNREADABLE");
    assert.equal((error as Error).message, "KEYFILE_UNREADABLE");
    const detail = `${(error as Error).message}\n${(error as Error).stack ?? ""}`;
    assert.ok(!detail.includes(homeDir), "error leaked the key store path");
    assert.ok(!detail.includes("absent.json"), "error leaked the key file name");
    return true;
  });
});
