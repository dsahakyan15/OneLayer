// Ticket 09 review: the publication keys file holds HMAC secrets and must be
// loaded through the same private-file discipline as other key material.
import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadPublicationConfig, parsePublicationKeys, readPrivateKeysFile } from "../src/publication-config.ts";

const HEX = "11".repeat(32);
const validKeys = JSON.stringify({ idKey: HEX, fieldKeyMaster: "22".repeat(32) });

async function tempDir(): Promise<string> {
  return await mkdtemp(join(tmpdir(), "onelayer-pubcfg-"));
}

test("publication keys JSON must carry two 32-byte hex keys", () => {
  assert.deepEqual(parsePublicationKeys(validKeys).idKey.length, 32);
  assert.throws(() => parsePublicationKeys("{}"), /PUBLICATION_KEYS_INVALID/);
  assert.throws(() => parsePublicationKeys(JSON.stringify({ idKey: "zz", fieldKeyMaster: HEX })), /PUBLICATION_KEYS_INVALID/);
});

test("private keys file rejects world-readable, symlinked and oversized files", async () => {
  const dir = await tempDir();
  try {
    const good = join(dir, "keys.json");
    await writeFile(good, validKeys, { mode: 0o600 });
    assert.equal((await readPrivateKeysFile(good)).toString("utf8"), validKeys);

    const loose = join(dir, "loose.json");
    await writeFile(loose, validKeys, { mode: 0o644 });
    await chmod(loose, 0o644);
    await assert.rejects(readPrivateKeysFile(loose), /PUBLICATION_KEYS_FILE_REJECTED/);

    const link = join(dir, "link.json");
    await symlink(good, link);
    await assert.rejects(readPrivateKeysFile(link), /PUBLICATION_KEYS_FILE_REJECTED/);

    const big = join(dir, "big.json");
    await writeFile(big, "x".repeat(5000), { mode: 0o600 });
    await assert.rejects(readPrivateKeysFile(big), /PUBLICATION_KEYS_FILE_REJECTED/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("publication config is absent, incomplete or valid as a whole", async () => {
  const dir = await tempDir();
  try {
    assert.equal(await loadPublicationConfig({}, { home: dir }), undefined);
    await assert.rejects(loadPublicationConfig({ ONELAYER_PUBLICATION_KEYS_FILE: join(dir, "x") }, { home: dir }), /PUBLICATION_CONFIG_INCOMPLETE/);

    const keys = join(dir, "keys.json");
    await writeFile(keys, validKeys, { mode: 0o600 });
    const { persistentKeyRoot } = await import("../scripts/live-demo-key-store.ts");
    const signerDir = persistentKeyRoot({ home: dir });
    const { mkdir } = await import("node:fs/promises");
    await mkdir(signerDir, { recursive: true, mode: 0o700 });
    const signer = join(signerDir, "demo-operator.json");
    await writeFile(signer, JSON.stringify([...new Uint8Array(64)]), { mode: 0o600 });
    const approval = join(signerDir, "approval-issuer.json");
    await writeFile(approval, JSON.stringify([...new Uint8Array(64)]), { mode: 0o600 });
    const base = {
      ONELAYER_PUBLICATION_KEYS_FILE: keys, ONELAYER_PUBLICATION_OPERATOR_KEY_ID: "demo-operator-1",
      ONELAYER_PUBLICATION_SIGNER_FILE: signer, ONELAYER_PUBLICATION_APPROVAL_KEY_FILE: approval,
      ONELAYER_PUBLICATION_CLUSTER: "solana:devnet",
    };
    // A signer path outside the allow-list is refused even with valid other values.
    await assert.rejects(loadPublicationConfig({ ...base, ONELAYER_PUBLICATION_SIGNER_FILE: "/etc/passwd" }, { home: dir }), /PUBLICATION_SIGNER_FILE_REJECTED/);
    // The approval key is required with the rest and must be a distinct file.
    await assert.rejects(loadPublicationConfig({ ...base, ONELAYER_PUBLICATION_APPROVAL_KEY_FILE: "/etc/passwd" }, { home: dir }), /PUBLICATION_APPROVAL_FILE_REJECTED/);
    await assert.rejects(loadPublicationConfig({ ...base, ONELAYER_PUBLICATION_APPROVAL_KEY_FILE: signer }, { home: dir }), /PUBLICATION_APPROVAL_KEY_REUSED/);
    await assert.rejects(loadPublicationConfig({ ...base, ONELAYER_PUBLICATION_CLUSTER: "not-a-cluster" }, { home: dir }), /PUBLICATION_CLUSTER_INVALID/);
    await assert.rejects(loadPublicationConfig({ ...base, ONELAYER_RPC_GENESIS_HASH: "not-a-hash" }, { home: dir }), /PUBLICATION_GENESIS_HASH_INVALID/);
    const config = await loadPublicationConfig(base, { home: dir });
    assert.equal(config?.operatorKeyId, "demo-operator-1");
    assert.equal(config?.keys.fieldKeyMaster.length, 32);
    assert.equal(config?.cluster, "solana:devnet");
    assert.equal(config?.approvalKeyFile, approval);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
