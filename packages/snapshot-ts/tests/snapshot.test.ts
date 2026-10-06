import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { createSnapshotPackage, decodeSnapshotPackage, encodeSnapshotPackage, recoverRecoveryKek, restoreSnapshot, splitRecoveryKek } from "../src/index.ts";

test("chunked package round-trips through deterministic CBOR and 3-of-5 recovery", () => {
  const kek = randomBytes(32);
  const shares = splitRecoveryKek(kek);
  assert.throws(() => recoverRecoveryKek(shares.slice(0, 2)), /at least 3/);
  const recoveredKek = recoverRecoveryKek([shares[0], shares[2], shares[4]]);
  assert.deepEqual(Buffer.from(recoveredKek), kek);
  const plaintext = Buffer.from("registry snapshot payload spanning several authenticated chunks");
  const snapshot = createSnapshotPackage({ registryId: "gov.registry.land", snapshotId: new Uint8Array(16).fill(7), snapshotVersion: 1n, chunkSize: 13, plaintext, keyEncryptionVersion: "lab-kek-v1", kek });
  const encoded = encodeSnapshotPackage(snapshot);
  assert.deepEqual(encodeSnapshotPackage(decodeSnapshotPackage(encoded)), encoded);
  assert.deepEqual(restoreSnapshot(decodeSnapshotPackage(encoded), recoveredKek), plaintext);
  assert.deepEqual(snapshot.chunks.map((chunk) => Buffer.from(chunk.nonce).toString("hex")), [0, 1, 2, 3, 4].map((index) => `0000000000000000${index.toString(16).padStart(8, "0")}`));
});

test("corruption is rejected before plaintext is returned", () => {
  const kek = randomBytes(32);
  const snapshot = createSnapshotPackage({ registryId: "gov.registry.land", snapshotId: randomBytes(16), snapshotVersion: 2n, chunkSize: 8, plaintext: Buffer.from("authenticated backup"), keyEncryptionVersion: "lab-kek-v1", kek });
  snapshot.chunks[0].ciphertext[0] ^= 1;
  assert.throws(() => restoreSnapshot(snapshot, kek), /ciphertext hash mismatch/);
});
