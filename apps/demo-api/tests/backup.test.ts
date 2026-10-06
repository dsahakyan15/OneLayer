import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { decodeCanonical } from "../../../packages/canonical-ts/src/index.ts";
import { decodeSnapshotPackage, restoreSnapshot } from "../../../packages/snapshot-ts/src/index.ts";
import {
  encodeRecoveryShare,
  encodeSnapshotState,
  encryptSnapshotState,
  parseRecoveryShare,
  retentionVictims,
  SNAPSHOT_STATE_FORMAT,
  splitEncodedRecoveryShares,
} from "../src/backup.ts";

function state(extra: Record<string, unknown> = {}) {
  return {
    registryId: "gov.registry.land",
    capturedAt: "2026-08-04T00:00:00Z",
    records: [{ internalRecordId: "SYNTHETIC-1", status: "ACTIVE", ...extra }],
    recordVersions: [{ internalRecordId: "SYNTHETIC-1", recordVersion: "1" }],
    certificatePackages: [{ certificateId: "certificate-1", packageBase64Url: "encrypted-by-envelope" }],
    qrMetadata: [{ certificateId: "certificate-1", qrUrl: "http://127.0.0.1/c/certificate-1" }],
    proofs: [{ leafHash: "aa".repeat(32) }],
    roots: [{ merkleRoot: "bb".repeat(32) }],
    manifests: [{ manifestHash: "cc".repeat(32) }],
    anchorReferences: [{ batchSequence: "1" }],
    operationHistory: [{ eventType: "RECORD_UPSERTED" }],
  };
}

test("the full snapshot state is deterministic and encrypted as SnapshotPackageV1", () => {
  const left = encodeSnapshotState(state({ b: "two", a: "one" }));
  const right = encodeSnapshotState(state({ a: "one", b: "two" }));
  assert.deepEqual(left, right);

  const kek = randomBytes(32);
  const encrypted = encryptSnapshotState({
    registryId: "gov.registry.land",
    snapshotId: Uint8Array.from({ length: 16 }, (_unused, index) => index),
    snapshotVersion: 1n,
    state: state(),
    kek,
  });
  const decoded = decodeSnapshotPackage(encrypted.encoded);
  const restored = restoreSnapshot(decoded, kek);
  const payload = decodeCanonical(restored);
  assert.equal(payload.type, "map");
  if (payload.type === "map") {
    assert.equal(payload.entries.format.type, "text");
    if (payload.entries.format.type === "text") assert.equal(payload.entries.format.value, SNAPSHOT_STATE_FORMAT);
    assert.equal(payload.entries.records.type, "array");
    assert.equal(payload.entries.recordVersions.type, "array");
    assert.equal(payload.entries.certificatePackages.type, "array");
    assert.equal(payload.entries.qrMetadata.type, "array");
    assert.equal(payload.entries.proofs.type, "array");
    assert.equal(payload.entries.roots.type, "array");
    assert.equal(payload.entries.manifests.type, "array");
    assert.equal(payload.entries.anchorReferences.type, "array");
    assert.equal(payload.entries.operationHistory.type, "array");
  }
});

test("retention removes the oldest non-finalized replica and protects the only finalized one", () => {
  const replicas = Array.from({ length: 13 }, (_unused, index) => ({
    replicaId: `replica-${index}`,
    snapshotId: `snapshot-${index}`,
    snapshotStatus: index === 4 ? "FINALIZED" : "NON_FINALIZED",
    createdAt: new Date(1_000 + index * 1_000).toISOString(),
  }));
  const victims = retentionVictims(replicas);
  assert.equal(victims.length, 1);
  assert.equal(victims[0].snapshotId, "snapshot-0");

  const finalized = replicas.map((replica) => ({ ...replica, snapshotStatus: "FINALIZED" }));
  assert.equal(retentionVictims(finalized)[0].snapshotId, "snapshot-0");
});

test("recovery share text is round-trippable without becoming snapshot state", () => {
  const shares = splitEncodedRecoveryShares(randomBytes(32));
  assert.equal(shares.length, 5);
  assert.match(shares[0], /^ONELAYER_RECOVERY_SHARE_V1:1:[0-9a-f]{64}$/);
  const parsed = parseRecoveryShare(shares[0]);
  assert.equal(encodeRecoveryShare(parsed), shares[0]);
  assert.throws(() => parseRecoveryShare("ONELAYER_RECOVERY_SHARE_V1:1:00"), /recovery share is invalid/);
});
