// Bounded local backup primitives for the Admin control plane.
//
// The state payload is canonical CBOR and is only ever handed to the
// SnapshotPackageV1 encryptor. Callers persist the returned envelope, never
// the plaintext state. This module deliberately contains no PostgreSQL or
// HTTP concerns so the package and retention invariants can be unit-tested in
// isolation.
import { encode, toHex, type CborValue } from "../../../packages/canonical-ts/src/index.ts";
import {
  createSnapshotPackage,
  encodeSnapshotPackage,
  splitRecoveryKek,
  type KeyShare,
  type SnapshotPackageV1,
} from "../../../packages/snapshot-ts/src/index.ts";

export const SNAPSHOT_FORMAT = "SnapshotPackageV1" as const;
export const SNAPSHOT_STATE_FORMAT = "ONELAYER_SNAPSHOT_STATE_V1" as const;
export const SNAPSHOT_CHUNK_SIZE = 64 * 1024;
export const RETENTION_WINDOW = 12;
export const SNAPSHOT_KEY_ENCRYPTION_VERSION = "mvp-memory-kek-v1";
export const RECOVERY_SHARE_FORMAT = "ONELAYER_RECOVERY_SHARE_V1";

function validateRecoveryShare(share: KeyShare): void {
  if (!Number.isSafeInteger(share.index) || share.index < 1 || share.index > 5 || share.bytes.length !== 32) {
    throw new TypeError("recovery share is invalid");
  }
}

/**
 * The share text is an out-of-band custody artifact. It is intentionally
 * simple to paste into a masked input, while the API never echoes it back or
 * writes it to persistence. The bytes remain inside the request only long
 * enough to reconstruct the operation KEK.
 */
export function encodeRecoveryShare(share: KeyShare): string {
  validateRecoveryShare(share);
  return `${RECOVERY_SHARE_FORMAT}:${share.index}:${toHex(share.bytes)}`;
}

export function parseRecoveryShare(value: unknown): KeyShare {
  if (typeof value !== "string") throw new TypeError("recovery share is invalid");
  const match = new RegExp(`^${RECOVERY_SHARE_FORMAT}:([1-5]):([0-9a-f]{64})$`).exec(value);
  if (match === null) throw new TypeError("recovery share is invalid");
  return { index: Number(match[1]), bytes: Uint8Array.from(Buffer.from(match[2], "hex")) };
}

/** Used by bounded runtime setup and tests; callers must keep the result out of logs and responses. */
export function splitEncodedRecoveryShares(kek: Uint8Array): string[] {
  return splitRecoveryKek(kek).map(encodeRecoveryShare);
}

export interface SnapshotStateV1 {
  registryId: string;
  capturedAt: string;
  records: readonly Record<string, unknown>[];
  recordVersions: readonly Record<string, unknown>[];
  certificatePackages: readonly Record<string, unknown>[];
  qrMetadata: readonly Record<string, unknown>[];
  proofs: readonly Record<string, unknown>[];
  roots: readonly Record<string, unknown>[];
  manifests: readonly Record<string, unknown>[];
  anchorReferences: readonly Record<string, unknown>[];
  operationHistory: readonly Record<string, unknown>[];
}

export interface EncryptedSnapshot {
  snapshot: SnapshotPackageV1;
  encoded: Uint8Array;
  plaintextLength: number;
}

function cborValue(value: unknown): CborValue {
  if (value === null || value === undefined) return { type: "null" };
  if (value instanceof Uint8Array) return { type: "bytes", hex: toHex(value) };
  if (value instanceof Date) return { type: "text", value: value.toISOString() };
  if (typeof value === "string") return { type: "text", value };
  if (typeof value === "boolean") return { type: "bool", value };
  if (typeof value === "bigint") return { type: "int", value: value.toString() };
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError("snapshot state contains a non-integer number");
    return { type: "int", value: String(value) };
  }
  if (Array.isArray(value)) return { type: "array", items: value.map(cborValue) };
  if (typeof value === "object") {
    const entries: Record<string, CborValue> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      entries[key] = cborValue((value as Record<string, unknown>)[key]);
    }
    return { type: "map", entries };
  }
  throw new TypeError("snapshot state contains an unsupported value");
}

/** Builds the deterministic, full-state plaintext for one snapshot. */
export function encodeSnapshotState(state: SnapshotStateV1): Uint8Array {
  return encode({
    type: "map",
    entries: {
      format: { type: "text", value: SNAPSHOT_STATE_FORMAT },
      version: { type: "int", value: "1" },
      registryId: { type: "text", value: state.registryId },
      capturedAt: { type: "text", value: state.capturedAt },
      records: { type: "array", items: state.records.map(cborValue) },
      recordVersions: { type: "array", items: state.recordVersions.map(cborValue) },
      certificatePackages: { type: "array", items: state.certificatePackages.map(cborValue) },
      qrMetadata: { type: "array", items: state.qrMetadata.map(cborValue) },
      proofs: { type: "array", items: state.proofs.map(cborValue) },
      roots: { type: "array", items: state.roots.map(cborValue) },
      manifests: { type: "array", items: state.manifests.map(cborValue) },
      anchorReferences: { type: "array", items: state.anchorReferences.map(cborValue) },
      operationHistory: { type: "array", items: state.operationHistory.map(cborValue) },
    },
  });
}

/** Encrypts one complete state and returns only the encrypted envelope. */
export function encryptSnapshotState(input: {
  registryId: string;
  snapshotId: Uint8Array;
  snapshotVersion: bigint;
  state: SnapshotStateV1;
  kek: Uint8Array;
  keyEncryptionVersion?: string;
}): EncryptedSnapshot {
  const plaintext = encodeSnapshotState(input.state);
  try {
    const snapshot = createSnapshotPackage({
      registryId: input.registryId,
      snapshotId: input.snapshotId,
      snapshotVersion: input.snapshotVersion,
      chunkSize: SNAPSHOT_CHUNK_SIZE,
      plaintext,
      keyEncryptionVersion: input.keyEncryptionVersion ?? SNAPSHOT_KEY_ENCRYPTION_VERSION,
      kek: input.kek,
    });
    return {
      snapshot,
      encoded: encodeSnapshotPackage(snapshot),
      plaintextLength: plaintext.length,
    };
  } finally {
    // The caller never receives the plaintext buffer. Clear it as soon as the
    // authenticated envelope has been produced.
    plaintext.fill(0);
  }
}

export function snapshotObjectKey(snapshotId: Uint8Array): string {
  return `snapshots/${toHex(snapshotId)}/snapshot-package-v1.cbor`;
}

export interface RetentionReplica {
  replicaId: string;
  snapshotId: string;
  snapshotStatus: string;
  createdAt: string;
}

/** Returns the oldest removable replicas while preserving a Finalized copy. */
export function retentionVictims(
  replicas: readonly RetentionReplica[],
  limit = RETENTION_WINDOW,
): RetentionReplica[] {
  if (!Number.isSafeInteger(limit) || limit < 1) throw new RangeError("retention limit is invalid");
  const active = [...replicas].sort((left, right) =>
    left.createdAt.localeCompare(right.createdAt) || left.replicaId.localeCompare(right.replicaId),
  );
  const victims: RetentionReplica[] = [];
  while (active.length - victims.length > limit) {
    const remaining = active.filter((candidate) => !victims.includes(candidate));
    const finalized = remaining.filter((candidate) => candidate.snapshotStatus === "FINALIZED");
    const candidate = remaining.find((entry) => entry.snapshotStatus !== "FINALIZED") ??
      (finalized.length > 1 ? finalized[0] : undefined);
    if (candidate === undefined) {
      throw new RangeError("retention cannot remove the only Finalized Snapshot");
    }
    victims.push(candidate);
  }
  return victims;
}
