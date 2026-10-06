import { createHash, timingSafeEqual } from "node:crypto";
import type { Pool } from "pg";
import { SNAPSHOT_KEY_VERSION_PATTERN, type SnapshotKeyConfig } from "./snapshot-key-config.ts";

export class SnapshotKeyBindingError extends Error {
  constructor() { super("SNAPSHOT_KEY_VERSION_CONFLICT"); }
}

/**
 * Registers a key version, or proves that this process reloaded the same
 * material. The unique index arbitrates concurrent first registrations. The
 * immutable table retains every old version; rotation appends a new binding.
 * No plaintext key, share, path or fingerprint is returned or put in errors.
 */
export async function bindSnapshotKeyVersion(
  executor: Pick<Pool, "query">,
  registryId: string,
  config: SnapshotKeyConfig,
): Promise<void> {
  if (typeof registryId !== "string" || !/^[a-z0-9][a-z0-9._-]{0,127}$/.test(registryId)
    || config === null || typeof config !== "object"
    || typeof config.keyEncryptionVersion !== "string"
    || !SNAPSHOT_KEY_VERSION_PATTERN.test(config.keyEncryptionVersion)
    || !(config.kek instanceof Uint8Array) || config.kek.length !== 32) {
    throw new TypeError("SNAPSHOT_KEY_CONFIG_INVALID");
  }
  const version = config.keyEncryptionVersion;
  const fingerprint = createHash("sha256")
    .update("ONELAYER:SNAPSHOT-KEY-BINDING:V1\0")
    .update(registryId).update("\0").update(config.kek).digest();
  await executor.query(
    `INSERT INTO snapshot_key_version (registry_id, key_encryption_version, key_material_fingerprint)
       VALUES ($1, $2, $3) ON CONFLICT (registry_id, key_encryption_version) DO NOTHING`,
    [registryId, version, fingerprint],
  );
  const result = await executor.query(
    `SELECT key_material_fingerprint FROM snapshot_key_version
       WHERE registry_id=$1 AND key_encryption_version=$2`,
    [registryId, version],
  );
  const stored: unknown = result.rows[0]?.key_material_fingerprint;
  if (!(stored instanceof Uint8Array) || stored.length !== fingerprint.length
    || !timingSafeEqual(stored, fingerprint)) throw new SnapshotKeyBindingError();
}
