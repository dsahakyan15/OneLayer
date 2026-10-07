// Explicit, restart-stable configuration for the snapshot writer KEK.
//
// The writer key is provisioned out of band as a 32-byte binary file and is
// loaded once at startup. This module never generates, splits, persists or
// regenerates key material: with no configuration the API still starts and
// snapshot creation fails closed, and an incomplete or invalid configuration
// refuses startup instead of substituting a process-random or issuer key.
//
// Configuration errors are deliberately generic: they never contain the file
// path, key bytes, or any other secret material.
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from "node:fs";

export const SNAPSHOT_KEK_FILE_ENV = "ONELAYER_SNAPSHOT_KEK_FILE";
export const SNAPSHOT_KEY_VERSION_ENV = "ONELAYER_SNAPSHOT_KEY_VERSION";
export const SNAPSHOT_KEK_BYTES = 32;

/** Stable lowercase versioned identifiers: no whitespace, separators or path characters. */
export const SNAPSHOT_KEY_VERSION_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export const SNAPSHOT_KEK_FILE_INVALID = SNAPSHOT_KEK_FILE_ENV + " is invalid";
export const SNAPSHOT_KEY_VERSION_INVALID = SNAPSHOT_KEY_VERSION_ENV + " is invalid";
export const SNAPSHOT_KEY_CONFIG_INCOMPLETE =
  SNAPSHOT_KEK_FILE_ENV + " and " + SNAPSHOT_KEY_VERSION_ENV + " must be configured together";

export interface SnapshotKeyConfig {
  /** Exactly 32 bytes read from the configured private file; never generated here. */
  kek: Uint8Array;
  /**
   * Configured stable version identifier this writer commits into every
   * package. Stability across restarts is only guaranteed once the version is
   * bound to this key material durably (bindSnapshotKeyVersion).
   */
  keyEncryptionVersion: string;
}

/**
 * Reads the KEK with an absolute bound: one nonblocking read-only descriptor
 * that must already be a private regular file when it is inspected and again
 * when it is opened. A symlink, FIFO, directory, non-private mode, or any size
 * other than exactly 32 bytes is refused before a byte is returned.
 */
function readSnapshotKek(path: string): Uint8Array {
  let descriptor: number;
  try {
    const inspected = lstatSync(path);
    if (!inspected.isFile() || (inspected.mode & 0o077) !== 0) throw new Error(SNAPSHOT_KEK_FILE_INVALID);
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch {
    throw new Error(SNAPSHOT_KEK_FILE_INVALID);
  }
  try {
    // The descriptor is re-checked after opening so a path swapped between the
    // two calls cannot smuggle in a different file type or mode.
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || (opened.mode & 0o077) !== 0) throw new Error(SNAPSHOT_KEK_FILE_INVALID);
    const buffer = Buffer.alloc(SNAPSHOT_KEK_BYTES + 1);
    try {
      let total = 0;
      while (total <= SNAPSHOT_KEK_BYTES) {
        const read = readSync(descriptor, buffer, total, SNAPSHOT_KEK_BYTES + 1 - total, total);
        if (read === 0) break;
        total += read;
      }
      if (total !== SNAPSHOT_KEK_BYTES) throw new Error(SNAPSHOT_KEK_FILE_INVALID);
      return Uint8Array.from(buffer.subarray(0, SNAPSHOT_KEK_BYTES));
    } finally {
      buffer.fill(0);
    }
  } finally {
    closeSync(descriptor);
  }
}

/**
 * Returns the explicit writer configuration, or `undefined` when neither
 * variable is set. Only an unset variable is disabled configuration: an
 * explicitly empty value, a one-sided pair, an unstable version identifier, or
 * an unsafe key file refuses startup instead.
 */
export function loadSnapshotKeyConfig(env: NodeJS.ProcessEnv = process.env): SnapshotKeyConfig | undefined {
  const path = env[SNAPSHOT_KEK_FILE_ENV];
  const version = env[SNAPSHOT_KEY_VERSION_ENV];
  if (path === undefined && version === undefined) return undefined;
  if (path === undefined || version === undefined) throw new Error(SNAPSHOT_KEY_CONFIG_INCOMPLETE);
  if (path === "") throw new Error(SNAPSHOT_KEK_FILE_INVALID);
  if (version === "") throw new Error(SNAPSHOT_KEY_VERSION_INVALID);
  if (!SNAPSHOT_KEY_VERSION_PATTERN.test(version)) throw new Error(SNAPSHOT_KEY_VERSION_INVALID);
  return { kek: readSnapshotKek(path), keyEncryptionVersion: version };
}
