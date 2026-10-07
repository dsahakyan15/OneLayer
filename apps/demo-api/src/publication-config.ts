// Deployment-owned configuration for the workflow publication runtime.
//
// All three values are required together or not configured at all: a partial
// configuration refuses startup instead of silently disabling or substituting
// key material. The id and field-key master are never generated here, never
// persisted and never returned to a caller. Nothing is written to the DB by
// this module; it only parses already-provisioned material.
import { constants as fsConstants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import * as path from "node:path";
import type { KeyStoreOptions } from "../scripts/live-demo-key-store.ts";
import { assertKeyFilePolicy } from "../scripts/live-demo-key-store.ts";
import type { PublicationKeys } from "./publication-intent.ts";
import { assertClusterLabel, assertGenesisHash } from "./publication-identity.ts";

const HEX32 = /^[0-9a-f]{64}$/;
const KEY_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
/** The keys file holds HMAC key material; it is small and never a device pipe. */
export const MAX_PUBLICATION_KEYS_BYTES = 4096;

export class PublicationConfigError extends Error {
  readonly code: string;
  constructor(code: string) { super(code); this.code = code; }
}

export interface PublicationConfig {
  /** HMAC id key + per-version field-key master for the FIELDMAP:V1 intent. */
  keys: PublicationKeys;
  operatorKeyId: string;
  /** Solana CLI keypair in the hardened demo key store; loaded only to sign. */
  signerKeyFile: string;
  /** Explicit deployment cluster label, e.g. `solana:devnet`. Never defaulted. */
  cluster: string;
  /** Pinned expected genesis hash; required for local/unknown clusters. */
  genesisHash?: string;
  /** Distinct approval-issuer keypair in the hardened store (H5). Never the
   * operator/chain key, never the renderer key or journal material. */
  approvalKeyFile: string;
}

/**
 * Bounded, symlink-free read of a private regular file. The publication keys are
 * HMAC secrets: only an absolute path owned by this user (or root), with no
 * group/other permission bits, opened without following symlinks and re-checked
 * against the opened descriptor, is accepted.
 */
export async function readPrivateKeysFile(file: string): Promise<Buffer> {
  if (typeof file !== "string" || !path.isAbsolute(file)) throw new PublicationConfigError("PUBLICATION_KEYS_FILE_REJECTED");
  const resolved = path.resolve(file);
  const stats = await lstat(resolved).catch(() => undefined);
  const uid = process.getuid?.();
  if (uid === undefined || stats === undefined || !stats.isFile() || stats.isSymbolicLink()) {
    throw new PublicationConfigError("PUBLICATION_KEYS_FILE_REJECTED");
  }
  if (stats.uid !== uid && stats.uid !== 0) throw new PublicationConfigError("PUBLICATION_KEYS_FILE_REJECTED");
  if ((stats.mode & 0o077) !== 0) throw new PublicationConfigError("PUBLICATION_KEYS_FILE_REJECTED");
  if (stats.size <= 0 || stats.size > MAX_PUBLICATION_KEYS_BYTES) throw new PublicationConfigError("PUBLICATION_KEYS_FILE_REJECTED");
  let handle;
  try { handle = await open(resolved, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW); }
  catch { throw new PublicationConfigError("PUBLICATION_KEYS_FILE_REJECTED"); }
  try {
    const opened = await handle.stat().catch(() => undefined);
    if (
      opened === undefined || !opened.isFile() || opened.dev !== stats.dev || opened.ino !== stats.ino ||
      opened.size !== stats.size || (opened.mode & 0o077) !== 0 || (opened.uid !== uid && opened.uid !== 0)
    ) throw new PublicationConfigError("PUBLICATION_KEYS_FILE_REJECTED");
    const bytes = Buffer.alloc(opened.size);
    const { bytesRead } = await handle.read(bytes, 0, opened.size, 0);
    if (bytesRead !== opened.size) { bytes.fill(0); throw new PublicationConfigError("PUBLICATION_KEYS_FILE_REJECTED"); }
    return bytes;
  } finally {
    await handle.close().catch(() => undefined);
  }
}

function bytes32(value: unknown, name: string): Uint8Array {
  if (typeof value !== "string" || !HEX32.test(value)) throw new PublicationConfigError(`PUBLICATION_KEYS_INVALID:${name}`);
  return Uint8Array.from(Buffer.from(value, "hex"));
}

/** Parses the JSON key file. Exported for tests; no key bytes leave the caller. */
export function parsePublicationKeys(raw: string): PublicationKeys {
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new PublicationConfigError("PUBLICATION_KEYS_INVALID:json"); }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new PublicationConfigError("PUBLICATION_KEYS_INVALID:shape");
  const record = parsed as Record<string, unknown>;
  return {
    idKey: bytes32(record.idKey, "idKey"),
    fieldKeyMaster: bytes32(record.fieldKeyMaster, "fieldKeyMaster"),
  };
}

/**
 * Returns the configuration, or `undefined` when no publication variable is
 * set (publication routes are then unavailable, and the API still starts).
 * Throws for a partial or invalid configuration. The approval-issuer key file
 * and the explicit cluster are required with the other three: a runtime that
 * could sign without an independent approval key or a pinned chain identity is
 * never configured (H5/M4).
 */
export async function loadPublicationConfig(
  env: NodeJS.ProcessEnv = process.env,
  keyStore: KeyStoreOptions = {},
): Promise<PublicationConfig | undefined> {
  const keysFile = env.ONELAYER_PUBLICATION_KEYS_FILE;
  const operatorKeyId = env.ONELAYER_PUBLICATION_OPERATOR_KEY_ID;
  const signerKeyFile = env.ONELAYER_PUBLICATION_SIGNER_FILE;
  const approvalKeyFile = env.ONELAYER_PUBLICATION_APPROVAL_KEY_FILE;
  const cluster = env.ONELAYER_PUBLICATION_CLUSTER;
  const configured = [keysFile, operatorKeyId, signerKeyFile, approvalKeyFile, cluster].filter((value) => value !== undefined && value !== "");
  if (configured.length === 0) return undefined;
  if (configured.length !== 5) throw new PublicationConfigError("PUBLICATION_CONFIG_INCOMPLETE");
  if (typeof operatorKeyId !== "string" || !KEY_ID.test(operatorKeyId)) throw new PublicationConfigError("PUBLICATION_OPERATOR_KEY_ID_INVALID");
  try { assertClusterLabel(cluster); } catch { throw new PublicationConfigError("PUBLICATION_CLUSTER_INVALID"); }
  let genesisHash: string | undefined;
  if (env.ONELAYER_RPC_GENESIS_HASH !== undefined && env.ONELAYER_RPC_GENESIS_HASH !== "") {
    try { genesisHash = assertGenesisHash(env.ONELAYER_RPC_GENESIS_HASH); } catch { throw new PublicationConfigError("PUBLICATION_GENESIS_HASH_INVALID"); }
  }
  // Both key paths must be inside the hardened demo key store allow-list. The
  // keys are read lazily, but an arbitrary path is refused now.
  let signerKeyFileResolved: string;
  try { signerKeyFileResolved = assertKeyFilePolicy(signerKeyFile as string, keyStore).resolved; }
  catch { throw new PublicationConfigError("PUBLICATION_SIGNER_FILE_REJECTED"); }
  let approvalKeyFileResolved: string;
  try { approvalKeyFileResolved = assertKeyFilePolicy(approvalKeyFile as string, keyStore).resolved; }
  catch { throw new PublicationConfigError("PUBLICATION_APPROVAL_FILE_REJECTED"); }
  if (approvalKeyFileResolved === signerKeyFileResolved) throw new PublicationConfigError("PUBLICATION_APPROVAL_KEY_REUSED");
  let keys: PublicationKeys;
  try {
    const bytes = await readPrivateKeysFile(keysFile as string);
    try { keys = parsePublicationKeys(bytes.toString("utf8")); } finally { bytes.fill(0); }
  } catch (error) {
    if (error instanceof PublicationConfigError) throw error;
    throw new PublicationConfigError("PUBLICATION_KEYS_FILE_UNREADABLE");
  }
  return { keys, operatorKeyId, signerKeyFile: signerKeyFileResolved, approvalKeyFile: approvalKeyFileResolved, cluster: cluster as string, ...(genesisHash === undefined ? {} : { genesisHash }) };
}
