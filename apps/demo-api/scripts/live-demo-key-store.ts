// Persistent devnet key storage for the live-demo launcher (A1 revision).
//
// During development the synthetic devnet test keypairs live outside the
// repository so they survive reboots:
//
//   ~/.local/state/onelayer-devnet-demo/keys/   (directory 0700, files 0600/0400)
//
// The legacy runtime location under /dev/shm keeps working for compatibility.
// Only those two roots are ever accepted — an arbitrary filesystem path is
// refused. Every path component is validated (ownership, mode, symlinks), the
// private subtree is additionally pinned against the opened directory handles,
// and the key file itself is opened without following symlinks and re-checked
// against the opened descriptor, so a swapped file is refused instead of read.
//
// Key material never leaves this module: reads return only an imported key and
// its public address, initialization returns only the public address. Key
// contents never appear in argv, output channels or logs. Production secret
// custody is explicitly out of scope.
import { createPrivateKey, createPublicKey, randomBytes, type KeyObject } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { mkdir, open, lstat } from "node:fs/promises";
import { homedir } from "node:os";
import * as path from "node:path";
import { getAddressDecoder, type Address } from "@solana/kit";

export class KeyStoreError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

export type KeyStoreErrorCode = "KEYFILE_REJECTED" | "KEYFILE_UNREADABLE" | "KEYPAIR_INVALID";

/** Store directory below the user state root (private, 0700). */
export const KEY_STORE_SEGMENT = path.join(".local", "state", "onelayer-devnet-demo", "keys");
/** Namespace directory that owns both the key store and the rest of the demo state. */
export const DEMO_STATE_SEGMENT = path.join(".local", "state", "onelayer-devnet-demo");
export const DEFAULT_KEY_NAME = "demo-operator.json";
/** Legacy runtime root kept for compatibility with existing /dev/shm keys. */
export const SHM_KEY_ROOT = "/dev/shm";
export const MAX_KEY_FILE_BYTES = 1_024;
const KEYPAIR_BYTES = 64;
const SEED_BYTES = 32;
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export interface KeyStoreOptions {
  /**
   * Home directory used to locate the persistent store. Exposed for tests and
   * out-of-band seeding only; the signer CLI never accepts it, so a caller
   * cannot point the allow-list at an arbitrary location.
   */
  home?: string;
}

export type KeyRootKind = "persistent" | "shm";

export interface KeyRoot {
  root: string;
  kind: KeyRootKind;
}

export interface KeyPathPolicy {
  resolved: string;
  root: string;
  kind: KeyRootKind;
}

export interface LoadedSigningKey {
  address: Address;
  privateKey: KeyObject;
}

export interface EnsureKeyPairResult {
  /** Public address only — key bytes are never returned or printed. */
  address: string;
  path: string;
  created: boolean;
}

function absoluteHome(options?: KeyStoreOptions): string {
  const home = options?.home ?? homedir();
  if (typeof home !== "string" || !path.isAbsolute(home)) throw new KeyStoreError("KEYFILE_REJECTED");
  return path.resolve(home);
}

/** Persistent store root: `~/.local/state/onelayer-devnet-demo/keys`. */
export function persistentKeyRoot(options?: KeyStoreOptions): string {
  return path.join(absoluteHome(options), KEY_STORE_SEGMENT);
}

/** Namespace directory above the persistent store (`…/onelayer-devnet-demo`). */
export function demoStateRoot(options?: KeyStoreOptions): string {
  return path.join(absoluteHome(options), DEMO_STATE_SEGMENT);
}

/** Default key file: `<persistent store>/demo-operator.json`. */
export function defaultKeyFile(options?: KeyStoreOptions): string {
  return path.join(persistentKeyRoot(options), DEFAULT_KEY_NAME);
}

/** The complete allow-list: persistent store first, then the legacy /dev/shm root. */
export function keyRoots(options?: KeyStoreOptions): readonly KeyRoot[] {
  return [
    { root: persistentKeyRoot(options), kind: "persistent" },
    { root: SHM_KEY_ROOT, kind: "shm" },
  ];
}

function isStrictlyBelow(candidate: string, root: string): boolean {
  return candidate !== root && candidate.startsWith(root + path.sep);
}

/**
 * Path-shape allow-list check: absolute, no dot segments, inside exactly one
 * allowed root. The legacy /dev/shm root additionally requires a private
 * subdirectory (never a file in the shared tmpfs root itself).
 */
export function assertKeyFilePolicy(keyFile: string, options?: KeyStoreOptions): KeyPathPolicy {
  if (typeof keyFile !== "string" || !path.isAbsolute(keyFile)) throw new KeyStoreError("KEYFILE_REJECTED");
  const resolved = path.resolve(keyFile);
  for (const segment of resolved.split(path.sep)) {
    if (segment === "." || segment === "..") throw new KeyStoreError("KEYFILE_REJECTED");
  }
  for (const { root, kind } of keyRoots(options)) {
    const relative = path.relative(root, resolved);
    if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) continue;
    const segments = relative.split(path.sep);
    if (segments.some((part) => part === "" || part === "." || part === "..")) throw new KeyStoreError("KEYFILE_REJECTED");
    // Keys never sit in a shared root: /dev/shm requires a private
    // subdirectory, while the persistent store may hold files directly.
    if (kind === "shm" && segments.length < 2) continue;
    return { resolved, root, kind };
  }
  throw new KeyStoreError("KEYFILE_REJECTED");
}

function currentUid(): number {
  const uid = process.getuid?.();
  // Without an owning identity the key file cannot be attributed to this user.
  if (uid === undefined) throw new KeyStoreError("KEYFILE_REJECTED");
  return uid;
}

async function lstatOf(target: string, missingCode: KeyStoreErrorCode) {
  const stats = await lstat(target).catch(() => undefined);
  if (stats === undefined) throw new KeyStoreError(missingCode);
  return stats;
}

/**
 * Ancestors above the private subtree must be trusted system directories:
 * real directories (no symlinks), owned by root or the current user, and not
 * writable by group/other unless they are root-owned sticky system scratch
 * directories such as /dev/shm or /tmp.
 */
async function checkSystemDirectory(directory: string, uid: number): Promise<void> {
  const stats = await lstatOf(directory, "KEYFILE_REJECTED");
  if (!stats.isDirectory() || stats.isSymbolicLink()) throw new KeyStoreError("KEYFILE_REJECTED");
  if (stats.uid !== 0 && stats.uid !== uid) throw new KeyStoreError("KEYFILE_REJECTED");
  const writableByOthers = (stats.mode & 0o022) !== 0;
  const stickySystemScratch = stats.uid === 0 && (stats.mode & 0o1000) !== 0;
  if (writableByOthers && !stickySystemScratch) throw new KeyStoreError("KEYFILE_REJECTED");
}

/**
 * Directories of the private key subtree: owned by the current user, never
 * symlinks, never writable by group/other. The persistent store root is
 * additionally required to be fully private (0700-class). Each directory is
 * pinned against its opened handle so a swapped directory is refused.
 */
async function checkPrivateDirectory(directory: string, uid: number, strict: boolean): Promise<void> {
  const stats = await lstatOf(directory, "KEYFILE_REJECTED");
  if (!stats.isDirectory() || stats.isSymbolicLink()) throw new KeyStoreError("KEYFILE_REJECTED");
  if (stats.uid !== uid) throw new KeyStoreError("KEYFILE_REJECTED");
  if (strict ? (stats.mode & 0o077) !== 0 : (stats.mode & 0o022) !== 0) throw new KeyStoreError("KEYFILE_REJECTED");
  let handle;
  try {
    handle = await open(directory, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
  } catch {
    throw new KeyStoreError("KEYFILE_REJECTED");
  }
  try {
    const opened = await handle.stat().catch(() => undefined);
    if (
      opened === undefined ||
      !opened.isDirectory() ||
      opened.dev !== stats.dev ||
      opened.ino !== stats.ino ||
      opened.uid !== uid ||
      (strict ? (opened.mode & 0o077) !== 0 : (opened.mode & 0o022) !== 0)
    ) {
      throw new KeyStoreError("KEYFILE_REJECTED");
    }
  } finally {
    await handle.close().catch(() => undefined);
  }
}

async function checkAncestry(policy: KeyPathPolicy, uid: number): Promise<void> {
  const chain: string[] = [];
  for (let cursor = path.dirname(policy.resolved); ; cursor = path.dirname(cursor)) {
    chain.unshift(cursor);
    if (path.dirname(cursor) === cursor) break;
  }
  const namespaceDir = path.dirname(policy.root);
  for (const directory of chain) {
    if (isStrictlyBelow(directory, policy.root)) {
      await checkPrivateDirectory(directory, uid, policy.kind === "persistent");
    } else if (directory === policy.root) {
      if (policy.kind === "persistent") await checkPrivateDirectory(directory, uid, true);
      else await checkSystemDirectory(directory, uid);
    } else if (policy.kind === "persistent" && directory === namespaceDir) {
      // `…/onelayer-devnet-demo` is our namespace, but it also holds other
      // demo state, so it is private without being store-strict.
      await checkPrivateDirectory(directory, uid, false);
    } else {
      await checkSystemDirectory(directory, uid);
    }
  }
}

/** Full path validation (shape + ancestry) without touching the key file. */
export async function validateKeyPath(keyFile: string, options?: KeyStoreOptions): Promise<KeyPathPolicy> {
  const policy = assertKeyFilePolicy(keyFile, options);
  await checkAncestry(policy, currentUid());
  return policy;
}

/**
 * Bounded, symlink-free read of a Solana CLI keypair file. The caller must
 * zero the returned buffer once the key is imported.
 */
export async function readKeyFileBytes(keyFile: string, options?: KeyStoreOptions): Promise<Buffer> {
  const policy = assertKeyFilePolicy(keyFile, options);
  const uid = currentUid();
  await checkAncestry(policy, uid);
  const stats = await lstatOf(policy.resolved, "KEYFILE_UNREADABLE");
  if (!stats.isFile() || stats.isSymbolicLink()) throw new KeyStoreError("KEYFILE_REJECTED");
  if (stats.uid !== uid || (stats.mode & 0o077) !== 0) throw new KeyStoreError("KEYFILE_REJECTED");
  let handle;
  try {
    handle = await open(policy.resolved, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch {
    throw new KeyStoreError("KEYFILE_UNREADABLE");
  }
  try {
    const opened = await handle.stat().catch(() => undefined);
    if (opened === undefined) throw new KeyStoreError("KEYFILE_UNREADABLE");
    // The opened descriptor must be the very file that was inspected above.
    if (opened.dev !== stats.dev || opened.ino !== stats.ino) throw new KeyStoreError("KEYFILE_REJECTED");
    if (!opened.isFile() || opened.uid !== uid || (opened.mode & 0o077) !== 0) throw new KeyStoreError("KEYFILE_REJECTED");
    if (opened.size <= 0 || opened.size > MAX_KEY_FILE_BYTES) throw new KeyStoreError("KEYPAIR_INVALID");
    const bytes = Buffer.alloc(opened.size);
    const { bytesRead } = await handle.read(bytes, 0, opened.size, 0);
    if (bytesRead !== opened.size) throw new KeyStoreError("KEYFILE_UNREADABLE");
    return bytes;
  } finally {
    await handle.close().catch(() => undefined);
  }
}

function derivePublicKey(seed: Buffer): Buffer {
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  return Buffer.from(createPublicKey(privateKey).export({ format: "der", type: "spki" })).subarray(-32);
}

/** Validates a Solana CLI keypair (64-byte seed||publicKey) and copies both parts. */
function parseSolanaCliKeypair(bytes: Buffer): { seed: Buffer; publicKey: Buffer } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new KeyStoreError("KEYPAIR_INVALID");
  }
  if (
    !Array.isArray(parsed) ||
    parsed.length !== KEYPAIR_BYTES ||
    parsed.some((value) => !Number.isInteger(value) || (value as number) < 0 || (value as number) > 255)
  ) {
    throw new KeyStoreError("KEYPAIR_INVALID");
  }
  const keypairBytes = Buffer.from(parsed as number[]);
  try {
    const seed = Buffer.from(keypairBytes.subarray(0, SEED_BYTES));
    const publicKey = Buffer.from(keypairBytes.subarray(SEED_BYTES));
    if (!derivePublicKey(seed).equals(publicKey)) throw new KeyStoreError("KEYPAIR_INVALID");
    return { seed, publicKey };
  } finally {
    keypairBytes.fill(0);
  }
}

function importSigningKeyBytes(bytes: Buffer): LoadedSigningKey {
  let seed: Buffer | undefined;
  let publicKey: Buffer | undefined;
  try {
    const parsed = parseSolanaCliKeypair(bytes);
    seed = parsed.seed;
    publicKey = parsed.publicKey;
    const privateKey = createPrivateKey({
      key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
      format: "der",
      type: "pkcs8",
    });
    return { address: getAddressDecoder().decode(new Uint8Array(publicKey)), privateKey };
  } finally {
    // The KeyObject holds its own copy of the key, so the raw bytes can be
    // destroyed before this function returns to its caller.
    seed?.fill(0);
    publicKey?.fill(0);
    bytes.fill(0);
  }
}

/**
 * Reads the Solana CLI keypair file (64-byte seed||publicKey JSON array) and
 * imports it. All raw key bytes are zeroed before this returns; the returned
 * handle holds its own copy and is the only key material that leaves.
 */
export async function loadSigningKey(keyFile: string, options?: KeyStoreOptions): Promise<LoadedSigningKey> {
  const bytes = await readKeyFileBytes(keyFile, options);
  return importSigningKeyBytes(bytes);
}

/** Ensures the persistent store exists with private permissions (idempotent). */
export async function ensureKeyStore(options?: KeyStoreOptions): Promise<string> {
  const root = persistentKeyRoot(options);
  await mkdir(root, { recursive: true, mode: 0o700 });
  // Re-validate instead of trusting mkdir: an existing store with unsafe
  // permissions is refused rather than silently chmod'd.
  await validateKeyPath(defaultKeyFile(options), options);
  return root;
}

function buildKeypairBytes(seed: Buffer): Buffer {
  if (seed.length !== SEED_BYTES) throw new KeyStoreError("KEYPAIR_INVALID");
  return Buffer.concat([seed, derivePublicKey(seed)]);
}

export interface EnsureKeyPairOptions extends KeyStoreOptions {
  /** Target key file; defaults to the persistent `demo-operator.json`. */
  keyFile?: string;
  /** Solana CLI keypair (64 bytes) to install; generated when omitted. */
  keypair?: Uint8Array;
}

/**
 * Initializes one devnet keypair file with idempotent no-overwrite semantics:
 * an existing file is validated and kept as-is, a missing one is created 0600
 * from the supplied keypair (or a freshly generated development key). Only the
 * public address is returned — key contents never leave this function.
 */
export async function ensureKeyPair(options: EnsureKeyPairOptions = {}): Promise<EnsureKeyPairResult> {
  const keyFile = options.keyFile ?? defaultKeyFile(options);
  const policy = assertKeyFilePolicy(keyFile, options);
  await mkdir(path.dirname(policy.resolved), { recursive: true, mode: 0o700 });
  await validateKeyPath(keyFile, options);

  const existing = await lstat(policy.resolved).catch(() => undefined);
  if (existing !== undefined) {
    if (!existing.isFile() || existing.isSymbolicLink()) throw new KeyStoreError("KEYFILE_REJECTED");
    const loaded = await loadSigningKey(keyFile, options);
    return { address: String(loaded.address), path: policy.resolved, created: false };
  }

  let seed: Buffer | undefined;
  let keypairBytes: Buffer | undefined;
  let payload: Buffer | undefined;
  try {
    if (options.keypair === undefined) {
      seed = randomBytes(SEED_BYTES);
      keypairBytes = buildKeypairBytes(seed);
    } else {
      if (options.keypair.length !== KEYPAIR_BYTES) throw new KeyStoreError("KEYPAIR_INVALID");
      keypairBytes = Buffer.from(options.keypair);
      // Rejects a seed/publicKey mismatch and anything that is not the
      // validated Solana CLI layout (64-byte seed||publicKey).
      if (!derivePublicKey(keypairBytes.subarray(0, SEED_BYTES)).equals(keypairBytes.subarray(SEED_BYTES))) {
        throw new KeyStoreError("KEYPAIR_INVALID");
      }
    }
    payload = Buffer.from(JSON.stringify([...keypairBytes]), "utf8");
    if (payload.length > MAX_KEY_FILE_BYTES) throw new KeyStoreError("KEYPAIR_INVALID");
    let handle;
    try {
      handle = await open(policy.resolved, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    } catch (error) {
      // A concurrent initializer won the race: keep its file (no overwrite).
      if ((error as NodeJS.ErrnoException).code === "EEXIST") {
        const loaded = await loadSigningKey(keyFile, options);
        return { address: String(loaded.address), path: policy.resolved, created: false };
      }
      throw new KeyStoreError("KEYFILE_UNREADABLE");
    }
    try {
      await handle.write(payload, 0, payload.length, 0);
      await handle.sync();
    } finally {
      await handle.close().catch(() => undefined);
    }
    const loaded = await loadSigningKey(keyFile, options);
    return { address: String(loaded.address), path: policy.resolved, created: true };
  } finally {
    seed?.fill(0);
    keypairBytes?.fill(0);
    payload?.fill(0);
  }
}
