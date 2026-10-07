// Durable trust-policy acceptance: threshold-authenticated distribution, root-set
// rotation, an external freshness-checked revision floor and local anti-rollback.
// Everything here fails closed. A missing, unreadable, corrupt or unsafely stored
// watermark is never treated as "start over"; only a digest-pinned bootstrap creates it.
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readFile, realpath, rename, rm } from "node:fs/promises";
import { hostname } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";
import { parseTrustPolicy, type TrustPolicy } from "./trust-policy.ts";
import {
  deploymentIdOf, ENVELOPES, exactKeys, resolveRootSet, TrustStateError, validateRootSet, verifyThreshold,
  type DeploymentPin, type RootSet, type TrustRootKey,
} from "./trust-envelope.ts";
import { acquireTrustFloor, FileTrustFloorSource, type TrustFloor, type TrustFloorSource } from "./trust-floor.ts";

export { TrustStateError, type DeploymentPin, type RootSet, type TrustRootKey } from "./trust-envelope.ts";
export const SIGNED_POLICY_FORMAT = ENVELOPES.policy.format;
/** Domain separation: a trust-root signature can never be replayed as another OneLayer signature. */
export const POLICY_SIGNATURE_DOMAIN = Buffer.from(ENVELOPES.policy.domain, "utf8");
export const TRUST_STATE_FORMAT = "onelayer.trust-state.v2";
const TRUST_STATE_FORMAT_V1 = "onelayer.trust-state.v1";
/** Largest accepted revision increase per acceptance; stops exhausting the revision space in one step. */
export const MAX_REVISION_STEP = 1_000;
export const DEFAULT_FLOOR_MAX_AGE_MS = 24 * 60 * 60_000;
const MAX_FLOOR_MAX_AGE_MS = 30 * 24 * 60 * 60_000;
const LOCK_TIMEOUT_MS = 5_000;
const { O_RDONLY, O_WRONLY, O_CREAT, O_EXCL, O_NOFOLLOW, O_DIRECTORY } = constants;

export type TrustMode =
  | {
    kind: "signed";
    /** Pinned anchor root set (epoch 1, or the re-pinned epoch after a root compromise) with its k-of-n threshold. */
    anchor: RootSet;
    /** Threshold-signed rotation envelopes, oldest first; a JSON array file. */
    rotationsFile?: string;
    deployment: DeploymentPin;
    floor: TrustFloorSource;
    floorMaxAgeMs?: number;
  }
  | { kind: "unsigned"; deployment?: DeploymentPin };

export interface TrustWatermark {
  format: typeof TRUST_STATE_FORMAT;
  revision: number;
  policyDigest: string;
  authenticated: boolean;
  /** 0 for unsigned acceptance. */
  rootEpoch: number;
  rootSetDigest: string | null;
}

const HEX32 = /^[0-9a-f]{64}$/;
const errno = (error: unknown) => (error as NodeJS.ErrnoException).code ?? "error";

export function parseTrustRootKeys(value: string): TrustRootKey[] {
  const keys = value.split(",").map(entry => {
    const [keyId, publicKeyHex, ...rest] = entry.split(":");
    if (rest.length !== 0 || !keyId || !HEX32.test(publicKeyHex ?? "")) throw new TrustStateError("TRUST_ROOT_INVALID", "expected keyId:publicKeyHex[,…]");
    return { keyId, publicKeyHex };
  });
  if (new Set(keys.map(key => key.keyId)).size !== keys.length) throw new TrustStateError("TRUST_ROOT_INVALID", "duplicate trust-root keyId");
  return keys;
}

/**
 * Canonical `<genesisHash>/<registryId>/<programIdHex>`: base58 genesis hash,
 * registry id of [A-Za-z0-9._:-] (no '/', no whitespace), lowercase 32-byte hex.
 */
export function parseDeploymentPin(value: string): DeploymentPin {
  const parts = value.split("/");
  const [genesisHash, registryId, programIdHex] = parts;
  if (parts.length !== 3 || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(genesisHash) || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(registryId)
    || registryId.includes("..") || !HEX32.test(programIdHex)) {
    throw new TrustStateError("TRUST_DEPLOYMENT_INVALID", "expected canonical <base58 genesisHash>/<registryId>/<lowercase programIdHex>");
  }
  return { genesisHash, registryId, programIdHex };
}

/**
 * Returns the exact policy document bytes. Unsigned mode: the file. Signed mode:
 * the payload of a policy envelope carrying valid signatures from at least the
 * threshold of distinct keys of the *current* (post-rotation) root set.
 */
export function authenticatePolicyDocument(fileBytes: Buffer, roots: RootSet | undefined): Buffer {
  if (roots === undefined) return fileBytes;
  let parsed: unknown;
  try { parsed = JSON.parse(fileBytes.toString("utf8")); } catch { parsed = undefined; }
  return verifyThreshold(parsed, "policy", roots, { unsigned: "TRUST_POLICY_UNSIGNED", signature: "TRUST_POLICY_SIGNATURE_INVALID" });
}

/**
 * The policy digest used by the watermark and by ONELAYER_TRUST_STATE_BOOTSTRAP:
 * sha256 of the exact policy JSON document bytes. Unsigned mode: the policy file
 * bytes. Signed mode: the decoded `payloadBase64` bytes (the same policy JSON),
 * never the envelope, so one document has one digest in both modes.
 */
export function policyDigest(documentBytes: Buffer): string {
  return createHash("sha256").update(documentBytes).digest("hex");
}

function parseWatermark(bytes: Buffer): TrustWatermark {
  let value: unknown;
  try { value = JSON.parse(bytes.toString("utf8")); } catch { throw new TrustStateError("TRUST_STATE_CORRUPT", "unparseable watermark"); }
  const corrupt = () => new TrustStateError("TRUST_STATE_CORRUPT", "invalid watermark");
  const v2 = exactKeys(value, ["format", "revision", "policyDigest", "authenticated", "rootEpoch", "rootSetDigest"]);
  const v1 = exactKeys(value, ["format", "revision", "policyDigest", "authenticated"]);
  const state = v2 ?? v1;
  if (!state || state.format !== (v2 ? TRUST_STATE_FORMAT : TRUST_STATE_FORMAT_V1) || !Number.isSafeInteger(state.revision) || (state.revision as number) < 1
    || typeof state.policyDigest !== "string" || !HEX32.test(state.policyDigest) || typeof state.authenticated !== "boolean") throw corrupt();
  if (!v2) return { ...(state as Omit<TrustWatermark, "rootEpoch" | "rootSetDigest">), format: TRUST_STATE_FORMAT, rootEpoch: 0, rootSetDigest: null };
  const rootEpoch = v2.rootEpoch as number;
  if (!Number.isSafeInteger(rootEpoch) || rootEpoch < 0 || (rootEpoch === 0) !== (v2.rootSetDigest === null)
    || (v2.rootSetDigest !== null && (typeof v2.rootSetDigest !== "string" || !HEX32.test(v2.rootSetDigest)))
    || (rootEpoch > 0) !== v2.authenticated) throw corrupt();
  return v2 as unknown as TrustWatermark;
}

/**
 * Local high-water mark of accepted external floors, kept in `<state>.floor`
 * next to (but separate from) the watermark. It survives a watermark reset and
 * refuses the replay of an older, still unexpired floor statement.
 */
export const FLOOR_HWM_FORMAT = "onelayer.trust-floor-hwm.v1";
export interface FloorHighWater {
  format: typeof FLOOR_HWM_FORMAT;
  deploymentId: string;
  floorSequence: number;
  rootEpoch: number;
  minimumPolicyRevision: number;
  minimumRootEpoch: number;
  issuedAt: string;
}
export const floorStateFile = (stateFile: string) => `${stateFile}.floor`;

function parseFloorHighWater(bytes: Buffer): FloorHighWater {
  let value: unknown;
  try { value = JSON.parse(bytes.toString("utf8")); } catch { value = undefined; }
  const hwm = exactKeys(value, ["format", "deploymentId", "floorSequence", "rootEpoch", "minimumPolicyRevision", "minimumRootEpoch", "issuedAt"]);
  const positive = (field: unknown) => Number.isSafeInteger(field) && (field as number) >= 1;
  if (!hwm || hwm.format !== FLOOR_HWM_FORMAT || typeof hwm.deploymentId !== "string" || !positive(hwm.floorSequence) || !positive(hwm.rootEpoch)
    || !positive(hwm.minimumPolicyRevision) || !positive(hwm.minimumRootEpoch) || typeof hwm.issuedAt !== "string" || Number.isNaN(Date.parse(hwm.issuedAt))) {
    throw new TrustStateError("TRUST_FLOOR_STATE_CORRUPT", "invalid floor high-water mark");
  }
  return hwm as unknown as FloorHighWater;
}

/** Returns the high-water mark to persist, or undefined when it is unchanged. Throws on floor replay/rollback. */
function advanceFloor(current: FloorHighWater | undefined, floor: TrustFloor): FloorHighWater | undefined {
  const next: FloorHighWater = {
    format: FLOOR_HWM_FORMAT, deploymentId: floor.deploymentId, floorSequence: floor.floorSequence, rootEpoch: floor.rootEpoch,
    minimumPolicyRevision: floor.minimumPolicyRevision, minimumRootEpoch: floor.minimumRootEpoch, issuedAt: floor.issuedAt,
  };
  if (current === undefined) return next;
  if (current.deploymentId !== floor.deploymentId) throw new TrustStateError("TRUST_FLOOR_DEPLOYMENT_MISMATCH", "floor high-water mark belongs to another deployment");
  if (floor.floorSequence < current.floorSequence) {
    throw new TrustStateError("TRUST_FLOOR_ROLLBACK", `floor sequence ${floor.floorSequence} is below the accepted ${current.floorSequence}`);
  }
  if (floor.floorSequence === current.floorSequence) {
    if (JSON.stringify(next) !== JSON.stringify(current)) throw new TrustStateError("TRUST_FLOOR_CONFLICT", `a different floor statement was accepted for sequence ${floor.floorSequence}`);
    return undefined;
  }
  if (floor.minimumPolicyRevision < current.minimumPolicyRevision || floor.minimumRootEpoch < current.minimumRootEpoch
    || floor.rootEpoch < current.rootEpoch || Date.parse(floor.issuedAt) < Date.parse(current.issuedAt)) {
    throw new TrustStateError("TRUST_FLOOR_ROLLBACK", "a newer floor sequence may not lower the floor, the signing epoch or issuedAt");
  }
  return next;
}

const unsafe = (why: string) => new TrustStateError("TRUST_STATE_LOCATION_UNSAFE", why);
const within = (child: string, parent: string) => child === parent || child.startsWith(parent.endsWith(sep) ? parent : parent + sep);
async function realOrResolved(path: string): Promise<string> {
  try { return await realpath(path); } catch { return resolve(path); }
}

/**
 * The watermark must live in its own private directory, disjoint from the policy:
 * whoever can replace the policy must not also be able to replace the watermark.
 * - the configured state directory path contains no symlinks (it equals its realpath);
 * - it is neither equal to, inside, nor a parent of the policy directory, compared
 *   against both the policy's directory and the real location of the policy file;
 * - every ancestor up to `/` is owned by root or the verifier user and is not
 *   group/world-writable unless it carries the sticky bit (e.g. /tmp);
 * - the state directory itself is owned by the verifier user and not group/world-writable.
 * The state file itself is only ever opened with O_NOFOLLOW and checked via fstat.
 */
export async function assertPrivateStateLocation(stateFile: string, policyFile: string): Promise<void> {
  const uid = process.getuid?.();
  const directory = dirname(resolve(stateFile));
  let real: string;
  try { real = await realpath(directory); }
  catch (error) { throw new TrustStateError("TRUST_STATE_UNAVAILABLE", `state directory unavailable (${errno(error)})`); }
  if (real !== directory) throw unsafe("state directory path must not traverse symlinks");
  for (const policyDirectory of new Set([await realOrResolved(dirname(resolve(policyFile))), dirname(await realOrResolved(policyFile))])) {
    if (within(real, policyDirectory) || within(policyDirectory, real)) throw unsafe("state directory must be disjoint from the policy directory");
  }
  for (let current = real; ; current = dirname(current)) {
    const stats = await lstat(current);
    if (!stats.isDirectory()) throw unsafe(`${current} is not a directory`);
    if (current === real) {
      if (uid !== undefined && stats.uid !== uid) throw unsafe("state directory is owned by another user");
      if ((stats.mode & 0o022) !== 0) throw unsafe("state directory is group/world-writable");
    } else {
      if (uid !== undefined && stats.uid !== 0 && stats.uid !== uid) throw unsafe(`ancestor ${current} is owned by another user`);
      if ((stats.mode & 0o022) !== 0 && (stats.mode & 0o1000) === 0) throw unsafe(`ancestor ${current} is writable by others without the sticky bit`);
    }
    if (dirname(current) === current) break;
  }
}

/** Reads the watermark through an O_NOFOLLOW descriptor and validates it with fstat. */
async function readStateBytes(stateFile: string): Promise<Buffer | undefined> {
  let handle;
  try { handle = await open(stateFile, O_RDONLY | O_NOFOLLOW); }
  catch (error) {
    if (errno(error) === "ENOENT") return undefined;
    if (errno(error) === "ELOOP") throw unsafe("state file is a symlink");
    throw new TrustStateError("TRUST_STATE_UNAVAILABLE", `watermark unreadable (${errno(error)})`);
  }
  try {
    const stats = await handle.stat();
    const uid = process.getuid?.();
    if (!stats.isFile()) throw unsafe("state file is not a regular file");
    if ((stats.mode & 0o022) !== 0) throw unsafe("state file is group/world-writable");
    if (uid !== undefined && stats.uid !== uid) throw unsafe("state file is owned by another user");
    return await handle.readFile();
  } catch (error) {
    if (error instanceof TrustStateError) throw error;
    throw new TrustStateError("TRUST_STATE_UNAVAILABLE", `watermark unreadable (${errno(error)})`);
  } finally { await handle.close(); }
}

/** Atomic replace: same-directory temp file, fsync, rename, fsync directory. */
async function writeWatermark(stateFile: string, state: TrustWatermark | FloorHighWater): Promise<void> {
  const temp = join(dirname(stateFile), `.${basename(stateFile)}.${process.pid}.${Date.now()}.tmp`);
  try {
    const handle = await open(temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600);
    try { await handle.writeFile(`${JSON.stringify(state)}\n`); await handle.sync(); } finally { await handle.close(); }
    await rename(temp, stateFile);
    const directory = await open(dirname(stateFile), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    try { await directory.sync(); } finally { await directory.close(); }
  } catch (error) {
    await rm(temp, { force: true }).catch(() => undefined);
    throw new TrustStateError("TRUST_STATE_UNAVAILABLE", `watermark not persisted (${errno(error)})`);
  }
}

function describeLockHolder(content: string): string {
  const [pidText, host] = content.trim().split(" ");
  const pid = Number(pidText);
  if (!Number.isSafeInteger(pid) || pid <= 0) return "unknown holder";
  if (host !== hostname()) return `pid ${pid} on host ${host ?? "?"}`;
  try { process.kill(pid, 0); return `pid ${pid} (running)`; }
  catch (error) { return errno(error) === "EPERM" ? `pid ${pid} (running as another user)` : `pid ${pid} (NOT running: likely stale after a crash)`; }
}

/**
 * Exclusive O_EXCL lock around read→compare→write, so concurrent verifiers cannot
 * interleave and lower the watermark. A lock left by a crash is never removed
 * automatically (pid reuse and cross-host locks make that unsafe): it fails closed
 * with a diagnostic, and the documented procedure is to confirm that no verifier or
 * provisioning run uses this state file, then delete `<state>.lock`.
 */
async function withStateLock<T>(stateFile: string, action: () => Promise<T>, timeoutMs = LOCK_TIMEOUT_MS): Promise<T> {
  const lockFile = `${stateFile}.lock`;
  const deadline = Date.now() + timeoutMs;
  let handle;
  for (;;) {
    try { handle = await open(lockFile, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600); break; }
    catch (error) {
      if (errno(error) !== "EEXIST") throw new TrustStateError("TRUST_STATE_UNAVAILABLE", `state lock unavailable (${errno(error)})`);
      if (Date.now() > deadline) {
        const holder = await readFile(lockFile, "utf8").then(describeLockHolder, () => "unknown holder");
        throw new TrustStateError("TRUST_STATE_LOCKED", `${lockFile} is held by ${holder}; delete it only after confirming no verifier or provisioning run uses this state`);
      }
      await new Promise(resolve => setTimeout(resolve, 10 + Math.random() * 20));
    }
  }
  try {
    await handle.writeFile(`${process.pid} ${hostname()}\n`);
    return await action();
  } finally {
    await handle.close().catch(() => undefined);
    await rm(lockFile, { force: true }).catch(() => undefined);
  }
}

/**
 * Enforces the durable high-watermark of accepted policy revisions and persists a
 * newer accepted revision (or the signed upgrade of the same document) before use.
 * `bootstrapDigest` creates a missing watermark only for exactly that document.
 */
export interface AcceptedTrust { revision: number; digest: string; authenticated: boolean; rootEpoch: number; rootSetDigest: string | null }

export async function enforceTrustWatermark(
  stateFile: string,
  accepted: AcceptedTrust,
  options: { bootstrapDigest?: string; minimumRevision?: number; lockTimeoutMs?: number; floor?: TrustFloor } = {},
): Promise<void> {
  await withStateLock(stateFile, async () => {
    const bytes = await readStateBytes(stateFile);
    const current = bytes === undefined ? undefined : parseWatermark(bytes);
    const floorBytes = await readStateBytes(floorStateFile(stateFile));
    const floorMark = floorBytes === undefined ? undefined : parseFloorHighWater(floorBytes);
    // A watermark written after a floor-checked acceptance implies a floor high-water mark.
    if (floorMark === undefined && current !== undefined && current.rootEpoch > 0) {
      throw new TrustStateError("TRUST_FLOOR_STATE_MISSING", "the floor high-water mark is missing although a floor-checked acceptance exists; restore it from backup");
    }
    let unchanged = false;
    if (current === undefined) {
      if (options.bootstrapDigest === undefined) throw new TrustStateError("TRUST_STATE_MISSING", "no accepted-policy watermark; bootstrap with the expected policy digest");
      if (options.bootstrapDigest !== accepted.digest) throw new TrustStateError("TRUST_STATE_BOOTSTRAP_MISMATCH", "bootstrap digest does not match the policy document");
      if (accepted.revision > (options.minimumRevision ?? 1) + MAX_REVISION_STEP) {
        throw new TrustStateError("TRUST_POLICY_REVISION_JUMP", `bootstrap revision may exceed the revision floor by at most ${MAX_REVISION_STEP}`);
      }
    } else {
      if (current.authenticated && !accepted.authenticated) throw new TrustStateError("TRUST_POLICY_DOWNGRADE", "an authenticated policy was accepted; unsigned policy refused");
      if (accepted.rootEpoch < current.rootEpoch) throw new TrustStateError("TRUST_ROOT_ROLLBACK", `root set epoch ${accepted.rootEpoch} is below accepted ${current.rootEpoch}`);
      if (accepted.rootEpoch === current.rootEpoch && accepted.rootSetDigest !== current.rootSetDigest) {
        throw new TrustStateError("TRUST_ROOT_CONFLICT", `a different root set was accepted for epoch ${accepted.rootEpoch}`);
      }
      if (accepted.revision < current.revision) throw new TrustStateError("TRUST_POLICY_ROLLBACK", `revision ${accepted.revision} is below accepted ${current.revision}`);
      if (accepted.revision === current.revision && accepted.digest !== current.policyDigest) {
        throw new TrustStateError("TRUST_POLICY_CONFLICT", `revision ${accepted.revision} has a different digest than the accepted policy`);
      }
      if (accepted.revision - current.revision > MAX_REVISION_STEP) throw new TrustStateError("TRUST_POLICY_REVISION_JUMP", `revision may advance by at most ${MAX_REVISION_STEP}`);
      unchanged = accepted.revision === current.revision && accepted.authenticated === current.authenticated && accepted.rootEpoch === current.rootEpoch;
    }
    // Floor high-water mark: checked after the watermark, and independently of it
    // (it survives a watermark reset).
    let nextFloor: FloorHighWater | undefined;
    if (options.floor) nextFloor = advanceFloor(floorMark, options.floor);
    else if (floorMark !== undefined) throw new TrustStateError("TRUST_POLICY_DOWNGRADE", "a floor-checked policy was accepted; acceptance without a floor refused");
    if (floorMark !== undefined && (accepted.revision < floorMark.minimumPolicyRevision || accepted.rootEpoch < floorMark.minimumRootEpoch)) {
      throw new TrustStateError("TRUST_POLICY_ROLLBACK", "policy revision or root epoch is below the recorded external floor");
    }
    // Floor first: a crash in between leaves a higher floor, never a lower one.
    if (nextFloor) await writeWatermark(floorStateFile(stateFile), nextFloor);
    if (unchanged) return;
    await writeWatermark(stateFile, {
      format: TRUST_STATE_FORMAT, revision: accepted.revision, policyDigest: accepted.digest,
      authenticated: accepted.authenticated, rootEpoch: accepted.rootEpoch, rootSetDigest: accepted.rootSetDigest,
    });
  }, options.lockTimeoutMs);
}

export interface LoadTrustPolicyOptions {
  policyFile: string;
  stateFile: string;
  minimumRevision: number;
  mode: TrustMode;
  /** policyDigest of the exact policy document; creates a missing watermark for that document only. */
  bootstrapDigest?: string;
  lockTimeoutMs?: number;
  now?: number;
}

export interface TrustDocument {
  policy: TrustPolicy;
  digest: string;
  /** Present in signed mode: the resolved current root set and the verified external floor. */
  roots?: { epoch: number; digest: string };
  floor?: TrustFloor;
}

async function readRotations(file: string | undefined): Promise<unknown[]> {
  if (file === undefined) return [];
  let parsed: unknown;
  try { parsed = JSON.parse(await readFile(file, "utf8")); }
  catch (error) { throw new TrustStateError("TRUST_ROOT_UNAVAILABLE", `rotation chain unreadable (${errno(error)})`); }
  if (!Array.isArray(parsed)) throw new TrustStateError("TRUST_ROOT_ROTATION_INVALID", "rotation chain must be a JSON array");
  return parsed;
}

/**
 * Reads, authenticates and validates the policy document without touching local
 * state. Signed mode: resolves the root rotation chain from the pinned anchor,
 * requires a fresh floor signed by the current root set, authenticates the policy
 * with that set and enforces the floor on both the policy revision and root epoch.
 */
export async function readTrustPolicyDocument(options: Pick<LoadTrustPolicyOptions, "policyFile" | "minimumRevision" | "mode" | "now">): Promise<TrustDocument> {
  const mode = options.mode;
  let roots: { set: RootSet; digest: string } | undefined;
  let floor: TrustFloor | undefined;
  if (mode.kind === "signed") {
    const deploymentId = deploymentIdOf(mode.deployment);
    roots = resolveRootSet(mode.anchor, await readRotations(mode.rotationsFile), deploymentId);
    floor = await acquireTrustFloor(mode.floor, roots.set, deploymentId, { now: options.now, maxAgeMs: mode.floorMaxAgeMs ?? DEFAULT_FLOOR_MAX_AGE_MS });
    if (roots.set.epoch < floor.minimumRootEpoch) throw new TrustStateError("TRUST_ROOT_ROLLBACK", `root set epoch ${roots.set.epoch} is below the external floor ${floor.minimumRootEpoch}`);
  }
  let fileBytes: Buffer;
  try { fileBytes = await readFile(options.policyFile); }
  catch (error) { throw new TrustStateError("TRUST_POLICY_UNAVAILABLE", `policy unreadable (${errno(error)})`); }
  const document = authenticatePolicyDocument(fileBytes, roots?.set);
  let policy: TrustPolicy;
  try { policy = parseTrustPolicy(JSON.parse(document.toString("utf8")), options.minimumRevision); }
  catch (error) { throw new TrustStateError("TRUST_POLICY_INVALID", (error as Error).message); }
  const pin = mode.deployment;
  if (pin && (policy.genesisHash !== pin.genesisHash || policy.registryId !== pin.registryId || policy.programIdHex !== pin.programIdHex)) {
    throw new TrustStateError("TRUST_POLICY_DEPLOYMENT_MISMATCH", "policy is for another cluster, registry or program");
  }
  if (floor && policy.revision < floor.minimumPolicyRevision) {
    throw new TrustStateError("TRUST_POLICY_ROLLBACK", `revision ${policy.revision} is below the external floor ${floor.minimumPolicyRevision}`);
  }
  if ((options.now ?? Date.now()) >= Date.parse(policy.validUntil)) throw new TrustStateError("TRUST_POLICY_EXPIRED", "policy validUntil has passed");
  return { policy, digest: policyDigest(document), roots: roots && { epoch: roots.set.epoch, digest: roots.digest }, floor };
}

/** The only supported way to obtain a runtime TrustPolicy from disk. */
export async function loadTrustPolicy(options: LoadTrustPolicyOptions): Promise<TrustDocument> {
  const document = await readTrustPolicyDocument(options);
  await assertPrivateStateLocation(options.stateFile, options.policyFile);
  await enforceTrustWatermark(options.stateFile, {
    revision: document.policy.revision, digest: document.digest, authenticated: options.mode.kind === "signed",
    rootEpoch: document.roots?.epoch ?? 0, rootSetDigest: document.roots?.digest ?? null,
  }, {
    bootstrapDigest: options.bootstrapDigest,
    // The first-bootstrap revision bound is relative to the highest authenticated floor available.
    minimumRevision: Math.max(options.minimumRevision, document.floor?.minimumPolicyRevision ?? 0),
    lockTimeoutMs: options.lockTimeoutMs,
    floor: document.floor,
  });
  return document;
}

/** Strict environment contract of the verifier process; any ambiguity is a configuration error. */
export function trustOptionsFromEnv(env: NodeJS.ProcessEnv): LoadTrustPolicyOptions {
  const required = (name: string) => {
    const value = env[name];
    if (value === undefined || value.length === 0) throw new TrustStateError("TRUST_CONFIG_INVALID", `${name} is required`);
    return value;
  };
  const minimum = required("ONELAYER_TRUST_POLICY_MIN_REVISION");
  if (!/^[1-9][0-9]*$/.test(minimum) || !Number.isSafeInteger(Number(minimum))) throw new TrustStateError("TRUST_CONFIG_INVALID", "ONELAYER_TRUST_POLICY_MIN_REVISION must be a positive integer");
  const signed = env.ONELAYER_TRUST_ROOT_KEYS !== undefined;
  const unsigned = env.ONELAYER_TRUST_POLICY_UNSIGNED !== undefined;
  if (signed === unsigned || (unsigned && env.ONELAYER_TRUST_POLICY_UNSIGNED !== "1")) {
    throw new TrustStateError("TRUST_CONFIG_INVALID", "set exactly one of ONELAYER_TRUST_ROOT_KEYS (signed) or ONELAYER_TRUST_POLICY_UNSIGNED=1 (explicit unsigned opt-in)");
  }
  const deployment = env.ONELAYER_TRUST_DEPLOYMENT === undefined ? undefined : parseDeploymentPin(env.ONELAYER_TRUST_DEPLOYMENT);
  let mode: TrustMode;
  if (signed) {
    if (!deployment) throw new TrustStateError("TRUST_CONFIG_INVALID", "ONELAYER_TRUST_DEPLOYMENT is required with signed policies");
    const threshold = required("ONELAYER_TRUST_ROOT_THRESHOLD");
    if (!/^[1-9][0-9]*$/.test(threshold)) throw new TrustStateError("TRUST_CONFIG_INVALID", "ONELAYER_TRUST_ROOT_THRESHOLD must be a positive integer");
    // Required: the operator states which epoch the pinned keys are, so a re-pin is never implicit.
    const epoch = required("ONELAYER_TRUST_ROOT_EPOCH");
    if (!/^[1-9][0-9]*$/.test(epoch) || !Number.isSafeInteger(Number(epoch))) throw new TrustStateError("TRUST_CONFIG_INVALID", "ONELAYER_TRUST_ROOT_EPOCH must be a positive integer");
    const anchor = validateRootSet({ epoch: Number(epoch), threshold: Number(threshold), keys: parseTrustRootKeys(env.ONELAYER_TRUST_ROOT_KEYS!) });
    const maxAge = env.ONELAYER_TRUST_FLOOR_MAX_AGE_SECONDS;
    if (maxAge !== undefined && (!/^[1-9][0-9]*$/.test(maxAge) || Number(maxAge) * 1_000 > MAX_FLOOR_MAX_AGE_MS)) {
      throw new TrustStateError("TRUST_CONFIG_INVALID", "ONELAYER_TRUST_FLOOR_MAX_AGE_SECONDS must be a positive integer of at most 30 days");
    }
    const rotationsFile = env.ONELAYER_TRUST_ROOT_ROTATIONS_FILE;
    if (rotationsFile !== undefined && rotationsFile.length === 0) throw new TrustStateError("TRUST_CONFIG_INVALID", "ONELAYER_TRUST_ROOT_ROTATIONS_FILE is empty");
    mode = {
      kind: "signed", anchor, rotationsFile, deployment,
      floor: new FileTrustFloorSource(required("ONELAYER_TRUST_FLOOR_FILE")),
      floorMaxAgeMs: maxAge === undefined ? DEFAULT_FLOOR_MAX_AGE_MS : Number(maxAge) * 1_000,
    };
  } else {
    for (const name of ["ONELAYER_TRUST_ROOT_THRESHOLD", "ONELAYER_TRUST_ROOT_EPOCH", "ONELAYER_TRUST_ROOT_ROTATIONS_FILE", "ONELAYER_TRUST_FLOOR_FILE", "ONELAYER_TRUST_FLOOR_MAX_AGE_SECONDS"]) {
      if (env[name] !== undefined) throw new TrustStateError("TRUST_CONFIG_INVALID", `${name} applies only to signed policies`);
    }
    mode = { kind: "unsigned", deployment };
  }
  const bootstrap = env.ONELAYER_TRUST_STATE_BOOTSTRAP;
  if (bootstrap !== undefined && !HEX32.test(bootstrap)) throw new TrustStateError("TRUST_CONFIG_INVALID", "ONELAYER_TRUST_STATE_BOOTSTRAP must be the policy digest (sha256 hex of the policy JSON document)");
  return {
    policyFile: required("ONELAYER_TRUST_POLICY_FILE"),
    stateFile: required("ONELAYER_TRUST_STATE_FILE"),
    minimumRevision: Number(minimum),
    mode,
    bootstrapDigest: bootstrap,
  };
}

/** Accepted revision for provisioning tools; undefined when no watermark exists. Corrupt state throws. */
export async function readAcceptedRevision(stateFile: string): Promise<number | undefined> {
  const bytes = await readStateBytes(stateFile);
  return bytes === undefined ? undefined : parseWatermark(bytes).revision;
}

/** Re-validation cadence of signed trust material in a running verifier. */
export const TRUST_REFRESH_INTERVAL_MS = 60_000;

/**
 * Periodically re-runs the full signed acceptance (rotation chain, fresh floor,
 * policy, watermark and floor high-water mark) and swaps the runtime policy.
 * Any failure — including a floor that expired and was not renewed — removes the
 * policy, so verification answers TRUST_POLICY_UNAVAILABLE until trust material
 * is valid again. Bootstrap is never re-applied.
 */
export function startTrustRefresh(
  options: LoadTrustPolicyOptions,
  target: { trustPolicy?: TrustPolicy },
  { intervalMs = TRUST_REFRESH_INTERVAL_MS, onFailure = () => undefined }: { intervalMs?: number; onFailure?: (error: Error) => void } = {},
): { tick(): Promise<void>; stop(): void } {
  const reload = { ...options, bootstrapDigest: undefined };
  let running: Promise<void> | undefined;
  const tick = () => running ??= (async () => {
    try { target.trustPolicy = (await loadTrustPolicy(reload)).policy; }
    catch (error) { target.trustPolicy = undefined; onFailure(error as Error); }
    finally { running = undefined; }
  })();
  const timer = setInterval(() => { void tick(); }, intervalMs);
  timer.unref();
  return { tick, stop: () => clearInterval(timer) };
}
