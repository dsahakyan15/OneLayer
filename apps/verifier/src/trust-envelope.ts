// Threshold-signed trust envelopes and the trust-root set rotation chain.
// The anchor root set (normally epoch 1) and its threshold are pinned by deployment
// configuration outside the package; every later set must be signed by a
// threshold of the set before it. Everything fails closed.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";

export class TrustStateError extends Error {
  readonly code: string;
  constructor(code: string, message: string) { super(`${code}: ${message}`); this.code = code; }
}

/** Trust-root public keys are pinned by deployment configuration, never read from a package or the policy itself. */
export interface TrustRootKey { keyId: string; publicKeyHex: string }
/** k-of-n trust-root set. The pinned anchor has epoch ≥ 1 (normally 1); rotations increase it by exactly one. */
export interface RootSet { epoch: number; threshold: number; keys: TrustRootKey[] }
/** Locally pinned deployment identity. */
export interface DeploymentPin { genesisHash: string; registryId: string; programIdHex: string }

export const ENVELOPES = {
  policy: { format: "onelayer.signed-trust-policy.v1", domain: "onelayer.trust-policy.v1\0" },
  rootSet: { format: "onelayer.signed-trust-root-set.v1", domain: "onelayer.trust-root-set.v1\0" },
  floor: { format: "onelayer.signed-trust-floor.v1", domain: "onelayer.trust-floor.v1\0" },
} as const;
export type EnvelopeKind = keyof typeof ENVELOPES;
export const ROOT_SET_FORMAT = "onelayer.trust-root-set.v1";

const HEX32 = /^[0-9a-f]{64}$/;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;

export function exactKeys(value: unknown, keys: string[]): Record<string, unknown> | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join(",") !== [...keys].sort().join(",")) return undefined;
  return value as Record<string, unknown>;
}

export function deploymentIdOf(pin: DeploymentPin): string {
  return `${pin.genesisHash}/${pin.registryId}/${pin.programIdHex}`;
}

export function validateRootSet(value: RootSet, code = "TRUST_ROOT_INVALID"): RootSet {
  const fail = (why: string) => new TrustStateError(code, why);
  if (!Number.isSafeInteger(value.epoch) || value.epoch < 1) throw fail("invalid root epoch");
  if (!Array.isArray(value.keys) || value.keys.length === 0 || value.keys.length > 32) throw fail("root set needs 1..32 keys");
  for (const key of value.keys) {
    if (!exactKeys(key, ["keyId", "publicKeyHex"]) || !KEY_ID.test(key.keyId) || !HEX32.test(key.publicKeyHex)) throw fail("invalid root key");
  }
  if (new Set(value.keys.map(key => key.keyId)).size !== value.keys.length
    || new Set(value.keys.map(key => key.publicKeyHex)).size !== value.keys.length) throw fail("duplicate root keyId or public key");
  if (!Number.isSafeInteger(value.threshold) || value.threshold < 1 || value.threshold > value.keys.length) throw fail("threshold must be 1..n");
  // Fixed field order: the digest must not depend on the field order of the source (env or rotation payload).
  return { epoch: value.epoch, threshold: value.threshold, keys: value.keys.map(key => ({ keyId: key.keyId, publicKeyHex: key.publicKeyHex })) };
}

/** Canonical digest of a root set (keys sorted by keyId). */
export function rootSetDigest(set: RootSet): string {
  // Code-unit order, not localeCompare: the digest must not depend on the ICU locale of the host.
  const keys = set.keys.map(key => ({ keyId: key.keyId, publicKeyHex: key.publicKeyHex }));
  const canonical = { epoch: set.epoch, threshold: set.threshold, keys: keys.sort((a, b) => (a.keyId < b.keyId ? -1 : a.keyId > b.keyId ? 1 : 0)) };
  return createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
}

function ed25519Verify(publicKeyHex: string, message: Buffer, signatureHex: string): boolean {
  try {
    const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(publicKeyHex, "hex")]), format: "der", type: "spki" });
    return verify(null, message, key, Buffer.from(signatureHex, "hex"));
  } catch { return false; }
}

/** Decodes an envelope (parsed JSON) of the given kind; returns its exact payload bytes and raw signature entries. */
export function openEnvelope(value: unknown, kind: EnvelopeKind, unsignedCode: string): { payload: Buffer; signatures: unknown[] } {
  const envelope = exactKeys(value, ["format", "payloadBase64", "signatures"]);
  if (!envelope || envelope.format !== ENVELOPES[kind].format || typeof envelope.payloadBase64 !== "string"
    || !/^[A-Za-z0-9+/]+={0,2}$/.test(envelope.payloadBase64) || !Array.isArray(envelope.signatures)) {
    throw new TrustStateError(unsignedCode, `not a ${ENVELOPES[kind].format} envelope`);
  }
  const payload = Buffer.from(envelope.payloadBase64, "base64");
  if (payload.toString("base64") !== envelope.payloadBase64) throw new TrustStateError(unsignedCode, "non-canonical payload encoding");
  return { payload, signatures: envelope.signatures };
}

/** Upper bound on signature entries per envelope (bounds verification work on hostile input). */
export const MAX_SIGNATURE_ENTRIES = 64;

/**
 * Accepts the envelope only with valid signatures from at least `threshold`
 * distinct keys of `roots`. Malformed entries and entries of unknown keys are
 * skipped: they neither count nor veto. Each pinned keyId is verified at most
 * once (its first well-formed entry), so duplicates cannot multiply the work.
 */
export function verifyThreshold(value: unknown, kind: EnvelopeKind, roots: RootSet, codes: { unsigned: string; signature: string }): Buffer {
  const { payload, signatures } = openEnvelope(value, kind, codes.unsigned);
  if (signatures.length > MAX_SIGNATURE_ENTRIES) throw new TrustStateError(codes.unsigned, `more than ${MAX_SIGNATURE_ENTRIES} signature entries`);
  const message = Buffer.concat([Buffer.from(ENVELOPES[kind].domain, "utf8"), payload]);
  const valid = new Set<string>();
  const attempted = new Set<string>();
  for (const entry of signatures) {
    const signature = exactKeys(entry, ["rootKeyId", "signatureHex"]);
    if (!signature || typeof signature.signatureHex !== "string" || !/^[0-9a-f]{128}$/.test(signature.signatureHex)) continue;
    const root = roots.keys.find(key => key.keyId === signature.rootKeyId);
    if (!root || attempted.has(root.keyId)) continue;
    attempted.add(root.keyId);
    if (ed25519Verify(root.publicKeyHex, message, signature.signatureHex)) valid.add(root.keyId);
  }
  if (valid.size < roots.threshold) {
    throw new TrustStateError(codes.signature, `${valid.size} of required ${roots.threshold} valid trust-root signatures (root epoch ${roots.epoch})`);
  }
  return payload;
}

/**
 * Walks the rotation chain from the pinned anchor. Each rotation must be signed
 * by a threshold of the previous set, name this deployment and increase the epoch
 * by exactly one. A broken link fails closed; it never truncates the chain.
 * The anchor is normally epoch 1. After a compromise of a threshold of an older
 * set the deployment re-pins the anchor at the current epoch N (env
 * ONELAYER_TRUST_ROOT_EPOCH): the chain file then starts at N+1, so nothing
 * signed by the compromised older sets can be resolved any more.
 */
export function resolveRootSet(anchor: RootSet, rotations: unknown[], deploymentId: string): { set: RootSet; digest: string } {
  let current = validateRootSet(anchor);
  for (const [index, rotation] of rotations.entries()) {
    const fail = (why: string) => new TrustStateError("TRUST_ROOT_ROTATION_INVALID", `rotation ${index + 1}: ${why}`);
    let payload: Buffer;
    try { payload = verifyThreshold(rotation, "rootSet", current, { unsigned: "TRUST_ROOT_ROTATION_INVALID", signature: "TRUST_ROOT_ROTATION_INVALID" }); }
    catch (error) { throw fail((error as Error).message); }
    let parsed: unknown;
    try { parsed = JSON.parse(payload.toString("utf8")); } catch { throw fail("unparseable root set"); }
    const next = exactKeys(parsed, ["format", "deploymentId", "epoch", "threshold", "keys"]);
    if (!next || next.format !== ROOT_SET_FORMAT) throw fail("invalid root set document");
    if (next.deploymentId !== deploymentId) throw fail("root set is for another deployment");
    if (next.epoch !== current.epoch + 1) throw fail(`epoch must be ${current.epoch + 1}`);
    try { current = validateRootSet({ epoch: next.epoch as number, threshold: next.threshold as number, keys: next.keys as TrustRootKey[] }); }
    catch (error) { throw fail((error as Error).message); }
  }
  return { set: current, digest: rootSetDigest(current) };
}

// Lab signing helpers (synthetic keys only; production signing belongs in an HSM/ceremony).
function privateKeyFromSeed(seed: Uint8Array) {
  if (seed.length !== 32) throw new TypeError("Ed25519 seed must be 32 bytes");
  return createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
}

export function publicKeyHexFromSeed(seed: Uint8Array): string {
  return createPublicKey(privateKeyFromSeed(seed)).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
}

export function createEnvelope(kind: EnvelopeKind, payload: Buffer): { format: string; payloadBase64: string; signatures: Array<{ rootKeyId: string; signatureHex: string }> } {
  return { format: ENVELOPES[kind].format, payloadBase64: payload.toString("base64"), signatures: [] };
}

export function addEnvelopeSignature(value: unknown, kind: EnvelopeKind, keyId: string, seed: Uint8Array) {
  const { payload, signatures } = openEnvelope(value, kind, "TRUST_ENVELOPE_INVALID");
  if (!KEY_ID.test(keyId)) throw new TypeError("invalid keyId");
  if (signatures.some(entry => (entry as { rootKeyId?: unknown })?.rootKeyId === keyId)) throw new TypeError(`${keyId} already signed`);
  const signatureHex = sign(null, Buffer.concat([Buffer.from(ENVELOPES[kind].domain, "utf8"), payload]), privateKeyFromSeed(seed)).toString("hex");
  return { format: ENVELOPES[kind].format, payloadBase64: payload.toString("base64"), signatures: [...signatures, { rootKeyId: keyId, signatureHex }] };
}
