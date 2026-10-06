// External minimum-revision floor. The floor lives outside the recoverable
// database and outside the verifier state file; it is a statement signed by a
// threshold of the current trust-root set and is only accepted while fresh.
// Production sources (hardware monotonic counter, separate floor service,
// on-chain account) implement TrustFloorSource; the lab adapters below are not
// production custody.
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { addEnvelopeSignature, createEnvelope, exactKeys, TrustStateError, verifyThreshold, type RootSet } from "./trust-envelope.ts";
import { timestamp } from "./trust-policy.ts";

export const FLOOR_FORMAT = "onelayer.trust-floor.v1";
/** Tolerated clock skew for a statement issued "in the future". */
const CLOCK_SKEW_MS = 5 * 60_000;

export interface TrustFloor {
  deploymentId: string;
  /** Strictly monotonic per deployment; the verifier keeps a local high-water mark of it. */
  floorSequence: number;
  /** Epoch of the root set that signed this statement; must equal the current resolved epoch. */
  rootEpoch: number;
  minimumPolicyRevision: number;
  minimumRootEpoch: number;
  issuedAt: string;
  expiresAt: string;
  /** Echo of the verifier's challenge for challenge-bound sources; null for time-bounded ones. */
  nonce: string | null;
}

export interface TrustFloorSource {
  /** True when the source signs on demand and must echo the challenge nonce (replay-proof). */
  readonly challengeBound: boolean;
  /** Returns the signed floor envelope as JSON bytes. */
  fetch(nonce: string): Promise<Buffer>;
}

/** Lab adapter: a floor statement delivered as a file (time-bounded freshness only). */
export class FileTrustFloorSource implements TrustFloorSource {
  readonly challengeBound = false;
  private readonly path: string;
  constructor(path: string) { this.path = path; }
  async fetch(): Promise<Buffer> { return readFile(this.path); }
}

type LabFloorFields = { deploymentId: string; floorSequence: number; rootEpoch: number; minimumPolicyRevision: number; minimumRootEpoch: number };

/** Lab adapter: an in-process signer standing in for a floor service; echoes the nonce. Synthetic keys only. */
export class LabChallengeFloorSource implements TrustFloorSource {
  readonly challengeBound = true;
  private readonly signers: Array<{ keyId: string; seed: Uint8Array }>;
  private readonly floor: LabFloorFields;
  private readonly ttlMs: number;
  private readonly overrideNonce?: string;
  constructor(signers: Array<{ keyId: string; seed: Uint8Array }>, floor: LabFloorFields, ttlMs = 60_000, overrideNonce?: string) {
    this.signers = signers; this.floor = floor; this.ttlMs = ttlMs; this.overrideNonce = overrideNonce;
  }
  async fetch(nonce: string): Promise<Buffer> {
    const now = Date.now();
    const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
    const statement: TrustFloor & { format: string } = {
      format: FLOOR_FORMAT, ...this.floor, issuedAt: iso(now), expiresAt: iso(now + this.ttlMs), nonce: this.overrideNonce ?? nonce,
    };
    let envelope: unknown = createEnvelope("floor", Buffer.from(JSON.stringify(statement)));
    for (const signer of this.signers) envelope = addEnvelopeSignature(envelope, "floor", signer.keyId, signer.seed);
    return Buffer.from(JSON.stringify(envelope));
  }
}

export function parseFloorStatement(payload: Buffer): TrustFloor {
  let parsed: unknown;
  try { parsed = JSON.parse(payload.toString("utf8")); } catch { parsed = undefined; }
  const floor = exactKeys(parsed, ["format", "deploymentId", "floorSequence", "rootEpoch", "minimumPolicyRevision", "minimumRootEpoch", "issuedAt", "expiresAt", "nonce"]);
  const fail = () => new TrustStateError("TRUST_FLOOR_INVALID", "invalid floor statement");
  if (!floor || floor.format !== FLOOR_FORMAT || typeof floor.deploymentId !== "string"
    || !Number.isSafeInteger(floor.minimumPolicyRevision) || (floor.minimumPolicyRevision as number) < 1
    || !Number.isSafeInteger(floor.minimumRootEpoch) || (floor.minimumRootEpoch as number) < 1
    || !Number.isSafeInteger(floor.floorSequence) || (floor.floorSequence as number) < 1
    || !Number.isSafeInteger(floor.rootEpoch) || (floor.rootEpoch as number) < 1
    || !(floor.nonce === null || (typeof floor.nonce === "string" && /^[0-9a-f]{64}$/.test(floor.nonce)))) throw fail();
  try { if (timestamp(floor.issuedAt) >= timestamp(floor.expiresAt)) throw fail(); } catch { throw fail(); }
  const { format: _format, ...statement } = floor;
  return statement as unknown as TrustFloor;
}

/**
 * Fetches and verifies a fresh floor: threshold-signed by `roots`, for this
 * deployment, within its validity window, no longer-lived than `maxAgeMs`, and
 * for challenge-bound sources echoing a fresh random nonce. Any failure is fatal.
 */
export async function acquireTrustFloor(source: TrustFloorSource, roots: RootSet, deploymentId: string, options: { now?: number; maxAgeMs: number }): Promise<TrustFloor> {
  const nonce = randomBytes(32).toString("hex");
  let bytes: Buffer;
  try { bytes = await source.fetch(nonce); }
  catch (error) { throw new TrustStateError("TRUST_FLOOR_UNAVAILABLE", `floor source failed (${(error as NodeJS.ErrnoException).code ?? (error as Error).message})`); }
  let envelope: unknown;
  try { envelope = JSON.parse(bytes.toString("utf8")); } catch { throw new TrustStateError("TRUST_FLOOR_INVALID", "unparseable floor envelope"); }
  const floor = parseFloorStatement(verifyThreshold(envelope, "floor", roots, { unsigned: "TRUST_FLOOR_INVALID", signature: "TRUST_FLOOR_SIGNATURE_INVALID" }));
  if (floor.deploymentId !== deploymentId) throw new TrustStateError("TRUST_FLOOR_DEPLOYMENT_MISMATCH", "floor statement is for another deployment");
  const now = options.now ?? Date.now();
  const issued = Date.parse(floor.issuedAt);
  const expires = Date.parse(floor.expiresAt);
  if (issued - CLOCK_SKEW_MS > now) throw new TrustStateError("TRUST_FLOOR_NOT_YET_VALID", "floor statement issued in the future");
  if (now >= expires) throw new TrustStateError("TRUST_FLOOR_STALE", "floor statement expired");
  if (expires - issued > options.maxAgeMs) throw new TrustStateError("TRUST_FLOOR_STALE", "floor statement validity exceeds the pinned maximum age");
  if (floor.rootEpoch !== roots.epoch) throw new TrustStateError("TRUST_FLOOR_EPOCH_MISMATCH", `floor signed for root epoch ${floor.rootEpoch}, current is ${roots.epoch}`);
  if (source.challengeBound ? floor.nonce !== nonce : floor.nonce !== null) {
    throw new TrustStateError("TRUST_FLOOR_REPLAYED", source.challengeBound ? "floor statement does not answer this challenge" : "a time-bounded floor statement must carry nonce null");
  }
  return floor;
}
