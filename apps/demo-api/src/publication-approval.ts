// Independently authenticated approval receipts for workflow publication (H5).
//
// The publisher's own plan-hash recomputation only proves "the request agrees
// with itself". This module makes the operator's approval a separately signed
// capability: a trusted issuer (loaded from a hardened key file at the API
// boundary, distinct from the operator/chain key) signs an immutable receipt
// bound to the operation, the exact reserved attempt plan hash, the actor and
// device, the cluster and genesis hash, a nonce and an expiry. The signer
// verifies it against a pinned public key it received out of band; the
// publisher verifies it with the same pinned key (verifier capability only,
// never the issuer private key).
//
// Lab limit (stated honestly): this is a software issuer in the same Node
// process as the API. It gives object-level and cryptographic separation — a
// forged or self-minted receipt fails verification and the publisher never
// holds the issuer key — but it is NOT process isolation. Production needs an
// HSM/KMS/provider issuer with the same receipt contract (tickets 16/22).
import { createHash, createPublicKey, randomUUID, sign as ed25519Sign, verify as ed25519Verify, type KeyObject } from "node:crypto";
import { getAddressEncoder, type Address } from "@solana/kit";
import { loadSigningKey, type KeyStoreOptions } from "../scripts/live-demo-key-store.ts";
import { canonicalWorkflow } from "./registry-workflow.ts";
import { assertGenesisHash, assertClusterLabel, expectedGenesisHash } from "./publication-identity.ts";
import type { PublicationConfig } from "./publication-config.ts";

export const PUBLICATION_APPROVAL_DOMAIN = "ONELAYER:WORKFLOW:PUBLICATION-APPROVAL:V1";
export const PUBLICATION_APPROVAL_VERSION = 1;
/** Receipts are short-lived capabilities; a replayed one expires quickly. */
export const PUBLICATION_APPROVAL_MAX_TTL_MS = 10 * 60_000;
const PUBLICATION_APPROVAL_CLOCK_SKEW_MS = 30_000;
const HEX64 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const BASE64 = /^[A-Za-z0-9+/]{86}==$/;
/** Printable, no control/format characters; identities are server-derived. */
const ACTOR = /^[^\p{Cc}\p{Cf}]{1,128}$/u;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export class PublicationApprovalError extends Error {
  readonly code: string;
  constructor(code: string) { super(code); this.code = code; }
}

export interface PublicationApprovalClaims {
  version: 1;
  domain: typeof PUBLICATION_APPROVAL_DOMAIN;
  /** Unique nonce; a receipt is a one-shot capability within its TTL. */
  receiptId: string;
  operationId: string;
  intentHash: string;
  /** The exact reserved attempt commitment the operator approved. */
  attemptPlanHash: string;
  cluster: string;
  genesisHash: string;
  /** Authenticated principal (HTTP session username). */
  actor: string;
  /** Authenticated device (session device id, else session id). */
  device: string;
  issuedAt: string;
  expiresAt: string;
}

export interface PublicationApprovalReceipt {
  claims: PublicationApprovalClaims;
  /** Ed25519 signature (base64) over the domain-separated canonical claims. */
  signature: string;
}

export interface PublicationApprovalBinding {
  operationId: string;
  intentHash: string;
  attemptPlanHash: string;
}

/** Capability held by the runtime: mints receipts, exposes only the public key. */
export interface PublicationApprovalService {
  readonly publicKey: string;
  issue(binding: PublicationApprovalBinding, actor: string, device: string): PublicationApprovalReceipt;
}

export interface PublicationApprovalIssuerPolicy {
  cluster: string;
  /** Pinned chain identity; defaults to the known genesis hash of `cluster`. */
  genesisHash?: string;
  maxTtlMs?: number;
  /** Clock seam for tests; defaults to the wall clock. */
  now?: () => Date;
}

export interface PublicationApprovalVerifierPolicy {
  /** Pinned Ed25519 public key (base58) of the trusted approval issuer. */
  approvalPublicKey: string;
  cluster: string;
  genesisHash: string;
  maxTtlMs?: number;
  now?: () => Date;
}

/** Exact expected binding + verifier policy for one verification. */
export type PublicationApprovalExpectation = PublicationApprovalBinding & PublicationApprovalVerifierPolicy;

function claimsBytes(claims: PublicationApprovalClaims): Buffer {
  const canonical = Buffer.from(canonicalWorkflow({ version: PUBLICATION_APPROVAL_VERSION, domain: PUBLICATION_APPROVAL_DOMAIN, claims }), "utf8");
  return Buffer.concat([Buffer.from(PUBLICATION_APPROVAL_DOMAIN + "\n", "utf8"), canonical]);
}

/** Stable audit identity of a receipt (claims + signature), for the journal. */
export function publicationApprovalReceiptHash(receipt: PublicationApprovalReceipt): string {
  return createHash("sha256").update(claimsBytes(receipt.claims)).update(Buffer.from(receipt.signature, "base64")).digest("hex");
}

function publicKeyOf(address: string): KeyObject {
  let raw: Uint8Array;
  try { raw = Uint8Array.from(getAddressEncoder().encode(address as Address)); }
  catch { throw new PublicationApprovalError("PUBLICATION_APPROVAL_INVALID"); }
  if (raw.length !== 32) throw new PublicationApprovalError("PUBLICATION_APPROVAL_INVALID");
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]), format: "der", type: "spki" });
}

function text(value: unknown, pattern: RegExp, code: string): string {
  if (typeof value !== "string" || !pattern.test(value)) throw new PublicationApprovalError(code);
  return value;
}

function instant(value: unknown): number {
  if (typeof value !== "string") throw new PublicationApprovalError("PUBLICATION_APPROVAL_INVALID");
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) throw new PublicationApprovalError("PUBLICATION_APPROVAL_INVALID");
  return ms;
}

/**
 * Loads the approval issuer from a hardened key file and pins the expected
 * chain identity. The returned service exposes the public key plus `issue`;
 * the private key stays inside the issuer closure.
 */
export class PublicationApprovalIssuer implements PublicationApprovalService {
  readonly publicKey: string;
  readonly cluster: string;
  readonly genesisHash: string;
  readonly #key: KeyObject;
  readonly #maxTtlMs: number;
  readonly #now: () => Date;

  private constructor(address: string, key: KeyObject, policy: PublicationApprovalIssuerPolicy) {
    this.publicKey = address;
    this.cluster = assertClusterLabel(policy.cluster);
    this.genesisHash = expectedGenesisHash(this.cluster, policy.genesisHash);
    this.#key = key;
    this.#maxTtlMs = policy.maxTtlMs ?? PUBLICATION_APPROVAL_MAX_TTL_MS;
    this.#now = policy.now ?? (() => new Date());
  }

  static async create(keyFile: string, policy: PublicationApprovalIssuerPolicy, options: KeyStoreOptions = {}): Promise<PublicationApprovalIssuer> {
    let loaded;
    try { loaded = await loadSigningKey(keyFile, options); }
    catch { throw new PublicationApprovalError("PUBLICATION_APPROVAL_KEY_UNAVAILABLE"); }
    return new PublicationApprovalIssuer(String(loaded.address), loaded.privateKey, policy);
  }

  issue(binding: PublicationApprovalBinding, actor: string, device: string): PublicationApprovalReceipt {
    const operationId = text(binding?.operationId, UUID, "PUBLICATION_APPROVAL_INVALID");
    const intentHash = text(binding?.intentHash, HEX64, "PUBLICATION_APPROVAL_INVALID");
    const attemptPlanHash = text(binding?.attemptPlanHash, HEX64, "PUBLICATION_APPROVAL_INVALID");
    const principal = text(actor, ACTOR, "PUBLICATION_APPROVAL_ACTOR_REQUIRED");
    const deviceId = text(device, ACTOR, "PUBLICATION_APPROVAL_ACTOR_REQUIRED");
    const issued = this.#now();
    const claims: PublicationApprovalClaims = {
      version: PUBLICATION_APPROVAL_VERSION,
      domain: PUBLICATION_APPROVAL_DOMAIN,
      receiptId: randomUUID(),
      operationId, intentHash, attemptPlanHash,
      cluster: this.cluster, genesisHash: this.genesisHash,
      actor: principal, device: deviceId,
      issuedAt: issued.toISOString(),
      expiresAt: new Date(issued.getTime() + this.#maxTtlMs).toISOString(),
    };
    const signature = Buffer.from(ed25519Sign(null, claimsBytes(claims), this.#key)).toString("base64");
    return { claims, signature };
  }
}

/**
 * Verifies a receipt against the pinned approval key and the exact expected
 * binding/identity. Throws {@link PublicationApprovalError} with a coded reason;
 * never falls back to an unverified approval.
 */
export function verifyPublicationApproval(
  receipt: unknown,
  expected: PublicationApprovalBinding & PublicationApprovalVerifierPolicy,
): PublicationApprovalClaims {
  if (typeof receipt !== "object" || receipt === null) throw new PublicationApprovalError("PUBLICATION_APPROVAL_INVALID");
  const candidate = receipt as { claims?: unknown; signature?: unknown };
  if (typeof candidate.claims !== "object" || candidate.claims === null) throw new PublicationApprovalError("PUBLICATION_APPROVAL_INVALID");
  const raw = candidate.claims as Record<string, unknown>;
  if (raw.version !== PUBLICATION_APPROVAL_VERSION || raw.domain !== PUBLICATION_APPROVAL_DOMAIN) throw new PublicationApprovalError("PUBLICATION_APPROVAL_INVALID");
  const signature = text(candidate.signature, BASE64, "PUBLICATION_APPROVAL_INVALID");
  const claims: PublicationApprovalClaims = {
    version: PUBLICATION_APPROVAL_VERSION,
    domain: PUBLICATION_APPROVAL_DOMAIN,
    receiptId: text(raw.receiptId, UUID, "PUBLICATION_APPROVAL_INVALID"),
    operationId: text(raw.operationId, UUID, "PUBLICATION_APPROVAL_INVALID"),
    intentHash: text(raw.intentHash, HEX64, "PUBLICATION_APPROVAL_INVALID"),
    attemptPlanHash: text(raw.attemptPlanHash, HEX64, "PUBLICATION_APPROVAL_INVALID"),
    cluster: text(raw.cluster, /^.{1,64}$/u, "PUBLICATION_APPROVAL_INVALID"),
    genesisHash: (() => {
      try { return assertGenesisHash(raw.genesisHash); }
      catch { throw new PublicationApprovalError("PUBLICATION_APPROVAL_INVALID"); }
    })(),
    actor: text(raw.actor, ACTOR, "PUBLICATION_APPROVAL_ACTOR_REQUIRED"),
    device: text(raw.device, ACTOR, "PUBLICATION_APPROVAL_ACTOR_REQUIRED"),
    issuedAt: text(raw.issuedAt, /^.{1,64}$/u, "PUBLICATION_APPROVAL_INVALID"),
    expiresAt: text(raw.expiresAt, /^.{1,64}$/u, "PUBLICATION_APPROVAL_INVALID"),
  };
  let valid = false;
  try { valid = ed25519Verify(null, claimsBytes(claims), publicKeyOf(expected.approvalPublicKey), Buffer.from(signature, "base64")); }
  catch { valid = false; }
  if (!valid) throw new PublicationApprovalError("PUBLICATION_APPROVAL_SIGNATURE");
  if (claims.operationId !== expected.operationId || claims.intentHash !== expected.intentHash || claims.attemptPlanHash !== expected.attemptPlanHash) {
    throw new PublicationApprovalError("PUBLICATION_APPROVAL_MISMATCH");
  }
  if (claims.cluster !== expected.cluster || claims.genesisHash !== expected.genesisHash) {
    throw new PublicationApprovalError("PUBLICATION_APPROVAL_IDENTITY");
  }
  const issuedAt = instant(claims.issuedAt);
  const expiresAt = instant(claims.expiresAt);
  const now = (expected.now ?? (() => new Date()))().getTime();
  const maxTtlMs = expected.maxTtlMs ?? PUBLICATION_APPROVAL_MAX_TTL_MS;
  if (expiresAt <= issuedAt || expiresAt - issuedAt > maxTtlMs) throw new PublicationApprovalError("PUBLICATION_APPROVAL_INVALID");
  if (issuedAt > now + PUBLICATION_APPROVAL_CLOCK_SKEW_MS) throw new PublicationApprovalError("PUBLICATION_APPROVAL_NOT_YET_VALID");
  if (now > expiresAt) throw new PublicationApprovalError("PUBLICATION_APPROVAL_EXPIRED");
  return claims;
}

/**
 * Deployment wiring: loads the approval issuer key from the hardened store and
 * pins the deployment identity. Refuses a key reused from the operator/chain
 * signer (the approval authority must be a distinct key).
 */
export interface PublicationApprovalConfig {
  service: PublicationApprovalService;
  issuer: PublicationApprovalIssuer;
  publicKey: string;
}

export async function loadPublicationApproval(
  config: PublicationConfig,
  options: KeyStoreOptions = {},
): Promise<PublicationApprovalConfig> {
  const issuer = await PublicationApprovalIssuer.create(config.approvalKeyFile, {
    cluster: config.cluster,
    genesisHash: config.genesisHash,
  }, options);
  const operator = await loadSigningKey(config.signerKeyFile, options).catch(() => {
    throw new PublicationApprovalError("PUBLICATION_APPROVAL_KEY_UNAVAILABLE");
  });
  if (String(operator.address) === issuer.publicKey) throw new PublicationApprovalError("PUBLICATION_APPROVAL_KEY_REUSED");
  return { service: issuer, issuer, publicKey: issuer.publicKey };
}
