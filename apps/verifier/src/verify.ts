import { authorizeCertificate, type TrustPolicy } from "./trust-policy.ts";
import { timingSafeEqual } from "node:crypto";
import {
  batchLeafHash,
  fieldCommitment,
  pathBytes,
  recordCommitment,
  registryIdHash,
  verifyCertificateSignature,
  type CertificateBody,
  type SignedCertificate,
} from "../../../packages/canonical-ts/src/index.ts";
import {
  leafHash,
  root,
  rootFromProof,
  type Hash,
  type ProofStep,
} from "../../../packages/merkle-ts/src/index.ts";

export type IncidentIndexStatus = "CHECKED" | "STALE" | "UNAVAILABLE" | "INDEX_INCONSISTENT";
export type VerificationStatus =
  | "VERIFIED"
  | "VERIFIED_HISTORICAL"
  | "SUPERSEDED"
  | "VERIFIED_NO_INCIDENT_CHECK"
  | "DISPUTED"
  | "INVALID";

export interface ObservedAnchor {
  registryConfigPda: Uint8Array;
  programId: Uint8Array;
  segmentPda: Uint8Array;
  derivedSegmentPda: Uint8Array;
  batchSequence: bigint;
  registryVersion: bigint;
  merkleRoot: Hash;
  manifestHash: Hash;
  transactionSignature: Uint8Array;
  slot: bigint;
  commitment: "finalized" | "confirmed" | "processed";
}

export interface ObservedRegistry {
  configPda: Uint8Array;
  programId: Uint8Array;
  registryIdHash: Hash;
  paused: boolean;
}

export interface ChainReader {
  getGenesisHash(): Promise<string>;
  getAnchor(body: CertificateBody): Promise<ObservedAnchor>;
  getRegistryConfig(body: CertificateBody): Promise<ObservedRegistry>;
  getFinalizedHeadSlot(): Promise<bigint>;
}

export class AnchorDisputedError extends Error {}

export type IncidentResolutionStatus = "OPEN" | "CONFIRMED" | "FALSE_POSITIVE" | "RESOLVED";

export interface IncidentNotice {
  firstBatchSequence: bigint;
  lastBatchSequence: bigint;
  /** Incident wire V1: `OPEN` = blocking, `RESOLVED` = not blocking (legacy). */
  status: "OPEN" | "RESOLVED";
  /** Exact on-chain disposition, when the index provides it. */
  resolutionStatus?: IncidentResolutionStatus;
  /** Explicit blocking flag, when the index provides it. */
  blocking?: boolean;
}

/**
 * ADR-0008: OPEN, CONFIRMED and RESOLVED keep data in the suspect range
 * blocked; only FALSE_POSITIVE lifts this incident's block. Every signal is
 * combined fail-closed: any field saying "blocking" wins. A legacy `RESOLVED`
 * without `resolutionStatus` cannot be told apart from a closed but real
 * incident, so it blocks too.
 */
export function incidentBlocks(incident: IncidentNotice): boolean {
  if (incident.status === "OPEN" || incident.blocking === true) return true;
  if (incident.resolutionStatus === undefined) return true;
  return incident.resolutionStatus !== "FALSE_POSITIVE";
}

export interface IncidentIndexResponse {
  registryId: string;
  indexedThroughSlot: bigint;
  incidents: IncidentNotice[];
}

export interface IncidentIndex {
  query(registryId: string, batchSequence: bigint): Promise<IncidentIndexResponse | null>;
}

/**
 * Lifecycle of the certificate itself and of the record version it discloses.
 * `VERIFIED_HISTORICAL` and `SUPERSEDED` are computed from this, never inferred
 * from the incident index (§2.3).
 */
export interface RecordLifecycle {
  registryId: string;
  certificateId?: string;
  currentRecordVersion: bigint;
  certificateStatus: "ACTIVE" | "SUPERSEDED" | "REVOKED";
}

export interface LifecycleIndex {
  query(registryId: string, certificateId: string): Promise<RecordLifecycle | null>;
}

export interface VerifyOptions {
  trustPolicy?: TrustPolicy;
  maxIndexLagSlots?: bigint;
  lifecycle?: LifecycleIndex;
}

export interface VerificationResult {
  status: VerificationStatus;
  code?: string;
  certificateId: string;
  batchSequence: string;
  solanaSlot?: string;
  incidentIndexStatus?: IncidentIndexStatus;
  indexedThroughSlot?: string;
  rpcFinalizedHeadSlot?: string;
  indexLagSlots?: string;
  recordVersion?: string;
  currentRecordVersion?: string;
  certificateLifecycle?: RecordLifecycle["certificateStatus"];
  warnings: string[];
  /** Present only once the disclosure and the proofs have been verified. */
  disclosureMode?: CertificateBody["disclosureMode"];
  disclosedFields?: Record<string, string | boolean | null>;
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

function certificateId(body: CertificateBody): string {
  return Buffer.from(body.certificateId).toString("hex");
}

function invalid(body: CertificateBody, code: string): VerificationResult {
  return {
    status: "INVALID",
    code,
    certificateId: certificateId(body),
    batchSequence: body.anchor.batchSequence.toString(),
    warnings: [],
  };
}

function proofSteps(bodySteps: Array<{ side: "LEFT" | "RIGHT"; sibling: Hash }>): ProofStep[] {
  return bodySteps.map((step) => ({ side: step.side, sibling: step.sibling }));
}

function verifyDisclosure(body: CertificateBody): boolean {
  const paths = Object.keys(body.disclosedFields).sort();
  const saltPaths = Object.keys(body.fieldSalts).sort();
  if (paths.length === 0 || paths.join("\0") !== saltPaths.join("\0")) return false;

  if (body.disclosureMode === "FULL_RECORD") {
    if (body.fieldProofs.length !== 0) return false;
    const commitments = paths.map((path) => ({
      path,
      value: body.disclosedFields[path],
      commitment: fieldCommitment(path, body.disclosedFields[path], body.fieldSalts[path]),
    }));
    const tree = buildFieldTreeFromCommitments(commitments);
    return equal(tree, body.fieldRoot);
  }

  const proofPaths = body.fieldProofs.map((proof) => proof.path).sort();
  if (paths.join("\0") !== proofPaths.join("\0") || proofPaths.length !== body.fieldProofs.length) {
    return false;
  }
  return body.fieldProofs.every((proof) => {
    const commitment = fieldCommitment(
      proof.path,
      body.disclosedFields[proof.path],
      body.fieldSalts[proof.path],
    );
    const calculated = rootFromProof(leafHash(commitment), proofSteps(proof.siblings));
    return equal(calculated, body.fieldRoot);
  });
}

function buildFieldTreeFromCommitments(
  entries: Array<{ path: string; value: unknown; commitment: Hash }>,
): Hash {
  const ordered = entries
    .map((entry) => ({ path: pathBytes(entry.path), leaf: leafHash(entry.commitment) }))
    .sort((left, right) => Buffer.compare(left.path, right.path));
  if (ordered.some((entry, index) => index > 0 && Buffer.compare(ordered[index - 1].path, entry.path) === 0)) {
    throw new RangeError("duplicate disclosure path");
  }
  if (entries.some((entry) => entry.value === undefined)) throw new RangeError("missing disclosed value");
  return root(ordered.map((entry) => entry.leaf));
}

function verifyBatchProof(body: CertificateBody): boolean {
  const commitment = recordCommitment(
    registryIdHash(body.registryId),
    body.recordIdCommitment,
    body.recordVersion,
    body.fieldRoot,
  );
  const batchLeaf = batchLeafHash(commitment);
  if (!equal(batchLeaf, body.batchProof.leafHash)) return false;
  const calculatedRoot = rootFromProof(batchLeaf, proofSteps(body.batchProof.siblings));
  return (
    equal(calculatedRoot, body.batchProof.expectedRoot) &&
    equal(calculatedRoot, body.anchor.merkleRoot)
  );
}

function verifyObservedAnchor(body: CertificateBody, observed: ObservedAnchor): string | null {
  if (observed.commitment !== "finalized") return "ANCHOR_NOT_FINALIZED";
  if (!equal(observed.programId, body.anchor.solanaProgramId)) return "ANCHOR_PROGRAM_MISMATCH";
  if (!equal(observed.segmentPda, observed.derivedSegmentPda)) return "SEGMENT_PDA_MISMATCH";
  if (!equal(observed.segmentPda, body.anchor.segmentPda)) return "SEGMENT_PDA_MISMATCH";
  if (observed.batchSequence !== body.anchor.batchSequence) return "ANCHOR_SEQUENCE_MISMATCH";
  if (observed.registryVersion !== body.anchor.registryVersion) return "ANCHOR_VERSION_MISMATCH";
  if (!equal(observed.merkleRoot, body.anchor.merkleRoot)) return "ANCHOR_ROOT_MISMATCH";
  if (!equal(observed.manifestHash, body.anchor.manifestHash)) return "ANCHOR_MANIFEST_MISMATCH";
  if (!equal(observed.transactionSignature, body.anchor.transactionSignature)) return "ANCHOR_SIGNATURE_MISMATCH";
  if (observed.slot !== body.anchor.anchorSlot) return "ANCHOR_SLOT_MISMATCH";
  return null;
}

function verifyWorkingRegistry(body: CertificateBody, observed: ObservedRegistry): string | null {
  if (!equal(observed.registryIdHash, registryIdHash(body.registryId))) return "REGISTRY_ID_MISMATCH";
  if (observed.paused) return "REGISTRY_PAUSED";
  return null;
}

export async function verifyCertificate(
  signed: SignedCertificate,
  chain: ChainReader,
  incidents: IncidentIndex,
  options: VerifyOptions = {},
): Promise<VerificationResult> {
  const result = await verifyAgainstAnchor(signed, chain, incidents, options);
  if (result.status === "INVALID") return result;
  const withLifecycle = await applyLifecycle(signed.body, result, options.lifecycle);
  // The disclosure is reported only here, after signature, field proofs and
  // batch proof succeeded: a consumer must never render values that were not
  // proven against the anchored root.
  return {
    ...withLifecycle,
    disclosureMode: signed.body.disclosureMode,
    disclosedFields: plainFields(signed.body.disclosedFields),
  };
}

/** Canonical values in a form a UI can render without decoding CBOR. */
function plainFields(fields: CertificateBody["disclosedFields"]): Record<string, string | boolean | null> {
  const plain: Record<string, string | boolean | null> = {};
  for (const path of Object.keys(fields).sort()) {
    const value = fields[path];
    plain[path] =
      value.type === "text" ? value.value
      : value.type === "bool" ? value.value
      : value.type === "int" ? value.value
      : value.type === "bytes" ? value.hex
      : null;
  }
  return plain;
}

/**
 * Downgrades a cryptographically proven certificate by its lifecycle.
 * `DISPUTED` and `VERIFIED_NO_INCIDENT_CHECK` are never upgraded away: an open
 * incident or an unproven incident index outranks record freshness.
 */
async function applyLifecycle(
  body: CertificateBody,
  result: VerificationResult,
  lifecycle: LifecycleIndex | undefined,
): Promise<VerificationResult> {
  const enriched: VerificationResult = { ...result, recordVersion: body.recordVersion.toString() };
  if (lifecycle === undefined) return enriched;
  let current: RecordLifecycle | null;
  try {
    current = await lifecycle.query(body.registryId, certificateId(body));
  } catch {
    current = null;
  }
  if (current === null || current.registryId !== body.registryId) {
    return {
      ...enriched,
      code: enriched.code ?? "CURRENT_STATUS_UNAVAILABLE",
      warnings: [...enriched.warnings, "Current record status is unavailable."],
    };
  }
  const withStatus: VerificationResult = {
    ...enriched,
    currentRecordVersion: current.currentRecordVersion.toString(),
    certificateLifecycle: current.certificateStatus,
  };
  if (result.status !== "VERIFIED") return withStatus;
  if (current.certificateStatus !== "ACTIVE") {
    return {
      ...withStatus,
      status: "SUPERSEDED",
      code: "RECORD_SUPERSEDED",
      warnings: [...withStatus.warnings, "This certificate has been replaced."],
    };
  }
  if (current.currentRecordVersion > body.recordVersion) {
    return {
      ...withStatus,
      status: "VERIFIED_HISTORICAL",
      code: "RECORD_SUPERSEDED",
      warnings: [...withStatus.warnings, "A newer version of this record exists."],
    };
  }
  return withStatus;
}

async function verifyAgainstAnchor(
  signed: SignedCertificate,
  chain: ChainReader,
  incidents: IncidentIndex,
  options: VerifyOptions = {},
): Promise<VerificationResult> {
  const body = signed.body;
  const trustError = authorizeCertificate(body, options.trustPolicy);
  if (trustError !== null) return invalid(body, trustError);
  const policy = options.trustPolicy!;
  try {
    if (!verifyCertificateSignature(signed)) return invalid(body, "CERT_SIGNATURE_INVALID");
    if (body.schemaVersion !== 1) return invalid(body, "UNSUPPORTED_SCHEMA");
    if (!verifyDisclosure(body)) return invalid(body, "FIELD_PROOF_INVALID");
    if (!verifyBatchProof(body)) return invalid(body, "MERKLE_PROOF_INVALID");
  } catch {
    return invalid(body, "CERTIFICATE_FORMAT_INVALID");
  }

  let registry: ObservedRegistry;
  try {
    if (await chain.getGenesisHash() !== policy.genesisHash) return invalid(body, "CLUSTER_UNTRUSTED");
    registry = await chain.getRegistryConfig(body);
  } catch {
    return invalid(body, "REGISTRY_STATUS_UNAVAILABLE");
  }
  if (!equal(registry.configPda, Buffer.from(policy.configPdaHex, "hex")) || !equal(registry.programId, Buffer.from(policy.programIdHex, "hex"))) return invalid(body, "REGISTRY_CONFIG_UNTRUSTED");
  const registryError = verifyWorkingRegistry(body, registry);
  if (registryError !== null) return invalid(body, registryError);

  let observed: ObservedAnchor;
  try {
    observed = await chain.getAnchor(body);
  } catch (error) {
    return invalid(body, error instanceof AnchorDisputedError ? "ANCHOR_DISPUTED" : "ANCHOR_NOT_FOUND");
  }
  if (!equal(observed.registryConfigPda, registry.configPda)) return invalid(body, "LEDGER_REGISTRY_MISMATCH");
  const anchorError = verifyObservedAnchor(body, observed);
  if (anchorError !== null) return invalid(body, anchorError);

  const base = {
    certificateId: certificateId(body),
    batchSequence: body.anchor.batchSequence.toString(),
    solanaSlot: observed.slot.toString(),
    warnings: [] as string[],
  };
  let response: IncidentIndexResponse | null;
  let head: bigint;
  try {
    [response, head] = await Promise.all([
      incidents.query(body.registryId, body.anchor.batchSequence),
      chain.getFinalizedHeadSlot(),
    ]);
  } catch {
    return {
      ...base,
      status: "VERIFIED_NO_INCIDENT_CHECK",
      incidentIndexStatus: "UNAVAILABLE",
      warnings: ["Incident index unavailable."],
    };
  }
  if (response === null || response.registryId !== body.registryId) {
    return {
      ...base,
      status: "VERIFIED_NO_INCIDENT_CHECK",
      incidentIndexStatus: "UNAVAILABLE",
      rpcFinalizedHeadSlot: head.toString(),
      warnings: ["Incident index response did not match the registry."],
    };
  }
  if (response.indexedThroughSlot > head) {
    return {
      ...base,
      status: "VERIFIED_NO_INCIDENT_CHECK",
      incidentIndexStatus: "INDEX_INCONSISTENT",
      indexedThroughSlot: response.indexedThroughSlot.toString(),
      rpcFinalizedHeadSlot: head.toString(),
      warnings: ["Incident index watermark exceeds the finalized RPC head."],
    };
  }
  const lag = head - response.indexedThroughSlot;
  const maxLag = options.maxIndexLagSlots ?? 300n;
  if (lag > maxLag || response.indexedThroughSlot < observed.slot) {
    return {
      ...base,
      status: "VERIFIED_NO_INCIDENT_CHECK",
      incidentIndexStatus: "STALE",
      indexedThroughSlot: response.indexedThroughSlot.toString(),
      rpcFinalizedHeadSlot: head.toString(),
      indexLagSlots: lag.toString(),
      warnings: ["Incident index is stale."],
    };
  }
  const disputed = response.incidents.some(
    (incident) =>
      incidentBlocks(incident) &&
      incident.firstBatchSequence <= body.anchor.batchSequence &&
      incident.lastBatchSequence >= body.anchor.batchSequence,
  );
  return {
    ...base,
    status: disputed ? "DISPUTED" : "VERIFIED",
    incidentIndexStatus: "CHECKED",
    indexedThroughSlot: response.indexedThroughSlot.toString(),
    rpcFinalizedHeadSlot: head.toString(),
    indexLagSlots: lag.toString(),
  };
}
