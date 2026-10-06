// Shared status vocabulary for both route groups. Every status is rendered as
// icon + text; colour is decoration only (§5.4 design system).
import type { ReactNode } from "react";

export type Tone = "ok" | "warn" | "bad" | "info" | "neutral";

export interface StatusDescriptor {
  icon: string;
  label: string;
  tone: Tone;
  explanation: string;
}

const VERIFICATION_STATUS: Record<string, StatusDescriptor> = {
  VERIFIED: {
    icon: "✔",
    label: "VERIFIED",
    tone: "ok",
    explanation: "Signature, proofs and the finalized Solana anchor match, and the incident index proved its freshness.",
  },
  VERIFIED_HISTORICAL: {
    icon: "◷",
    label: "VERIFIED · HISTORICAL",
    tone: "info",
    explanation: "The certificate is proven, but a newer version of this record exists.",
  },
  SUPERSEDED: {
    icon: "⟳",
    label: "SUPERSEDED",
    tone: "warn",
    explanation: "This certificate has been replaced by a newer one for the same record.",
  },
  VERIFIED_NO_INCIDENT_CHECK: {
    icon: "!",
    label: "VERIFIED · NO INCIDENT CHECK",
    tone: "warn",
    explanation: "Cryptography checks out, but the incident index did not prove completeness. This is not a green result.",
  },
  DISPUTED: {
    icon: "✖",
    label: "DISPUTED",
    tone: "bad",
    explanation: "An open integrity incident covers the batch this certificate belongs to.",
  },
  INVALID: {
    icon: "✖",
    label: "INVALID",
    tone: "bad",
    explanation: "The package failed a cryptographic or schema check.",
  },
};

/**
 * V2 verdicts. No member can assert proven currentness: without an authenticated
 * lifecycle source a healthy certificate still answers UNKNOWN, and a lifecycle
 * report can only downgrade the verdict conservatively.
 */
const VERIFICATION_STATUS_V2: Record<string, StatusDescriptor> = {
  UNKNOWN: {
    icon: "?",
    label: "UNKNOWN",
    tone: "warn",
    explanation: "The disclosed data and its proofs were established against the finalized anchor, but this result does not prove the certificate or record version is current: no authenticated lifecycle source exists yet.",
  },
  REVOKED: {
    icon: "✖",
    label: "REVOKED · ADVISORY",
    tone: "warn",
    explanation: "The disclosed data is proven against the finalized anchor. An unauthenticated lifecycle report says the certificate is revoked; that report is advisory, not proof.",
  },
  HISTORICAL: {
    icon: "◷",
    label: "HISTORICAL · ADVISORY",
    tone: "info",
    explanation: "The disclosed data is proven against the finalized anchor, and an unauthenticated lifecycle report indicates a newer record version exists. The report is advisory.",
  },
  DISPUTED: {
    icon: "✖",
    label: "DISPUTED",
    tone: "bad",
    explanation: "An open integrity incident covers the batch this certificate belongs to. Verification is blocked until the incident is resolved.",
  },
  INVALID: {
    icon: "✖",
    label: "INVALID",
    tone: "bad",
    explanation: "The package failed a cryptographic or schema check; no proof was established.",
  },
};

const PROOF_STATUS: Record<string, StatusDescriptor> = {
  VERIFIED: { icon: "✔", label: "PROOFS VERIFIED", tone: "ok", explanation: "The issuer signature, the field proofs and the batch Merkle proof all match the finalized anchor. This is proof about the anchored package, not about its current suitability." },
  NOT_ESTABLISHED: { icon: "✖", label: "PROOFS NOT ESTABLISHED", tone: "bad", explanation: "No proof was established, so nothing in this answer comes from the anchored record." },
};

const REGISTRY_STATUS: Record<string, StatusDescriptor> = {
  CHECKED: { icon: "✔", label: "REGISTRY CHECKED", tone: "ok", explanation: "The package's registry identity was checked against the deployment policy and the chain, and the registry was not paused at the anchor." },
  NOT_ESTABLISHED: { icon: "✖", label: "REGISTRY NOT ESTABLISHED", tone: "bad", explanation: "The registry identity could not be established for this package." },
};

const LIFECYCLE_STATUS: Record<string, StatusDescriptor> = {
  UNAUTHENTICATED: { icon: "!", label: "ADVISORY · UNVERIFIED SOURCE", tone: "warn", explanation: "The lifecycle report comes from an unauthenticated source. It is an advisory hint only and never upgrades this result to a current verdict." },
  UNKNOWN: { icon: "?", label: "LIFECYCLE UNKNOWN", tone: "neutral", explanation: "No usable lifecycle report was available, so current status stays unproven." },
};

/** Rendered when a verifier answers in a shape this build cannot interpret. */
export const UNINTERPRETABLE_RESULT: StatusDescriptor = {
  icon: "✖",
  label: "UNINTERPRETABLE RESULT",
  tone: "bad",
  explanation: "The verifier answered in a shape this browser cannot interpret: a missing or unreadable envelope, an unknown result version, verdict or proof state. The answer is discarded, and no proof, disclosed value or lifecycle claim from it is shown. Verify again; if the verifier keeps answering this way, the web application needs an update.",
};

const TRANSACTION_STATE: Record<string, StatusDescriptor> = {
  DRAFT: { icon: "·", label: "DRAFT", tone: "neutral", explanation: "Nothing has been prepared yet." },
  PREPARED: { icon: "·", label: "PREPARED", tone: "neutral", explanation: "Transaction built, simulation pending." },
  SIMULATED: { icon: "→", label: "SIMULATED", tone: "info", explanation: "Simulation succeeded; the wallet signature is the next step." },
  SIGNED: { icon: "→", label: "SIGNED", tone: "info", explanation: "The wallet signed the reviewed bytes." },
  SUBMITTED: { icon: "◷", label: "SUBMITTED", tone: "info", explanation: "Sent to devnet; waiting for finalization." },
  FINALIZED: { icon: "✔", label: "FINALIZED", tone: "ok", explanation: "The anchor transaction is finalized." },
  ISSUED: { icon: "✔", label: "ISSUED", tone: "ok", explanation: "The certificate package and QR have been issued." },
  SIMULATION_FAILED: { icon: "✖", label: "SIMULATION FAILED", tone: "bad", explanation: "Simulation failed; no signature was requested." },
  SIGNING_REJECTED: { icon: "✖", label: "SIGNING REJECTED", tone: "warn", explanation: "The wallet rejected the request." },
  EXPIRED: { icon: "!", label: "EXPIRED", tone: "warn", explanation: "The blockhash expired; prepare and simulate again." },
  UNKNOWN: { icon: "?", label: "UNKNOWN", tone: "warn", explanation: "The submit response was lost. The known signature is being polled; nothing is rebuilt." },
  FAILED: { icon: "✖", label: "FAILED", tone: "bad", explanation: "The transaction failed on chain." },
};

const INCIDENT_INDEX_STATUS: Record<string, StatusDescriptor> = {
  CHECKED: { icon: "✔", label: "INDEX CHECKED", tone: "ok", explanation: "Watermark reached the anchor slot within the allowed lag." },
  STALE: { icon: "!", label: "INDEX STALE", tone: "warn", explanation: "The index lags behind the finalized head or has not reached the anchor slot." },
  UNAVAILABLE: { icon: "!", label: "INDEX UNAVAILABLE", tone: "warn", explanation: "The incident index did not answer, or answered without a watermark." },
  INDEX_INCONSISTENT: { icon: "!", label: "INDEX INCONSISTENT", tone: "bad", explanation: "The index claims to be ahead of the finalized head." },
  NOT_CHECKED: { icon: "·", label: "INDEX NOT CHECKED", tone: "warn", explanation: "The incident index was not consulted for this result." },
};

const BACKUP_STATUS: Record<string, StatusDescriptor> = {
  COPIED: { icon: "✔", label: "COPIED", tone: "ok", explanation: "The encrypted SnapshotPackageV1 was copied and its ciphertext hash was verified." },
  PENDING_RETRY: { icon: "◷", label: "PENDING RETRY", tone: "warn", explanation: "This center is unavailable; the same immutable replica can be retried after recovery." },
  FAILED: { icon: "✖", label: "ERROR", tone: "bad", explanation: "The center rejected the encrypted replica. No plaintext was stored." },
  HEALTHY: { icon: "✔", label: "HEALTHY", tone: "ok", explanation: "The local BackupCenter is available for encrypted replicas." },
  UNAVAILABLE: { icon: "◷", label: "UNAVAILABLE", tone: "warn", explanation: "The local BackupCenter is unavailable for writes." },
  ERROR: { icon: "✖", label: "ERROR", tone: "bad", explanation: "The local BackupCenter reported an error." },
};

const RECOVERY_STATUS: Record<string, StatusDescriptor> = {
  AWAITING_APPROVAL: { icon: "◷", label: "AWAITING RESTORE APPROVAL", tone: "warn", explanation: "Threshold and integrity checks passed; a chief_admin must approve this exact snapshot, root and target." },
  APPROVED: { icon: "→", label: "APPROVED · VALIDATION READY", tone: "info", explanation: "The chief_admin approval is bound to this snapshot, Merkle root and target; the operator may validate the approved recovery material." },
  VALIDATED: { icon: "◷", label: "VALIDATED · TARGET IMPORT PENDING", tone: "warn", explanation: "The recovery material passed integrity checks. Recovery completes after target data is imported and verified." },
  RESTORED: { icon: "✔", label: "RESTORED", tone: "ok", explanation: "Snapshot data was imported into the target and verified." },
  FAILED: { icon: "✖", label: "RECOVERY FAILED", tone: "bad", explanation: "Recovery stopped fail-closed. No partial restore was reported." },
};

const UNKNOWN_STATUS: StatusDescriptor = {
  icon: "?",
  label: "UNKNOWN",
  tone: "neutral",
  explanation: "No description for this status.",
};

/**
 * Plain-object maps must never answer from the prototype chain: a status named
 * `constructor` or `toString` is not a known status.
 */
function lookup<T>(map: Record<string, T>, key: unknown): T | undefined {
  if (typeof key !== "string" || !Object.hasOwn(map, key)) return undefined;
  return map[key];
}

/**
 * Wire enums the v2 result view accepts. A value outside these sets is not part of
 * the published contract, so the view discards the whole answer before any badge
 * appears instead of choosing a label or a claim for it. Each guard is also the
 * runtime narrowing that proves the value is one of the published strings.
 */
export function isKnownRegistryStatus(status: unknown): status is string {
  return lookup(REGISTRY_STATUS, status) !== undefined;
}

export function isKnownIncidentIndexStatus(status: unknown): status is string {
  return lookup(INCIDENT_INDEX_STATUS, status) !== undefined;
}

export function isKnownLifecycleStatus(status: unknown): status is string {
  return lookup(LIFECYCLE_STATUS, status) !== undefined;
}

/** The only disclosure modes a result view may label; anything else is discarded. */
export function isKnownDisclosureMode(mode: unknown): mode is string {
  return mode === "FULL_RECORD" || mode === "SELECTIVE_FIELDS";
}

/** Reported certificate states the advisory lifecycle projection may carry. */
export function isKnownReportedCertificateStatus(status: unknown): status is string {
  return status === "ACTIVE" || status === "SUPERSEDED" || status === "REVOKED";
}

export function describeVerification(status: string | undefined): StatusDescriptor {
  return lookup(VERIFICATION_STATUS, status) ?? UNKNOWN_STATUS;
}

/** The strongest v2 verdict is UNKNOWN: v2 never reports a certificate as current. */
export function describeVerificationV2(status: string | undefined): StatusDescriptor {
  return lookup(VERIFICATION_STATUS_V2, status) ?? UNKNOWN_STATUS;
}

/**
 * A v2 answer is only read with v2 assumptions when the version, the verdict, the
 * proof state and the pairing of the last two are all part of the published
 * contract: INVALID establishes no proof, and every other verdict is paired with
 * VERIFIED. Anything else is discarded by the result view, never partly rendered.
 */
export function isInterpretableVerificationV2(status: string | undefined, proofStatus: string | undefined): boolean {
  if (lookup(VERIFICATION_STATUS_V2, status) === undefined) return false;
  return status === "INVALID" ? proofStatus === "NOT_ESTABLISHED" : proofStatus === "VERIFIED";
}

/** A legacy answer with an unrecognised status is malformed and must not be labelled either. */
export function isKnownVerification(status: string | undefined): boolean {
  return lookup(VERIFICATION_STATUS, status) !== undefined;
}

/**
 * Legacy v1 statuses whose response carries disclosed values proven against the
 * anchored root. Any other status (including INVALID) proves nothing.
 */
export function legacyFieldsProven(status: string | undefined): boolean {
  return status === "VERIFIED" || status === "VERIFIED_HISTORICAL" || status === "SUPERSEDED"
    || status === "VERIFIED_NO_INCIDENT_CHECK" || status === "DISPUTED";
}

/**
 * Legacy v1 proof verdicts are shown as historical proof: an "ok" v1 status
 * must never read as a claim that the record or certificate is current.
 */
export function describeLegacyVerification(status: string | undefined): StatusDescriptor {
  const base = describeVerification(status);
  if (base.tone !== "ok") return base;
  return {
    ...base,
    label: `${base.label} · HISTORICAL PROOF`,
    tone: "info",
    explanation: `${base.explanation} Legacy v1 response: this proves the anchored package only, never that the record is current.`,
  };
}

/** An absent proof status means no proof was established. */
export function describeProof(status: string | undefined): StatusDescriptor {
  if (status === undefined) return PROOF_STATUS.NOT_ESTABLISHED;
  return lookup(PROOF_STATUS, status) ?? UNKNOWN_STATUS;
}

export function describeRegistry(status: string | undefined): StatusDescriptor {
  if (status === undefined) return REGISTRY_STATUS.NOT_ESTABLISHED;
  return lookup(REGISTRY_STATUS, status) ?? UNKNOWN_STATUS;
}

export function describeLifecycle(status: string | undefined): StatusDescriptor {
  if (status === undefined) return LIFECYCLE_STATUS.UNKNOWN;
  return lookup(LIFECYCLE_STATUS, status) ?? UNKNOWN_STATUS;
}

export function describeTransaction(state: string | undefined): StatusDescriptor {
  return lookup(TRANSACTION_STATE, state) ?? UNKNOWN_STATUS;
}

export function describeIncidentIndex(status: string | undefined): StatusDescriptor {
  // An absent status means the index was never consulted, which is not the same
  // as an unrecognised status from the verifier.
  if (status === undefined) return INCIDENT_INDEX_STATUS.NOT_CHECKED;
  return lookup(INCIDENT_INDEX_STATUS, status) ?? UNKNOWN_STATUS;
}

export function describeBackup(status: string | undefined): StatusDescriptor {
  return lookup(BACKUP_STATUS, status) ?? UNKNOWN_STATUS;
}

export function describeRecovery(status: string | undefined): StatusDescriptor {
  return lookup(RECOVERY_STATUS, status) ?? UNKNOWN_STATUS;
}

export function StatusBadge({ status, testId }: { status: StatusDescriptor; testId?: string }): ReactNode {
  return (
    <span className="ol-status" data-tone={status.tone} data-testid={testId} role="status">
      <span className="ol-status-icon" aria-hidden="true">{status.icon}</span>
      <span>{status.label}</span>
    </span>
  );
}

export function Field({ label, value }: { label: string; value: ReactNode }): ReactNode {
  return (
    <div className="ol-field">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}
