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
  RPC_DISAGREEMENT: { icon: "!", label: "RPC DISAGREEMENT", tone: "warn", explanation: "Independent RPC endpoints disagree about the finalized head." },
};

const UNKNOWN_STATUS: StatusDescriptor = {
  icon: "?",
  label: "UNKNOWN",
  tone: "neutral",
  explanation: "No description for this status.",
};

export function describeVerification(status: string | undefined): StatusDescriptor {
  return (status !== undefined && VERIFICATION_STATUS[status]) || UNKNOWN_STATUS;
}

export function describeTransaction(state: string | undefined): StatusDescriptor {
  return (state !== undefined && TRANSACTION_STATE[state]) || UNKNOWN_STATUS;
}

export function describeIncidentIndex(status: string | undefined): StatusDescriptor {
  return (status !== undefined && INCIDENT_INDEX_STATUS[status]) || UNKNOWN_STATUS;
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
