"use client";

import type { ReactNode } from "react";
import { describeIncidentIndex, describeVerification, Field, StatusBadge } from "./status";

export interface VerificationResponse {
  status?: string;
  code?: string;
  certificateId?: string;
  batchSequence?: string;
  solanaSlot?: string;
  incidentIndexStatus?: string;
  indexedThroughSlot?: string;
  rpcFinalizedHeadSlot?: string;
  indexLagSlots?: string;
  recordVersion?: string;
  currentRecordVersion?: string;
  certificateLifecycle?: string;
  warnings?: string[];
  disclosureMode?: string;
  disclosedFields?: Record<string, unknown>;
}

/**
 * One result view per status. Every state shows an icon, a name, a reason and
 * the chain evidence; nothing is communicated by colour alone.
 */
export function VerificationResult({
  result,
  disclosedFields,
}: {
  result: VerificationResponse;
  disclosedFields?: Record<string, unknown>;
}): ReactNode {
  const status = describeVerification(result.status);
  const index = describeIncidentIndex(result.incidentIndexStatus);
  // The values come from the verifier, which returns them only after the
  // signature and both proofs succeeded; nothing here is read from a database.
  const fields = result.disclosedFields ?? disclosedFields;
  return (
    <section className="ol-card" aria-labelledby="verification-heading" data-testid="verification-result" data-status={result.status}>
      <h2 id="verification-heading">Verification result</h2>
      <p>
        <StatusBadge status={status} testId="verification-status" />
      </p>
      <p data-testid="verification-explanation">{status.explanation}</p>
      {result.code !== undefined ? (
        <p className="ol-muted">
          Reason code: <code data-testid="verification-code">{result.code}</code>
        </p>
      ) : null}
      {(result.warnings ?? []).map((warning) => (
        <p key={warning} className="ol-muted">{warning}</p>
      ))}
      <dl className="ol-grid">
        <Field label="Cluster" value="solana:devnet" />
        <Field label="Certificate" value={result.certificateId ?? "—"} />
        <Field label="Batch sequence" value={result.batchSequence ?? "—"} />
        <Field label="Anchor slot" value={result.solanaSlot ?? "—"} />
        <Field label="Record version" value={result.recordVersion ?? "—"} />
        <Field label="Current record version" value={result.currentRecordVersion ?? "unknown"} />
        <Field label="Certificate lifecycle" value={result.certificateLifecycle ?? "unknown"} />
      </dl>
      <h3>Incident index</h3>
      <p>
        <StatusBadge status={index} testId="incident-index-status" />
      </p>
      <p className="ol-muted">{index.explanation}</p>
      <dl className="ol-grid">
        <Field label="Indexed through slot" value={result.indexedThroughSlot ?? "—"} />
        <Field label="Finalized RPC head" value={result.rpcFinalizedHeadSlot ?? "—"} />
        <Field label="Index lag (slots)" value={result.indexLagSlots ?? "—"} />
      </dl>
      {fields !== undefined ? (
        <>
          <h3>Disclosed fields</h3>
          <p className="ol-muted" data-testid="disclosure-mode">
            {result.disclosureMode === "SELECTIVE_FIELDS"
              ? "Selective disclosure: the package proves these fields against the anchored record. Undisclosed fields are absent — not hidden behind this page."
              : "Full record: every field of this record version is in the package."}
          </p>
          <dl className="ol-grid" data-testid="disclosed-fields">
            {Object.entries(fields).map(([path, value]) => (
              <Field key={path} label={path} value={String(value)} />
            ))}
          </dl>
        </>
      ) : null}
    </section>
  );
}
