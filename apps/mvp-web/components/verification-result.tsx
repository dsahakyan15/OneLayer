"use client";

import type { ReactNode } from "react";
import {
  describeIncidentIndex,
  describeLegacyVerification,
  describeLifecycle,
  describeProof,
  describeRegistry,
  describeVerificationV2,
  Field,
  isInterpretableVerificationV2,
  isKnownDisclosureMode,
  isKnownIncidentIndexStatus,
  isKnownLifecycleStatus,
  isKnownRegistryStatus,
  isKnownReportedCertificateStatus,
  isKnownVerification,
  legacyFieldsProven,
  StatusBadge,
  UNINTERPRETABLE_RESULT,
} from "./status";

/**
 * Envelopes this build knows how to render. `discarded` is the fail-closed
 * state for an answer this build cannot interpret; `local` is a failure the
 * browser detected before any verifier answered; `v1` renders a legacy body
 * that a caller passes in, and is never produced by an automatic fallback.
 */
export type VerifyEnvelope = "v2" | "v1" | "discarded" | "local";

export interface VerificationResponse {
  /** `2` marks the current v2 envelope; a legacy v1 body carries no version. */
  resultVersion?: number;
  status?: string;
  code?: string;
  checkedAt?: string;
  certificateId?: string;
  batchSequence?: string;
  recordVersion?: string;
  solanaSlot?: string;
  proofs?: { status?: string; anchorSlot?: string };
  registry?: { registryId?: string; status?: string };
  incidents?: { status?: string; indexedThroughSlot?: string; finalizedHeadSlot?: string; lagSlots?: string };
  lifecycle?: {
    status?: string;
    code?: string;
    reported?: { certificateStatus?: string; currentRecordVersion?: string };
  };
  incidentIndexStatus?: string;
  indexedThroughSlot?: string;
  rpcFinalizedHeadSlot?: string;
  indexLagSlots?: string;
  currentRecordVersion?: string;
  certificateLifecycle?: string;
  warnings?: string[];
  disclosureMode?: string;
  disclosedFields?: Record<string, string | boolean | null>;
}

/** Decimal wire values (record versions, batch sequences, slots) are unsigned integers in string form. */
const DECIMAL = /^[0-9]{1,20}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/** A required decimal wire value. */
function isDecimal(value: unknown): value is string {
  return typeof value === "string" && DECIMAL.test(value);
}

/** An optional decimal field may be absent; anything that is not a decimal string is refused. */
function isDecimalOrAbsent(value: unknown): value is string | undefined {
  return value === undefined || isDecimal(value);
}

/** Warnings are display strings; a structured entry is not text this view may show. */
function isWarningList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

/**
 * Disclosed evidence is scalar on the wire: the verifier maps canonical text,
 * booleans, integers and bytes to strings or booleans and maps nested values to
 * null. A record carrying an array or an object is not that contract, so it is
 * refused instead of being coerced into text.
 */
function isDisclosedFields(value: unknown): value is Record<string, string | boolean | null> {
  if (!isRecord(value)) return false;
  return Object.values(value).every((entry) => entry === null || typeof entry === "string" || typeof entry === "boolean");
}

/** Disclosed evidence is already a scalar; rendering never converts an object. */
function displayDisclosedValue(value: string | boolean | null): string {
  if (value === null) return "null";
  return typeof value === "boolean" ? (value ? "true" : "false") : value;
}

/** The advisory lifecycle projection of one record version. */
function isReportedLifecycle(value: unknown): value is { certificateStatus: string; currentRecordVersion: string } {
  return isRecord(value)
    && isKnownReportedCertificateStatus(value.certificateStatus)
    && isDecimal(value.currentRecordVersion);
}

/**
 * The published v2 wire contract as this view reads it. Every field the view can
 * render is checked before any badge, chain value or disclosed field appears: an
 * unknown enum, a scalar carrying an object or an array, or a lifecycle projection
 * attached to a non-advisory status makes the whole answer uninterpretable, and it
 * is discarded rather than partly rendered or stringified into a value it does not
 * carry. The producer only omits the optional fields accepted here, so every
 * proper answer passes.
 */
function validateVerificationV2(body: unknown): VerificationResponse | null {
  if (!isRecord(body) || body.resultVersion !== 2) return null;
  const { status, proofs, registry, incidents, lifecycle, code, checkedAt, certificateId, batchSequence, recordVersion, warnings, disclosureMode, disclosedFields } = body;
  if (typeof status !== "string" || !isRecord(proofs)) return null;
  const proofStatus = proofs.status;
  // INVALID establishes no proof; every other verdict carries VERIFIED. A
  // mismatched pair is not this contract, and an unknown state is not a label.
  if (typeof proofStatus !== "string" || !isInterpretableVerificationV2(status, proofStatus)) return null;
  if (!isNonEmptyString(code) || !isNonEmptyString(checkedAt)) return null;
  if (!isNonEmptyString(certificateId)) return null;
  if (!isDecimal(recordVersion) || !isDecimal(batchSequence)) return null;
  if (!isDecimalOrAbsent(proofs.anchorSlot)) return null;
  if (!isRecord(registry) || !isNonEmptyString(registry.registryId) || !isKnownRegistryStatus(registry.status)) return null;
  const registryId = registry.registryId;
  const registryStatus = registry.status;
  if (!isRecord(incidents) || !isKnownIncidentIndexStatus(incidents.status)
    || !isDecimalOrAbsent(incidents.indexedThroughSlot)
    || !isDecimalOrAbsent(incidents.finalizedHeadSlot)
    || !isDecimalOrAbsent(incidents.lagSlots)) return null;
  const incidentStatus = incidents.status;
  const indexedThroughSlot = incidents.indexedThroughSlot;
  const finalizedHeadSlot = incidents.finalizedHeadSlot;
  const lagSlots = incidents.lagSlots;
  if (!isRecord(lifecycle) || !isKnownLifecycleStatus(lifecycle.status)) return null;
  const lifecycleStatus = lifecycle.status;
  // Reported values exist only as the advisory projection of UNAUTHENTICATED;
  // attaching them to any other status is not this contract.
  let reported: { certificateStatus: string; currentRecordVersion: string } | undefined;
  if (lifecycle.reported !== undefined) {
    if (lifecycleStatus !== "UNAUTHENTICATED" || !isReportedLifecycle(lifecycle.reported)) return null;
    reported = {
      certificateStatus: lifecycle.reported.certificateStatus,
      currentRecordVersion: lifecycle.reported.currentRecordVersion,
    };
  }
  if (!isWarningList(warnings)) return null;
  if (disclosureMode !== undefined && !isKnownDisclosureMode(disclosureMode)) return null;
  if (disclosedFields !== undefined && !isDisclosedFields(disclosedFields)) return null;
  // A disclosed set is labelled by the mode it was declared with; fields without
  // a mode cannot be described honestly.
  if (disclosedFields !== undefined && disclosureMode === undefined) return null;
  return {
    resultVersion: 2,
    status,
    code,
    checkedAt,
    certificateId,
    batchSequence,
    recordVersion,
    proofs: proofs.anchorSlot === undefined ? { status: proofStatus } : { status: proofStatus, anchorSlot: proofs.anchorSlot },
    registry: { registryId, status: registryStatus },
    incidents: {
      status: incidentStatus,
      ...(indexedThroughSlot === undefined ? {} : { indexedThroughSlot }),
      ...(finalizedHeadSlot === undefined ? {} : { finalizedHeadSlot }),
      ...(lagSlots === undefined ? {} : { lagSlots }),
    },
    lifecycle: {
      status: lifecycleStatus,
      ...(typeof lifecycle.code === "string" ? { code: lifecycle.code } : {}),
      ...(reported === undefined ? {} : { reported }),
    },
    warnings: [...warnings],
    ...(disclosureMode === undefined ? {} : { disclosureMode }),
    ...(disclosedFields === undefined ? {} : { disclosedFields }),
  };
}

/** `blocking` stops use, `advisory` is an unverified hint, `unproven` proves the package only. */
type Verdict = "blocking" | "advisory" | "unproven" | "historical-proof";

function verdictOf(status: string | undefined, legacy: boolean): Verdict {
  if (status === "INVALID" || status === "DISPUTED") return "blocking";
  if (legacy) return "historical-proof";
  if (status === "REVOKED" || status === "HISTORICAL") return "advisory";
  return "unproven";
}

/** A failure detected before a verifier answered: the verdict is INVALID with a reason, nothing more. */
function LocalFailure({ result }: { result: VerificationResponse | null }): ReactNode {
  const reportedStatus = result?.status ?? "INVALID";
  const status = describeVerificationV2(reportedStatus);
  return (
    <section
      className="ol-card"
      aria-labelledby="verification-heading"
      data-testid="verification-result"
      data-status={reportedStatus}
      data-result-version="local"
      data-verdict={verdictOf(reportedStatus, false)}
    >
      <h2 id="verification-heading">Verification result</h2>
      <p>
        <StatusBadge status={status} testId="verification-status" />
      </p>
      <p data-testid="verification-explanation">{status.explanation}</p>
      {result !== null && typeof result.code === "string" ? (
        <p className="ol-muted">
          Reason code: <code data-testid="verification-code">{result.code}</code>
        </p>
      ) : null}
    </section>
  );
}

/**
 * An answer this build cannot interpret is discarded, never partly rendered. The
 * body may be any JSON value, including null for an empty 200 answer, so nothing
 * here reads a field before its type is known.
 */
function DiscardedResult({ result }: { result: VerificationResponse | null }): ReactNode {
  return (
    <section
      className="ol-card"
      aria-labelledby="verification-heading"
      data-testid="verification-result"
      data-status="UNINTERPRETABLE"
      data-result-version="discarded"
      data-verdict="blocking"
    >
      <h2 id="verification-heading">Verification result</h2>
      <p>
        <StatusBadge status={UNINTERPRETABLE_RESULT} testId="verification-status" />
      </p>
      <p data-testid="verification-explanation">
        {UNINTERPRETABLE_RESULT.explanation}
        {result !== null && typeof result.resultVersion === "number"
          ? ` The verifier reported result version ${result.resultVersion}.`
          : ""}
      </p>
      {result !== null && typeof result.code === "string" ? (
        <p className="ol-muted">
          Reason code: <code data-testid="verification-code">{result.code}</code>
        </p>
      ) : null}
    </section>
  );
}

/**
 * One result view per verdict. The v2 envelope shows proof, registry, incident
 * and lifecycle evidence separately so "proven against the anchor" is never
 * read as "current": the wire contract has no CURRENT value, and a lifecycle
 * report stays advisory while its source is unauthenticated. A legacy v1 answer
 * is rendered as a historical proof only. Every v2 field this view can display is
 * validated against the wire contract before any badge appears, and an answer
 * that fails is discarded whole. Disclosed values appear only once the envelope
 * says proofs were established and only under the disclosure mode it declares, so
 * an INVALID body cannot smuggle unproven values into the page and an unknown mode
 * cannot be labelled as a full record. Every state shows an icon, a name, a reason
 * and the chain evidence; nothing is communicated by colour alone.
 */
export function VerificationResult({
  result: answer,
  disclosedFields,
  envelope = "v2",
}: {
  result: VerificationResponse | null;
  /** Caller-supplied disclosed values, shown only under a declared disclosure mode. */
  disclosedFields?: Record<string, string | boolean | null>;
  envelope?: VerifyEnvelope;
}): ReactNode {
  if (envelope === "local") return <LocalFailure result={answer} />;
  if (envelope === "discarded") return <DiscardedResult result={answer} />;
  const v2 = envelope === "v2";
  // Every field a v2 answer can display is validated before any badge appears;
  // an answer that fails the contract is discarded whole, never partly rendered
  // and never stringified into a value it does not carry.
  const result = v2 ? validateVerificationV2(answer) : answer;
  if (result === null || (!v2 && !isKnownVerification(result.status))) {
    return <DiscardedResult result={answer} />;
  }
  const status = v2 ? describeVerificationV2(result.status) : describeLegacyVerification(result.status);
  const proofs = describeProof(result.proofs?.status);
  const registry = describeRegistry(result.registry?.status);
  const lifecycle = describeLifecycle(result.lifecycle?.status);
  const incidents = describeIncidentIndex(v2 ? result.incidents?.status : result.incidentIndexStatus);
  // Values come from the verifier only after the signature and both proofs
  // succeeded; an INVALID body must not render anything as proven.
  const proven = v2
    ? result.status !== "INVALID" && result.proofs?.status === "VERIFIED"
    : legacyFieldsProven(result.status);
  const declaredFields = result.disclosedFields ?? disclosedFields;
  // Disclosed evidence is labelled by the mode declared with it and is shown only
  // as a record of scalars: an array or an object is not a value this view may
  // print, and nothing here may be coerced into text.
  const fields = proven && isKnownDisclosureMode(result.disclosureMode) && isDisclosedFields(declaredFields)
    ? declaredFields
    : undefined;
  // Warnings are display strings; anything else is dropped rather than rendered.
  const warnings = isWarningList(result.warnings) ? result.warnings : [];
  const anchorSlot = v2 ? result.proofs?.anchorSlot : result.solanaSlot;
  const reported = result.lifecycle?.reported;

  return (
    <section
      className="ol-card"
      aria-labelledby="verification-heading"
      data-testid="verification-result"
      data-status={result.status}
      data-result-version={v2 ? "2" : "1"}
      data-verdict={verdictOf(result.status, !v2)}
    >
      <h2 id="verification-heading">Verification result</h2>
      <p>
        <StatusBadge status={status} testId="verification-status" />
      </p>
      <p data-testid="verification-explanation">{status.explanation}</p>
      {v2 ? null : (
        <p className="ol-error" data-testid="verification-legacy-notice">
          Legacy v1 response. Everything below is a historical proof about the anchored package; it does not
          establish that the record or certificate is current.
        </p>
      )}
      {typeof result.code === "string" ? (
        <p className="ol-muted">
          Reason code: <code data-testid="verification-code">{result.code}</code>
        </p>
      ) : null}
      {v2 && result.checkedAt !== undefined ? (
        <p className="ol-muted">
          Checked at <time data-testid="verification-checked-at" dateTime={result.checkedAt}>{result.checkedAt}</time>
        </p>
      ) : null}
      {warnings.map((warning) => (
        <p key={warning} className="ol-muted" data-testid="verification-warning">{warning}</p>
      ))}
      <dl className="ol-grid">
        <Field label="Cluster" value="solana:devnet" />
        <Field label="Certificate" value={result.certificateId ?? "—"} />
        <Field label="Batch sequence" value={result.batchSequence ?? "—"} />
        <Field label="Anchor slot" value={anchorSlot ?? "—"} />
        <Field label="Record version" value={result.recordVersion ?? "—"} />
      </dl>
      {v2 ? (
        <>
          <h3>Proof and source evidence</h3>
          <p>
            <StatusBadge status={proofs} testId="proofs-status" />
          </p>
          <p className="ol-muted" data-testid="proofs-explanation">{proofs.explanation}</p>
          <p>
            <StatusBadge status={registry} testId="registry-status" />
          </p>
          <p className="ol-muted" data-testid="registry-explanation">
            {registry.explanation}
            {result.registry?.registryId === undefined ? "" : ` Registry: ${result.registry.registryId}.`}
          </p>
          <p>
            <StatusBadge status={incidents} testId="incident-index-status" />
          </p>
          <p className="ol-muted" data-testid="incidents-explanation">{incidents.explanation}</p>
          <dl className="ol-grid">
            <Field label="Indexed through slot" value={result.incidents?.indexedThroughSlot ?? "—"} />
            <Field label="Finalized RPC head" value={result.incidents?.finalizedHeadSlot ?? "—"} />
            <Field label="Index lag (slots)" value={result.incidents?.lagSlots ?? "—"} />
          </dl>
          <p>
            <StatusBadge status={lifecycle} testId="lifecycle-status" />
          </p>
          <p className="ol-muted" data-testid="lifecycle-explanation">{lifecycle.explanation}</p>
          {reported === undefined ? null : (
            <dl className="ol-grid" data-testid="lifecycle-reported">
              <Field label="Reported certificate status" value={reported.certificateStatus ?? "—"} />
              <Field label="Reported current record version" value={reported.currentRecordVersion ?? "—"} />
            </dl>
          )}
        </>
      ) : (
        <>
          <h3>Incident index</h3>
          <p>
            <StatusBadge status={incidents} testId="incident-index-status" />
          </p>
          <p className="ol-muted" data-testid="incidents-explanation">{incidents.explanation}</p>
          <dl className="ol-grid">
            <Field label="Indexed through slot" value={result.indexedThroughSlot ?? "—"} />
            <Field label="Finalized RPC head" value={result.rpcFinalizedHeadSlot ?? "—"} />
            <Field label="Index lag (slots)" value={result.indexLagSlots ?? "—"} />
          </dl>
          <h3>Reported lifecycle (legacy, unverified source)</h3>
          <dl className="ol-grid">
            <Field label="Reported current record version" value={result.currentRecordVersion ?? "unknown"} />
            <Field label="Reported certificate lifecycle" value={result.certificateLifecycle ?? "unknown"} />
          </dl>
        </>
      )}
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
              <Field key={path} label={path} value={displayDisclosedValue(value)} />
            ))}
          </dl>
        </>
      ) : null}
    </section>
  );
}
