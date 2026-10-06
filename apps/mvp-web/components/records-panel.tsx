"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { admin, ApiError } from "../lib/api";
import { useAdminSession } from "./admin-session";
import { Field } from "./status";

interface SchemaField {
  path: string;
  type: "text" | "decimal" | "timestamp" | "bool" | "hex";
  required: boolean;
  label: string;
  values: string[] | null;
  maxBytes: number | null;
  scale: number | null;
  example: string;
  hint: string;
}

interface RecordField {
  path: string;
  type: string;
  value: string;
}

interface RecordRow {
  internalRecordId: string;
  recordVersion: string;
  status: string;
  origin: string;
  sourceCursor: string;
  schemaId: string;
  fields: RecordField[];
}

interface RecordDetail {
  internalRecordId: string;
  recordVersion: string;
  status: string;
  origin: string;
  schemaId: string;
  recordIdCommitment: string;
  fieldRoot: string;
  recordCommitment: string;
  batchLeafHash: string;
  fields: Array<{ path: string; value: string | null; fieldCommitment: string; fieldLeafIndex: number }>;
  certificates: Array<{
    certificateId: string;
    status: string;
    issuedAt: string;
    disclosureMode: string;
    disclosedPaths: string[];
    recordVersion: string;
  }>;
}

interface Preview {
  merkleRoot: string;
  manifestHash: string;
  previousAnchorHash: string;
  batchSequence: string;
  leafCount: number;
  records: Array<{
    internalRecordId: string;
    recordVersion: string;
    recordIdCommitment: string;
    fieldRoot: string;
    recordCommitment: string;
    batchLeafHash: string;
    disclosedFields: Record<string, string>;
    fields: Array<{ path: string; value: string | null; fieldCommitment: string; fieldLeafIndex: number }>;
  }>;
}

interface ImportReport {
  schemaId: string;
  dryRun: boolean;
  accepted: Array<{ row: number; internalRecordId: string; status: string; fields: RecordField[] }>;
  rejected: Array<{ row: number; code: string; path: string | null }>;
  applied: Array<{ row: number; internalRecordId: string; recordVersion: string }>;
}

const CSV_EXAMPLE = [
  "internalRecordId,status,cadastralNumber,parcelAddress,areaSquareMeters,rightType",
  "SYNTHETIC-11,ACTIVE,01-004-0123-045,\"Yerevan, Arshakunyats 12\",1250.50,OWNERSHIP",
].join("\n");

/**
 * Wizard, JSON/CSV import and canonical preview. The field set comes from the
 * certificate the user supplies; the form is rendered from the schema the API
 * serves, so the browser is never a second source of truth about it.
 */
export function RecordsPanel(): ReactNode {
  const { session } = useAdminSession();
  const [schema, setSchema] = useState<SchemaField[]>([]);
  const [records, setRecords] = useState<RecordRow[]>([]);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [detail, setDetail] = useState<RecordDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [recordId, setRecordId] = useState("SYNTHETIC-11");
  const [values, setValues] = useState<Record<string, string>>({});
  const [format, setFormat] = useState<"json" | "csv">("json");
  const [content, setContent] = useState("");
  const [report, setReport] = useState<ImportReport | null>(null);

  const reload = useCallback(async () => {
    const [list, canonical] = await Promise.all([admin("/records"), admin("/preview")]);
    setRecords(list.records);
    setPreview(canonical);
  }, []);

  useEffect(() => {
    admin("/schema")
      .then((body) => {
        setSchema(body.fields);
        setValues(Object.fromEntries(
          (body.fields as SchemaField[])
            .filter((field) => field.required)
            .map((field) => [field.path, field.example]),
        ));
      })
      .catch(() => setError("SCHEMA_LOAD_FAILED"));
  }, []);

  useEffect(() => { void reload().catch(() => setError("LOAD_FAILED")); }, [reload]);

  const readOnly = session?.role !== "operator";

  async function run(action: () => Promise<void>): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (cause) {
      setError(cause instanceof ApiError ? `${cause.code} ${cause.message === cause.code ? "" : cause.message}`.trim() : "REQUEST_FAILED");
    } finally {
      setBusy(false);
    }
  }

  function jsonExample(): string {
    const fields = Object.fromEntries(
      schema.filter((field) => field.required).map((field) => [field.path, field.example]),
    );
    return JSON.stringify({ internalRecordId: "SYNTHETIC-12", fields }, null, 2);
  }

  return (
    <>
      <section className="ol-card">
        <h2>Registry records</h2>
        <p className="ol-muted">
          Schema <code data-testid="schema-id">{records[0]?.schemaId ?? "land-registry-v1"}</code>. A path outside the
          schema is rejected as <code>CANONICALIZATION_FAILED</code>; nothing is silently dropped.
        </p>
        <table>
          <thead>
            <tr>
              <th>Record</th><th>Version</th><th>Status</th><th>Fields</th><th>Origin</th><th>Cursor</th>
              <th><span className="ol-visually-hidden">Actions</span></th>
            </tr>
          </thead>
          <tbody data-testid="records-table">
            {records.map((row) => (
              <tr key={row.internalRecordId}>
                <td>{row.internalRecordId}</td>
                <td>{row.recordVersion}</td>
                <td>{row.status}</td>
                <td>{row.fields.length + 1}</td>
                <td>{row.origin}</td>
                <td>{row.sourceCursor}</td>
                <td>
                  <button
                    type="button"
                    data-testid={`record-open-${row.internalRecordId}`}
                    onClick={() => void run(async () => setDetail(await admin(`/records/${row.internalRecordId}`)))}
                  >
                    Details
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {detail !== null ? (
        <section className="ol-card" data-testid="record-detail">
          <h2>Record {detail.internalRecordId} · version {detail.recordVersion}</h2>
          <dl className="ol-grid">
            <Field label="Status" value={detail.status} />
            <Field label="Origin" value={detail.origin} />
            <Field label="Schema" value={detail.schemaId} />
            <Field label="recordIdCommitment" value={detail.recordIdCommitment} />
            <Field label="fieldRoot" value={<span data-testid="detail-field-root">{detail.fieldRoot}</span>} />
            <Field label="recordCommitment" value={detail.recordCommitment} />
            <Field label="batch leaf" value={detail.batchLeafHash} />
          </dl>
          <h3>Fields and their commitments</h3>
          <table>
            <thead><tr><th>#</th><th>Path</th><th>Value</th><th>field_commitment</th></tr></thead>
            <tbody data-testid="detail-fields">
              {detail.fields.map((field) => (
                <tr key={field.path}>
                  <td>{field.fieldLeafIndex}</td>
                  <td>{field.path}</td>
                  <td>{field.value}</td>
                  <td>{field.fieldCommitment}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h3>Certificates of this record</h3>
          {detail.certificates.length === 0 ? <p className="ol-muted">None issued yet.</p> : (
            <table>
              <thead><tr><th>Certificate</th><th>Version</th><th>Status</th><th>Disclosure</th><th>Issued</th></tr></thead>
              <tbody data-testid="detail-certificates">
                {detail.certificates.map((certificate) => (
                  <tr key={certificate.certificateId}>
                    <td>{certificate.certificateId}</td>
                    <td>{certificate.recordVersion}</td>
                    <td>{certificate.status}</td>
                    <td>
                      {certificate.disclosureMode === "FULL_RECORD"
                        ? "FULL_RECORD"
                        : `SELECTIVE_FIELDS: ${certificate.disclosedPaths.join(", ")}`}
                    </td>
                    <td>{new Date(certificate.issuedAt).toISOString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p><button type="button" onClick={() => setDetail(null)} data-testid="detail-close">Close</button></p>
        </section>
      ) : null}

      <section className="ol-card">
        <h2>Enter a certificate</h2>
        {readOnly ? (
          <p className="ol-muted" data-testid="records-readonly">
            The auditor role is read-only. The Admin API refuses this operation regardless of the UI.
          </p>
        ) : null}
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void run(async () => {
              if (session === null) return;
              const fields = Object.fromEntries(
                Object.entries(values).filter(([, value]) => value.trim().length > 0),
              );
              await admin("/records", {
                method: "POST",
                body: { internalRecordId: recordId, fields },
                csrfToken: session.csrfToken,
              });
              setDetail(await admin(`/records/${recordId}`));
              await reload();
            });
          }}
        >
          <label className="ol-field">
            <span className="ol-label">Internal record ID</span>
            <input
              value={recordId}
              onChange={(event) => setRecordId(event.target.value)}
              data-testid="record-id"
              disabled={readOnly}
            />
          </label>
          <div className="ol-grid">
            {schema.map((field) => (
              <label className="ol-field" key={field.path}>
                <span className="ol-label">
                  {field.label}
                  {field.required ? " *" : ""} · <code>{field.path}</code>
                </span>
                {field.values !== null ? (
                  <select
                    value={values[field.path] ?? ""}
                    onChange={(event) => setValues({ ...values, [field.path]: event.target.value })}
                    data-testid={`field-${field.path}`}
                    disabled={readOnly}
                  >
                    <option value="">—</option>
                    {field.values.map((value) => <option key={value} value={value}>{value}</option>)}
                  </select>
                ) : (
                  <input
                    value={values[field.path] ?? ""}
                    placeholder={field.example}
                    onChange={(event) => setValues({ ...values, [field.path]: event.target.value })}
                    data-testid={`field-${field.path}`}
                    disabled={readOnly}
                  />
                )}
                <span className="ol-muted">{field.hint}</span>
              </label>
            ))}
          </div>
          <p>
            <button type="submit" data-variant="primary" disabled={busy || readOnly} data-testid="record-submit">
              Save record
            </button>
          </p>
        </form>
      </section>

      <section className="ol-card">
        <h2>Import certificates (JSON or CSV)</h2>
        <p className="ol-muted">
          A dry run validates without writing anything. Every rejected row is reported with its number and
          the path that failed.
        </p>
        <div className="ol-nav" role="group" aria-label="Import format">
          <button type="button" aria-pressed={format === "json"} data-testid="import-format-json" onClick={() => setFormat("json")}>JSON</button>
          <button type="button" aria-pressed={format === "csv"} data-testid="import-format-csv" onClick={() => setFormat("csv")}>CSV</button>
        </div>
        <label className="ol-field">
          <span className="ol-label">
            {format === "json" ? "One record object or an array of them" : "First line names the field paths"}
          </span>
          <textarea
            rows={8}
            value={content}
            onChange={(event) => setContent(event.target.value)}
            data-testid="import-content"
            disabled={readOnly}
            placeholder={format === "json" ? jsonExample() : CSV_EXAMPLE}
          />
        </label>
        <p>
          <button
            type="button"
            data-testid="import-example"
            disabled={readOnly}
            onClick={() => setContent(format === "json" ? jsonExample() : CSV_EXAMPLE)}
          >
            Insert example
          </button>
          {" "}
          <button
            type="button"
            disabled={busy || readOnly}
            data-testid="import-dry-run"
            onClick={() => void run(async () => {
              if (session === null) return;
              setReport(await admin("/records/import", {
                method: "POST",
                body: { format, content, dryRun: true },
                csrfToken: session.csrfToken,
              }));
            })}
          >
            Validate (dry run)
          </button>
          {" "}
          <button
            type="button"
            data-variant="primary"
            disabled={busy || readOnly}
            data-testid="import-apply"
            onClick={() => void run(async () => {
              if (session === null) return;
              setReport(await admin("/records/import", {
                method: "POST",
                body: { format, content, dryRun: false },
                csrfToken: session.csrfToken,
              }));
              await reload();
            })}
          >
            Import
          </button>
        </p>
        {report !== null ? (
          <div data-testid="import-report">
            <p>
              {report.dryRun ? "Dry run: " : "Imported: "}
              <strong data-testid="import-accepted">{report.accepted.length}</strong> accepted,{" "}
              <strong data-testid="import-rejected">{report.rejected.length}</strong> rejected.
            </p>
            {report.rejected.length > 0 ? (
              <table>
                <thead><tr><th>Row</th><th>Reason</th><th>Path</th></tr></thead>
                <tbody data-testid="import-rejections">
                  {report.rejected.map((rejection) => (
                    <tr key={`${rejection.row}-${rejection.code}-${rejection.path ?? ""}`}>
                      <td>{rejection.row}</td>
                      <td>{rejection.code}</td>
                      <td>{rejection.path ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : null}
            {report.accepted.length > 0 ? (
              <table>
                <thead><tr><th>Row</th><th>Record</th><th>Status</th><th>Fields</th></tr></thead>
                <tbody data-testid="import-accepted-rows">
                  {report.accepted.map((entry) => (
                    <tr key={entry.row}>
                      <td>{entry.row}</td>
                      <td>{entry.internalRecordId}</td>
                      <td>{entry.status}</td>
                      <td>{entry.fields.map((field) => `${field.path}=${field.value}`).join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : null}
          </div>
        ) : null}
        {error !== null ? <p className="ol-error" data-testid="records-error">{error}</p> : null}
      </section>

      <section className="ol-card">
        <h2>Canonical preview</h2>
        <p className="ol-muted">
          Commitments computed from the current records. No <code>certificateHash</code> exists yet:
          it appears only after a finalized anchor and an issued package.
        </p>
        {preview === null ? <p role="status">Building preview…</p> : (
          <>
            <dl className="ol-grid" data-testid="preview-summary">
              <Field label="Next batch sequence" value={preview.batchSequence} />
              <Field label="Leaf count" value={preview.leafCount} />
              <Field label="Merkle root" value={preview.merkleRoot} />
              <Field label="Manifest hash" value={preview.manifestHash} />
              <Field label="Previous anchor hash" value={preview.previousAnchorHash} />
            </dl>
            <table>
              <thead>
                <tr>
                  <th>Record</th><th>Fields</th><th>recordIdCommitment</th><th>fieldRoot</th><th>recordCommitment</th><th>batch leaf</th>
                </tr>
              </thead>
              <tbody data-testid="preview-records">
                {preview.records.map((record) => (
                  <tr key={record.internalRecordId}>
                    <td>{record.internalRecordId} v{record.recordVersion}</td>
                    <td>{Object.entries(record.disclosedFields).map(([path, value]) => `${path}=${value}`).join(", ")}</td>
                    <td>{record.recordIdCommitment}</td>
                    <td>{record.fieldRoot}</td>
                    <td>{record.recordCommitment}</td>
                    <td>{record.batchLeafHash}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </section>
    </>
  );
}
