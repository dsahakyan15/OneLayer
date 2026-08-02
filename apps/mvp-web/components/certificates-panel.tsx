"use client";

import { useEffect, useState, type ReactNode } from "react";
import { admin } from "../lib/api";
import { CertificateMeta, loadCertificateMetadata, type CertificateMetadata } from "./certificate-meta";

interface CertificateRow {
  certificateId: string;
  batchSequence: string;
  status: string;
  issuedAt: string;
  qrUrl: string;
  internalRecordId: string | null;
  recordVersion: string | null;
  certificateHash: string;
  disclosureMode: string;
  disclosedPaths: string[];
}

/** Issued certificates with their disclosure, QR artifact and anchor. */
export function CertificatesPanel(): ReactNode {
  const [rows, setRows] = useState<CertificateRow[]>([]);
  const [selected, setSelected] = useState<CertificateMetadata | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    admin("/certificates")
      .then((body) => setRows(body.certificates))
      .catch(() => setError("LOAD_FAILED"));
  }, []);

  async function open(certificateId: string): Promise<void> {
    setError(null);
    try {
      setSelected(await loadCertificateMetadata(certificateId));
    } catch {
      setError("METADATA_FAILED");
    }
  }

  return (
    <>
      <section className="ol-card">
        <h2>Issued certificates</h2>
        {error !== null ? <p className="ol-error">{error}</p> : null}
        <table>
          <thead>
            <tr>
              <th>Certificate</th><th>Record</th><th>Batch</th><th>Status</th><th>Disclosure</th><th>Issued</th><th>QR link</th>
            </tr>
          </thead>
          <tbody data-testid="certificates-table">
            {rows.map((row) => (
              <tr key={row.certificateId} data-status={row.status}>
                <td>
                  <button
                    type="button"
                    data-testid={`certificate-open-${row.certificateId}`}
                    onClick={() => void open(row.certificateId)}
                  >
                    {row.certificateId}
                  </button>
                </td>
                <td>{row.internalRecordId ?? "—"}{row.recordVersion === null ? "" : ` v${row.recordVersion}`}</td>
                <td>{row.batchSequence}</td>
                <td>{row.status}</td>
                <td data-testid={`certificate-disclosure-${row.certificateId}`}>
                  {row.disclosureMode === "SELECTIVE_FIELDS"
                    ? `SELECTIVE_FIELDS (${(row.disclosedPaths ?? []).join(", ")})`
                    : "FULL_RECORD"}
                </td>
                <td>{new Date(row.issuedAt).toISOString()}</td>
                <td><a href={row.qrUrl}>open</a></td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 ? <p className="ol-muted">No certificates yet.</p> : null}
      </section>

      {selected !== null ? (
        <div data-testid="certificate-detail">
          <CertificateMeta metadata={selected} downloads />
          <p>
            <button type="button" onClick={() => setSelected(null)} data-testid="certificate-detail-close">Close</button>
          </p>
        </div>
      ) : null}
    </>
  );
}
