"use client";

import Link from "next/link";
import { useEffect, useState, type ReactNode } from "react";
import { admin } from "../lib/api";
import { Field } from "./status";
import { useAdminSession } from "./admin-session";

interface Dashboard {
  registryId: string;
  cluster: string;
  schemaId: string;
  records: { total: string; versions: string; imported: string };
  certificates: { byStatus: Record<string, number>; selective: number };
  lastAnchor: {
    batchSequence: string;
    anchorSlot: string;
    transactionSignature: string;
    merkleRoot: string;
    finalizedAt: string;
    explorerUrl: string;
  } | null;
  openIncidents: string;
  intents: Record<string, number>;
}

/** Every number here is a query result, not a placeholder. */
export function AdminDashboard(): ReactNode {
  const { session } = useAdminSession();
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    admin("/dashboard").then(setData).catch(() => setError("LOAD_FAILED"));
  }, []);

  const certificates = data === null
    ? 0
    : Object.values(data.certificates.byStatus).reduce((total, count) => total + count, 0);

  return (
    <>
      <section className="ol-card">
        <h2>Dashboard</h2>
        {error !== null ? <p className="ol-error" data-testid="dashboard-error">{error}</p> : null}
        <dl className="ol-grid" data-testid="dashboard-metrics">
          <Field label="Cluster" value={data?.cluster ?? "solana:devnet"} />
          <Field label="Registry" value={data?.registryId ?? "—"} />
          <Field label="Record schema" value={data?.schemaId ?? "—"} />
          <Field label="Role" value={session?.role ?? "—"} />
          <Field label="Records" value={<span data-testid="metric-records">{data?.records.total ?? "…"}</span>} />
          <Field label="Record versions" value={data?.records.versions ?? "…"} />
          <Field label="Imported through the UI" value={data?.records.imported ?? "…"} />
          <Field
            label="Issued certificates"
            value={<span data-testid="metric-certificates">{data === null ? "…" : certificates}</span>}
          />
          <Field label="Selective disclosures" value={data === null ? "…" : data.certificates.selective} />
          <Field label="Open on-chain incidents" value={<span data-testid="metric-incidents">{data?.openIncidents ?? "…"}</span>} />
        </dl>
      </section>

      <section className="ol-card">
        <h2>Last finalized anchor</h2>
        {data?.lastAnchor == null ? (
          <p className="ol-muted" data-testid="dashboard-no-anchor">
            Nothing has been anchored yet. Prepare a batch to publish the first Merkle root on devnet.
          </p>
        ) : (
          <>
            <dl className="ol-grid" data-testid="dashboard-anchor">
              <Field label="Batch sequence" value={data.lastAnchor.batchSequence} />
              <Field label="Anchor slot" value={data.lastAnchor.anchorSlot} />
              <Field label="Merkle root" value={data.lastAnchor.merkleRoot} />
              <Field label="Signature" value={data.lastAnchor.transactionSignature} />
              <Field label="Finalized at" value={new Date(data.lastAnchor.finalizedAt).toISOString()} />
            </dl>
            <p>
              <a
                className="ol-button"
                href={data.lastAnchor.explorerUrl}
                target="_blank"
                rel="noreferrer"
                data-testid="dashboard-explorer"
              >
                Open in Solana Explorer (devnet)
              </a>
            </p>
          </>
        )}
      </section>

      <section className="ol-card">
        <h2>Next step</h2>
        <p>
          {session?.role === "operator"
            ? (
              <>
                <Link className="ol-button" href="/admin/records" data-testid="dashboard-records">
                  Enter or import a certificate
                </Link>
                {" "}
                <Link className="ol-button" href="/admin/publish" data-testid="dashboard-publish">
                  Prepare and publish a batch
                </Link>
              </>
            )
            : <span className="ol-muted" data-testid="dashboard-readonly">
                The auditor role can read records, certificates and the timeline, but cannot prepare a
                batch, request a signature or issue a certificate.
              </span>}
        </p>
      </section>
    </>
  );
}
