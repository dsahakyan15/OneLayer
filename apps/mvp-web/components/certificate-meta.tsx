"use client";

import { useEffect, useState, type ReactNode } from "react";
import { Field } from "./status";

export interface CertificateMetadata {
  certificateId: string;
  registryId: string;
  cluster: string;
  status: string;
  issuedAt: string;
  recordVersion: string;
  certificateHash: string;
  qrUrl: string;
  disclosureMode: string;
  disclosedPaths: string[];
  batchSequence: string;
  anchorSlot: string;
  transactionSignature: string;
  merkleRoot: string;
  manifestHash: string;
  explorerUrl: string;
}

export async function loadCertificateMetadata(certificateId: string): Promise<CertificateMetadata> {
  const response = await fetch(`/api/public/certificates/${certificateId}/metadata`, { cache: "no-store" });
  if (!response.ok) throw new Error("METADATA_FAILED");
  return await response.json() as CertificateMetadata;
}

/**
 * The certificate as an artifact: which anchor it points at, how much of the
 * record it discloses and the QR that carries it. Field values are not shown
 * here — they come from the verified package, never from this endpoint.
 */
export function CertificateMeta({
  metadata,
  downloads = false,
}: {
  metadata: CertificateMetadata;
  downloads?: boolean;
}): ReactNode {
  return (
    <section className="ol-card" data-testid="certificate-meta">
      <h2>Certificate artifact</h2>
      <dl className="ol-grid">
        <Field label="Certificate" value={metadata.certificateId} />
        <Field label="Registry" value={metadata.registryId} />
        <Field label="Cluster" value={metadata.cluster} />
        <Field label="Issued at" value={new Date(metadata.issuedAt).toISOString()} />
        <Field label="Record version" value={metadata.recordVersion} />
        <Field label="Disclosure" value={<span data-testid="meta-disclosure">{metadata.disclosureMode}</span>} />
        <Field label="Disclosed paths" value={(metadata.disclosedPaths ?? []).join(", ") || "all"} />
        <Field label="Certificate hash" value={metadata.certificateHash} />
        <Field label="Batch sequence" value={metadata.batchSequence} />
        <Field label="Merkle root" value={metadata.merkleRoot} />
        <Field label="Manifest hash" value={metadata.manifestHash} />
        <Field label="Anchor slot" value={metadata.anchorSlot} />
        <Field label="Signature" value={metadata.transactionSignature} />
      </dl>
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src={`/api/public/qr/${metadata.certificateId}.svg`}
        alt={`QR code for certificate ${metadata.certificateId}`}
        width={200}
        height={200}
        data-testid="certificate-qr"
      />
      <p>
        <a className="ol-button" href={metadata.explorerUrl} target="_blank" rel="noreferrer" data-testid="meta-explorer">
          Open the anchor transaction on Solana Explorer (devnet)
        </a>
        {downloads ? (
          <>
            {" "}
            <a className="ol-button" href={`/api/public/qr/${metadata.certificateId}.png`} download>Download QR (PNG)</a>
            {" "}
            <a className="ol-button" href={`/api/public/qr/${metadata.certificateId}.svg`} download>Download QR (SVG)</a>
            {" "}
            <a className="ol-button" href={metadata.qrUrl}>Open public page</a>
          </>
        ) : null}
      </p>
    </section>
  );
}

/** Loads the metadata itself; used where no parent already has it. */
export function CertificateMetaPanel({ certificateId }: { certificateId: string }): ReactNode {
  const [metadata, setMetadata] = useState<CertificateMetadata | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    loadCertificateMetadata(certificateId).then(setMetadata).catch(() => setFailed(true));
  }, [certificateId]);

  if (failed) {
    return (
      <p className="ol-muted" data-testid="certificate-meta-unavailable">
        Certificate metadata is unavailable. The verification result above does not depend on it.
      </p>
    );
  }
  if (metadata === null) return <p role="status">Loading certificate metadata…</p>;
  return <CertificateMeta metadata={metadata} />;
}
