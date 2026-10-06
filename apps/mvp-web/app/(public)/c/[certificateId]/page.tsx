import Link from "next/link";
import { notFound } from "next/navigation";
import type { ReactNode } from "react";
import { CertificateMetaPanel } from "../../../../components/certificate-meta";
import { ScanPanel } from "../../../../components/scan-panel";

interface PageProps {
  params: Promise<{ certificateId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

/** QR landing page: the hash from the code is required, not optional. */
export default async function CertificatePage({ params, searchParams }: PageProps): Promise<ReactNode> {
  const { certificateId } = await params;
  const query = await searchParams;
  const qrHash = typeof query.h === "string" ? query.h : "";
  if (!/^[0-9a-f]{32}$/.test(certificateId)) notFound();
  const bound = /^[A-Za-z0-9_-]{43}$/.test(qrHash);
  return (
    <main className="ol-shell">
      <div className="ol-nav">
        <Link href="/verify">← Check another certificate</Link>
        <Link href="/how-it-works">How this works</Link>
      </div>
      <h1>Certificate {certificateId}</h1>
      {bound
        ? <ScanPanel initial={{ certificateId, qrHash }} />
        : <p className="ol-error" data-testid="qr-hash-missing">
            This link carries no certificate hash, so the QR binding cannot be checked. Scan the code again.
          </p>}
      {/* Metadata about the artifact. The field values above come from the
          package the verifier checked, never from this endpoint. */}
      {bound ? <CertificateMetaPanel certificateId={certificateId} /> : null}
    </main>
  );
}
