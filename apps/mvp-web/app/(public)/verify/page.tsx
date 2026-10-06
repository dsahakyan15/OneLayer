import Link from "next/link";
import type { ReactNode } from "react";
import { ScanPanel } from "../../../components/scan-panel";

export default function VerifyPage(): ReactNode {
  return (
    <main className="ol-shell">
      <div className="ol-nav">
        <Link href="/">← Home</Link>
      </div>
      <h1>OneLayer verification</h1>
      <p>
        Scan the QR code, upload a photo of it, or paste the certificate URL or package. The check
        runs against the finalized Solana devnet anchor and the incident index.
      </p>
      <ScanPanel />
    </main>
  );
}
