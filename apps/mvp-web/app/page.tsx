import Link from "next/link";
import type { ReactNode } from "react";

export default function HomePage(): ReactNode {
  return (
    <main className="ol-shell">
      <h1>OneLayer devnet MVP</h1>
      <p>
        Two panels over one frozen protocol: an operator-facing Admin panel that anchors registry
        records on Solana devnet, and a public panel that verifies the certificates it issues.
      </p>
      <div className="ol-nav">
        <Link className="ol-button" href="/verify" data-testid="link-verify">Verify a certificate</Link>
        <Link className="ol-button" href="/admin" data-testid="link-admin">Admin panel</Link>
        <Link className="ol-button" href="/how-it-works" data-testid="link-how-it-works">How it works</Link>
      </div>
      <section className="ol-card">
        <h2>The flow</h2>
        <ol>
          <li>a certificate arrives as JSON or CSV and is validated against the registry schema;</li>
          <li>its fields become commitments, the records become a batch with one Merkle root;</li>
          <li>an operator reviews the devnet transaction and signs it with a wallet;</li>
          <li>after finalization a signed certificate package and its QR code are issued;</li>
          <li>anyone scanning the QR gets the anchored data checked against the chain.</li>
        </ol>
      </section>
      <section className="ol-card">
        <h2>Boundaries</h2>
        <p>
          The chain stores the batch <code>merkleRoot</code> and <code>manifestHash</code>. The
          certificate hash is never written on chain: the package binds itself to the anchor through
          the issuer signature and the Merkle proof.
        </p>
        <p className="ol-muted">
          Synthetic data, devnet only, test keys only. This demo is not an access-control or
          production identity system.
        </p>
      </section>
    </main>
  );
}
