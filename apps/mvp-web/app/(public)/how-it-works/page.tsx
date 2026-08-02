import Link from "next/link";
import type { ReactNode } from "react";

/**
 * Public explainer: what the chain stores, what it does not, and what a green
 * result does and does not prove. Written for someone who scanned a QR code.
 */
export default function HowItWorksPage(): ReactNode {
  return (
    <main className="ol-shell">
      <div className="ol-nav">
        <Link href="/">← Home</Link>
        <Link href="/verify">Check a certificate</Link>
      </div>
      <h1>How this verification works</h1>

      <section className="ol-card">
        <h2>1. The registry record becomes a commitment</h2>
        <p>
          Every field of a record — status, cadastral number, area, right type — is hashed together with a
          secret per-record salt into a <code>field_commitment</code>. Those commitments form a Merkle tree
          whose root is the <code>fieldRoot</code> of the record version.
        </p>
        <p className="ol-muted">
          The salt means the commitment cannot be brute-forced back into the value, even though the set of
          possible values is small.
        </p>
      </section>

      <section className="ol-card">
        <h2>2. Records become a batch, the batch becomes one hash</h2>
        <p>
          Record commitments are combined into a second Merkle tree. Its root — the{" "}
          <code>merkleRoot</code> — together with the manifest hash is what a single Solana transaction
          writes on devnet. One transaction covers the whole batch, no matter how many records it holds.
        </p>
      </section>

      <section className="ol-card">
        <h2>3. What Solana stores</h2>
        <ul className="ol-checklist">
          <li>✔ <span><code>merkleRoot</code> and <code>manifestHash</code> of the batch</span></li>
          <li>✔ <span>the anchor chain: each batch references the previous anchor hash</span></li>
          <li>✔ <span>who published it and when, as recorded by the program</span></li>
          <li>✖ <span>no field values, no names, no addresses, no certificate hash</span></li>
        </ul>
        <p className="ol-muted">
          Personal data never leaves the registry. What is public is a hash that only matches data someone
          already has.
        </p>
      </section>

      <section className="ol-card">
        <h2>4. What the QR code carries</h2>
        <p>
          The QR encodes a URL, the certificate ID and the certificate hash — nothing else. The hash binds
          the code to one exact package: swapping the package for another one fails before any chain lookup.
        </p>
      </section>

      <section className="ol-card">
        <h2>5. What checking a certificate proves</h2>
        <ol>
          <li>the issuer signature over the package is valid;</li>
          <li>the disclosed values, with their salts, rebuild the <code>fieldRoot</code>;</li>
          <li>the record commitment, with the Merkle proof, rebuilds the <code>merkleRoot</code>;</li>
          <li>that root is in a finalized Solana transaction, in the account the certificate names;</li>
          <li>no open incident covers this batch, and the incident index proved its own freshness.</li>
        </ol>
        <p>
          If all five hold, the certificate shows exactly the data that was anchored — and a green result is
          only shown when the last one holds too.
        </p>
      </section>

      <section className="ol-card">
        <h2>Boundaries</h2>
        <p>
          The anchor proves that the data has not changed since publication. It does not prove that the data
          was correct when the registry entered it: correctness stays the registry&apos;s responsibility.
        </p>
        <p className="ol-muted">
          This deployment is a devnet demo on synthetic data with test keys. It is not a production identity
          or access-control system.
        </p>
      </section>
    </main>
  );
}
