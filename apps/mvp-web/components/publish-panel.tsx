"use client";

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { admin, ApiError } from "../lib/api";
import { connect, devnetWallets, signTransaction, WalletError, type ConnectedWallet } from "../lib/wallet";
import { useAdminSession } from "./admin-session";
import { describeTransaction, Field, StatusBadge } from "./status";

interface Intent {
  intentId: string;
  state: string;
  batchSequence: string;
  intentHash: string;
  review: any;
  recentBlockhash: string;
  lastValidBlockHeight: string;
  expiresAt: string;
  transactionSignature: string | null;
  anchorSlot: string | null;
  certificateId: string | null;
  failureCode: string | null;
  simulationLogs: string[] | null;
}

interface Issued {
  certificateId: string;
  certificateHash: string;
  qrUrl: string;
  transactionSignature: string;
  anchorSlot: string;
  explorerUrl: string;
  disclosureMode: string;
  disclosedPaths: string[];
  fieldCount: number;
}

const STEPS = ["Prepare", "Simulate", "Review", "Sign", "Finalize", "Issue"] as const;

function stepIndex(state: string | undefined): number {
  switch (state) {
    case "PREPARED": return 1;
    case "SIMULATED": return 2;
    case "SIGNED": return 3;
    case "SUBMITTED": case "UNKNOWN": return 4;
    case "FINALIZED": return 5;
    case "ISSUED": return 5;
    default: return 0;
  }
}

/**
 * Prepare → simulate → review → wallet signature → finalized anchor → certificate.
 * The signature is only requested after a successful simulation, and the
 * certificate button stays disabled until the anchor is finalized.
 */
export function PublishPanel(): ReactNode {
  const { session } = useAdminSession();
  const [wallet, setWallet] = useState<ConnectedWallet | null>(null);
  const [walletNames, setWalletNames] = useState<string[]>([]);
  const [intent, setIntent] = useState<Intent | null>(null);
  const [issued, setIssued] = useState<Issued | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [recordId, setRecordId] = useState("SYNTHETIC-1");
  // Empty means "disclose everything": FULL_RECORD stays the default.
  const [disclosed, setDisclosed] = useState<string[]>([]);
  // One idempotency key per prepared batch: reload and double click reuse it.
  const idempotencyKey = useRef<string>(crypto.randomUUID().replaceAll("-", ""));

  useEffect(() => {
    setWalletNames(devnetWallets().map((candidate) => candidate.name));
  }, []);

  const poll = useCallback(async () => {
    if (session === null || intent === null) return;
    const next = await admin(`/publish-intents/${intent.intentId}/reconciliation`, {
      method: "POST",
      csrfToken: session.csrfToken,
    });
    setIntent(next);
  }, [session, intent]);

  useEffect(() => {
    if (intent === null) return;
    if (intent.state !== "SUBMITTED" && intent.state !== "UNKNOWN") return;
    const timer = setInterval(() => { void poll().catch(() => undefined); }, 3_000);
    return () => clearInterval(timer);
  }, [intent, poll]);

  const readOnly = session?.role !== "operator";

  async function run(action: () => Promise<void>): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (cause) {
      if (cause instanceof ApiError) setError(cause.code);
      else if (cause instanceof WalletError) setError(cause.code);
      else setError("REQUEST_FAILED");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <section className="ol-card">
        <h2>Wallet</h2>
        <p className="ol-muted">
          Wallet Standard only. The panel accepts no keypair file, private key or seed phrase, and
          only a <code>solana:devnet</code> account can sign.
        </p>
        <p data-testid="wallet-list">Detected devnet wallets: {walletNames.length === 0 ? "none" : walletNames.join(", ")}</p>
        <p>
          <button
            type="button"
            disabled={readOnly || busy}
            data-testid="wallet-connect"
            onClick={() => void run(async () => {
              const [candidate] = devnetWallets();
              if (candidate === undefined) throw new WalletError("WALLET_NOT_FOUND");
              setWallet(await connect(candidate));
            })}
          >
            Connect wallet
          </button>
        </p>
        {wallet !== null ? (
          <dl className="ol-grid">
            <Field label="Wallet" value={wallet.walletName} />
            <Field label="Operator address" value={<span data-testid="wallet-address">{wallet.address}</span>} />
          </dl>
        ) : null}
      </section>

      <section className="ol-card">
        <h2>Prepare batch</h2>
        <ol className="ol-steps">
          {STEPS.map((step, index) => (
            <li key={step} aria-current={index === stepIndex(intent?.state) ? "step" : undefined}>{step}</li>
          ))}
        </ol>
        <p>
          <button
            type="button"
            data-variant="primary"
            disabled={readOnly || busy || wallet === null}
            data-testid="prepare-batch"
            onClick={() => void run(async () => {
              if (session === null || wallet === null) return;
              setIssued(null);
              setIntent(await admin("/publish-intents", {
                method: "POST",
                body: { operator: wallet.address, cluster: "solana:devnet" },
                csrfToken: session.csrfToken,
                idempotencyKey: idempotencyKey.current,
              }));
            })}
          >
            Prepare and simulate
          </button>
          {intent !== null ? (
            <>
              {" "}
              <button
                type="button"
                disabled={busy}
                data-testid="new-batch"
                onClick={() => {
                  idempotencyKey.current = crypto.randomUUID().replaceAll("-", "");
                  setIntent(null);
                  setIssued(null);
                }}
              >
                Start a new batch
              </button>
            </>
          ) : null}
        </p>
        {error !== null ? <p className="ol-error" data-testid="publish-error">{error}</p> : null}
      </section>

      {intent !== null ? (
        <section className="ol-card" data-testid="transaction-review" data-state={intent.state}>
          <h2>Transaction review</h2>
          <p>
            <StatusBadge status={describeTransaction(intent.state)} testId="transaction-state" />
          </p>
          <p>{describeTransaction(intent.state).explanation}</p>
          <dl className="ol-grid">
            <Field label="Cluster" value={<span data-testid="review-cluster">{intent.review.cluster}</span>} />
            <Field label="Program ID" value={<span data-testid="review-program">{intent.review.programId}</span>} />
            <Field label="Instruction" value="publish_anchor" />
            <Field label="Registry config" value={intent.review.configPda} />
            <Field label="Operator role PDA" value={intent.review.rolePda} />
            <Field label="Ledger segment PDA" value={<span data-testid="review-segment">{intent.review.segmentPda}</span>} />
            <Field label="Segment index" value={String(intent.review.segmentIndex)} />
            <Field label="Batch sequence" value={intent.batchSequence} />
            <Field label="Merkle root" value={<span data-testid="review-merkle-root">{intent.review.merkleRoot}</span>} />
            <Field label="Manifest hash" value={intent.review.manifestHash} />
            <Field label="Previous anchor hash" value={intent.review.previousAnchorHash} />
            <Field label="Fee payer" value={intent.review.feePayer} />
            <Field label="Recent blockhash" value={intent.recentBlockhash} />
            <Field label="Valid until block height" value={intent.lastValidBlockHeight} />
            <Field label="Intent hash" value={intent.intentHash} />
          </dl>
          <h3>Accounts</h3>
          <table>
            <thead><tr><th>Address</th><th>Signer / writable</th></tr></thead>
            <tbody data-testid="review-accounts">
              {(intent.review.accounts ?? []).map((account: any) => (
                <tr key={account.address}>
                  <td>{account.address}</td>
                  <td>{account.role}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h3>Simulation</h3>
          <p data-testid="simulation-outcome">
            {intent.review.simulation?.ok ? "Simulation succeeded" : `Simulation failed: ${intent.review.simulation?.error ?? "unknown"}`}
            {intent.review.simulation?.unitsConsumed != null ? ` · ${intent.review.simulation.unitsConsumed} CU` : ""}
          </p>
          <pre data-testid="simulation-logs">{(intent.simulationLogs ?? []).join("\n") || "no logs"}</pre>

          <p>
            <button
              type="button"
              data-variant="primary"
              data-testid="sign-transaction"
              disabled={readOnly || busy || wallet === null || intent.state !== "SIMULATED"}
              onClick={() => void run(async () => {
                if (session === null || wallet === null) return;
                let signed: string;
                try {
                  signed = await signTransaction(wallet, intent.review.transactionBase64);
                } catch (cause) {
                  await admin(`/publish-intents/${intent.intentId}/rejection`, {
                    method: "POST",
                    csrfToken: session.csrfToken,
                  }).catch(() => undefined);
                  setIntent(await admin(`/publish-intents/${intent.intentId}`));
                  throw cause instanceof WalletError ? cause : new WalletError("WALLET_REJECTED");
                }
                setIntent(await admin(`/publish-intents/${intent.intentId}/signature`, {
                  method: "POST",
                  body: { signedTransactionBase64: signed },
                  csrfToken: session.csrfToken,
                }));
              })}
            >
              Review complete — request wallet signature
            </button>
            {" "}
            <button
              type="button"
              disabled={busy || (intent.state !== "SUBMITTED" && intent.state !== "UNKNOWN")}
              data-testid="poll-status"
              onClick={() => void run(poll)}
            >
              Check finalization
            </button>
          </p>
          {intent.transactionSignature !== null ? (
            <dl className="ol-grid">
              <Field label="Signature" value={<span data-testid="transaction-signature">{intent.transactionSignature}</span>} />
              <Field label="Anchor slot" value={intent.anchorSlot ?? "pending"} />
            </dl>
          ) : null}
          {intent.failureCode !== null ? <p className="ol-error" data-testid="failure-code">{intent.failureCode}</p> : null}
        </section>
      ) : null}

      {intent !== null && intent.state === "FINALIZED" ? (
        <section className="ol-card">
          <h2>Issue certificate</h2>
          <p className="ol-muted">The anchor is finalized, so a certificate may now be issued.</p>
          <label className="ol-field">
            <span className="ol-label">Record to certify</span>
            <select
              value={recordId}
              onChange={(event) => { setRecordId(event.target.value); setDisclosed([]); }}
              data-testid="certificate-record"
            >
              {(intent.review.records ?? []).map((record: any) => (
                <option key={record.internalRecordId} value={record.internalRecordId}>
                  {record.internalRecordId} · v{record.recordVersion}
                </option>
              ))}
            </select>
          </label>

          <h3>Disclosure</h3>
          <p className="ol-muted">
            Leave every field selected for a <code>FULL_RECORD</code> package. Selecting a subset issues{" "}
            <code>SELECTIVE_FIELDS</code>: the package then carries the values, the salts and a field proof of
            those paths only. The field root, the batch proof and the anchor stay the same.
          </p>
          <ul className="ol-checklist" data-testid="disclosure-fields">
            {((intent.review.records ?? []).find((record: any) => record.internalRecordId === recordId)?.fields ?? []).map((field: any) => {
              const selected = disclosed.length === 0 || disclosed.includes(field.path);
              return (
                <li key={field.path}>
                  <label>
                    <input
                      type="checkbox"
                      checked={selected}
                      data-testid={`disclose-${field.path}`}
                      disabled={readOnly}
                      onChange={(event) => {
                        const all = ((intent.review.records ?? [])
                          .find((record: any) => record.internalRecordId === recordId)?.fields ?? [])
                          .map((entry: any) => entry.path as string);
                        const current = disclosed.length === 0 ? all : disclosed;
                        const next = event.target.checked
                          ? [...new Set([...current, field.path])]
                          : current.filter((path: string) => path !== field.path);
                        setDisclosed(next.length === all.length ? [] : next);
                      }}
                    />
                    {" "}
                    <code>{field.path}</code> = {String(field.value)}
                  </label>
                </li>
              );
            })}
          </ul>
          <p data-testid="disclosure-summary">
            {disclosed.length === 0
              ? "FULL_RECORD — every field of this record version is disclosed."
              : `SELECTIVE_FIELDS — disclosing ${disclosed.length}: ${disclosed.join(", ")}`}
          </p>
          <p>
            <button
              type="button"
              data-variant="primary"
              disabled={readOnly || busy}
              data-testid="issue-certificate"
              onClick={() => void run(async () => {
                if (session === null) return;
                setIssued(await admin(`/publish-intents/${intent.intentId}/certificate`, {
                  method: "POST",
                  body: {
                    internalRecordId: recordId,
                    ...(disclosed.length === 0 ? {} : { disclosedPaths: disclosed }),
                  },
                  csrfToken: session.csrfToken,
                }));
                setIntent(await admin(`/publish-intents/${intent.intentId}`));
              })}
            >
              Issue certificate package
            </button>
          </p>
        </section>
      ) : null}

      {issued !== null ? (
        <section className="ol-card" data-testid="issued-certificate">
          <h2>Issued certificate</h2>
          <dl className="ol-grid">
            <Field label="Certificate ID" value={<span data-testid="issued-id">{issued.certificateId}</span>} />
            <Field label="Certificate hash" value={<span data-testid="issued-hash">{issued.certificateHash}</span>} />
            <Field label="Anchor slot" value={issued.anchorSlot} />
            <Field label="Signature" value={issued.transactionSignature} />
          </dl>
          <p>
            <a href={issued.qrUrl} data-testid="issued-qr-url">{issued.qrUrl}</a>
          </p>
          <p>
            <a href={issued.explorerUrl} target="_blank" rel="noreferrer" data-testid="explorer-link">
              Open in Solana Explorer (devnet)
            </a>
          </p>
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src={`/api/public/qr/${issued.certificateId}.svg`}
            alt={`QR code for certificate ${issued.certificateId}`}
            width={220}
            height={220}
            data-testid="issued-qr-image"
          />
          <p>
            <button
              type="button"
              data-testid="copy-qr-url"
              onClick={() => void navigator.clipboard?.writeText(issued.qrUrl)}
            >
              Copy certificate URL
            </button>
            {" "}
            <a className="ol-button" href={`/api/public/qr/${issued.certificateId}.svg`} download>
              Download QR (SVG)
            </a>
          </p>
        </section>
      ) : null}
    </>
  );
}
