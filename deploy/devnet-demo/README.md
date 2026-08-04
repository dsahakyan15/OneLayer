# OneLayer presentation devnet demo

This stack is fixed to Compose project `onelayer-devnet-demo`, PostgreSQL database `onelayer_demo`, Solana devnet, loopback-only host ports, synthetic records, and tmpfs test keys. It never targets mainnet, reads production credentials, publishes external artifacts, prunes Docker, or deletes resources outside its labeled project.

## Approval boundary

`./deploy/devnet-demo/demo plan` builds locally and prints two stable digests:

- `program-plan.txt`: program deployment summary and `approval_digest`;
- `chain-plan.txt`: registry/bootstrap/publish summary and `approval_digest`.

No Solana transaction is sent by `plan`. After those exact summaries are explicitly approved, run the full path with the two digest values:

```bash
ONELAYER_DEVNET_DEPLOY_APPROVED=<program-approval-digest> \
ONELAYER_DEVNET_TX_APPROVED=<chain-approval-digest> \
./deploy/devnet-demo/demo happy-path
```

The program deploy keeps Solana CLI preflight enabled; each registry/bootstrap/publish transaction is explicitly simulated before send and confirmed at `finalized` commitment. The payer and program test keypair live under `/dev/shm/onelayer-devnet-demo`, never in Git.

## Presentation flow

```bash
# finalized transaction -> certificate -> QR -> VERIFIED
./deploy/devnet-demo/demo happy-path

# direct synthetic PostgreSQL mutation -> incident -> DISPUTED
./deploy/devnet-demo/demo incident

# optional clean-room restore -> recomputed root equals finalized anchor
./deploy/devnet-demo/demo recovery

# data-only reset; does not delete containers, volumes, images, or chain state
./deploy/devnet-demo/demo reset
```

Artifacts are written under ignored `deploy/devnet-demo/artifacts/`. The QR SVG is `certificate-qr.svg`; its payload opens the loopback verification page, which submits the embedded certificate package to the verifier and requires a finalized devnet anchor.

## Visual MVP (§5.4)

The same guarded Compose project serves the two panels; only one UI port is
added and the loopback-only binding, labels, networks, tmpfs keys and synthetic
marker are unchanged.

```bash
./deploy/devnet-demo/demo ui
# Admin panel:    http://127.0.0.1:8091/admin
# OneLayer panel: http://127.0.0.1:8091/verify
# Demo credentials: /dev/shm/onelayer-devnet-demo/admin-credentials.json
```

`operator` prepares batches, reviews the transaction, requests the wallet
signature and issues certificates; `auditor` is read-only, and that limit is
enforced by the Admin API, not by hiding buttons. Credentials, the software
issuer key and the payer keypair are generated per run into tmpfs.

Two publish paths coexist and do not substitute for each other:

- CLI publish keeps the `ONELAYER_DEVNET_TX_APPROVED` approval digest;
- browser publish requires a reviewed click, a Wallet Standard prompt and
  server-side validation that the signed wire transaction matches the stored
  intent byte for byte.

Program deploy and upgrade stay CLI-only with their own approval digest.

The browser needs a Wallet Standard wallet on `solana:devnet` with the operator
role. No keypair file, private key or seed phrase is ever accepted by the UI.

## Browser tests

```bash
# deterministic, runs in default CI, spends no SOL and needs no Docker
npm --prefix tests/e2e-web test

# guarded live devnet smoke: separate explicit approval, run once before a
# presentation or release
APPROVE_ONELAYER_LIVE_DEVNET_SMOKE=yes \
ONELAYER_DEVNET_DEPLOY_APPROVED=<program-approval-digest> \
ONELAYER_DEVNET_TX_APPROVED=<chain-approval-digest> \
./deploy/devnet-demo/scripts/live-smoke
```

The live smoke verifies a certificate that the guarded CLI publish anchored, so
no key material enters the browser. Evidence lands in
`deploy/devnet-demo/artifacts/live-smoke/`.

## Gate C exit evidence

The release evidence runner stores machine-readable JSON, command logs, and the
human-readable report under `deploy/devnet-demo/artifacts/gate-c/`. It stops at
the preflight boundary when the host is not ready and records remediation
instead of starting a partial pilot:

```bash
./deploy/devnet-demo/scripts/release-report collect
```

After the guarded bootstrap has been approved and the demo services are up, a
72-hour synthetic run can be started. The additional soak approval is separate
from the deploy and transaction approvals:

```bash
APPROVE_ONELAYER_SOAK=yes \
  ./deploy/devnet-demo/scripts/soak start
```

For a local diagnostic run, `ONELAYER_SOAK_CYCLES` may limit the number of
cycles; that report remains `INCOMPLETE` until its finalized timestamps cover
the required 72 hours. Gate C accepts the default hourly run only when its
`soak.jsonl` contains at least 73 finalized cycles. Starting over from an existing JSONL marks the first
new cycle as manual intervention, so it cannot produce a clean no-manual Gate C
verdict. A completed run records `anchor_sequence_gap_total`,
the rebuilt `manifestHash`, incident-index watermark/status, and open/resolved
incident observations in `soak.jsonl`. Re-rendering an existing report is
read-only:

```bash
./deploy/devnet-demo/scripts/soak report
./deploy/devnet-demo/scripts/release-report report
```

The release report is explicitly classified as `BOUNDED_SYNTHETIC_MVP`. It
does not claim geographically independent Backup Centers, a production restore drill,
production recovery readiness, or closure of release gate 7. Live-devnet
evidence is accepted only after the separately approved `live-smoke` produces
`artifacts/live-smoke/evidence.json` with `finalized_anchor=true` and
`key_material_in_browser=false`. Browser traces/screenshots are retained in
the report's separate `browser-*` and `backup-*` artifact directories.

To collect that step as part of the report, set
`RUN_ONELAYER_LIVE_SMOKE=yes`; `live-smoke` still requires its own
`APPROVE_ONELAYER_LIVE_DEVNET_SMOKE=yes` and the two existing approval digests.

## QR transport

The normative QR transport is HTTPS. The only exception in this demo is the
exact loopback origin `http://127.0.0.1:8091`, visibly marked
`DEVNET SYNTHETIC DEMO`; any other HTTP URL is rejected. A phone cannot open the
demo host's loopback address, so responsive layout and the camera flow are
checked in a fresh browser context on the same host. Cross-device scanning needs
a separately approved HTTPS staging environment and is outside this stack.
