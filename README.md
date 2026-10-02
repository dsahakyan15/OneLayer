# OneLayer MVP

## Current implementation status — 2026-10-02

The full English desktop launcher is unfinished. Its normal startup exposes only Overview, Connection and local service checks; it cannot configure a connection, sign in or open role workspaces. Separate web/API modules are partially implemented, but workflow publication/certificate handoff and real full-state restore remain incomplete.

See [what works and what remains](docs/implementation-status-2026-10-02.md) and the [usage-pipeline review](.scratch/production-desktop/evidence/launcher-usage-pipeline-review-2026-10-02.md). This documents the local working tree; this documentation-only PR does not ship the uncommitted implementation. The demo flow below describes the legacy devnet pilot, not a completed desktop application.

OneLayer is a verifiable land-registry pilot for Solana devnet. It validates a
record, builds a Merkle batch, anchors the batch on-chain, issues a signed
certificate package, and verifies that package independently through a QR code.
The MVP also demonstrates encrypted local snapshots and bounded `3-of-5`
recovery.

## How it works

1. An operator imports JSON or CSV data using the closed `land-registry-v1`
   schema.
2. OneLayer canonicalizes the fields and builds record, field, and batch proofs.
3. The operator reviews and signs a devnet transaction with a Wallet Standard
   wallet.
4. After the anchor is `FINALIZED`, OneLayer issues a signed certificate and QR.
5. A registry worker uses the internal verifier to check the signature, proofs,
   finalized anchor, and incident index.

QR is available only while the on-chain `RegistryConfig` exists and has
`paused = false`. Issuance, internal QR endpoints, and verification fail closed
when the registry is paused.

## Access boundary

OneLayer is an internal registry site, not a public website. The site and its
Admin, QR, certificate-package, metadata, and verification endpoints must be
reachable only from managed registry workstations through the registry's private
network or VPN. Public internet ingress is forbidden.

Banks, notaries, buyers, and other external parties do not access the site
directly, even when they have a QR code. A registry worker performs the check
from an authorized workstation and shares the approved result through the
organization's process. Network/device restrictions complement user sessions
and roles; they do not replace RBAC.

## Components

- `onchain/` — Anchor registry program and IDL.
- `crates/` and `packages/` — canonicalization, Merkle proofs, certificates,
  snapshots, and the generated Solana client.
- `apps/demo-api/` — Admin API and snapshot/recovery control plane.
- `apps/verifier/` — independent certificate verifier.
- `apps/mvp-web/` — internal Admin and verification UI.
- `spec/` — frozen protocol documents and test vectors.

## Run the demo

```bash
./deploy/devnet-demo/native start
```

- Admin: <http://127.0.0.1:8091/admin>
- Verification: <http://127.0.0.1:8091/verify> (registry workstation only)
- Status: `./deploy/devnet-demo/native status`
- Stop: `./deploy/devnet-demo/native stop`

The native demo binds to loopback, so it is reachable only from the machine
running it. A deployed environment must enforce the same boundary with private
network/VPN access, managed-device controls, and no public ingress. The demo
uses synthetic data, Solana devnet, and test keys; it is not a production
identity system or a production restore drill.

## Test

```bash
cargo test --all
cargo test --manifest-path onchain/Cargo.toml
npm --prefix apps/demo-api test
npm --prefix apps/verifier test
npm --prefix tests/e2e-web test
npm --prefix packages/onchain-client run check-drift
```

See [MVP_IMPLEMENTATION_PLAN.md](MVP_IMPLEMENTATION_PLAN.md) for the MVP scope
and [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for the long-term plan.

The next implementation track is documented in the Russian
[application pipeline](docs/application-pipeline-ru.md): a role-scoped desktop
application, verifier hardening, independent monitoring, and real recovery.
It includes an [AI-agent runbook](docs/agents/implementation-runbook.md) and
[24 dependency-ordered tasks](.scratch/production-desktop/index.md).
These documents describe planned work, not features already shipped by the MVP.

Текущая реализация и границы готовности: [что работает и что осталось](docs/implementation-status-2026-10-02.md). Исторический отчёт: [первый этап защиты verifier/index](docs/implementation-progress-2026-09-19.md).
