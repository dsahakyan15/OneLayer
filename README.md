# OneLayer MVP

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
