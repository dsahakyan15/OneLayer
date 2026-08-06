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
5. A verifier checks the signature, proofs, finalized anchor, and incident index.

QR is available only while the on-chain `RegistryConfig` exists and has
`paused = false`. Issuance, public QR endpoints, and independent verification
fail closed when the registry is paused.

## Components

- `onchain/` — Anchor registry program and IDL.
- `crates/` and `packages/` — canonicalization, Merkle proofs, certificates,
  snapshots, and the generated Solana client.
- `apps/demo-api/` — Admin API and snapshot/recovery control plane.
- `apps/verifier/` — independent certificate verifier.
- `apps/mvp-web/` — Admin and public verification UI.
- `spec/` — frozen protocol documents and test vectors.

## Run the demo

```bash
./deploy/devnet-demo/native start
```

- Admin: <http://127.0.0.1:8091/admin>
- Verification: <http://127.0.0.1:8091/verify>
- Status: `./deploy/devnet-demo/native status`
- Stop: `./deploy/devnet-demo/native stop`

The demo uses synthetic data, Solana devnet, and test keys. It is not a
production identity system or a production restore drill.

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
