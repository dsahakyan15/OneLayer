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
