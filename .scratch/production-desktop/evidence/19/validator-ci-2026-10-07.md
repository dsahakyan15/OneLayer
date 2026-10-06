# Runnable validator and desktop CI gates — 2026-10-07

Coordinator implementation and verification in `feat/pipeline-live-demo-20261006` (CI commit fb7a80c, main merge 1317f28). Ticket 19 remains claimed; signed bundled installer/update/supply-chain acceptance is not closed.

Independent backend review B2 identified that CI ran validator tests without Agave and forced offline dependency resolution on a clean runner. CI now installs the official [Agave 3.1.10 release](https://github.com/anza-xyz/agave/releases/tag/v3.1.10), checks the Linux archive against SHA-256 `a7205ff29bcf0f7199740225ecae2b85a28ea9668892d5ec21bd9749882984a1`, and pins platform-tools v1.52. The build harness permits dependency fetches and passes `--locked`. The desktop job also installs the web package dependencies required by its real QR decoder.

## Reproduced results

- `bash scripts/ci/install-agave.sh <new absolute temporary directory>`: PASS, exit 0; archive digest checked, solana/validator/build-sbf version 3.1.10, platform-tools 1.52/rustc 1.89.0.
- `node --test --test-concurrency=1 --experimental-transform-types integration/incident-chain.test.ts integration/workflow-publication-validator.test.ts` in apps/demo-api: **2/2 PASS**, no skips, 552.437 seconds.
- Incident test: >100 notices, pagination, finality exclusion, restart/resume, foreign program and CPI events; 335.401 seconds.
- Publication test: durable publication finalized on the local validator after timeout-after-send reconciliation; 153.801 seconds.
- Registry SBF SHA-256: `db0c7203d771ed15b87fa418b810a555446fa991350f9dc7b0c2f39d36618ef9`; foreign fixture SHA-256: `87e783238c81f1c356a2162417f310093ca335700d20447465cfef5bc3066ee5`.
- Clean archived committed checkout fb7a80c: exact npm installs for client/API/verifier passed; client/verifier/deploy typechecks passed. API typecheck failed at the previously reviewed workflow-certificate Cbor text case, whose corrected working-tree file awaits integration with review fixes. This failure is not reported as PASS.
- Merge with main changed documentation file modes/metadata only relative to current source; all 68 conflicts resolved, no active backend/recovery source edits staged, `git diff --check` passed.

These are local chain and lab installer checks. They do not prove devnet deployment, use of a production signer, remote GitHub CI success, signed releases, sustained soak or external production acceptance. The real publication signer and HTTP disclosure/replay review findings remain under a separate repair/review task.
