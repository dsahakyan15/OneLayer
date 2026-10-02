# CI validation — 2026-10-02

## Failure and fix

PR #1's initial protocol run failed at the verifier typecheck: generated on-chain client source could not resolve `@solana/kit` and `@solana/program-client-core`. The verifier directly imports that sibling package, whose dependencies were installed later in the job. Implicit-any diagnostics were downstream of the missing imports.

The existing `npm ci` step for `packages/onchain-client` now runs immediately after Node setup in the protocol job, before verifier consumers. The browser job already had this order. Generated code, package versions and strict TypeScript checks were not changed.

## Validation before pushing the fix

Validation used the exact PR checkout, not the separate uncommitted application tree, with Node 24.10.0 and npm 11.6.1. Installing only verifier dependencies first reproduced exit 2 and the same missing-module errors. Installing on-chain client dependencies made the verifier typecheck pass.

All 22 run commands of the updated protocol job passed locally:

- Workspace and on-chain Rust tests, clippy with warnings denied, and formatting.
- Merkle (2), canonical (8), verifier (17), snapshot (2), generated client (4) and demo API (68) tests.
- Cross-language E2E: 6 passed, including the 1,000-record differential corpus.
- Verifier, snapshot, generated client and demo API typechecks; generated-client drift check.
- All required package installs from the committed lockfiles.

Browser validation passed web/E2E typechecks, production build, and all 66 desktop/mobile tests. Chromium was installed through Playwright; the host already had system browser libraries, so local validation did not invoke the CI step's apt dependency installation.

The first local Rust lint attempt exhausted space on the system partition. This run's Rust artifacts were moved to DATA. Sharing a target directory between the two Rust workspaces during that workaround then produced a local cached-artifact conflict in cross-language E2E; clearing the registry package artifacts and rerunning resolved it. These interrupted local attempts were not counted as passes. No workaround or shared-target setting was added to CI.

`git diff --check` passed. Application records, credentials, chain publication, backup/restore and deployment were not changed. These results validate the PR and CI fix; they do not establish full launcher readiness. The updated GitHub run must be checked separately after push.
