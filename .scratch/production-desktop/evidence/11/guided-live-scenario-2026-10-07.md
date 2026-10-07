# Guided live scenario — 2026-10-07

The GTK acceptance check used the real local validator, PostgreSQL, demo API and
verifier. A clean export of the selected PR files also ran its own demo API and
passed `bash ./deploy/devnet-demo/live-demo check-scenario`; no fixture transport,
fake chain or mock signer was used in that walkthrough.

One full business scenario is executable: create → submit → different approver →
commit → exact-plan review and explicit confirmation → finalized publication →
selective certificate/QR → verification → JSON export and re-verification.
Three tested branches are rejection/correction, forbidden worker approval
(actual HTTP 403), and tampered package (INVALID / QR_HASH_MISMATCH).
The native file chooser was used for the JSON export.

Public evidence from the clean walkthrough:

- Record: `DEMO-bf874f84ee06`; draft revision 2, record version 1.
- Operation: `f81514a1-413a-4094-979a-001f920b1bd4`.
- Finalized slot: `50964`.
- Signature: `2kiBzxSQZASQnBXovH9DmwA3X48C3X6PihvQ9BsZyhbPPmeqEwBxQUHMeDTb4UdV5aAL1HstRwyYcfA8p3rZ8xVu`.
- Certificate: `7307ec9be179be5091c3629ebd4b5f2c`.
- Proofs: `VERIFIED`; registry: `CHECKED`.
- Overall/current suitability: `UNKNOWN`; lifecycle source:
  `UNAUTHENTICATED`; incident index: `STALE`.

The proof pass does not assert current suitability. The retained incident-history
cursor was pruned during this long-lived lab session; it remains visibly STALE,
and V2 intentionally reports UNKNOWN for current suitability. No index, trust
watermark, record or ledger was reset to make this appear current.

Fixes found by the real walkthrough: missing workflow adapter helpers and health
JSON decoder import; new-record baseVersion=0; configured role usernames ending
in -1; durable lease renewal and targeted reclaim; field-map disclosure paths
payload.*; projection and trust policy support for initial registry version 0;
local-cluster explorer suppression; bounded retry of transient reconciliation.

Checks passed: clean API TypeScript check; 221 clean API unit tests; 6 clean
PostgreSQL integration tests; 295 full Python desktop tests (including GTK interaction); 85 verifier tests. No skips.

Validation artifacts remain under `/tmp/onelayer-orchestration-20261006/`:
`scenario-clean-command-check.log`, `scenario-clean-api-tests-final.log`,
`scenario-clean-typecheck-final.log`, `scenario-clean-pg-tests-r2.log`,
`scenario-python-tests.log`, `scenario-verifier-tests.log`,
`scenario-launcher-tests.log`. The initial walkthrough's public screenshots, JSON report
and exported certificate are under `/tmp/onelayer-scenario-proof-04jffvcp/`.

Recovery schemas 0023/0025 are included as retained-database prerequisites; this
change does not accept the pending full recovery-controller/runtime pipeline.
The native profile starts separate audit/monitor processes. Full critical-event
API wiring and scoped audit API routes remain separate, uncommitted integration
work; process readiness is not claimed as their acceptance. Production gates,
signed installed release and elapsed soak remain open.

## Retained-history correction

Repeated verification exposed pruning with the earlier 10,000-shred test ledger:
an older certificate returned ANCHOR_NOT_FOUND after its transaction disappeared.
The verifier was not bypassed. Local retention is now 1,000,000 shreds; the
active ledger stays retained on DATA and must not be cleared as build cache.
Already-pruned transactions are not reconstructed.

A full clean-source local launch retained the same genesis, program SHA256,
authorities, PostgreSQL records, keys and trust floor and reached READY with the
new validator limit. Its new GTK walkthrough passed all branches and export:
`scenario-clean-full-launch-final.log`, `scenario-retained-command-check.log`,
`/tmp/onelayer-scenario-proof-l0aza_ge/`. Finalized slot 52056, operation
69f9d790-18d1-4315-b085-cc477581f5f7. The clean web dependency copy was required
because Turbopack rejects a node_modules symlink outside its filesystem root;
no product source was changed to bypass that check.

The new certificate `4a6b61333f2412853022e3d4bd18964f` was fetched and verified
again when the finalized head reached slot 52589 (533 slots after its publication
at 52056): proofs remained VERIFIED, registry CHECKED, package hash MATCH.
`scenario-retained-proof-recheck.json` records the real V2 response. Overall
current suitability remains UNKNOWN and the retained incident index remains
STALE; neither condition was hidden or upgraded.
