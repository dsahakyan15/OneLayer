# Verification V2: contract and client increment

Date: 2026-10-01. Coordinator plus DeepSeek v4.1 Flash agents with max reasoning. This is bounded evidence for ticket 05; production acceptance remains open.

The existing V2 producer now has an exported typed result contract. Its client selects V2 explicitly, without automatic fallback to V1, and separates historical inclusion from current suitability. ACTIVE advisory data remains UNKNOWN. REVOKED and HISTORICAL are conservative advisory outcomes; DISPUTED takes precedence. Invalid signatures/trust/proofs do not trigger lifecycle lookup or disclose package fields. Lifecycle versions outside u64 are rejected as unusable. The application UI and errors are English.

Producer regression coverage includes missing/error/mismatched/rolled-back/out-of-u64 lifecycle data, blocking incidents, incomplete/stale incident observations and invalid signatures. Focused verifier verify/server tests: 26 PASS, typecheck PASS. Final broad checks and independent review are recorded in the continuation report rather than predeclared here.

The composed test `tests/e2e/service-verifier-read.test.ts` runs the actual OIDC API and V2 HTTP verifier with an isolated PostgreSQL database and real scoped service credentials. It checks ACTIVE→UNKNOWN, REVOKED, newer version→HISTORICAL and live credential revocation→UNKNOWN/unavailable. ChainReader and incident observations are controlled test fixtures: this is not live on-chain issuance or proof of lifecycle completeness. The earlier composed run passed 1 test; final rerun after the latest main/session changes is recorded separately.

The shared test-only child preload `tests/helpers/local-network-only.mjs` rejects external fetch dispatch and redirects before importing API main. Its self-probe must reject an external URL before the child starts listening. This prevents the demo refresh interval from reaching devnet during synthetic HTTP tests.

Contract: [verification-result-v2-contract.md](../../../../docs/verification-result-v2-contract.md). Browser fixture screenshot: V2 UNKNOWN view (локальный артефакт: `../../../../tests/e2e-web/evidence/v2-unknown-view.png`; не включён в документационный PR). Browser fixture evidence is distinct from the real API integration above.

Open gate: independently authenticated, complete and fresh lifecycle state connected to real issuance/revocation and rollback protection. No CURRENT verdict is implemented or claimed.

2026-10-02: strict runtime string status checking was added after a malformed array verdict reproduced an accepted response. Array/object/null/number cases now discard the envelope before badges/disclosure. Final public verification browser suite 36/36 PASS (desktop/mobile); typechecks/build PASS. [Final continuation report](../continuation-2026-10-01.md).

Final 2026-10-02 disposition: DeepSeek max review/cross-review completed; original findings corrected and validated. Coordinated affected browser suites 92/92 PASS, focused key/checksum 9/9 PASS, additional selective/scalar/retry coverage PASS. Full production/restart acceptance remains open. See [final continuation report](../continuation-2026-10-01.md).
