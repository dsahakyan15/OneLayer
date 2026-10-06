# Ticket 11 — English RegistryWorkflow workspace

Date: 2026-10-01. DeepSeek v4.1 Flash / max reasoning workers; coordinator integration. Bounded implementation, not full ticket acceptance.

`/admin/workflow` uses actual V2 workflow routes for draft creation (upsert/tombstone), read by UUID, revision edits, submission, independent approval/rejection and commit. Controls use server session permissions and deployment registry metadata, never inferred role grants. Approval/commit binds the server revision, payload hash and base version. An uncertain mutation retry preserves its idempotency key; changed input uses a new logical attempt. A 409 stops further actions until explicit reload and review. COMMITTED is database workflow state and never a published certificate or finalized chain verdict. All visible copy is English.

The browser fixture suite covers writer, independent approver, read-only and missing metadata flows, exact revision conflicts, self-approval denial, tombstones and uncertain retry. Full desktop/mobile suite at the initial final freeze: 94 PASS. Web and browser typechecks and production build PASS. Subsequent scope-hardening checks and independent review appear in the continuation report. Screenshot: workflow workspace (локальный артефакт: `../../../../tests/e2e-web/evidence/workflow-workspace.png`; не включён в документационный PR).

`tests/e2e/workflow-http.test.ts` exercises actual API main over sockets with a disposable PostgreSQL database and test OIDC IdP: identity/device enrollment, three independent principals with explicit LAND field grants, login/session metadata, create/edit/submit/approve/commit, stale revision and wrong-hash refusals, idempotent replay, read-only write denials, indistinguishable absent/hidden 404s, CSRF/Origin denial and live account/device revocation. Five worker runs passed; coordinator final rerun is recorded separately. The shared test preload prevents external fetch and redirects.

The real HTTP writer cannot hold approval permission due the server role ceiling, so its own approval fails PERMISSION_FORBIDDEN. The deeper SELF_APPROVAL contributor guard is exercised by the existing module integration; the over-provisioned browser self-approval fixture is explicitly a test variant. No reachable production configuration is claimed from that fixture.

Open: all other native role workspaces, reconnect/restart operation recovery, actual signer/publication/issuance, trusted lifecycle completeness, production IdP/device provisioning and recovery integration. This is web workspace plus actual backend evidence, not installed native UI or live-chain issuance acceptance.

2026-10-02 continuation: exact registry-scope gating and two create/edit retry defects were corrected and regression-tested. Final workspace suite 22/22 PASS on desktop/mobile; web/browser typechecks and production build PASS. [Detailed disposition and logs](../continuation-2026-10-01.md).

Final 2026-10-02 disposition: DeepSeek max review/cross-review completed; original findings corrected and validated. Coordinated affected browser suites 92/92 PASS, focused key/checksum 9/9 PASS, additional selective/scalar/retry coverage PASS. Full production/restart acceptance remains open. See [final continuation report](../continuation-2026-10-01.md).
