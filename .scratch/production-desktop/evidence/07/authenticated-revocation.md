# 07 — Authenticated account and device revocation

Date: 2026-09-24. Baseline commit: `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2` plus pre-existing working tree changes. No commit or deployment performed.
Environment: Linux, Node v24.10.0, disposable PostgreSQL via `isolatedPostgres`; synthetic accounts only.

Previously account/device revoke was available only through trusted provisioning methods. The OIDC Identity Admin can now revoke a scoped noncritical account or one device through authenticated backend routes, without supplying a trusted actor name. This is a partial local implementation of ticket 07, not production acceptance.

Interface: [admin access contract](../../../../docs/admin-access-contract.md). POST account/device revoke requires exact Origin, session, CSRF and optimistic revision. Account and device revision semantics are explicitly distinct. Shared transactional actor authorization is used by both assignment and revoke; critical roles and self changes remain forbidden. Device audit records deviceId. No migration required; existing 0008/0009 tables and audit JSON are used.

Negative cases: foreign/absent account indistinguishability, substituted device ID, self-management, critical role, worker acting as Identity Admin, stale and malformed revisions, revoked actor device, wrong Origin, missing CSRF/session, injected actor and numeric revision. Audit failure rolls back both revoke variants. Racing login cannot leave a valid session after committed revoke. Independent DB connection verifies invalidation and preservation of unrelated device sessions.

Commands/results (final checks run 2026-09-24 by the identity agent on the same dirty tree; synthetic data, disposable PostgreSQL 17.10 clusters started by `isolatedPostgres` inside the sandbox — no skip):

- `npm --prefix apps/demo-api run typecheck`: PASS.
- `npm --prefix apps/demo-api test`: 99 PASS, 0 fail, 0 skip (before the service-principal slice).
- `npm --prefix apps/demo-api run test:integration` (before the service-principal slice): 39 tests, 38 PASS, 1 FAIL, 0 skip. All four `identity-revocation.test.ts` cases PASS (foreign/absent indistinguishability, self/critical/stale/revoked actor; device vs account revoke across a second pool; audit rollback + racing login; route session/CSRF/Origin/exact body). The single failure was `registry-workflow.test.ts` "workflow binds independent approval…" (`[200,404]` vs `[200,409]`), in a file owned by a concurrently working agent that was modified the same day; it is outside this slice and passed in later runs.
- Re-run after the service-principal slice (see [service-principals.md](service-principals.md)): `test:integration` 52 PASS, 0 fail, 0 skip, including the four revocation cases above.

Limitations: route dispatcher tests use real PostgreSQL but do not start a TCP server; previous OIDC integration uses real HTTP test IdP. No corporate IdP, managed native device attestation, production revocation SLA, service principal policy, administrative listing/UI, or final mutation/signing revalidation was exercised. Revocation boundary is the next authorization read after commit; already authorized operations are not cancelled.

Review: coordinator review requested for backend/routes; complete acceptance remains open. Rollback requires application rollback only; no DB schema changes. Historical evidence remains available in report.md and oidc-device-admission.md.

2026-09-24 update after the security review:
- m8: a critical-role target in the actor's scope now returns 404 `ACCOUNT_NOT_FOUND`, the same as an absent or foreign account. It no longer returns 403.
- NIT: malformed percent-encoding in the path now returns 400, not 500.
- NIT: the device revoke audit now records `deviceRevision`.

The four `identity-revocation.test.ts` cases were updated and pass in the focused serial run (42/42). Details: [service-principals.md](service-principals.md#review-findings--disposition).
