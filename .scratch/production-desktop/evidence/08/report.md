# Evidence 08 — Registry Workflow V1

Commit: working tree above 3b93cd9; uncommitted predecessor changes preserved.
Environment: Linux, Node experimental TypeScript transform, disposable local PostgreSQL clusters using `integration/support/postgres.ts`; no existing DB URL consumed.
Dataset: generated synthetic identities, record payloads and Ed25519 key pairs; no external source or real registry data.

Interface: [workflow contract](../../../../docs/registry-workflow-contract.md). Immutable revision and record version tables, exact revision/hash/base-version approval binding, independent approval, transactional audit/outbox and signed contiguous source event contract.

Checks:
- `npm --prefix apps/demo-api run typecheck` — PASS.
- `node --test --experimental-transform-types apps/demo-api/integration/registry-workflow.test.ts` — PASS, 2 integration tests, 0 failures/skips (19.1s).

Negative scenarios: concurrent edits and record commits, self approval, incorrect hash, edit after approval, commit without approval, reject then commit, forced outbox trigger failure with complete rollback, immutable evidence deletion, duplicate idempotent request and conflicting request, resource-policy narrowing before replay. Source tests cover missing cursor, forged approver signature, self approval, duplicate/equivocation, physical delete rejection, tombstone and stale base-version without cursor advance.

Migration 0010 is additive and does not modify legacy demo tables. Do not roll back by dropping evidence tables after use. Schema version and trusted source signing contract are independent of frozen certificate/on-chain protocols. Outbox delivery bookkeeping must use separate tables in 09.

Limitations: prerequisite 07 is not complete; runtime HTTP wiring is owned by coordinator. No native/desktop acceptance, production IdP/stable-person identity proof, real source adapter, upstream tail high-watermark, permission revocation during a running transaction, durable outbox delivery or on-chain publication is claimed. Local source trust provisioning is a trusted configuration boundary. Legacy demo writers coexist and do not gain approval evidence automatically.

Reviewer: pending independent review; full ticket remains in-review/blocked on dependency07, not complete.

Independent coordinator review (2026-09-20) found three trust-boundary defects; all corrected and regression-tested:
1. Full replacement/tombstone now authorizes fields removed from the prior version as well as submitted fields; creation and commit check current record payload under its row lock, and other transitions check the bound base payload. Restricted writer cannot erase denied fields via `{}`.
2. Empty/dotted object keys are rejected to keep dot-path scope unambiguous, including signed source payloads.
3. Distinct source human IDs cannot share the same Ed25519 public key for approval.

Recheck: typecheck PASS; workflow PostgreSQL integration 2 PASS/0 skip, 8.1s. Additional cases exercise restricted replacement/tombstone creation and commit, dotted-key payload and source approver key alias. Coordinator owns final disposition and shared HTTP integration review.


## Continuation 2026-09-21 — immutable inputs and replay scope

Commit: working tree above 3b93cd9; predecessor changes preserved. Environment: Linux, Node experimental transform-types, PostgreSQL 17.10 disposable clusters, synthetic keys/data only.

Two regressions reproduced against predecessor implementation before fixing:
- Create a draft containing `secret`, edit it to `{}`, narrow the creator's fields to none, replay the creation request. Actual 201, expected 403: current revision authorization failed to cover historical returned evidence. Replay now checks the bound historical revision and base-version payload as well as current draft.
- Start signed ingestion, then mutate caller-owned event payload/record ID/signature while the connection is acquired. Actual record ID `unsigned-target`, expected signed `immutable-input`. Ingestion now canonicalizes and snapshots the envelope before its first await, ensuring verification, version, audit and source evidence use the same immutable input.

Commands:
- `node --experimental-transform-types apps/demo-api/integration/registry-workflow.test.ts` before fixes: 0 PASS / 2 FAIL, both new regression assertions reproduced.
- Same command after fixes and extra source cases: 2 PASS / 0 FAIL / 0 SKIP.
- `npm --prefix apps/demo-api run typecheck`: PASS.

Additional real disposable-PostgreSQL cases: forced cursor-update crash after version/outbox/audit/event inserts rolls every write back including newly allocated record; retry succeeds; simultaneous identical signed event ingestion deduplicates to one version; removal of approver trust denies replay. Synthetic integration does not establish production readiness.

Sandbox run could not start local PostgreSQL; permitted escalation ran isolated Unix-socket clusters successfully. No application database URL or existing cluster was used. No migration or public protocol change. Independent reviewer disposition is pending; prerequisite07 and previously recorded production/native/delivery gaps remain open.

## Continuation 2026-09-24 — scoped version reads and identity integration

Working tree preserved; no deployment or commit. Added scoped historical/latest committed-version API, with explicit COMMITTED state rather than finalized/publication claims. Absent and inaccessible versions/drafts share 404 responses. Request JSON is copied before connection acquisition to bind hashing, authorization and insertion to one input snapshot.

Validation: `node --test --experimental-transform-types apps/demo-api/integration/workflow-access.test.ts` exercises real disposable PostgreSQL and durable OIDC-mode accounts through `routeAdmin`: CSRF, role separation, independent approval, commit, field-restricted historical reads, version bounds, device revocation, and mutation during database acquisition. This calls the dispatcher directly; it is not a native or live HTTP transport acceptance claim.

Independent identity-agent review found no blocking issue; its suggested version2-versus-historical-version field-policy regression was added. Remaining prerequisite, source completeness, in-flight permission revocation and finalized publication gates stay open.

## ADR-0009 exclusion backend verification — 2026-10-01

Existing migration 0017 and maintenance implementation verified by new `apps/demo-api/integration/workflow-version-exclusion.test.ts`; no production exclusion code rewrite was necessary. Real disposable PostgreSQL with all migrations; fake chain only for the worker supersession check. Command `node --test --experimental-transform-types apps/demo-api/integration/workflow-version-exclusion.test.ts`: **3 PASS, 0 failures, 0 skips**.

Negative evidence: absent permission and record scope; author/original approver and case-variant self approval; wrong target/correction binding; absent or unpublishable correction; publishable target; concurrent second approvals; replay after scope revocation; DELETE/TRUNCATE of decision history. Both fresh queue and already claimed blocked operation retain original history and publish only correction membership; supersession signs/sends nothing.

Broader workflow/queue run: 6 PASS, 1 FAIL (the initial two exclusion cases plus existing suites). Existing `registry-workflow.test.ts:20` concurrent edits returned [200,404] instead of [200,409]. Cause: JOIN against the revision while waiting for `FOR UPDATE OF d` can lose the row after a concurrent revision update; this separate baseline defect is not changed by the exclusion test slice. Queue tests passed. No production DB, real chain publication, native UI, issuance or verifier CURRENT lifecycle acceptance is claimed. Independent coordinator review pending; ticket remains in-review.

## Continuation 2026-10-01 — concurrent-edit 404/409 defect closed

Commit: working tree above `3b93cd9`; no commit, no deployment. `apps/demo-api/src/registry-workflow.ts` is an untracked predecessor artifact of the earlier 08 slices; the two-statement lock-then-join below is present in that working file.

Root cause: the edit path used one statement, `SELECT d.*, r.payload, … FROM wf_draft d JOIN wf_revision r ON r.revision = d.revision … FOR UPDATE OF d`. A request that waited on the draft row lock rechecked the updated `wf_draft` row after the winner committed (revision 2), but the join against `wf_revision` still used the pre-wait statement snapshot, so the row was eliminated and the loser was answered `404 DRAFT_NOT_FOUND` instead of `409 REVISION_CONFLICT`.

Fix verified in the working tree: acquire the draft row lock in its own statement, then read the bound revision with a following statement whose snapshot includes the winner's commit. No protocol, DTO or status-code change.

Regression test `apps/demo-api/integration/workflow-concurrency.test.ts` (new) on a disposable PostgreSQL cluster per case; every request goes through the public interface and the interleaving is forced instead of relying on scheduler luck (a `pg_sleep` trigger holds the winner inside its insert, `pg_locks` confirms the loser is blocked before release):
- concurrent edits of one draft answer [200, 409] with `REVISION_CONFLICT`; the draft moves to revision+1, DRAFT, approver NULL; the stored revision payload is exactly the winner's request (no lost update); exactly one revision/audit/request row is added; the refused edit leaves no `wf_version`/`wf_outbox` row and its Idempotency-Key is not recorded.
- a stale revision, an absent expectedRevision (400 `INVALID_VERSION`) and an absent draft (404 `DRAFT_NOT_FOUND` for edit/submit/approve/commit) are distinct domain answers; a committed draft edit answers 409 `ALREADY_COMMITTED`.
- approval binding is intact: wrong-hash approve is 409 `APPROVAL_BINDING_MISMATCH` with zero writes; an edit after approval returns to DRAFT, drops the approver and invalidates the binding; committing with the old binding is 409 `REVISION_CONFLICT`; DRAFT/SUBMITTED commits are 409 `APPROVAL_REQUIRED`; the accepted commit writes exactly one version and one outbox event.
- concurrent commits of two approved drafts on the same base version through the admin dispatcher (`routeAdmin`, durable OIDC sessions) answer [200, 409] `BASE_VERSION_CONFLICT`; exactly one new version/outbox event and one record increment; the loser draft stays APPROVED with `committed_version NULL`, gets no COMMIT audit row and no idempotency record; the retry stays the same 409; missing draft/version reads answer 404 `DRAFT_NOT_FOUND`/`RECORD_VERSION_NOT_FOUND`.

Commands and results:
- `node --test --experimental-transform-types apps/demo-api/integration/workflow-concurrency.test.ts` — 2 PASS / 0 fail / 0 skip.
- Negative reproduction: the pre-fix single-statement join was temporarily restored in `registry-workflow.ts`; the same command failed with `actual: [200,404], expected: [200,409]` at the concurrent-edit assertion, then the file was restored byte-identically (md5 `a6076e580cff6f6d96ad56933adcd27c`) and the suite passed 2/2. The test therefore fails on the recorded defect and passes on the fix.
- Serial workflow suites (`registry-workflow`, `workflow-access`, `workflow-concurrency`, `workflow-version-exclusion`): 9 PASS / 0 fail / 0 skip.
- Publication/queue suites (`workflow-publication`, `workflow-publication-validator`, `workflow-publication-chain`, `publication-ambiguity`): 14 PASS / 0 fail (includes the live local-validator chain case).
- Full disposable-PostgreSQL integration suite (`node --test --test-concurrency=1 --experimental-transform-types apps/demo-api/integration/*.test.ts`, 21 files present in the tree at run time): 72 PASS / 0 fail / 0 cancelled / 0 skip (includes the live local-validator chain and service-principal cases; a sibling agent's newer `snapshot-key-lifecycle.test.ts` was not part of this glob).
- `npm --prefix apps/demo-api run typecheck` PASS; `npm --prefix apps/demo-api test` 124 PASS / 0 fail.

Related class reviewed, no change made: the create/commit head check (`LEFT JOIN wf_version … FOR UPDATE OF h`) can lose `v.payload` the same way during lock recheck. The base-version compare-and-swap in `appendWorkflowVersion` refuses such a transition with 409 (versions only increase), and the commit path re-checks the current head payload under its own lock, so the approximated scope check cannot be committed past. The replay path reads immutable revisions only.

Migration/rollback implications: none — no schema or route change; the tests create and drop synthetic triggers inside disposable clusters.

Limitations: dispatcher-level (`routeAdmin`) rather than live socket HTTP; no production database, commit or deployment; the lock-then-join correction is verified but not yet independently reviewed as part of the uncommitted 08 slice; prerequisite 07, production source high-watermark, native/desktop flows, issuance/verifier CURRENT lifecycle and the independent review remain open. Execution stays in-review.
