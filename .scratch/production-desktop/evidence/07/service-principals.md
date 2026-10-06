# Evidence 07: scoped service principals for internal routes

- **Commit:** baseline `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2`, plus the pre-existing uncommitted tree and this slice. Nothing was committed or deployed.
- **Environment:** Linux 6.8.0-106-generic, Node v24.10.0, PostgreSQL 17.10 (Homebrew `pg_ctl`). Disposable clusters come from `integration/support/postgres.ts` and run inside the sandbox; no sandbox override was needed.
- **Test labels:**
  - **[HTTP]**: real `src/main.ts` subprocesses (two at once for cross-process cases), the real CLI as subprocesses, and a loopback synthetic OIDC IdP.
  - **[store]**: `ServicePrincipalStore` / `PostgresSessionStore` against real PostgreSQL, without HTTP.
  - **[route]**: the `routeAdmin` dispatcher against real PostgreSQL, without a TCP server.
  - **[unit]**: pure functions.
- **Network:** no devnet RPC call is made.
- **Dataset:** synthetic only. It is `db/fixtures/devnet-demo.sql`, plus a `demo_anchor` row whose root equals `fixtureRoot()` of that fixture, plus `svc.*` principals and random test secrets. No real credentials or PII.

## Problem and invariant

Before this slice, `/internal/register|reconcile` accepted one static shared bearer. That bearer had no identity, scope, revocation, rotation or audit, and it was active in OIDC mode too.

Invariants now:

- A service principal is a separate durable identity type and never an `AdminSession`.
- Identity, action and registry scope come only from PostgreSQL. Headers, body fields and human cookies never contribute to the decision.
- A revoke or rotation applies to the next authorization check after commit, on any API process.
- For `/internal/register`, the write transaction checks the principal again before inserting.
- A service bearer is refused on non-internal routes. A human cookie is refused on internal routes.
- Excess internal load is refused before any database work.
- A failure is never turned into success.

## Changed interface

The contract is in [admin-access-contract.md](../../../../docs/admin-access-contract.md), section "Service principals for internal routes (2026-09-24, revised after security review)".

- **`src/service-principal.ts`**
  - `ServicePrincipalStore`: `authorize(header, action, registryId, { recordSuccess })`, `revalidate(client, principal)`, `provision`, `rotate`, `revoke`, `initialize`.
  - `ServiceRequestGate`: limits concurrency, per-credential rate and global rate.
  - Helpers: `parseServiceBearer`, `carriesServiceBearer`, `carriesHumanSession`, `auditableRegistryId`, `normalizeServiceScope`.
- **`src/main.ts`**
  - `admitInternal`: rejects a human cookie, checks the bearer syntax strictly (or the legacy token), then applies the gate. None of this reads the body or the DB.
  - `authorizeInternal`, and `internalBody` (400/413 for a bad body).
  - A separate identity pool with at most 2 connections.
  - `ONELAYER_INTERNAL_AUTH` with three values: `service-principal`, `disabled` (the default for the memory backend) and `legacy-demo-token`. In service-principal mode, startup checks for the 0012 schema on every backend.
  - `registerArtifact` calls `revalidate` inside its write transaction.
- **`db/migrations/0012_service_principals.sql`** (not yet applied anywhere except disposable test DBs)
  - Tables: principal, credential (one live credential per principal), event (append-only for UPDATE/DELETE/TRUNCATE; CHECK on `registry_id` format).
  - New table `service_principal_denial_window`.
- **CLI (`scripts/manage-admin-access.ts`)**
  - `service-provision`, `service-rotate`, `service-revoke`.
  - The token file is created with `wx` and mode 0600, then written and fsynced.
  - When the outcome is unknown, the CLI prints `OUTCOME_UNKNOWN`.
- **Review fixes outside the service code**
  - `src/postgres-session.ts`: a critical-role target now gets 404; the device revoke audit now includes `deviceRevision`.
  - `src/admin.ts` (only the `pathSegment` helper at the account access/revoke routes): malformed `%` encoding now gets 400.

## Commands and results

All commands were run 2026-09-24 in `/media/davit/DATA/projects/OneLayer` after the review fixes.

| Command | Result |
|---|---|
| `npm --prefix apps/demo-api run typecheck` | PASS (exit 0) |
| `npm --prefix apps/demo-api test` | 110 PASS, 0 fail, 0 skip. This includes 4 service-principal [unit] tests; the rest of the growth comes from other agents' tests. |
| `node --test --test-concurrency=1 --experimental-transform-types integration/{identity-revocation,service-principal,service-principal-http,oidc,oidc-session,oidc-http,postgres-session,admin-access,durable-admin-http,workflow-access}.test.ts` | 42 PASS, 0 fail, 0 cancelled, 0 skip. Of these, 7 are [store] service-principal tests and 2 are [HTTP]. |
| `npm --prefix apps/demo-api run test:integration` (full, at load ≈ 0.4) | 55 tests: 50 PASS, 5 FAIL, 0 skip. See the note below. |

About the 5 full-suite failures: all 5 are in `workflow-publication-chain.test.ts` and `workflow-publication-validator.test.ts`, which belong to another agent and were modified at 11:17, while this run was in progress. The error is `this.chain.finalizedSlot is not a function`, an interface mismatch in their slice. Every identity, OIDC and service-principal test in that run passed.

A re-run of `npm --prefix apps/demo-api run test:integration` at 11:20, after that agent's change settled, gave **57 PASS, 0 fail, 0 cancelled, 0 skip**. A later typecheck also passed.

Mutation checks:
- I moved the credential read ahead of the principal lock. The [store] EvalPlanQual rotation test then failed with `ALLOWED`. File restored.
- I disabled the revoked-credential and wrong-secret checks. The [store] scope and rotation tests failed. File restored.

## Negative cases

- **Credentials [HTTP]:**
  - Absent bearer: 401.
  - Spoofed `X-Forwarded-User/For/Host`, `X-Real-IP`, `X-OneLayer-Service-Principal`, `X-OneLayer-Role`: 401.
  - The old shared token in service-principal mode: 401.
  - A malformed bearer plus an invalid JSON body: 401, not 400. This shows the credential is checked before the body.
  - Double-space `Bearer`: 401.
  - Valid token with invalid JSON: 400. Valid token with `[]`: 400 `REQUEST_INVALID`.
- **Credential variants [store]:** wrong secret for an existing ID, unknown ID, `bearer`, trailing space or character, `Basic`, a human session ID used as bearer: all 401.
- **Scope [HTTP]:**
  - A register-only token on reconcile: 403. A reconcile-only token on register: 403 at the pre-body check, audited with the deployment registry (round 2 changed this from NULL).
  - A principal scoped to `other.registry`: 403 on both routes. `registryId: other.registry` in the body: 403.
  - Spoofed headers or body `actions` do not widen scope.
- **Scope [store]:** registry values that are malformed, a wildcard or an array get 403. Scope input with a malformed registry, an unknown action or an extra claim is rejected. Direct SQL inserts of a wildcard registry or an unknown action are rejected by constraints.
- **Human and service separation [HTTP]:**
  - A valid OIDC cookie on `/internal/reconcile`: 401, whether alone or together with a valid bearer. The same cookie works on `/v1/admin/session` of the other process.
  - A service bearer on `/v1/admin/session`, `/v1/admin/schema`, `/v2/admin/accounts/alice/revoke` and `/v1/anchors/1`: 401 `SERVICE_PRINCIPAL_NOT_ALLOWED`, with or without a valid cookie.
- **Human and service separation [store]:** a service token is not accepted by `PostgresSessionStore.get`, even when an account with the same name exists.
- **Rotation and revoke [HTTP]:**
  - After a CLI rotate, the old secret gets 401 on both processes and the new secret gets 200 on the other process.
  - After a CLI revoke, the new secret gets 401 on both processes.
- **Rotation and revoke [store]:**
  - Rotating or revoking a revoked principal: 404 (**m6**).
  - A second live credential is rejected by the unique index.
- **Rotation race [store] (m1):** deterministic test. A transaction holds the principal `FOR UPDATE` with the old credential already revoked. An `authorize` on another pool queues behind it. After COMMIT, that `authorize` is refused (`CREDENTIAL_REVOKED`).
- **Revoke race [store]:** 20 authorizations are started concurrently with a revoke. The only thing asserted is that **no authorization after the revoke commits succeeds**, on both pools. Whether the in-flight ones interleave is not asserted.
- **Write-time revalidation [store] (m2):** a register-style write transaction calls `revalidate` and rolls back after a rotation or a revoke. The HTTP register handler calls the same function, but a successful HTTP register was not run because it needs devnet RPC.
- **Flood (M1) [HTTP]:**
  - 80 concurrent reconcile requests with a revoked credential, alongside 10 human `GET /v1/admin/session` requests on the same process.
  - Outcomes: at least 20 requests got 429; all others got 401; all 10 human requests got 200.
  - The per-window denial counter equals the exact number of 401s. Only a bounded number of `CREDENTIAL_REVOKED` events were appended (2–4: one per credential per minute window).
- **Gate [unit]:** concurrency cap (BUSY), per-key burst and refill, global limit, LRU key cap, idempotent release.
- **Audit:**
  - [store] UPDATE, DELETE and TRUNCATE on the event table are refused (**m5**).
  - [store] Only a registry ID with a valid format reaches the audit; hostile text is stored as NULL (**m4**).
  - [store] The pre-body check writes no success event.
  - [store] If the audit insert fails, both allowed and denied requests fail closed (503), and provision, rotate and revoke roll back; the original credential is untouched.
  - [HTTP] The deduplicated event sequence, with reason, action and registry, is asserted.
- **Mode isolation [HTTP]:**
  - `legacy-demo-token` together with OIDC config fails startup. An unknown mode fails startup.
  - `service-principal` mode fails startup both with an unreachable DB and with a reachable DB that lacks 0012, including on the memory backend (**m9**).
  - On the memory backend the default is `disabled`: 503 `SERVICE_AUTH_DISABLED`.
  - In legacy mode: a wrong token, a missing `Bearer` scheme or a cookie get 401; a wrong token with a bad body gets 401 without the body being read; a good token with a bad body gets 400; a foreign registry gets 403; a service bearer on an admin route gets 401.
- **CLI [HTTP/CLI]:**
  - An existing output file is refused and no principal is created. The token file has mode 0600.
  - With an unreachable DB the CLI prints `OUTCOME_UNKNOWN`, exits 1 and removes the file (**m7**).
  - A write or fsync failure after commit was not reproduced by a test; the code path is reviewed only.
- **Human admin fixes [store]/[route]:**
  - A critical-role target in scope gets 404 `ACCOUNT_NOT_FOUND`, the same as a foreign or absent account (**m8**). This applies to both revoke and access change.
  - `%E0%A4%A` and `%ZZ` in revoke paths, and `%E0` in the access PATCH path, get 400 (**NIT**).
  - The device revoke audit contains `deviceRevision: "2"` (**NIT**).

## Real integration / native acceptance

Real components: PostgreSQL 17, two concurrent API processes sharing one DB, the CLI, and the synthetic IdP. An authorized reconcile returns a real 200 `CLEAN`.

Not exercised:
- A successful `/internal/register` over HTTP (it needs devnet RPC).
- A native/desktop client.
- A real service caller; there is no in-repo caller.
- Multi-host rate limits.

## Migration / rollback implications

Migration 0012 is additive: 4 tables, a partial unique index, a trigger function and 3 triggers. It has not been applied to any persistent DB, so it was edited in place after review.

Behaviour changes at startup and in defaults:
- With the PostgreSQL backend in default mode, startup now requires 0012.
- The memory backend now defaults to `disabled` internal routes.
- The shared token works only with `legacy-demo-token`.

`deploy/devnet-demo/native` is unchanged (outside my scope). It still passes `ONELAYER_INTERNAL_TOKEN_FILE`, which is now ignored.

Rollback options:
- Application only: the old binary ignores the new tables.
- Full removal: `DROP TABLE service_principal_denial_window, service_principal_event, service_principal_credential, service_principal; DROP FUNCTION service_principal_event_append_only();`. Export the audit history first.

## Limitations and what was NOT verified

- **Timing:**
  - Only the secret-digest comparison is constant time.
  - An unknown credential ID takes a shorter DB path, so response timing may reveal whether an ID exists. The ID is 128-bit random and not secret.
  - No timing measurement was performed.
- **Revocation boundary:**
  - The check reads live DB state per request with the lock order described in the contract. The statement "every request under FOR SHARE" is withdrawn: the syntactic, cookie and gate refusals happen before the DB.
  - `/internal/reconcile` is not revalidated at write time.
  - Requests already past their final check are not cancelled.
- **Rate limiting:**
  - Limits are per process and in memory; they reset on restart.
  - A caller with many IDs can exhaust the global internal budget. Only internal callers are affected; human routes are not.
  - Denials with an unknown credential ID are neither recorded nor locked out.
- **Audit protection:** triggers do not bind the table owner. The owner/runtime role split is documented in the contract but not implemented.
- **Credentials and provisioning:**
  - Service credentials have no TTL or scheduled rotation, and scope cannot be changed in place.
  - Provisioning `actor` is attribution entered by the operator, not proof of identity.
  - The bearer file is the only factor; there is no mTLS or workload attestation.
- **Not covered:** verifier reads of legacy routes in OIDC mode have no service action. Production IdP, SLA and load, and HA/replica behaviour were not tested.

## Review findings / disposition

Independent security review (coordinator, 2026-09-24): no blocker.

| Finding | Disposition |
|---|---|
| **M1** unbounded denial audit and pool exhaustion | Fixed. `ServiceRequestGate` (concurrency 2, per-credential and global token buckets, LRU key cap) runs before any DB work and returns 429. Internal auth uses a separate pool with at most 2 connections. Denials are aggregated per credential/reason/action/minute, and only the first in a window becomes an append-only event. Tests: [unit] gate, [HTTP] flood with human sessions still at 200. |
| **m1** rotate vs authorize (EvalPlanQual) | Fixed. Fixed lock order: principal `FOR SHARE`, then the credential re-read `FOR SHARE` in a separate statement. Deterministic [store] test; the mutation check fails without the fix. |
| **m2** register side-effect window | Fixed for register: `revalidate` runs in the write transaction ([store] test). For reconcile, the claim is narrowed in the contract. |
| **m3** body read before auth, loose regex, parse error gives 500 | Fixed. Strict parse, then a DB credential+action check, before the body; registry is checked after the body. 400/413 for a bad body. Legacy mode also checks the token first. [HTTP] tests. |
| **m4** untrusted registry text in audit | Fixed. Only a format-valid ID, otherwise NULL, and a DB CHECK enforces it. Scope input uses the same format. [store] test. |
| **m5** TRUNCATE / role split | TRUNCATE trigger added and tested [store]. The owner/runtime split is documented in the contract, not implemented. |
| **m6** revoking a revoked principal succeeds | Fixed with `AND enabled`, otherwise 404. [store] test. |
| **m7** CLI after commit | Fixed. The file is created before the transaction, then written and fsynced after commit. `OUTCOME_UNKNOWN` covers an unknown DB outcome and a write failure after commit. [CLI] test for unreachable DB; the write-failure-after-commit path is not tested. |
| **m8** 403 vs 404 oracle for critical accounts | Fixed. Critical-role targets get 404 `ACCOUNT_NOT_FOUND`. Existing [store] tests were updated and the contract amended. |
| **m9** memory backend skips the 0012 check | Fixed. `service-principal` mode checks at startup on any backend; the memory default is `disabled`. [HTTP] tests with an unreachable DB and with a reachable DB lacking 0012. |
| **NIT** `%` decoding gives 500 | Fixed via the `pathSegment` helper, only at the account access/revoke routes in `admin.ts`. The coordinator's `ledgerDay` import and `dayUtc` change are untouched. [route] tests. |
| **NIT** device revoke audit revision | Fixed. `deviceRevision` is added to the audit JSON (authenticated and trusted revoke paths). [store] assertion. |
| **U1–U7** evidence wording | I did not receive an item-by-item U1–U7 list. I applied the instructions as given: (1) store/HTTP/route/unit labels throughout; (2) "all exercised over real HTTP" removed; (3) "every request under FOR SHARE" corrected; (4) the "20 concurrent racing revoke" claim narrowed to what is asserted; (5) the timing-oracle claim narrowed to the digest comparison; (6) the reconcile revalidation limitation stated; (7) the untested CLI path stated. This section was added. If U1–U7 mean something else, please send the list. |

Author verification: typecheck, unit tests and the focused integration run above. A second independent review of these fixes is still needed, and Execution is not complete.

## Next ticket and handed-off contracts

- Handed off: the contract section and migration 0012.
- **Deploy owner:** set `ONELAYER_INTERNAL_AUTH` in `deploy/devnet-demo/native`, provision a principal if internal routes are needed, and implement the DB owner/runtime role split.
- **Workflow and publication owners:** future internal callers must use scoped principals.
- **Coordinator:** decide on a TTL/rotation policy and on a service action for verifier reads.

## Review round 2 (2026-09-24)

The coordinator's re-review found no blocker. Closed in round 1: M1, m1, m3, m4, m6, m7, m8, m9 and both NITs. m2 is closed for register; m5 is partially closed.

Round-2 findings:

| Finding | Disposition |
|---|---|
| **N2** (low) slow body after pre-check pins the gate | Fixed, two parts. (1) The register pre-check now runs the full check against the deployment registry without recording success, so a principal whose scope has no registry served here is refused with 403 before any body byte. (2) Internal bodies have their own 10 s read timeout (`ONELAYER_INTERNAL_BODY_TIMEOUT_MS`, 100–10000 ms); on timeout the socket is destroyed and the gate slot released. [HTTP]: a raw socket gets 403 with headers only. Two parallel slow bodies with a 1000 ms timeout were closed after 0.9–8 s, and a reconcile on that process then got 200, which shows both slots were released. |
| **N6** (NIT) register field validation gives 500 after RPC | Fixed. `registrationFields()` validates every field before `ensureFixture` and the RPC status call and returns 400 `REQUEST_INVALID`. [HTTP] test: a bad `batchSequence` gives 400, without devnet. |
| **N4** (low) `initialize()` checked one table only | Fixed. It now requires the 4 tables, the unique live-credential index, the enabled `append_only` and `append_only_truncate` triggers, and the validated audit `registry_id` CHECK. [store] test: dropping or disabling each object makes startup fail with `IdentityUnavailableError`; restoring it passes. Not done: comparing the sha256 of the applied migration with the file belongs in the migration runner (`deploy/devnet-demo/native` / `schema_migration`), which is not my file. The runner should record and verify the file digest. |
| **N5** (NIT) CLI leaves an empty token file when pool setup fails | Fixed. The DB URL is read before the token file is created. The file is created inside `try` and removed on any failure before persistence. [CLI] test: with `ONELAYER_DATABASE_URL_FILE` missing, the command exits 1 and no file exists. |
| **N3** contract "Human routes keep the main pool" | Corrected in the contract. Only authorization uses the identity pool; reconcile/register operations use the main pool; isolation comes from the gate's concurrency cap (2 of the main pool's 5). |
| **N1** targeted DoS via a public credential ID | Documented in the contract. Anyone who knows a credential ID can exhaust its per-key bucket and cause 429s for its holder. The ID is part of the bearer and may appear in logs. Recovery is `service-rotate`, which issues a new ID. There is no per-source blocking. |
| **N7** | Recorded as info, no code change. I did not receive its text beyond the "info" classification. |
| Contract lock wording | Corrected. Authorization does an unlocked credential-to-principal lookup, then locks the principal `FOR SHARE`, then re-reads the credential `FOR SHARE`. Rotation uses `SELECT … FOR UPDATE`; revoke takes the row lock through `UPDATE … WHERE enabled`. |
| Contract registry-ID format | Corrected. The full registry-ID format for `service_principal.registry_ids` is enforced in code. The DB only rejects NULL, `*` and the empty string there. The audit `registry_id` column has the full-format CHECK. |

Round-2 commands (2026-09-24):
- `npm --prefix apps/demo-api run typecheck`: PASS.
- `npm --prefix apps/demo-api test`: 116 PASS, 0 fail, 0 skip.
- `node --test --test-concurrency=1 --experimental-transform-types integration/service-principal.test.ts integration/service-principal-http.test.ts integration/identity-revocation.test.ts`: 14 PASS (8 [store] service principal, 2 [HTTP], 4 identity revocation), 0 fail, 0 skip.

The full integration suite was not re-run in round 2. The coordinator asked for the affected files only; the last full run was 57/57 in round 1.

Still not done: a successful HTTP `/internal/register` (needs devnet RPC), the DB role split (m5), migration digest verification (N4, runner owner), service credential TTL, and a service action for verifier reads. Execution stays `claimed`.
