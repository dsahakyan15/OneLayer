# Demo admin access: контракт локального среза 07

2026-09-20. Контракт существующего synthetic admin API, не production identity protocol. [Первый срез](../.scratch/production-desktop/evidence/07/report.md) и [durable sessions evidence](../.scratch/production-desktop/evidence/07/durable-sessions.md).

Каждый data handler `/v1/admin/*` требует server session, разрешение операции и точный `context.registryId` в session.registryIds. На mutation дополнительно действует CSRF. Login не принимает role/permissions/registry scope от клиента. Session inspection и logout разрешены самой сессии независимо от data grants.

| Permission | Операции |
|---|---|
| records.read | schema, records list/detail, preview |
| records.draft | создание и импорт synthetic records |
| publication.read | intent detail и preview |
| publication.prepare | создание publish intent |
| publication.submit | signature, reconciliation, rejection |
| certificates.read | admin certificate list |
| certificates.issue | issuance из finalized intent |
| backups.read | centers/snapshots overview/detail |
| backups.create | center creation/health, snapshot refresh/retry |
| recovery.read | operation list/detail |
| recovery.initiate | prepare recovery |
| recovery.approve | Restore Approval, только chief_admin |
| recovery.cutover | существующий demo restore handler, только operator |
| audit.read | timeline |

Permission авторизует операцию вместе с ее ответом. Preview требует records.read и publication.read. Dashboard требует все шесть read permissions, поскольку возвращает общие счетчики. Разрешение recovery.cutover не меняет существующие ограничения demo restore: полное восстановление еще не реализовано.

Default synthetic policy сохраняет поведение demo: все три роли получают read permissions; operator получает mutation permissions кроме recovery.approve; chief_admin получает recovery.approve; auditor не получает mutation permissions. Явные grants могут только сужать роль. Production роли и field/object scope вводятся отдельно; возвращаемый подписанный Certificate Package нельзя редактировать для маскировки полей.

## Deployment credentials

Существующий `ONELAYER_ADMIN_CREDENTIALS_FILE` по-прежнему принимает объект `role: password`. Для ограниченного доступа значение может быть объектом:

```json
{
  "operator": {
    "password": "synthetic-example-password-only",
    "permissions": ["records.read"],
    "registryIds": ["gov.registry.land"]
  },
  "auditor": "another-synthetic-example-password"
}
```

Это пример формата, не рекомендуемые пароли. Имена demo accounts остаются operator/auditor/chief_admin. Отсутствующие permissions означают compatibility permissions роли, отсутствующие registryIds — только gov.registry.land. Пустые массивы запрещают доступ. Null, wildcard registry, неверные типы, неизвестные поля и permissions выше role ceiling отклоняются при startup. Файл читается при запуске. В PostgreSQL режиме его grants используются только для первого создания аккаунта; существующие права и блокировки из БД не перезаписываются при restart. Пароли по-прежнему проверяются по файлу. Изменение пароля само по себе не отзывает уже выданные сессии: для этого используется управление доступом.

## Долговечное хранение

По умолчанию `main.ts` использует `PostgresSessionStore`. Native launcher явно задает `ONELAYER_SESSION_BACKEND=postgres`. Перед запуском требуется миграция `0008_admin_identity.sql`; отсутствующая/недоступная identity schema прерывает startup. `memory` остается явным режимом isolated synthetic tests; автоматического fallback нет.

Таблицы `demo_admin_account`, `demo_admin_session`, `demo_admin_access_event` хранят grants/enabled/access_revision, SHA-256 случайного 256-bit session token, CSRF token/TTL и transactional provisioning events. Raw session token и passwords в БД не записываются. TTL — 30 минут, expiry проверяется часами PostgreSQL. `get` проверяет enabled/revision/expiry из БД на каждом запросе, без локального cache разрешений. Credentials file остается demo password authenticator, а не OIDC.

`PostgresSessionStore.updateAccess(username, { role, permissions?, registryIds? }, actor)` и `revokeUser(username, actor)` — trusted provisioning interface. Смена прав или блокировка, увеличение revision, удаление всех сессий пользователя и audit event фиксируются одной транзакцией. Ошибка audit откатывает все изменение. Login сериализован с изменением аккаунта. Неуказанные permissions пересекаются с новой ролью, registryIds сохраняются; расширение grants требует явного перечисления. Смена прав не снимает блокировку. Автоматического reenable нет.

Граница отзыва — следующий authorization read, начавшийся после commit изменения, на любом экземпляре API с той же primary DB. Уже авторизованные операции не отменяются: финальная revalidation перед signer/commit остается частью workflow. Read replicas и cache для identity не предусмотрены. Restart сохраняет как активные неистекшие сессии, так и revoke/logout. Старые in-memory cookies при первом переходе потребуют повторного входа.

## Локальное управление demo accounts

Команда доступна только доверенному оператору host с database credentials. Это не HTTP endpoint и не корпоративный Identity Admin workflow. `actor` — введенная оператором audit attribution, не доказательство корпоративной личности.

```bash
ONELAYER_DATABASE_URL_FILE=/path/to/database-url \
  npm --prefix apps/demo-api run admin:access -- revoke operator local-maintainer

ONELAYER_DATABASE_URL_FILE=/path/to/database-url \
  npm --prefix apps/demo-api run admin:access -- access auditor local-maintainer /path/to/access.json
```

`access.json` содержит обязательный `role` и необязательные `permissions`/`registryIds`, как в deployment entry, без password. Неизвестные поля отклоняются. Команда не создает неизвестный аккаунт и не включает заблокированный. Для сужения доступа существующего аккаунта используйте эту команду, а не изменение bootstrap grants файла.

Совместимый `SessionStore` в памяти сохраняет прежний trusted interface для unit tests. Его revoke не долговечен. Он не используется native launcher и не является способом восстановления после сбоя БД.

Ошибки: 401 SESSION_REQUIRED для истекшего/отозванного session ID; 401 INVALID_CREDENTIALS при неверном login или revoked account; 403 CSRF_TOKEN_INVALID; совместимый 403 ROLE_FORBIDDEN для чужой mutation role; 403 PERMISSION_FORBIDDEN для недостаточного grant/registry scope. Загрузка intent по чужому registry не раскрывает существование и возвращает 404 INTENT_NOT_FOUND.

При ошибке durable identity read/login/logout API возвращает 503 IDENTITY_UNAVAILABLE без SQL/connection details и не выдает успешный logout. Если DB commit потерял подтверждение из-за разрыва связи, клиент получает ошибку и должен проверить состояние: это не доказательство rollback.

## Authenticated revocation (synthetic OIDC slice, 2026-09-24)

`POST /v2/admin/accounts/:username/revoke` and
`POST /v2/admin/accounts/:username/devices/:deviceId/revoke` accept exactly
`{"expectedRevision":"1"}` and return 204 after commit. The account route compares
`access_revision`; the device route compares that device's `revision`. Revisions
are positive decimal strings. A stale revision returns 409
`ACCESS_REVISION_CONFLICT` or `DEVICE_REVISION_CONFLICT`, respectively.

The actor comes only from a live OIDC session with `identity_admin` and
`access.manage`; CSRF and the configured browser Origin are required. The same
transaction revalidates the actor account, session expiry/revision and managed
device. The target must be an OIDC `registry_worker`, `registry_approver` or
`auditor` whose entire registry scope is within the actor's scope. Foreign and
absent accounts return the same 404 `ACCOUNT_NOT_FOUND`; a device belonging to
another account returns 404 `DEVICE_NOT_FOUND`. Self-management is denied (403
`SELF_ACCESS_CHANGE_FORBIDDEN`). A target holding a critical role (anything other
than `registry_worker`, `registry_approver`, `auditor`) returns the same 404
`ACCOUNT_NOT_FOUND` as an absent or foreign account, so the routes are not an
oracle for critical accounts in scope. Requesting a critical role for a
manageable target returns 403 `ROLE_ASSIGNMENT_FORBIDDEN` (it depends only on the
request). Critical roles remain trusted provisioning only. Malformed
percent-encoding in `:username`/`:deviceId` returns 400 `REQUEST_INVALID`. The
device revoke audit records `deviceId` and the new device `deviceRevision`.

Account revocation disables the account, increments its revision and removes all
its sessions. Device revocation disables that device, increments its own revision
and removes only that device's sessions; other devices keep their access. Audit
and revocation commit atomically. Device audit includes the affected device ID.
The next authorization read after commit on any API instance using the same
primary DB denies the revoked session. Requests already authorized are not
cancelled. Account/device listing and administrative UI are still separate work;
these endpoints do not introduce an account enumeration route or reenable flow.

## Service principals for internal routes (2026-09-24, revised after security review)

`POST /internal/register` and `POST /internal/reconcile` accept only a durable
service principal (migration `0012_service_principals.sql`). A service principal
is a separate identity type: no role, permissions, password, OIDC binding, device
or admin session, and it is never accepted on human routes.

| Route | Service action | Registry scope checked |
|---|---|---|
| `/internal/register` | `artifacts.register` | `registryId` from the JSON body |
| `/internal/reconcile` | `integrity.reconcile` | the deployment registry (`gov.registry.land`) |
| `GET /v1/anchors/:sequence` | `anchors.read` | deployment registry |
| `GET /v1/incidents` | `incidents.read` | deployment registry plus exact `registryId` selector |
| `GET /v1/certificates/:id/status` | `certificates.read` | deployment registry; query includes the registry filter |
| `GET /v1/certificates/:id/lifecycle` | `certificates.read` | deployment registry plus exact `registryId` selector |

The verifier read allowlist exists only in `service-principal` mode and matches
the entire GET path. It does not grant package/metadata/QR export, human/admin
access or mutations. A human session cookie cannot accompany the service bearer.
Credential/action/deployment scope is checked before resource lookup; the same
request gate covers the complete read operation, including incident refresh.
OIDC human-session/export admission is bypassed only for an authorized allowlisted
service read. Human requests retain their existing admission rules. Foreign
certificate IDs return the same 404 as an absent certificate. Anchor paths accept
canonical unsigned sequences of at most 20 digits; after authorization, a value
above u64 returns 400 and a valid u64 above the table's signed int8 domain returns
404 before SQL. Longer service paths are outside the allowlist (401).

### Credential and authorization

`Authorization: Bearer olsp_<credentialId>.<secret>`: 128-bit public credential ID,
256-bit random secret. PostgreSQL stores only the SHA-256 digest of the secret.
The digest comparison uses `timingSafeEqual` and also runs (against a fixed dummy
digest) for an unknown credential ID. This protects the secret comparison only:
the database lookup path for an unknown ID is shorter, so response timing may
reveal whether a credential ID exists. The ID is 128-bit random, not a secret.

Order of checks for every internal request, all before any database work:
1. Internal auth disabled → 503 `SERVICE_AUTH_DISABLED`.
2. Human `onelayer_admin_session` cookie present (even with a valid bearer) → 401 `SERVICE_CREDENTIAL_REQUIRED`.
3. Strict bearer syntax (`parseServiceBearer`) → otherwise 401, without reading the body.
4. In-process gate (below) → 429 `SERVICE_BUSY` or `SERVICE_RATE_LIMITED`, `Retry-After: 1`.

Then, with authorization checks on a separate identity pool (max 2 connections):
- `/internal/register`:
  1. Before the body is read, a pre-check verifies credential, action and that the principal's scope contains the deployment registry. A principal scoped only to foreign registries is refused (403) before any body byte. Success is not audited at this step.
  2. The body (≤ 1 MiB) must arrive within 10 s (`ONELAYER_INTERNAL_BODY_TIMEOUT_MS`, configurable 100–10000 ms). On timeout the connection is closed without a response and the gate slot is released. Invalid JSON or a non-object → 400 `REQUEST_INVALID`; too large → 413 `REQUEST_TOO_LARGE`.
  3. Credential + action + the body's `registryId` are checked again and REQUEST_AUTHORIZED is audited.
  4. All registration fields are validated (400 `REQUEST_INVALID`) before the fixture check, the RPC registry-status call or any write.
- `/internal/reconcile`: one check for credential + action + deployment registry.

Each check is one transaction:
1. An unlocked lookup maps the credential ID to its principal.
2. The principal row is locked `FOR SHARE`.
3. The credential row is re-read `FOR SHARE` in a separate statement (fresh READ COMMITTED snapshot).

A rotation or revoke that commits while the check waits is therefore observed.
Rotation takes the principal row lock with `SELECT … FOR UPDATE`. Revoke takes it
implicitly with `UPDATE service_principal … WHERE enabled`. Both change
credential rows only after holding that lock.

Errors: 401 `SERVICE_CREDENTIAL_REQUIRED` (absent, malformed, unknown, wrong
secret, rotated, revoked, expired, disabled, human cookie); 403
`SERVICE_PERMISSION_FORBIDDEN` (action outside allowlist, registry outside scope
or malformed); 503 `IDENTITY_UNAVAILABLE` (identity DB or audit failure, never
converted into success). Outside the exact verifier GET allowlist, any non-internal
route receiving `Bearer olsp_…` returns 401 `SERVICE_PRINCIPAL_NOT_ALLOWED`, even
with a valid admin cookie. An allowlisted service read carrying a human cookie
returns 401 `SERVICE_CREDENTIAL_REQUIRED`. Forwarded
headers (`X-Forwarded-*`, `X-Real-IP`, custom principal/role headers) and body
fields are never read for identity or scope.

### Revocation boundary

- Revoke/rotation applies to the next authorization check after commit on any API
  process sharing the primary DB. No cache.
- `/internal/register`: the write transaction re-validates, before inserting,
  that the principal is enabled at the same revision and the credential is still
  live, holding `FOR SHARE` locks until commit. A revoke/rotation committed during
  the RPC status call therefore rolls the registration back (401).
- `/internal/reconcile`: not re-validated at write time. A revoke committed after
  its authorization does not stop that one run (which can only mark a dispute).

### Abuse limits (per API process)

The gate caps concurrency at 2 in-flight internal requests (including the
operation) and applies token buckets: 20 burst / 5 per second per credential ID
(or `legacy`), and 60 burst / 20 per second for all internal traffic. At most
4096 keys are remembered (LRU). N processes allow N times these rates. Saturating
the gate denies internal callers only (429). Isolation for human routes comes
from the gate, not from pool separation: only authorization checks use the
separate identity pool, while the reconcile/register operations themselves use
the main API pool. The gate's concurrency cap of 2 bounds how many main-pool
connections internal work can hold (main pool max 5).

Anyone who knows a credential ID can exhaust that credential's per-key bucket
and cause 429s for its legitimate holder. The credential ID is not secret: it is
part of the bearer and may appear in logs. Such traffic is counted in
`service_principal_denial_window` (for known IDs with a wrong secret) but not
blocked by source. Recovery is `service-rotate`, which issues a new credential ID.

The same per-process gate also bounds verifier service reads. Releasing its
slot after credential validation alone would leave the SQL/RPC read work
unbounded; it is released after that work finishes or fails.

Denials for an existing credential ID are counted in
`service_principal_denial_window` per credential/reason/action/minute. Only the
first denial in each window is appended to `service_principal_event`, so a known
or revoked credential cannot grow the append-only log per request. Requests with
an unknown credential ID are not attributable and are not recorded. There is no
lockout.

### Audit

`service_principal_event` is append-only: row triggers refuse UPDATE/DELETE and a
statement trigger refuses TRUNCATE. It records PROVISIONED/ROTATED/REVOKED with
the host actor, REQUEST_AUTHORIZED, and REQUEST_DENIED with reason
(`SECRET_MISMATCH`, `CREDENTIAL_REVOKED`, `CREDENTIAL_EXPIRED`, `PRINCIPAL_DISABLED`,
`ACTION_NOT_ALLOWED`, `REGISTRY_OUT_OF_SCOPE`). `registry_id` is written only when
it is a well-formed registry ID (`^[a-z][a-z0-9-]{0,62}(\.[a-z][a-z0-9-]{0,62}){1,7}$`,
also enforced by a CHECK); otherwise it is NULL. The pre-body check writes
denials with registry NULL. A denial commits before its error is returned. An
audit insert failure fails the request closed and rolls back
provision/rotate/revoke.

**Role separation.** Migration `0016` creates the `onelayer_runtime` NOLOGIN role
and limits append-only tables to SELECT/INSERT. Deployment must create a separate
LOGIN member that owns no schema objects and use it for the API/CLI. Applying the
migration does not change the connection identity automatically. Triggers do not
bind the table owner, who can disable or drop them. Production must apply
migrations as a separate owner role and run the API/CLI as a runtime role with:
- `SELECT, INSERT` on `service_principal_event`, no UPDATE/DELETE/TRUNCATE/ownership;
- `SELECT, INSERT, UPDATE` on the principal, credential and denial-window tables.

Separately, audit events should ship to an external append-only store. The local
synthetic deployment uses a single owner role.

### Trusted host provisioning

Same trust boundary as the other `admin:access` commands. Not an HTTP endpoint.

```bash
ONELAYER_DATABASE_URL_FILE=/path/to/database-url npm --prefix apps/demo-api run admin:access -- \
  service-provision svc.reconciler local-maintainer /path/to/scope.json /path/to/new-token-file 30
ONELAYER_DATABASE_URL_FILE=... npm --prefix apps/demo-api run admin:access -- service-rotate svc.reconciler local-maintainer /path/to/new-token-file 30
ONELAYER_DATABASE_URL_FILE=... npm --prefix apps/demo-api run admin:access -- service-revoke svc.reconciler local-maintainer
```

`scope.json` is exactly `{"actions":[...],"registryIds":[...]}`: non-empty, unique,
actions from the table above, registry IDs in the full format above. The full
registry-ID format is enforced in code (`normalizeServiceScope`); the database
constraint on `service_principal.registry_ids` only rejects NULL, `*` and the
empty string. The audit `registry_id` column has the full-format CHECK. Principal IDs match `^[a-z][a-z0-9._-]{2,63}$`.

The DB URL file is read first, then the token file is created (`wx`, mode 0600)
before the DB transaction. A missing DB URL, or an existing or unwritable token
path, fails before any change and leaves no token file. After commit the raw bearer is
written and fsynced; it is never printed. Outcomes:

| Situation | Result |
|---|---|
| Success | `Service principal change committed.` |
| Validation or authorization error | That error; nothing committed. |
| The DB outcome itself is unknown (connection loss, including a lost COMMIT acknowledgement) | `OUTCOME_UNKNOWN: … verify service_principal_event and rotate or revoke the principal`, exit 1; the token file is removed. |
| The token write or fsync fails after commit | `OUTCOME_UNKNOWN`, plus `change committed but the new token was not persisted; rotate the principal`; the file is removed. |

- Rotation revokes the previous secret in the same transaction (at most one live credential, unique index).
- Revoke applies only to an enabled principal. Revoking an absent or already revoked principal returns `SERVICE_PRINCIPAL_NOT_FOUND`; there is no reenable.
- Scope cannot be changed in place: revoke and provision a new principal.
- Provisioning and rotation require an explicit `TTL_DAYS`. The host CLI bounds
  it by `ONELAYER_SERVICE_CREDENTIAL_MAX_TTL_DAYS` (default 90, allowed 1–366).
  The database enforces expiry after creation and a 366-day ceiling. Existing
  credentials receive `created_at + 90 days` in migration `0016`; already-old
  credentials expire immediately. Authorization and write-time revalidation use
  the database clock and deny credentials at or after expiry. Rotation creates
  a replacement credential with a new expiry; no scheduled rotation is provided.

### Mode selection

`ONELAYER_INTERNAL_AUTH`:

| Value | Where it is the default | Behaviour |
|---|---|---|
| `service-principal` | PostgreSQL session backend | Startup fails, on any backend, unless the required 0012 and 0016 objects are present: the 4 tables, the one-live-credential unique index, the enabled append-only row and TRUNCATE triggers, the validated audit `registry_id` CHECK, the NOT NULL `expires_at` column and validated `service_credential_ttl` CHECK. This API startup check inspects schema objects; migration file checksums are checked separately by the native migration runner. |
| `disabled` | Isolated `memory` test backend | Internal routes return 503 `SERVICE_AUTH_DISABLED`; no identity DB dependency. |
| `legacy-demo-token` | Never; explicit synthetic password-demo opt-in only | Shared bearer from `ONELAYER_INTERNAL_TOKEN_FILE` (32–512 printable chars). Compared by digest in constant time before the body is read. Deployment registry only. Admin cookie refused. Same gate. |

Startup refuses `legacy-demo-token` and `disabled` when `ONELAYER_OIDC_CONFIG_FILE`
is set; any other value also fails startup. `ONELAYER_INTERNAL_TOKEN_FILE` is read
only in legacy mode.

### Verifier outbound credentials

The verifier may set `ONELAYER_LOOKUP_SERVICE_TOKEN_FILE` for lifecycle/status/
anchor reads and `ONELAYER_INCIDENT_SERVICE_TOKEN_FILE` for incident reads.
Provision the corresponding action allowlist and registry scope through the
trusted host CLI. These files remain on the verifier host; neither native UI nor
human sessions receive them. Configured missing/unreadable/empty/malformed token
files fail verifier startup. Unset variables retain the anonymous demo mode.

Token-authenticated upstreams require a validated HTTPS origin or explicit
loopback HTTP origin, without userinfo, path, query or fragment. Redirects are
refused. A 404 becomes an absent lookup; 401/403/5xx remain errors and do not
become a successful lookup response. Existing verification compatibility rules
still distinguish a historical anchor proof from unavailable lifecycle data.
Tokens are loaded at startup; rotation
requires updating the holder's token file and restarting the verifier. This
transport does not authenticate a mutable lifecycle projection or prove current
document suitability; those guarantees remain part of ticket 05.
