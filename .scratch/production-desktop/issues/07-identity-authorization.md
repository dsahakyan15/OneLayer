# 07 — Identity, sessions и server-side permissions

Status: ready-for-agent
Execution: in-review
Owner: identity agent
Role: Backend/Identity
Phase: P2
Blocked by: 01, 06

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Durable sessions, permissions/scopes, test OIDC/device и service principals.
- Осталось: Реальный launcher login, provisioning, access/device UI и целевой IdP.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Реализовать серверные права для людей, устройств и service principals.

## Scope и источники

apps/demo-api/src/admin-session.ts; server routes; access module; db/migrations/; API contracts

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Corporate OIDC adapter проверяет token issuer/audience/expiry, user и device admission; test IdP заменяет demo credentials в integration.
- [ ] Permissions проверяются для action/object/field/scope на всех read/write/export paths; route lookup не раскрывает чужие данные через IDs и счетчики.
- [ ] Есть bootstrap, role assignment/revocation и запрет самоповышения/несовместимых ролей; claimed role из request не доверенная.
- [ ] Logout, account/device revoke и role change действуют в заданный SLA; service identities ограничены и не являются human sessions.

## Проверка

Permission matrix через прямые HTTP calls, object-ID substitution, expired token, revoked device, malicious forwarded header и restricted export.

## Evidence и handoff

При исполнении создать `../evidence/07/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.

2026-09-20: начат независимый локальный срез: явные permissions и registry scope действующего admin API, отзыв demo accounts/sessions. Dependencies 01/06 остаются частичными; production identity gate не закрывается.

2026-09-20: локальный admin access срез реализован и проверен; [evidence](../evidence/07/report.md), [контракт](../../../docs/admin-access-contract.md). 90 unit/route tests и 2 integration tests PASS. Независимый review и полный acceptance 07 открыты; in-review относится к частичному срезу.

2026-09-20: начат следующий срез — PostgreSQL accounts/sessions, transactional revoke/access changes, проверка после restart и между экземплярами API.

2026-09-20: durable accounts/sessions срез реализован: migrations 0008, async backend, transactional revoke/grants/audit и trusted CLI. [Evidence](../evidence/07/durable-sessions.md): 90 unit/route, 5 integration и 3 bind tests PASS. Полный acceptance и независимый review не закрыты; следующий срез — OIDC/device admission.

2026-09-20: реализован synthetic OIDC/device admission с real HTTP test IdP + disposable PostgreSQL, code/PKCE/nonce/browser binding, durable device revoke, mode isolation и legacy resource denial. [Evidence](../evidence/07/oidc-device-admission.md). Полный production acceptance и независимый review остаются открытыми.

2026-09-24: добавлен authenticated Identity Admin account/device revoke с точным Origin/CSRF, scoped lookup, revision conflict, запретом self-management/critical roles и transactional audit. [Evidence](../evidence/07/authenticated-revocation.md). Проверяется на disposable PostgreSQL и synthetic identities; полный production acceptance не закрыт.

2026-09-24: закрыт pending в [authenticated-revocation](../evidence/07/authenticated-revocation.md): typecheck PASS, unit 99 PASS, identity-revocation 4/4 PASS. В том run integration 38/39: единственный fail в registry-workflow другого агента, в последующих run он прошёл. Реализован срез scoped service principals: migration 0012, `service-principal.ts`, CLI `service-provision/rotate/revoke`. `/internal/register|reconcile` принимают только durable principal из PostgreSQL: хранится только SHA-256 digest, явный allowlist action + registry scope, timing-safe сравнение, append-only audit. Revoke и rotation действуют на следующий запрос в любом процессе API. Service bearer отклоняется на admin/legacy routes, human cookie — на internal routes. Legacy shared token остаётся только явным demo opt-in и отклоняется при startup в OIDC-режиме. [Evidence](../evidence/07/service-principals.md): unit 101 PASS, integration 52 PASS / 0 skip на disposable PostgreSQL и в двух реальных API процессах. Открыто: независимый review, изменение scope без reissue, TTL и rate limit для service credentials, service action для verifier reads, обновление deploy launcher (вне scope). Полный acceptance 07 не закрыт.

2026-09-24: независимое security-ревью, blocker нет. Исправлены:
- M1: gate до обращения к БД (concurrency и rate limit), отдельный пул identity на 2 соединения, агрегация денаев по окну.
- m1: EvalPlanQual при rotate, фиксированный порядок блокировок.
- m2: revalidate в транзакции записи register.
- m3: проверка credential до чтения тела; 400/413 на плохое тело.
- m4: в audit только валидный по формату registry ID.
- m5: TRUNCATE-триггер; разделение ролей owner/runtime описано в контракте, не реализовано.
- m6: повторный revoke отозванного principal → 404.
- m7: fsync токена и OUTCOME_UNKNOWN в CLI.
- m8: единый 404 для критических ролей.
- m9: проверка схемы 0012 на старте на любом backend; для memory по умолчанию `disabled`.
- NIT: 400 на битый `%` в пути; `deviceRevision` в audit device revoke.

Disposition по каждому пункту и исправленная evidence: [service-principals.md](../evidence/07/service-principals.md). Проверки:
- typecheck PASS;
- unit 110/110;
- identity/service-principal/oidc integration, последовательно: 42/42, 0 skip;
- полный integration: сначала 50/55, все 5 падений в workflow-publication-chain/validator другого агента (файлы изменены во время прогона, `finalizedSlot is not a function`); повторный прогон 57/57, 0 skip.

Execution остаётся claimed. Нужен повторный review этих исправлений.

2026-09-24: повторное ревью, blocker нет. Второй раунд исправлен:
- N2: pre-check register против deployment registry до чтения тела, таймаут тела 10 с.
- N6: валидация полей register до fixture и RPC → 400.
- N4: `initialize()` проверяет все объекты 0012. Сверка sha256 миграции описана для владельца runner.
- N5: CLI не оставляет пустой token-файл.
- N1, N3 и формулировки о блокировках и формате registry ID исправлены в контракте.
- N7 записан как info.

[Evidence, раунд 2](../evidence/07/service-principals.md#review-round-2-2026-09-24). Проверки: typecheck PASS, unit 116/116, service-principal* + identity-revocation 14/14, 0 skip. Execution остаётся claimed.

## Bounded continuation — 2026-10-01

Migration runner checks SHA-256 before pending migrations/fixtures, refuses
missing or changed historical migration evidence, and atomically applies a
private SQL snapshot with its checksum row. Real launcher/PostgreSQL regressions:
4/4 PASS, zero skips. PostgreSQL installation precedes root e2e in CI. Repaired
expiry/CLI fixtures and added expiry, revalidation, rotation and TTL-boundary
negative coverage: 10 store integration tests and 2 HTTP integration tests PASS.
Full API typecheck and unit suite PASS (120).
[Evidence and review disposition](../evidence/07/migration-integrity-and-ttl.md).
Full ticket acceptance remains open.

## Scoped verifier reads — 2026-10-01

Реализован ограниченный allowlist существующих GET для anchors/incidents/status/lifecycle с живыми service-principal scopes и deployment registry. Export/admin/mutations не разрешены. Gate удерживается до конца обработки, verifier читает ключи из настроенных файлов и запрещает перенаправления. Реальная composed OIDC API→verifier проверка после revoke PASS; API 124 unit, read/principal HTTP по 2 PASS. [Evidence и review disposition](../evidence/07/verifier-service-reads.md). Полный acceptance 07 остаётся открытым.
