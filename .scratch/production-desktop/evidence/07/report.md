# 07 — Admin permissions и отзыв demo sessions

Исторический отчет первого среза. Последующее изменение in-memory runtime на PostgreSQL: [durable sessions](durable-sessions.md).

Дата: 2026-09-20. Baseline: `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2`, рабочее дерево с ранее существовавшими изменениями. Commit/deployment не выполнялись. Это независимый локальный срез ticket 07, не завершение его acceptance; 01/06 остаются частичными.

## Реализовано

- Все data handlers `/v1/admin/*` проверяют именованное разрешение и registry scope серверной сессии перед SQL/RPC. Dashboard требует все разрешения своих агрегатов. Неизвестные маршруты не получают доступ по умолчанию; session introspection/logout остаются доступны владельцу сессии.
- Существующие роли ограничены явной synthetic compatibility policy. `operator` не получает `recovery.approve`, `chief_admin` не получает mutation permissions оператора. Старые ROLE_FORBIDDEN и CSRF ответы сохранены; недостаточный grant/scope дает 403 PERMISSION_FORBIDDEN.
- Deployment credentials допускают явное сужение permissions/registryIds. Пустой массив запрещает доступ; неизвестные поля, wildcard registry, null/неверные типы, grants выше role ceiling отклоняются. Flat credentials остаются совместимыми.
- `SessionStore.revokeUser` немедленно удаляет все сессии пользователя и запрещает новый login в этом процессе. `updateAccess` удаляет прежние сессии; повторный вход получает новые права. Неуказанные permissions сохраняются с пересечением новой роли, а не расширяются. Изменение доступа не отменяет revoke.
- Credentials копируются, выдаваемые session/grants заморожены: изменение исходного объекта не меняет авторизацию.
- Все вызовы `loadIntent` проверяют registry_id вместе с intent_id, включая mutation paths. Чужой ID дает тот же INTENT_NOT_FOUND, что отсутствующий.

## Контракт и совместимость

[Контракт demo admin access](../../../../docs/admin-access-contract.md). Формат Certificate Package V1, wire protocols, migrations и HTTP session DTO не менялись. Новые permissions действуют на операцию вместе с ее ответом; это не механизм field redaction. Production role matrix этим не утверждается.

## Проверки

Среда: Linux, Node v24.10.0. Dataset: только явно созданные synthetic credentials, IDs и временный PostgreSQL; реальные секреты/данные не читались.

| Команда | Результат |
|---|---|
| `npm --prefix apps/demo-api test` | 90 PASS, 0 skip |
| `npm --prefix apps/demo-api run typecheck` | PASS |
| `npm --prefix apps/demo-api run test:integration` | 2 PASS, 0 skip: реальный HTTP startup и existing disposable PostgreSQL migration/transaction suite |
| `git diff --check` | PASS |

Route matrix перебирает все действующие data paths/aliases для трех ролей с пустыми grants и чужим registry, запрещая любой SQL/RPC в test doubles. Есть positive narrow read, отказ доступа к агрегатам/metadata, expiry/logout/revoke/role change, malformed/elevated grants и изменяемые caller-owned объекты. Registry predicate intent проверен route-level SQL stub, не реальной multi-registry БД.

Новый integration test запускает реальный `apps/demo-api/src/main.ts` на временном loopback порту с credentials file. Через HTTP проверяет разрешенное чтение schema, forbidden reads/writes, чужой registry, игнорирование role/permissions в payload и forwarded identity headers, невозможность использовать internal bearer как human session, CSRF и logout. Database URL нерабочий: запреты должны происходить до доступа к БД. RPC по этим маршрутам не вызывается.

## Review и ограничения

Авторская проверка: сопоставлены все ветки dispatch с permission checks; исправлен registry predicate loadIntent; обнаруженное потенциальное расширение прав при updateAccess без permissions заменено пересечением прежних grants; null в provisioning policy теперь fail-closed. Независимый reviewer еще не назначен, acceptance ticket не закрыт.

- OIDC/PKCE/test IdP, device admission/revoke, MFA, service principal scopes, audit provisioning и запреты self-elevation не реализованы этим срезом.
- `revokeUser`/`updateAccess` — только trusted in-process interface; HTTP endpoint для назначения себе прав отсутствует. Нет долговечного identity store, multi-process invalidation или административного UI. Restart перечитывает deployment credentials; in-memory revoke не является durable account disable.
- Граница отзыва: следующий вызов authorize после возврата метода. Уже авторизованная операция не отменяется автоматически; production SLA и race с commit/signer требуют durable workflow и финальной revalidation.
- Demo остается single-registry: synthetic record tables не имеют tenant isolation. Проверка session registry не объявляется поддержкой multi-registry хранения.
- Object/field/territory scope, restricted export и не-admin certificate/QR/verifier/internal routes остаются незакрытой частью 07. Частичная защита admin API не дает оснований открывать сетевой доступ.
- Demo compatibility policy сохраняет прежние роли, в том числе создание записей оператором. Production разделение Worker/Approver/Operator и self-approval относится к 01/07/08.

Следующий срез 07: долговечные user/device grants и sessions, OIDC adapter с test IdP, единая policy для не-admin read/export paths; затем workflow 08. Полные production dependencies 01/06 и независимый review остаются открытыми.

## Continuation 2026-09-24

Authenticated OIDC Identity Admin account/device revocation, scoped target lookup,
revision conflicts, transactional audit and multi-instance invalidation are now
implemented. See [current evidence](authenticated-revocation.md); the limitations
above describe the original slice and are superseded only where newer evidence
explicitly documents implementation. Full ticket acceptance remains open.
