# 07 — Долговечные accounts и admin sessions

Дата: 2026-09-20. Baseline commit: `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2`; изменения поверх ранее существовавшего рабочего дерева. Commit, migration рабочей БД и deployment не выполнялись. Это следующий локальный срез 07 после [permissions](report.md), не полный acceptance identity.

## Результат и invariant

Блокировка или сужение прав пользователя больше не теряется при restart и не зависит от одного экземпляра API. После commit изменения следующий authorization read на той же primary PostgreSQL видит актуальное enabled/access_revision; cached grants и fallback на память отсутствуют.

- Additive migration 0008 создает demo_admin_account, demo_admin_session, demo_admin_access_event. Пароли не копируются в БД; случайный session bearer хранится как SHA-256 digest. CSRF и expiry переживают restart, срок действия проверяется по DB clock.
- PostgresSessionStore реализует async SessionBackend. Login и account mutation сериализуются row lock; revoke/update, session invalidation и audit фиксируются вместе. Ошибка audit откатывает изменение. Смена прав не включает disabled account.
- Bootstrap создает только отсутствующие accounts из deployment credentials. Существующая роль, grants, revision и disabled status не перезаписываются старым файлом при restart. Неуказанные grants при update остаются пересечением прежних с новой ролью.
- main.ts по умолчанию использует PostgreSQL, native launcher явно задает postgres. Schema/init failure останавливает startup. Runtime identity failure дает 503 IDENTITY_UNAVAILABLE, в том числе вместо успешного logout.
- Локальный `admin:access` позволяет trusted host maintainer изменить права или заблокировать account. Это не HTTP route; actor — операторская attribution, не corporate identity. Неизвестный account не создается, автоматического reenable нет.

Интерфейс/операции: [контракт](../../../../docs/admin-access-contract.md). Certificate V1, blockchain и HTTP session response shape не изменены. Sync memory backend остается только явно выбираемым synthetic/test режимом.

## Evidence

Среда: Linux, Node v24.10.0, локальный PostgreSQL через pg_config. Dataset: одноразовые PostgreSQL clusters с migrations 0001–0008; synthetic usernames/passwords/IDs. Ни один тест не использует приложение DATABASE_URL или реальную рабочую БД.

| Команда | Результат |
|---|---|
| `npm --prefix apps/demo-api test` | 90 PASS, 0 skip |
| `npm --prefix apps/demo-api run typecheck` | PASS, включая новый CLI и integration helpers |
| `npm --prefix apps/demo-api run test:integration` | 5 PASS, 0 skip |
| `node --test --experimental-strip-types tests/e2e/native-bind.test.ts` | 3 PASS, 0 skip |
| `bash -n deploy/devnet-demo/native` | PASS |
| `git diff --check` | PASS |

Новые проверки:

1. Два независимых DB pool/store видят одинаковую session; startup не сбрасывает grants/revoke. Logout, expiry, disabled flag и revision mismatch запрещают доступ. Database rows не содержат raw bearer/password.
2. Чужая role permission, неизвестный account и пустой actor отклоняются. Ошибка SQL-trigger audit при revoke/update сохраняет прежние account/session state. Конкурентные login/revoke не оставляют пригодную сессию заблокированного пользователя. Закрытое DB connection pool дает identity unavailable, не cache hit. Недопустимые grants в самой БД отклоняются при login/get.
3. Реальный main.ts запускается с disposable PostgreSQL, проходит несколько kill/start циклов и реальные HTTP calls. Существующая cookie и CSRF переживают restart; локальный CLI с отдельным процессом меняет роль/сужает grants и отзывает старую cookie; restart не возвращает прежнюю роль. CLI revoke запрещает login и cookie после restart. Другой пользователь продолжает работать.
4. В реальном HTTP процессе временно переименована session table: read/logout дают 503 без SQL details, после восстановления доступ возвращается. Это проверка недоступной relation; не полноценный network partition drill.
5. Loopback network tests остались зелеными. Их API fixture явно использует memory backend и не доказывает durable startup; durable startup покрыт отдельным тестом main.ts выше.

## Migration и эксплуатация

0008 добавляет таблицы, не меняя существующие records/proofs. Native restart применит ее перед запуском API; в этом сеансе он не выполнялся. Первое обновление инвалидирует прежние in-memory cookies; новые durable cookies переживают следующие перезапуски. Не откатывать приложение на legacy memory auth как способ recovery — такой бинарник не применяет durable revoke. Не удалять identity tables для повторного bootstrap.

Credentials-файл остается demo password authenticator, а grants после bootstrap живут в PostgreSQL. Изменение password-файла само по себе не является отзывом уже выданных сессий. Для revoke/scope changes применяется trusted maintenance CLI. После удаления identity state или восстановления старого backup можно потерять новейшие revocations: безопасная identity recovery/anti-rollback остается будущим gate.

## Review и незакрытые границы

Авторская проверка: все admin handlers переведены на awaitable SessionBackend, logout ждет durable delete, expiry сравнивается с DB clock, bootstrap никогда не обновляет существующий account. Bootstrap сортирует usernames для одинакового порядка row locks. Невалидная stored policy дает identity unavailable. Изменения транзакций и audit rollback проверены реальным PostgreSQL. В тестах исправлен порядок закрытия второго pool до остановки временного cluster. Независимый reviewer не назначен; Execution остается in-review для среза.

- Corporate OIDC/PKCE/test IdP, managed-device admission/revoke, MFA и service identities еще не реализованы.
- Human Identity Admin, self-elevation/role incompatibility workflow и защищенный provisioning quorum не заменяются trusted OS CLI. Audit хранится в той же mutable DB, не является независимым журналом доказательств.
- Объектные/полевые права, restricted export и не-admin QR/package/verifier paths остаются открытыми.
- Уже авторизованные операции не отменяются после revoke; финальная revalidation и signer/commit race относятся к workflow. Формальный production SLA/нагрузочный тест не выполнен.
- Backend demo accounts по-прежнему трехролевая synthetic compatibility policy. Установка durable storage не делает ее production RBAC.
- Не выполнялись live native/devnet deployment, native desktop acceptance, production DB restore или тест полного сетевого отказа DB.

Следующий срез 07: OIDC adapter с test IdP и durable device admission, затем распространение policy на не-admin read/export. Dependencies 01/06 и полный acceptance 07 остаются открытыми.
