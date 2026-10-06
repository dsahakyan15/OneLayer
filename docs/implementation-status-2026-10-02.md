# Что работает и что осталось — 2026-10-02

Полнофункциональный OneLayer Desktop не готов. Обычный launcher позволяет просматривать Overview/Connection и вручную проверять доступность трёх локальных сервисов. Настроить подключение, войти и выполнить рабочий ролевой процесс в нём нельзя. Все интерфейсы приложения должны быть английскими; внутренняя документация может оставаться русской.

Этот статус описывает локальное рабочее дерево, проверенное 2026-10-02, поверх commit `3b93cd9`. Часть реализации ещё не закоммичена. PR с документацией и исправлением порядка CI не публикует и не устанавливает описанные локальные изменения кода. Исторические PASS относятся к указанным в evidence окружениям и срезам, а не к текущему опубликованному релизу или полному приложению.

## Что проверено работающим

- GTK окно: две страницы, четыре кнопки, английские подписи, ручные credential-free health probes. Отображение authenticated summary не добавляет рабочих экранов.
- Локальный API и verifier отвечают health=200; web выдаёт /admin/workflow. Текущий API сообщает OIDC enabled=false. HTTP 200 не означает завершённый бизнес-сценарий.
- В отдельных backend/web срезах реализованы scoped identity/workflow, атомарный commit/outbox, durable publication modules, receipts/cancellation/recovery of pending workflow attempts и draft discovery. Их unit/integration/browser evidence не подтверждает интеграцию в установленный launcher.
- Legacy devnet publication/certificate и bounded snapshot/recovery являются демонстрационными путями. Они не объединены с новым workflow в полноценный desktop процесс.

## Состояние 24 задач

«Реализовано» ниже означает ограниченный модуль/срез. Ни одна полная задача этим документом не объявляется выполненной.

| Задача | Реализовано / текущая граница | Осталось |
|---|---|---|
| 01 — Baseline и contracts | Ведутся спецификация, ADR и permission contracts. | Завершить и принять все контракты, threat model и acceptance. |
| 02 — Desktop spike | GTK lab harness; отдельные callback/broker/install эксперименты. | Собрать выбранный desktop runtime с настоящими login/signer/update flows. |
| 03 — Verifier trust | Локальные trust-policy/anti-rollback проверки и harness. | Принять полный trust acceptance, provisioned roots и независимый review. |
| 04 — Incident index | Event-backed index, freshness и проверки отказов. | Завершить полноту/масштабирование, operational evidence и UI инцидентов. |
| 05 — Lifecycle | V2 contract/client честно возвращают UNKNOWN без доказанной актуальности. | Authenticated complete lifecycle source и CURRENT. |
| 06 — Private ingress | Локальные сервисы слушают loopback. | Managed-device private ingress и доказанная deployment boundary. |
| 07 — Identity | Durable sessions, permissions/scopes, test OIDC/device и service principals. | Реальный launcher login, provisioning, access/device UI и целевой IdP. |
| 08 — Registry workflow | Draft/revision/submit/independent approval/commit/outbox; recovery receipts и draft discovery в web/API. | Единый Records/import workflow, native screens и полный publication handoff. |
| 09 — Publication | Durable worker/intent/journal/reconciliation реализованы и тестируются отдельно. | Runtime consumer, signer UI, wf_version → finalized anchor → certificate issuance. |
| 10 — Desktop shell | English Overview/Connection и ручные health probes. | Настройка профиля, обычный вход, реальный workspace, credential/session integration. |
| 11 — Role workspaces | Отдельный English web workflow кабинет; часть legacy web screens. | Все native кабинеты, полный happy/deny pipeline каждой роли, reconnect/restart acceptance. |
| 12 — Independent Monitor | Есть исходный monitor и тестовые harness; полная runtime готовность этим ревью не подтверждена. | Независимый запуск, полномочия, tamper detection/projection repair и сквозная приемка. |
| 13 — Audit/evidence | Частичные audit events и legacy Timeline. | Scoped search/export, evidence bundles и восстановление projections. |
| 14 — Full-state checkpoint | Legacy snapshot capture; не включает новый workflow/publication state. | Полная inventory, consistent checkpoint, schema-versioned restore. |
| 15 — Backup Centers | Локальная demo модель copies/read-back/retention. | Реальные независимые storage adapters/centers и scoped custodian UI. |
| 16 — Key custody | Explicit software writer key config и immutable version binding. | Provisioning/custody/rotation, индивидуальные shares; default demo не provisioned автоматически. |
| 17 — Recovery Controller | Обычный API имеет bounded demo ceremony и software approval. | Изолированный controller, отдельные holder sessions и внешняя точная approval подпись. |
| 18 — Restore/cutover | Demo сохраняет digest/summary и ставит RESTORED. | Настоящий target import, validation, writer fencing, cutover и rollback. |
| 19 — Signed release | GTK CI/installed harness smoke; не пользовательская приемка. | Bundled installer, signed updates/rollback, compatibility и supply-chain gates. |
| 20 — Operations | Native devnet script, private state guards и отдельный readiness CLI. | Runtime wiring всех контуров, operational observability, runbooks и RPO/RTO. |
| 21 — Synthetic acceptance | Есть ограниченные unit/integration/browser-fixture проверки. | Installed-app happy/deny для 8 ролей, full restore и 72-hour soak. |
| 22 — Production provisioning | Не выполнено; нужны решения и инфраструктура владельца. | IdP, ingress, signer, storage, keys, release authority и ответственные. |
| 23 — Production validation | Не выполнено. | Независимые проверки, restore drill и shadow pilot. |
| 24 — Go-live/handover | Не выполнено. | Принятые gates, управляемый rollout и передача эксплуатации. |

## Блокеры пользовательского pipeline

1. Запуск → профиль → вход: нет настройки подключения; session доступна только через synthetic lab CLI flags. Обычный парольный demo пользователь не получает scoped workflow policy.
2. Вход → рабочий кабинет: в launcher отсутствуют Records, Approvals, Publication, Certificates, Verify, Incidents, Backup/Recovery, Access/Devices и Audit.
3. Draft → approve → commit → publish: wf_version/wf_outbox не соединены с legacy Publish/Certificate, которые читают synthetic_registry_record. Worker не включён в обычный runtime. Legacy Records create/import сохраняет напрямую без нового draft approval.
4. Certificate → пригодность сейчас: V2 не имеет CURRENT; lifecycle advisory/unauthenticated. Нельзя добавлять положительный verdict без доверенного полного источника.
5. Backup → recovery → usable target: snapshot не включает новые workflow/publication таблицы; доли вводятся одним оператором; RESTORED записывает summary, а не импортирует рабочую БД.

Подробные источники, воспроизведения и матрица ролей: [личное ревью pipeline](../.scratch/production-desktop/evidence/launcher-usage-pipeline-review-2026-10-02.md). Оно выполнено без субагентов. Новый chain publication, backup/restore и provisioning в ревью не выполнялись.

## Порядок оставшейся реализации

1. Обычный пользовательский запуск, connection profile, вход и English workspace в launcher.
2. Единые Records/import/drafts/approvals и серверные scopes обеих независимых ролей.
3. Runtime publisher + signer + finalized anchor + certificate issuance/export одной версии; QR/file verification и authenticated lifecycle.
4. Access/Devices, Incidents, Audit, Storage Custodian и личные Key Holder кабинеты.
5. Full-state checkpoint, isolated recovery, target import/validation/cutover/rollback и возобновление операций после restart.
6. Приемка установленного приложения для восьми ролей, network/restart/deny сценарии, затем подписанная поставка и production gates.

Критерий готовности: пользователь выполняет свой разрешённый процесс в установленном английском приложении от входа до проверяемого результата. Health cards, fixtures, window-mapped smoke и число тестов не заменяют этот критерий.
