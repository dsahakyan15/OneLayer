# Ревью пользовательского pipeline лаунчера — 2026-10-02

Ревью выполнено лично основным агентом, без субагентов. Проверен текущий код в `/media/davit/DATA/projects/OneLayer`, виджеты GTK и доступность локальных HTTP endpoints. Требования: `docs/application-pipeline-ru.md`, разделы 4–7, и acceptance задачи 11.

## Заключение

Полнофункционального лаунчера сейчас нет. Обычный запуск открывает английское окно Overview/Connection с проверкой трёх локальных сервисов. Вход в нём недоступен. Отдельные web/backend функции реализованы, но не образуют рабочий пользовательский путь установленного приложения. Предыдущие build, unit, browser-fixture и window-mapped проверки не подтверждают готовность этого пути.

Это также не только вопрос подключения production IdP или подписания релиза: отсутствуют интеграция рабочих экранов в приложение, единая цепочка workflow → publication → certificate, настоящий импорт recovery target и несколько ролевых кабинетов.

## Подтверждённые блокеры

### 1. [P1] Пользователь не может настроить подключение и войти

Источники: `apps/desktop/lab/native.py:21–30,50–54`; `apps/desktop/lab/launcher_view.py:290–316`; `apps/desktop/lab/launcher_state.py:28–32`.

В обычном запуске session=None. Connection содержит сообщение «Sign-in becomes available after the connection is configured», но не содержит формы, выбора профиля или действия настройки. Кнопки входа создаются только при переданных CLI `--lab-backend` и `--lab-issuer`. Проверка доступности всегда обращается к трём фиксированным loopback адресам, независимо от лабораторных параметров сессии.

Воспроизведение: открыть `./apps/desktop/launcher`, перейти в Connection. Настроить среду и выполнить вход невозможно. Проверка дерева виджетов: 0 Gtk.Entry; кнопки `_Overview`, `_Connection`, `_Check connection`, `C_lose`.

Нужно: поддерживаемый environment profile, выбор/проверка подключения в UI, понятная первичная настройка, реальный session adapter. Для локального использования — управляемый путь запуска/подключения к стеку без обязательного ручного терминала.

### 2. [P1] Успешная сессия не открывает рабочее приложение

Источники: `apps/desktop/lab/launcher_view.py:199–216,341–375`; `apps/desktop/lab/native.py:75–83`.

В Gtk.Stack добавлены только Overview и Connection. `set_session` меняет текст и доступность кнопок; новых кабинетов не создаёт. Обработчик знает только login/refresh/logout. Нет ни встроенных React экранов, ни перехода к web workspace.

Воспроизведение: передать представлению синтетический authenticated summary с ролью registry_worker. Страницы остаются overview/connection. Это проверка поведения представления, не реальный вход.

Нужно: подключить реальные экраны Records, Approvals, Publication, Certificates, Verify, Incidents, Backup/Recovery, Access/Devices и Audit, с навигацией по серверным permissions/scopes.

### 3. [P1] Лабораторный вход не совместим с обычным работающим стеком

Источники: `apps/desktop/lab/session.py:25–39,63–81`; `apps/demo-api/src/main.ts:57–59,111–116`; `deploy/devnet-demo/native:276–285`; `apps/demo-api/src/postgres-session.ts:189–192`.

LabSession принимает только отдельный синтетический loopback issuer и программно выполняет тестовый redirect flow. Callback ожидается с HTTP 200, тогда как обычный OIDC-контур main.ts настроен на successRedirect в web. Внешний браузер и native callback/credential broker из отдельных spike модулей не включены в этот путь.

Текущий живой API сообщает `GET /v2/admin/oidc/config → {enabled:false}`. Парольный demo-вход существует в web, но не в обычном launcher. Его session не содержит workflow resourcePolicy. Предыдущее сохранённое live evidence подтверждает login=201, workflow prepare=403 RESOURCE_FORBIDDEN; в этом ревью эта мутация повторно не выполнялась.

Нужно: единый реально запускаемый вход, provisioned роли/scopes и устройство; совместимый native/browser handoff. Нельзя исправлять это отключением авторизации или выдачей всем unrestricted доступа.

### 4. [P1] Commit workflow не попадает в существующий экран публикации/сертификатов

Источники: `apps/demo-api/src/registry-workflow.ts:69–78`; `apps/demo-api/src/admin.ts:189–199,324–326,573–586`; `apps/mvp-web/components/publish-panel.tsx:74–79`; `apps/mvp-web/lib/api.ts:46–56`.

Новый workflow пишет wf_record/wf_version/wf_outbox. Legacy Records читает synthetic_registry_record; legacy Publish пересобирает batch из syntheticRecords. Выдача сертификата ограничивает internalRecordId шаблоном SYNTHETIC-N и тем же batch. Следовательно, утверждённая новая workflow-запись не становится доступной для выдачи через существующий PublishPanel.

WorkflowPublisher и PostgreSQL publication journal реализованы отдельными модулями, но в runtime main.ts нет их создания/запуска; поиск production source usage publication-worker вне самого модуля находит только комментарии maintenance. Native runtime запускает API/verifier/web, а не этот publisher. Наличие worker integration tests не заменяет runtime wiring.

Нужно: запущенный consumer wf_outbox, список операций и их фаз, signer adapter, finalized anchor → proof/manifest → scope-aware certificate issuance, с привязкой к одной и той же версии записи.

### 5. [P1] Создание и импорт в legacy Records обходят новый процесс согласования

Источники: `apps/demo-api/src/admin.ts:852–868,899–902,2833–2838`; `apps/mvp-web/components/records-panel.tsx:350,367`.

Legacy create/import вызывают persistRecord напрямую с operator + records.draft. Они не создают wf_draft и не проходят независимое approve/commit. Пользователь видит одновременно два разных пути записи, а публикуется именно legacy набор.

Это подтверждённый разрыв с целевым процессом, а не утверждение об обходе проверки permissions текущего demo API. Нужно перенаправить создание/импорт в draft workflow и ограничить legacy writes явно выделенным demo режимом.

### 6. [P1] RESTORED не означает восстановленную рабочую базу

Источники: `apps/demo-api/src/admin.ts:2418–2463`.

После расшифровки код вычисляет stateSummary, записывает digest/summary в recovery_restore_target и ставит recovery_operation.state=RESTORED. Нет импорта таблиц в отдельную целевую БД, валидации работоспособности этой БД, переключения writers или rollback. Этот статус не удовлетворяет требованиям восстановления usable registry.

Нужно: изолированный recovery controller, создание/импорт target, проверки целостности и старых QR, подтверждённый cutover, writer fence и rollback; отдельные состояния VALIDATING/CUTOVER_APPROVED/ACTIVE.

### 7. [P1] Snapshot не включает полное текущее состояние приложения

Источник: `apps/demo-api/src/admin.ts:1264–1325` и продолжение snapshotState.

Snapshot собирает legacy records/canonical versions/certificates/anchors/batches/events/audit. Новые wf_version/wf_draft/wf_outbox, workflow attempts/cursors и publication journal отсутствуют в выборке. Даже полноценный импорт этого формата не вернёт текущий workflow и его незавершённые операции.

Нужно: полная inventory состояния, согласованный checkpoint, версия схемы и миграции restore, импорт + проверка всех зависимостей. Решение о переносе identity/device/session состояния должно быть явным, с безопасным повторным входом, а не случайным копированием credentials.

### 8. [P1] Backup/recovery не имеет законченного пользовательского пути подготовки ключей и долей

Источники: `apps/demo-api/src/main.ts:62–69,128–133`; `apps/demo-api/src/admin.ts:1438–1443`; `apps/mvp-web/components/backup-center-panel.tsx:357–378`.

Без provisioned snapshot KEK создание завершается SNAPSHOT_KEY_UNAVAILABLE. Native start сам не задаёт пару snapshot-key configuration; настройки могут быть унаследованы извне, но приложения для их provisioning нет. Ошибку создания backup в текущем живом стеке в этом ревью не вызывали: она подтверждена веткой кода, а не новой попыткой записи.

Web recovery предлагает одному оператору ввести все три shares. Нет пользовательской ceremony, где каждый Key Holder в собственной сессии передаёт только свою долю. Approval signing key main.ts генерирует в ordinary API при старте, а не получает внешнюю подпись Chief Admin.

Нужно: provisioning и custody ключей, отдельные роли/экраны contribution, сохранение ceremony/progress, внешнее approval точной операции и отдельный recovery controller. UI не должен собирать все секреты у оператора.

### 9. [P2] Проверка не умеет доказывать актуальность документа

Источник: `apps/verifier/src/verify-v2.ts:4,29–32,41–78`.

V2 контракт намеренно не содержит CURRENT, lifecycle является advisory/UNAUTHENTICATED. Активный документ с корректным proof не получает подтверждения пригодности «сейчас». Это корректное ограничение текущего verifier, но отсутствующая целевая функция.

Нужно: полный authenticated lifecycle source с freshness/completeness, revocation/supersession после выдачи нового сертификата; только затем CURRENT. В launcher дополнительно отсутствуют QR/file input и отображение самого результата.

### 10. [P2] Нет законченных кабинетов остальных ролей и эксплуатации приложения

Источники: native sidebar `launcher_view.py:211`; web navigation `apps/mvp-web/components/admin-session.tsx:163–171`; inventory маршрутов `apps/mvp-web/app/(admin)/admin`; installer `apps/desktop/lab/install.py:8–25`.

Даже отдельный web содержит только Dashboard/Records/Workflow/Publish/Certificates/Backups/Timeline. Не обнаружены кабинеты Access/Devices, Incidents с evidence и решениями, Key Holder contribution, отдельный scoped Storage Custodian, полноценный Audit search/export. Timeline не закрывает все требования аудита.

Установка сейчас копирует Python lab harness в disposable prefix, требует системные Python/GI и не включает рабочие экраны или управление стеком. Нет встроенных настроек версии/совместимости, подписанного updater/rollback и диагностики пользовательской операции. Отдельный readiness CLI не является этим пользовательским интерфейсом.

## Pipeline и роли

| Этап | Фактический результат | Что требуется |
|---|---|---|
| Запуск установленного приложения | Окно lab harness | Поддерживаемая установка, подключение/первичная настройка |
| Выбор среды → вход | Обычный launcher останавливается здесь | Profile, login/session/device flow |
| Records → draft/import | Native отсутствует; web имеет два разных пути | Единый scoped workflow и поиск/карточка/версии |
| Submit → approve/reject → commit | Частично реализовано в отдельном web/API | Рабочий native экран; provisioning обеих ролей |
| Commit → publish → finalization | Outbox и legacy публикация разъединены | Runtime worker и связанный UI/signer |
| Finalization → certificate → print/export | Legacy synthetic issuance; native отсутствует | Issuance той же wf_version и permission-aware disclosure/export |
| QR/file → verification | Отдельный web verifier, CURRENT недоступен | Native input + authenticated lifecycle |
| Backup → holders → approval | Demo web, централизованный ввод shares | Custody, индивидуальные contributions, внешний approval |
| Restore → validate → cutover | Summary помечается RESTORED | Настоящий target import и переключение |
| Incident → resolution / access revoke / audit | Части backend/CLI, нет кабинетов | Полные scoped пользовательские экраны |

| Роль | Что отсутствует в launcher |
|---|---|
| Registry Worker | Все рабочие действия: поиск, версии, draft/import, подача, выдача/проверка результата |
| Registry Approver | Входящая очередь, diff/основание, точное approve/reject |
| Operator | Очередь публикации, signer/finalization, backup операции и recovery initiation |
| Auditor | Scoped audit/evidence search и разрешённый export |
| Chief Admin | Собственное внешнее подтверждение точного Restore Approval |
| Identity Admin | Назначения/scopes, devices, revocation в UI |
| Key Holder | Личная contribution ceremony и результат собственной доли |
| Storage Custodian | Состояние своего центра, read-back/retry/retention |

Роль в GTK сейчас только текстовая метка. Наличие backend permission IDs не означает наличие кабинета.

## Что фактически проверено в этом ревью

- Текущее дерево GTK: 2 страницы, 4 кнопки, 0 полей ввода. Изменение summary на authenticated не добавляет экранов. Вызовы внешнего IdP не выполнялись.
- Live loopback API health=200; verifier health=200; web /admin/workflow=200; API OIDC enabled=false. HTTP 200 страницы означает выдачу HTML, не прохождение бизнес-сценария.
- Прослежены SQL write/read пути workflow, legacy records/publication/certificates, snapshot и restore.
- Не выполнялись новые изменения реестра, публикации в chain, provisioning, backup или restore. Код приложения не менялся; добавлен только этот отчёт.
- Полный manual/E2E прогон восьми ролей невозможен через текущий launcher: блокируется до входа. Более поздние выводы основаны на коде и существующем явно обозначенном evidence; они не выданы за новый end-to-end запуск.

## Порядок доведения до пригодного приложения

1. Закрыть запуск/подключение/вход и встроить English workspace в launcher. Должен существовать обычный пользовательский запуск без lab CLI flags.
2. Унифицировать Records/import/drafts/approvals, provisioned scopes и независимые роли. Убрать конкурирующий direct-write путь из штатного процесса.
3. Подключить durable publisher runtime и signer; связать каждую версию с finalized anchor и выдачей/экспортом сертификата. Реализовать QR/file verification и lifecycle.
4. Дать кабинеты Access/Devices, Incidents, Audit, Storage Custodian и индивидуальных Key Holders.
5. Реализовать полный checkpoint и настоящий isolated restore/validation/cutover/rollback; корректно отображать фазы и возобновлять операции после restart.
6. Проверить установленное приложение на целевой машине: по одному полному happy/deny сценарию каждой роли, перезапуск/потеря сети, повторные клики, экспорты. Затем installer/update/compatibility/release gates.

Критерий «готово»: сотрудник выполняет свой разрешённый процесс внутри установленного английского приложения от входа до проверяемого конечного результата. Ни green health cards, ни сумма unit tests этого критерия не заменяют.
