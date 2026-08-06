# OneLayer MVP: вертикальный pilot, визуальная верификация и bounded recovery

Status: ready-for-agent

## Problem Statement

Администратору реестра нужен понятный и проверяемый путь от структурированного
сертификата пользователя до публичного доказательства состояния записи. Сейчас
MVP-контур должен одновременно решить несколько связанных задач:

- принять JSON или CSV по закрытой схеме `land-registry-v1`, не потеряв
  типизацию, версии и доказательства полей;
- построить batch, `Merkle Root` и manifest, опубликовать anchor в devnet и
  дождаться именно `FINALIZED` состояния;
- дать оператору безопасный transaction review и Wallet Standard-подпись без
  передачи keypair или seed в браузер;
- выдать подписанный `Certificate Package` и QR, а проверяющему — показать
  только те данные, которые доказаны package и Merkle proofs;
- корректно различать `VERIFIED`, исторические и спорные состояния, включая
  недоступный или устаревший incident index;
- показать администратору bounded backup/recovery control plane с пятью
  локальными `BackupCenter`-ами, immutable `Snapshot`-ами, retention и
  threshold recovery;
- разделить полномочия `operator`, `auditor` и `chief_admin`, чтобы ни одна
  роль не могла единолично выполнить восстановление.

Проекту нужна одна agent-ready спецификация Gate C, в которой эти задачи
связаны общей моделью данных, пользовательскими историями, границами доверия и
проверяемыми acceptance criteria. Спецификация также должна отличать bounded
MVP control plane от production recovery и не выдавать synthetic devnet demo за
production-ready систему.

## Solution

Реализовать Gate C как один вертикальный пользовательский контур на
synthetic-данных и Solana devnet:

1. `operator` создаёт или импортирует JSON/CSV по `land-registry-v1`.
2. Система выполняет schema validation, canonicalization и показывает
   canonical preview.
3. Система создаёт `Record Version`, строит field tree, batch, `Merkle Root` и
   manifest hash.
4. Admin готовит транзакцию, выполняет simulation и показывает полный
   transaction review.
5. Wallet Standard test operator подписывает ровно подготовленные bytes после
   явного review.
6. Durable publisher отправляет signed wire transaction, отслеживает её по
   известной signature и принимает только `FINALIZED` anchor.
7. После finalized checks система выпускает подписанный `Certificate Package`
   в режиме `FULL_RECORD` или `SELECTIVE_FIELDS`, создаёт QR и показывает
   signature/slot.
8. Публичный OneLayer-контур принимает QR из камеры, image upload или manual
   input, проверяет binding, issuer signature, field/batch Merkle proofs,
   program/account ownership, finalized anchor и incident status.
9. Admin создаёт и обновляет зашифрованные `Snapshot`-ы, реплицирует одну
   immutable-копию во все активные `BackupCenter`-ы и применяет `Retention
   Window` максимум 12 snapshots на центр.
10. Recovery принимает три `Recovery Share` из пяти только в памяти операции,
    сверяет `Merkle Root` с самым новым finalized anchor без открытого incident
    и требует отдельный `Restore Approval` от `chief_admin`.

Замороженный on-chain протокол не изменяется. Blockchain хранит доказательный
anchor с `Merkle Root` и manifest hash. Полный JSON объекта является частью
подписанного `Certificate Package`, а не on-chain record; verifier возвращает
его только после проверки package и доказательств.

### Acceptance Criteria

1. Admin создаёт или импортирует synthetic-запись; synthetic marker и schema
   validation выполняются до операций с данными, а UI показывает canonical
   preview.
2. Devnet-транзакция сначала проходит simulation; transaction review показывает
   program ID, instruction, accounts с signer/writable flags, registry, segment
   PDA, batch, roots, fee payer, fee/rent и simulation logs.
3. Повторный click или reload не создаёт второй batch или вторую транзакцию;
   expired blockhash возвращает flow к preparation/simulation.
4. Certificate не выдаётся до `FINALIZED`; после finalized checks Admin получает
   package, `certificateHash`, QR, signature и slot.
5. Camera, image upload и manual QR input в fresh browser context приводят к
   `VERIFIED` на demo-host; cross-device scan допускается только на отдельно
   разрешённом HTTPS staging.
6. Подмена QR hash, package или field даёт `INVALID`; прямое synthetic DB
   tampering даёт `DISPUTED`; stale/unavailable incident index даёт
   `VERIFIED_NO_INCIDENT_CHECK`, а не ложный зелёный `VERIFIED`.
7. Есть fixtures для `VERIFIED_HISTORICAL` и `SUPERSEDED`.
8. UI адаптивен для desktop и mobile scan, управляется с клавиатуры, имеет
   camera fallback и не выражает status только цветом.
9. Admin и OneLayer используют общий набор design tokens/status components и
   доступную high-contrast тему.
10. `auditor` видит данные, но не может подготовить batch, запросить подпись или
    выдать certificate; ограничение проверяется на Admin API, а не только
    скрытием элементов UI.
11. Deploy и CLI publish требуют собственных approval digests; browser publish
    требует reviewed intent, wallet prompt и server-side validation signed wire
    transaction.
12. Default CI проходит IDL-to-client drift check и детерминированный browser
    E2E без расхода SOL; guarded live-devnet smoke запускается только с
    отдельным подтверждением.
13. На clean host native preflight либо подтверждает все зависимости, либо
    сообщает remediation и завершается до mutation; fixture reset не затрагивает
    чужие процессы или данные.
14. JSON/CSV принимает валидный сертификат пользователя и отклоняет неизвестное
    поле (`CANONICALIZATION_FAILED`), неверный тип, чужой decimal scale,
    timestamp с дробной частью и пустое обязательное поле. Отчёт называет
    строку и путь; dry-run не меняет БД.
15. `fieldRoot`, `recordCommitment`, batch leaf и `Merkle Root` строятся из
    фактического набора полей. Повторный `internalRecordId` создаёт новую
    `Record Version`, а прежний certificate после нового anchor получает
    `SUPERSEDED`.
16. `SELECTIVE_FIELDS` даёт `VERIFIED` для подмножества путей; package не
    содержит значения и соли нераскрытых путей, а `fieldRoot`, batch proof и
    anchor совпадают с `FULL_RECORD` той же версии.
17. Public certificate detail показывает ровно поля из проверенного package и
    не получает значения в обход package из БД.
18. Каждый пользовательский сценарий MVP доступен из UI без curl, psql или
    shell, кроме явно названных CLI-only операций; dashboard показывает
    фактические API-метрики.
19. Backup Admin показывает пять стартовых центров, их folders, health и
    per-center replica status; создание добавляет шестой или следующий пустой
    локальный центр с отдельными volume и credentials.
20. `Обновить копии` создаёт одну новую immutable-копию полного `Snapshot` и
    отправляет её во все активные центры; старые папки не перезаписываются,
    недоступный центр получает `PENDING_RETRY`, частичный успех виден явно.
21. Ни один `BackupCenter` не хранит больше 12 snapshots; при переполнении
    удаляется старейший не-`FINALIZED`, а хотя бы один `Finalized Snapshot`
    сохраняется.
22. `Snapshot` включает records, `Record Version`-ы, `Certificate Package`-ы,
    QR metadata, proofs, roots, manifests, anchor references и operation
    history; plaintext не покидает encrypted package при репликации.
23. Recovery автоматически выбирает самый новый `FINALIZED` anchor без
    открытого incident, принимает `3-of-5`, отклоняет `2-of-5`, не сохраняет
    shares и останавливается при mismatch ciphertext, plaintext или `Merkle
    Root`.
24. Только `chief_admin` может подписать `Approve restore`; `operator` создаёт
    центры и копии, `auditor` остаётся read-only, ручное удаление backup
    запрещено.
25. Локальный E2E покрывает пять стартовых центров, создание дополнительного
    центра, активные replicas, retry, retention, повреждённый package,
    `2-of-5`/`3-of-5`, root mismatch и успешный restore. Это evidence bounded
    MVP, а не release gate 7.

## User Stories

1. Как `operator`, я хочу инициализировать registry и выдать операторскую
   роль, чтобы начать контролируемый pilot.
2. Как governance-администратор, я хочу отозвать операторскую роль, чтобы
   неактивный signer не мог публиковать новые anchors.
3. Как `operator`, я хочу создавать ledger segments capacity 46 с монотонным
   `segmentIndex`, чтобы дневной ledger укладывался в on-chain allocation
   limit без промежуточного partially allocated состояния.
4. Как `operator`, я хочу публиковать anchor с `Merkle Root`, manifest hash,
   предыдущим anchor hash и registry version, чтобы состояние batch было
   связано с последовательностью registry.
5. Как `operator`, я хочу seal-ить все segments дня в правильном порядке,
   чтобы дневной ledger нельзя было незаметно изменить после закрытия.
6. Как emergency-администратор, я хочу pause/resume registry, чтобы временно
   остановить публикацию при operational incident.
7. Как reporter, я хочу открыть incident для batch range, чтобы verifier не
   показывал недоказанный зелёный статус.
8. Как governance-администратор, я хочу resolve только incident моего registry,
   чтобы чужое состояние нельзя было изменить через неправильный account.
9. Как `operator`, я хочу импортировать JSON сертификата пользователя, чтобы
   исходные поля записи приходили из реестрового источника, а не из хардкода.
10. Как `operator`, я хочу импортировать CSV с путями полей в первой строке,
    чтобы загружать несколько структурированных записей одним действием.
11. Как `operator`, я хочу получить dry-run с ошибками по строке и пути, чтобы
    исправить вход до записи в БД.
12. Как владелец записи, я хочу, чтобы неизвестные поля, неверные типы и
    неканоничные decimal/timestamp отклонялись явно, чтобы доказательство не
    зависело от молчаливого отбрасывания данных.
13. Как `operator`, я хочу повторно импортировать тот же `internalRecordId` как
    новую `Record Version`, чтобы сохранять provenance изменения вместо
    overwrite текущей записи.
14. Как `operator`, я хочу видеть canonical preview фактических полей,
    `fieldCommitment`, `fieldRoot`, `recordCommitment` и batch leaf, чтобы
    проверить содержимое до публикации.
15. Как pipeline, я хочу применять одну схему к builder, reconcile и fixture,
    чтобы одинаковые данные не давали ложный `DISPUTED` из-за расхождения
    реализаций.
16. Как `operator`, я хочу строить batch и manifest из `Record Version`-ов,
    чтобы verifier мог проверить включение записи в конкретный batch.
17. Как publisher, я хочу durable queue с lease и отдельной immutable записью
    каждой signed attempt, чтобы сбой RPC не приводил к слепой пересборке
    транзакции.
18. Как publisher, я хочу отслеживать `UNKNOWN` по известной signature, чтобы
    одна транзакция не была отправлена повторно из-за неопределённого ответа.
19. Как `operator`, я хочу видеть список synthetic records и их versions,
    чтобы выбрать точное состояние для batch.
20. Как `operator`, я хочу выбрать `FULL_RECORD`, чтобы выдать все разрешённые
    поля выбранной `Record Version`.
21. Как `operator`, я хочу выбрать `SELECTIVE_FIELDS`, чтобы раскрыть только
    нужные пути и не включать значения или соли остальных путей в package.
22. Как verifier, я хочу подтвердить один и тот же `fieldRoot` для full и
    selective disclosure, чтобы раскрытие не меняло anchor доказательства.
23. Как `operator`, я хочу подготовить транзакцию и увидеть все accounts,
    signer/writable flags, roots, fees и simulation logs, чтобы осознанно
    согласовать действие до wallet prompt.
24. Как `operator`, я хочу, чтобы endpoint и wallet вне `solana:devnet`
    отклонялись до подписи, чтобы synthetic demo не отправил данные в другой
    cluster.
25. Как владелец test wallet, я хочу подписывать только exact prepared message,
    чтобы UI не мог незаметно подменить intent между review и подписанием.
26. Как `operator`, я хочу видеть transaction state от `DRAFT` до `ISSUED`,
    чтобы отличать simulation failure, signing rejection, expiry, unknown и
    окончательную публикацию.
27. Как `operator`, я хочу, чтобы certificate не выдавался до `FINALIZED`,
    чтобы QR не ссылался на незавершённый anchor.
28. Как `operator`, я хочу получить signed `Certificate Package`, QR SVG/PNG,
    signature, slot и Explorer link после выпуска, чтобы передать результат
    проверяющему.
29. Как проверяющий, я хочу сканировать QR камерой, чтобы быстро открыть
    публичную проверку.
30. Как проверяющий, я хочу загрузить изображение QR или ввести URL/package
    вручную, чтобы camera permission не была обязательным условием.
31. Как проверяющий, я хочу, чтобы verifier проверял QR binding, issuer
    signature, field proof, batch proof, ownership и finalized anchor, чтобы
    доверять не сайту, а доказательствам.
32. Как проверяющий, я хочу видеть раскрытые поля только из проверенного
    `Certificate Package`, чтобы публичная карточка не подмешивала значения из
    текущей БД.
33. Как проверяющий, я хочу различать `VERIFIED`, `VERIFIED_HISTORICAL`,
    `SUPERSEDED`, `INVALID`, `DISPUTED` и `VERIFIED_NO_INCIDENT_CHECK`, чтобы
    причина результата не скрывалась за одним цветом.
34. Как проверяющий, я хочу видеть cluster, slot, signature и incident-index
    lag, чтобы оценить контекст проверки.
35. Как verifier, я хочу обрабатывать finalized `IncidentOpened` и
    `IncidentResolved` с watermark, чтобы текущий incident status не зависел от
    недоказуемой исторической полноты индекса.
36. Как `auditor`, я хочу просматривать records, certificates, backup folders,
    roots и operation timeline, чтобы выполнять read-only аудит.
37. Как `auditor`, я хочу, чтобы API запрещал mutations независимо от скрытия
    кнопок, чтобы роль нельзя было обойти прямым HTTP-запросом.
38. Как `operator`, я хочу dashboard с фактическими records, versions, batches,
    finalized anchor, certificates и incidents, чтобы видеть состояние контура.
39. Как демонстратор, я хочу native preflight с проверкой PostgreSQL/Node
    toolchain, devnet RPC, test-key balance, ports и synthetic marker, чтобы запуск не
    оставлял устаревшие artifacts после неуспешной подготовки.
40. Как `operator`, я хочу видеть пять стартовых `BackupCenter`-ов с отдельными
    volume, credentials, health и replica status, чтобы понимать состояние
    bounded backup plane.
41. Как `operator`, я хочу создать шестой или следующий локальный BackupCenter,
    чтобы расширить набор destinations без регистрации внешней production
    системы.
42. Как `operator`, я хочу нажать `Обновить копии`, чтобы система создала один
    полный immutable `Snapshot` и отправила его во все активные центры.
43. Как `operator`, я хочу видеть per-center `COPIED`, `PENDING_RETRY` и error,
    чтобы частичный успех не маскировался общим зелёным статусом.
44. Как `operator`, я хочу, чтобы новый Snapshot не перезаписывал старые
    folders, чтобы сохранялась provenance и выполнялась retention policy.
45. Как `operator`, я хочу, чтобы Retention Window удаляла старейший
    не-`FINALIZED` Snapshot после 13-й копии, чтобы центр не рос бесконечно.
46. Как владелец recovery-процесса, я хочу, чтобы единственный Finalized
    Snapshot сохранялся при retention cleanup, чтобы всегда оставалась
    минимально необходимая доверенная копия.
47. Как `operator`, я хочу выбрать BackupCenter и Snapshot и ввести три masked
    `Recovery Share`, чтобы начать восстановление без сохранения shares в
    browser storage, БД или logs.
48. Как система, я хочу отклонять `2-of-5`, чтобы одной недостаточной долей
    доверия нельзя было расшифровать Snapshot.
49. Как система, я хочу проверять ciphertext hash, plaintext hash и `Merkle
    Root`, чтобы повреждённый или подменённый Snapshot завершался fail-closed.
50. Как система, я хочу автоматически выбрать самый новый `FINALIZED` anchor
    без открытого incident, чтобы recovery возвращал доказуемое состояние, а не
    просто самый новый файл.
51. Как `chief_admin`, я хочу отдельно подписать `Restore Approval`, связанный
    с `snapshotId`, `Merkle Root` и target, чтобы оператор не мог единолично
    восстановить state.
52. Как `auditor`, я хочу видеть restore attempt и approval outcome без shares и
    plaintext, чтобы контролировать процесс, не получая секретов.
53. Как владелец MVP, я хочу один browser acceptance flow для Admin, OneLayer и
    backup UI, чтобы проверять внешний пользовательский результат на одном
    высоком seam.
54. Как release owner, я хочу отдельный guarded live-devnet smoke, чтобы
    подтвердить реальную finalization перед презентацией, не делая devnet
    транзакции частью обычного CI.
55. Как владелец registry, я хочу видеть ясные границы synthetic demo,
    `Certificate Package`, blockchain anchor и production recovery, чтобы MVP не
    воспринимался как доказательство истинности исходных кадастровых данных
    или готовность production.

## Implementation Decisions

### MVP task coverage

Каждая задача Gate C покрыта этой спецификацией отдельно. Номера `OL-C-07`…
`OL-C-09` и `OL-C-16`…`OL-C-19` в исходной нумерации не назначены.

| ID | Покрываемый результат | Состояние |
|---|---|---|
| `OL-C-01` | Инициализация registry и lifecycle operator role. | baseline |
| `OL-C-02` | Segmented ledger capacity 46 и монотонный segment index. | baseline |
| `OL-C-03` | `publish_anchor`, anchor hash и события. | baseline |
| `OL-C-04` | Seal дневных ledger segments и entries hash. | baseline |
| `OL-C-05` | Pause/resume registry. | baseline |
| `OL-C-06` | Open/resolve incident и registry-scoped validation. | baseline |
| `OL-C-10` | Canonicalization и Merkle implementations. | baseline |
| `OL-C-11` | Synthetic source, workflow event, Record Version, batch и manifest. | baseline |
| `OL-C-12` | Builder/publisher, finalized tracking и durable queue. | baseline |
| `OL-C-13` | Certificate issuance, disclosure modes, segment references и QR. | baseline |
| `OL-C-14` | Verifier lifecycle statuses, segment checks и incident index. | baseline |
| `OL-C-15` | Durable publish schema, immutable attempts и audit journal. | baseline |
| `OL-C-20` | Deterministic integration smoke до `VERIFIED`. | baseline |
| `OL-C-21` | Единый Admin/OneLayer web client и trust boundaries. | baseline |
| `OL-C-22` | Record list/detail, JSON import и pre-anchor canonical preview. | baseline |
| `OL-C-23` | Полный transaction review и untrusted RPC account validation. | baseline |
| `OL-C-24` | Wallet Standard test operator на devnet и exact-message signing. | baseline |
| `OL-C-25` | Transaction state machine и error branches. | baseline |
| `OL-C-26` | Certificate Package, QR, URL, signature/slot и timeline после finalized. | baseline |
| `OL-C-27` | Camera, image и manual QR verification inputs. | baseline |
| `OL-C-28` | Все verifier result views и объяснение причины результата. | baseline |
| `OL-C-29` | Deterministic browser E2E с fixture backend и mock wallet. | baseline |
| `OL-C-30` | Native integration, loopback binding и approval boundaries. | baseline |
| `OL-C-31` | Runtime credentials, session, CSRF и server-enforced roles. | baseline |
| `OL-C-32` | Generated on-chain client и drift check. | baseline |
| `OL-C-33` | Versioned Admin API, intent hash, idempotency и signed-transaction validation. | baseline |
| `OL-C-34` | Guarded live-devnet smoke до `QR → VERIFIED`. | baseline |
| `OL-C-35` | Fail-closed presentation preflight и synthetic safety checks. | baseline |
| `OL-C-36` | Closed `land-registry-v1` schema и единый schema source. | baseline |
| `OL-C-37` | JSON/CSV import, dry-run, row errors и idempotent new version. | baseline |
| `OL-C-38` | Dynamic field tree, commitments и shared builder/reconcile/fixture logic. | baseline |
| `OL-C-39` | `SELECTIVE_FIELDS`, field proofs и salt isolation. | baseline |
| `OL-C-40` | Dynamic QR и public card из verified package. | baseline |
| `OL-C-41` | Полный UI navigation flow, dashboard и incident panel. | baseline |
| `OL-C-42` | Five local BackupCenter-ов, folders, health/status и additional centers. | remaining |
| `OL-C-43` | Full Snapshot creation и immutable replication во все active centers. | remaining |
| `OL-C-44` | Retention Window максимум 12 с сохранением Finalized Snapshot. | remaining |
| `OL-C-45` | Masked 3-of-5 recovery, hash/root checks и fail-closed behavior. | remaining |
| `OL-C-46` | Operator/auditor/chief_admin separation и signed Restore Approval. | remaining |
| `OL-C-47` | End-to-end evidence для backup, retry, retention, mismatch и restore. | remaining |

- Scope состоит из `OL-C-01`…`OL-C-06`, `OL-C-10`…`OL-C-15`, `OL-C-20` и
  `OL-C-21`…`OL-C-47`: on-chain vertical pilot, pipeline, verifier, Admin,
  OneLayer и bounded backup/recovery control plane.
- Протокол, schema/account/package versions и frozen canonicalization contract
  не меняются. Любое нормативное изменение требует отдельного ADR и новой
  версии protocol artifact.
- `Record Version` является immutable состоянием объекта в момент публикации.
  Повторный импорт того же `internalRecordId` создаёт новую версию, а не
  перезаписывает существующую.
- `land-registry-v1` — закрытый demo registry schema и единственный источник
  допустимых field paths, types, required fields и length constraints для
  import, preview, batch builder, reconcile и fixture.
- Decimal и timestamp канонизируются как строки; float в canonical payload не
  допускается. Unknown field приводит к `CANONICALIZATION_FAILED`.
- Demo-контур хранит legacy `status` для seeded fixture и CLI happy path, а
  остальные пути — в typed field records. Целевая canonical payload остаётся
  источником протокольной модели и не подменяется demo-таблицами.
- `FULL_RECORD` остаётся default issuance mode. `SELECTIVE_FIELDS` включает в
  package только раскрытые values, salts и field proofs; `fieldRoot`, batch
  proof и anchor не меняются.
- `Certificate Package` является источником certificate data. Blockchain хранит
  `Merkle Root` и manifest hash, а QR связывает package через `certificateId` и
  `certificateHash`; полный JSON не записывается в Solana.
- Один web client содержит Admin и публичный OneLayer route groups. Публичная
  verification не требует wallet. Внутренние API доступны через same-origin
  proxy, без нового широкого CORS.
- Wallet Standard используется напрямую через стандартные connect/sign
  features и mock wallet в browser E2E. Browser подписывает только exact
  prepared bytes на `solana:devnet`; keypair, seed и issuer private key в UI не
  появляются.
- Transaction flow имеет состояния `DRAFT`, `PREPARED`, `SIMULATED`, `SIGNED`,
  `SUBMITTED`, `FINALIZED`, `ISSUED` и terminal/error branches
  `SIMULATION_FAILED`, `SIGNING_REJECTED`, `EXPIRED`, `UNKNOWN`, `FAILED`.
  `ISSUED` недостижимо без finalized checks.
- Admin API хранит typed intent, immutable intent hash, idempotency key и
  expiry. Перед broadcast сервер проверяет signature и соответствие signed wire
  transaction сохранённому intent, затем создаёт immutable publish attempt.
- `UNKNOWN` reconciles по известной signature и не пересобирает transaction.
  `publish_attempt` сохраняет подписанные bytes и позволяет ровно один
  terminal outcome transition.
- Verifier принимает только finalized anchor. Incident index получает
  on-chain finalized `IncidentOpened`/`IncidentResolved` с watermark; локальные
  monitor findings могут отображаться отдельно, но не меняют watermark.
- On-chain ledger использует сегменты capacity 46 и segment PDA; publish
  проверяет registry, role, sequence, previous anchor, schema/tree algorithms,
  segment ownership, day, seal и available capacity.
- `operator` может публиковать, создавать BackupCenter и обновлять Snapshots;
  `auditor` read-only; `chief_admin` отдельно подписывает Restore Approval.
  Role enforcement живёт на server session и Admin API, не в client state.
- Test credentials генерируются runtime и живут в tmpfs. Deploy/upgrade,
  operator-role grant, fixture reset и live smoke остаются CLI-only и требуют
  отдельных approval digests.
- MVP использует существующий native demo contour, loopback-only binding и
  synthetic marker. Никакие новые сервисы не выделяются без
  подтверждённой deployment/ownership boundary.
- Пять стартовых `BackupCenter`-ов — локальные encrypted storage locations с
  отдельными volume и credentials; они не являются key holders и не доказывают
  географическую независимость.
- `Snapshot` включает records, `Record Version`-ы, `Certificate Package`-ы, QR
  metadata, proofs, roots, manifests, anchor references и operation history.
  Plaintext и Recovery Share не сохраняются в backup tables, browser storage,
  logs или replica storage.
- `Обновить копии` создаёт один immutable Snapshot и реплицирует его во все
  active centers. Новый BackupCenter получает данные со следующего обновления;
  старые Snapshot folders не перезаписываются.
- Retention Window ограничивает каждый центр 12 snapshots. После 13-й
  валидной копии удаляется старейший не-`FINALIZED`; если все snapshots
  finalized, удаляется самая старая при сохранении хотя бы одного Finalized
  Snapshot. Ручное удаление запрещено.
- Replica status является per-center. Недоступный center получает retry state,
  а общий результат явно показывает partial success.
- Recovery принимает три masked Recovery Share из пяти только в памяти
  операции, автоматически выбирает newest finalized anchor без открытого
  incident, проверяет ciphertext/plaintext hashes и Merkle Root и затем требует
  Restore Approval, связанный с snapshot, root и target.
- Любой mismatch, недоступный anchor, повреждённый ciphertext, недостаточное
  число shares или отсутствие approval завершает recovery fail-closed.
- Целевые сущности хранения включают anchor/batch/leaf, durable publish queue и
  immutable attempts, а также backup center, snapshot, replica и restore
  attempt. Одна Snapshot получает не более одной replica на BackupCenter.
- Высший acceptance seam — browser E2E Admin/OneLayer/backup flow против
  deterministic fixture backend с mock Wallet Standard. On-chain invariants,
  cryptographic proofs и низкоуровневые canonicalization properties остаются
  supporting tests, а не отдельными пользовательскими seams.

## Testing Decisions

- Хороший тест проверяет наблюдаемое поведение и доменный инвариант: что получил
  пользователь, какой статус вернул API/verifier, какие данные вошли в package,
  было ли действие разрешено ролью и изменилось ли состояние после операции.
  Тесты не должны фиксировать внутренний способ реализации, расположение
  компонентов или конкретный SQL, если внешний контракт тот же.
- Основной acceptance test — один детерминированный browser seam, на котором
  пользователь проходит import → preview → review → wallet sign → finalized
  package → QR → verification, а также backup center → snapshot → replication →
  recovery. В него входят reload/double-click, role restrictions, result views,
  tampering и fail-closed branches.
- Этот seam использует fixture backend и mock Wallet Standard. Он проверяет
  browser flow, Admin API contract, session/CSRF, idempotency, transaction state
  machine и QR binding, но не притворяется проверкой реальной Solana
  finalization.
- Отдельный guarded live-devnet smoke проверяет публичный `QR → finalized
  anchor → VERIFIED` path и tampered QR rejection перед презентацией/release.
  Он не запускается в default CI и не подписывает transaction из браузера.
- On-chain module tests покрывают account ownership, signer permissions, role
  lifecycle, pause/resume, segment capacity 46, sequence continuity,
  previous-anchor check, schema/tree algorithm checks, seal, incident lifecycle
  и rejected invalid accounts.
- Canonicalization and Merkle tests покрывают Unicode NFC, decimal strings,
  timestamps, field sorting, field commitments, RFC 6962 proofs для разных
  leaf counts и deterministic manifest/root rebuild.
- Pipeline/publisher tests покрывают duplicate/out-of-order CDC, cursor gaps,
  restart, workflow mismatch, deterministic rebuild, concurrent publish,
  immutable signed attempt, `UNKNOWN → FINALIZED`, expiry и sanitized errors.
- Verifier tests покрывают forged record ID/value/salt/proof/root/program/
  segment PDA, open incident, finalized incident events, watermark, lag,
  unavailable index, `VERIFIED_HISTORICAL`, `SUPERSEDED` и rejection of
  non-finalized commitment.
- Import/API tests покрывают unknown paths, wrong types, decimal scale,
  fractional timestamp, required-field errors, row-level CSV failure, dry-run
  non-mutation, idempotent new `Record Version` и schema consistency между
  builder, reconcile и fixture.
- Disclosure tests проверяют, что selective package содержит salts and proofs
  только раскрытых paths, не содержит `record_field_key` или encrypted key,
  не возвращает скрытые values и ломается при подмене раскрытой salt.
- Backup tests покрывают five-center bootstrap, additional center, immutable
  replication, per-center retry, 13th-copy retention, preservation of a
  Finalized Snapshot, damaged ciphertext, `2-of-5` rejection, `3-of-5` success,
  hash/root mismatch, no open incident, role separation and chief approval.
- Accessibility and presentation tests проверяют keyboard navigation,
  high-contrast theme, icon-plus-text status, camera fallback, responsive mobile
  layout, screenshot/trace evidence и fail-closed preflight.
- Existing prior art is the deterministic browser fixture backend and mock
  Wallet Standard flow, the guarded devnet smoke, existing Rust on-chain
  invariant tests, and existing canonical/Merkle/verifier unit and property
  tests. Новые тесты должны расширять эти seams, а не создавать параллельный
  test harness без необходимости.
- Количество тестов, 95% coverage как самоцель, live-devnet transactions в
  default CI и нагрузка на 10⁶ записей не являются acceptance criteria.

## Out of Scope

- Mainnet, production credentials, реальные кадастровые данные и любые claims о
  законности или истинности первоначального ввода.
- Production IdP, SSO/RBAC, hardware key custody, production HSM, multisig,
  timelock, durable nonce и governance/key ceremony.
- Независимый Monitor Gate D и production-like recovery infrastructure.
- Recovery Lab Gate E0 и настоящий restore drill; локальные центры на одном host
  не доказывают независимость дата-центров.
- Регистрация существующих внешних backup-систем, географически независимые
  custodians и production object-lock environments.
- Второй RPC provider, banking SDK, Kubernetes, Helm, Terraform, OPA, SIEM и
  algorithm transition.
- OCR, PDF/scan parsing, произвольное извлечение полей, адресные справочники,
  нормализация адресов и загрузка исходных документов; внешняя связь возможна
  только через заранее вычисленный `documentHash`.
- Bulk issuance, native mobile app, PWA/offline mode, push/email, analytics,
  localization, formal accessibility certification и cross-device loopback QR
  scanning.
- Изменение frozen protocol, account layout, package version, certificate data
  boundary или canonicalization contract в рамках этой спецификации.
- Fixture-only reset/recovery как замена нормативному `SnapshotPackage`,
  threshold recovery или release gate 7.

## Further Notes

- `OL-C-01`…`OL-C-41` считаются уже реализованным baseline; агентская работа
  должна не регрессировать их внешний контракт.
- `OL-C-42`…`OL-C-47` — основной оставшийся implementation scope: backup UI,
  Snapshot lifecycle, replication, Retention Window, recovery и bounded E2E.
- Gate C не считается закрытым без 72-часового synthetic-прогона,
  `anchor_sequence_gap_total = 0`, идентичного `manifestHash` при повторной
  сборке, корректного finalized incident index, approved live smoke и полного
  backup evidence.
- Принятые решения о Wallet Standard и fixture backend, границе Certificate
  Package, а также пяти локальных BackupCenter-ах и threshold recovery должны
  считаться обязательными architectural constraints этой спецификации.
- Любая заявка, расширяющая MVP за пределы bounded local control plane, должна
  назвать новый acceptance criterion, наблюдавшийся отказ или зафиксированный
  риск и пройти отдельное архитектурное решение.
- Общий implementation plan намеренно не изменяется; эта спецификация является
  agent-ready представлением MVP scope и публикуется с triage label
  `ready-for-agent`.
