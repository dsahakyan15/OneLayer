# OneLayer — MVP-план

**Дата:** 2026-08-04
**Область:** Gate C — вертикальный pilot и визуальный MVP на synthetic-данных и
devnet.
**Источник выделения:** `IMPLEMENTATION_PLAN.md`, §5–§7.
**Важно:** этот документ — отдельный рабочий план всех MVP-задач; Gate A/B,
Monitor Gate D, будущая
production recovery hardening и Gate E здесь не планируются.

## 1. Цель и границы MVP

MVP должен показать один проверяемый пользовательский контур:

```text
JSON/CSV сертификата пользователя
  → schema validation land-registry-v1
  → canonical preview
  → batch + Merkle root + manifest hash
  → simulation
  → transaction review + Wallet Standard signature
  → finalized anchor
  → signed CertificatePackageV1 + QR
  → публичная проверка OneLayer
```

Параллельно Admin должен поддерживать bounded local backup/recovery flow:

```text
пять стартовых BackupCenter-ов
  → зашифрованный SnapshotPackageV1
  → immutable-копия во все активные центры
  → retention максимум 12 snapshots на центр
  → три Recovery Share из пяти
  → проверка последнего FINALIZED anchor
  → отдельный chief_admin: Approve restore
  → восстановление полного state
```

MVP не меняет замороженный on-chain протокол. Solana хранит anchor с
`merkleRoot` и `manifestHash`; полный JSON находится в подписанном
`CertificatePackageV1` и возвращается только после проверки package, Merkle
proof, finalized anchor и incident status.

### Текущий статус

- `OL-C-01`…`OL-C-47` реализованы.
- Выход Gate C не закрыт: требуется 72-часовой synthetic-прогон и полный
  backup E2E.
- Отклонение `OL-C-29` от первоначального Surfpool-подхода зафиксировано в
  `docs/adr/0003-visual-mvp-boundaries.md`: детерминированный browser E2E
  использует fixture backend, а devnet проверяется отдельным guarded smoke.

## 2. Реестр MVP-задач

Статусы ниже отражают состояние, зафиксированное в исходном плане.

### 2.1. On-chain, pipeline и verifier

| ID | Задача | Состояние |
|---|---|---|
| `OL-C-01` | On-chain: `initialize_registry`, `grant_operator`, `revoke_operator`. | готово |
| `OL-C-02` | On-chain: `create_ledger_segment` по ADR-0002, capacity 46, монотонный `segment_index` внутри дня. | готово |
| `OL-C-03` | On-chain: `publish_anchor` (§8.4), `anchor_hash` по §2.2 и события. | готово |
| `OL-C-04` | On-chain: `seal_daily_ledger` запечатывает все сегменты дня; `entries_hash` считается по `segment_index`. | готово |
| `OL-C-05` | On-chain: `pause_registry` / `resume_registry`. | готово |
| `OL-C-06` | On-chain: `open_incident` / `resolve_incident`, счётчик `incident_count`; resolve проверяет принадлежность incident реестру. | готово |
| `OL-C-10` | `crates/canonical` и `crates/merkle`: реализация по Gate B. | готово |
| `OL-C-11` | `apps/pilot-pipeline`: synthetic source, workflow-событие, canonical version, batch и manifest. | готово |
| `OL-C-12` | Единый builder/publisher для devnet, отслеживание `finalized`, durable queue в PostgreSQL и раздельные test-key контуры CLI/UI. | готово |
| `OL-C-13` | Выдача сертификата в обоих режимах раскрытия, `recordIdCommitment`, `segmentIndex`, segment PDA и QR `URL + id + hash`; QR разрешён только для рабочего registry. | готово |
| `OL-C-14` | `apps/verifier`: проверка segment PDA, lifecycle-статусы `VERIFIED_HISTORICAL` / `SUPERSEDED`, event-backed incident index с watermark и REST. | готово |
| `OL-C-15` | Схема БД: durable publish queue, неизменяемые `publish_attempt` с однократным outcome и append-only audit journal без hash-chain. | готово |
| `OL-C-20` | Детерминированный integration smoke: synthetic change → `VERIFIED` в verifier на локальной Solana-среде. | готово |

### 2.2. Admin, OneLayer и transaction flow

| ID | Задача | Состояние |
|---|---|---|
| `OL-C-21` | Один Next.js App Router client `apps/mvp-web` с закрытой Admin-панелью и публичной OneLayer-панелью, общими tokens/status components и разными trust boundaries. | готово |
| `OL-C-22` | Admin: список/детали записей, ручной ввод/JSON-import и preview canonical payload, disclosed fields, commitments и batch leaf; `certificateHash` только после finalized package. | готово |
| `OL-C-23` | Transaction review: program ID, instruction, accounts с signer/writable flags, registry, segment PDA, batch, roots, fee payer, fee/rent, simulation logs; RPC accounts проверяются по owner, длине и discriminator. | готово |
| `OL-C-24` | Wallet Standard для test operator на `solana:devnet`; browser подписывает только точное prepared message, keypair/seed в UI отсутствуют, signed transaction передаётся единственному durable publisher. | готово |
| `OL-C-25` | State machine `DRAFT → PREPARED → SIMULATED → SIGNED → SUBMITTED → FINALIZED → ISSUED` с ветками `SIMULATION_FAILED`, `SIGNING_REJECTED`, `EXPIRED`, `UNKNOWN`, `FAILED`; `ISSUED` запрещён до finalized checks. | готово |
| `OL-C-26` | После `FINALIZED`: certificate package, QR SVG/PNG, URL, transaction signature, Explorer devnet link и timeline без секретов. | готово |
| `OL-C-27` | OneLayer: QR из камеры, image upload и manual URL/package input; проверка QR binding, issuer signature, field/batch proof, ownership, finalized transaction и incident index. | готово |
| `OL-C-28` | OneLayer result views: `VERIFIED`, `VERIFIED_HISTORICAL`, `SUPERSEDED`, `INVALID`, `DISPUTED`, `VERIFIED_NO_INCIDENT_CHECK` с причиной, cluster, slot, signature, lag и раскрытыми полями. | готово |
| `OL-C-29` | Детерминированный browser E2E с mock Wallet Standard: happy path, package/QR tampering и synthetic DB tampering; live devnet не запускается в обычном CI. | готово |
| `OL-C-30` | Запустить native-контур `deploy/devnet-demo` с одним UI-port, сохранив synthetic marker, tmpfs keys и loopback binding; deploy остаётся CLI-only. | готово |
| `OL-C-31` | Runtime-generated test credentials в tmpfs, короткая server-side session с `HttpOnly`/`SameSite` cookie и CSRF; `operator` пишет, `auditor` читает. | готово |
| `OL-C-32` | IDL → Codama → checked-in Kit-native TypeScript client; CI drift check; ручная Borsh/PDA/account layout логика во frontend запрещена. | готово |
| `OL-C-33` | Versioned Admin API: idempotency key, immutable intent hash, expiry, server-session role checks и повторная валидация signed wire transaction. | готово |
| `OL-C-34` | Один guarded live-devnet browser smoke перед презентацией/release: finalized transaction → certificate → QR → `VERIFIED`, без ключей в браузере. | готово |
| `OL-C-35` | Presentation preflight: native PostgreSQL/Node toolchain, devnet-only RPC, test-key balance/rent, ports и synthetic marker; fail closed до создания новых artifacts. | готово |

### 2.3. Динамические записи и selective disclosure

| ID | Задача | Состояние |
|---|---|---|
| `OL-C-36` | Закрытая demo-схема реестра `land-registry-v1`: допустимые пути, типы, обязательные поля и ограничения; неизвестное поле → `CANONICALIZATION_FAILED`; один источник для preview, issuance и reconcile. | готово |
| `OL-C-37` | Импорт JSON (`internalRecordId` + `fields`) и CSV; построчная валидация, dry-run, отчёт строки/пути и идемпотентный upsert новой версии. | готово |
| `OL-C-38` | Динамические canonical metadata: field tree из фактических полей, per-field commitments, `fieldRoot`, `recordCommitment`, batch leaf; общий источник для builder, reconcile и fixture. | готово |
| `OL-C-39` | `SELECTIVE_FIELDS`: в package попадают только выбранные значения, соли и field proofs; `fieldRoot` и anchor не меняются; `FULL_RECORD` остаётся default. | готово |
| `OL-C-40` | Динамический QR и публичная карточка: QR строится из выданного package только при `RegistryConfig.paused = false`; UI показывает только доказанные раскрытые поля и cluster/slot/signature. | готово |
| `OL-C-41` | Полный UI-контур: dashboard с фактическими метриками, record/certificate details, incident panel и «как это работает»; навигация покрывает use cases. | готово |

### 2.4. Backup и recovery control plane

| ID | Задача | Состояние |
|---|---|---|
| `OL-C-42` | Backup Admin: пять стартовых локальных `BackupCenter`-ов с отдельными volume/credentials, folders, health/replica status и созданием дополнительных центров. | готово |
| `OL-C-43` | Backup lifecycle: полный `SnapshotPackageV1`, `Обновить копии`, новая immutable-папка и одна копия во все активные центры; статусы `COPIED` / `PENDING_RETRY` / ошибка. | готово |
| `OL-C-44` | Retention максимум 12 папок на центр; при переполнении удаляется старейшая не-`FINALIZED`, единственная `FINALIZED` не удаляется; ручное удаление запрещено. | готово |
| `OL-C-45` | Recovery UI: центр/папка, три masked share без persistence, `ciphertextHash`/`plaintextHash`, последний `FINALIZED` anchor без открытого incident и сверка `MerkleRoot`; fail-closed. | готово |
| `OL-C-46` | Разделение полномочий: `operator` создаёт центры/копии, `auditor` читает, `chief_admin` отдельно подписывает `Approve restore`, approval связан с `snapshotId`, root и target. | готово |
| `OL-C-47` | Backup/recovery E2E: пять центров, шестой центр, replication, offline retry, retention, damaged ciphertext, `2-of-5` отказ, `3-of-5` успех, root mismatch и chief approval. | готово |

## 3. Нормативные MVP-ограничения

### 3.1. Реестр и канонизация

`land-registry-v1` допускает только следующие пути:

| Путь | Тип | Требование |
|---|---|---|
| `status` | enum text | обязателен: `ACTIVE \| ARCHIVED \| PENDING \| DISPUTED` |
| `cadastralNumber` | text | обязателен, NFC, byte length ≤ 64 |
| `parcelAddress` | text | NFC, byte length ≤ 256 |
| `areaSquareMeters` | decimal string | scale 2, например `"1250.50"`; float запрещён |
| `landCategory` | enum text | `AGRICULTURAL \| SETTLEMENT \| INDUSTRIAL \| FOREST \| WATER \| RESERVE` |
| `permittedUse` | text | NFC, byte length ≤ 128 |
| `rightType` | enum text | `OWNERSHIP \| LEASE \| EASEMENT \| MORTGAGE` |
| `rightRegisteredAt` | timestamp | RFC 3339 UTC без дробной части |
| `encumbered` | bool | — |
| `holderCommitment` | hex(64) | commitment к личности, не сама личность |
| `documentHash` | hex(64) | SHA-256 документа, если он есть |

Правила:

- неизвестное поле отклоняется с `CANONICALIZATION_FAILED`; молчаливое
  отбрасывание запрещено;
- decimal и timestamp принимаются строками;
- персональные данные правообладателя не хранятся — только
  `holderCommitment`;
- повторный `internalRecordId` создаёт новую Record Version; предыдущий
  сертификат после нового anchor получает `SUPERSEDED`;
- CSV: первая строка задаёт пути, каждая следующая строка — отдельная запись;
  ошибочная строка не импортируется частично и не скрывает номер строки/пути;
- dry-run не меняет БД и показывает канонические значения, типы и ошибки.
  Итоговые commitments появляются после сохранения версии записи.

### 3.2. Disclosure, QR и верификация

- `FULL_RECORD` раскрывает все разрешённые поля выбранной версии.
- `SELECTIVE_FIELDS` раскрывает только выбранные пути, их соли и proofs;
  значения и соли остальных путей в package не попадают.
- `fieldRoot`, batch proof и anchor одинаковы для `FULL_RECORD` и
  `SELECTIVE_FIELDS` одной версии.
- QR содержит `URL + certificateId + certificateHash`, но не данные записи.
- Рабочий registry — это существующий on-chain `RegistryConfig` с
  `paused = false`. QR нельзя выдать, получить, открыть или проверить, пока
  registry paused; Admin API, public QR routes и независимый verifier обязаны
  проверять этот флаг и возвращать `REGISTRY_PAUSED` (или fail-closed при
  недоступном config).
- Публичная карточка получает значения только из проверенного package, а не из
  БД; нераскрытые поля не подменяются плейсхолдерами.
- Локальный MVP принимает только loopback HTTP с заметкой
  `DEVNET SYNTHETIC DEMO`; остальные HTTP origins отклоняются. Нормативный
  транспорт — HTTPS.
- incident index строится из finalized `IncidentOpened` / `IncidentResolved`
  и содержит watermark. Недоступный или устаревший индекс не может дать
  зелёный `VERIFIED` и приводит к `VERIFIED_NO_INCIDENT_CHECK`.

### 3.3. UI, роли и публикация

Один `apps/mvp-web` содержит route groups Admin и OneLayer. Wallet hooks живут
только в client leaf-components; публичная проверка wallet не требует.
Внутренние API доступны браузеру через same-origin proxy, без широкого CORS.

Роли:

- `operator`: импорт, подготовка batch, simulation, запрос подписи, issuance,
  создание BackupCenter и обновление копий;
- `auditor`: read-only записи, сертификаты, backup folders и timeline;
- `chief_admin`: отдельная асимметричная подпись `Approve restore`.

Session и CSRF проверяются сервером. Роль берётся только из server session,
не из `localStorage`, query/body или состояния кнопок. Test credentials живут
в tmpfs. Browser test wallet имеет только operator role; issuer key в браузер
не передаётся.

Transaction review блокирует wallet prompt и показывает cluster `devnet`,
program ID, instruction, signer/writable accounts, registry, segment PDA,
batch sequence, roots, fee payer, fee/rent и simulation logs. Backend хранит
typed intent, `intentHash`, idempotency key и expiry, после чего сверяет exact
signed wire transaction. `UNKNOWN` reconciles только известную signature;
слепая пересборка запрещена.

### 3.4. Backup и recovery

Каждый стартовый BackupCenter создаётся локально с отдельными volume и
credentials. Center хранит ciphertext, но не recovery shares. Один snapshot
реплицируется как одна immutable-копия в каждый активный центр; новый центр
получает данные со следующего обновления.

Snapshot включает records, record versions, certificate packages, QR metadata,
proofs, roots, manifests, anchor references и operation history. В таблицах
не сохраняются recovery shares и plaintext.

Retention:

- максимум 12 snapshots на центр;
- после 13-й валидной копии сначала удаляется самая старая не-`FINALIZED`;
- если все копии `FINALIZED`, удаляется самая старая при сохранении хотя бы
  одной `FINALIZED` версии;
- ручное удаление недоступно;
- частичный успех репликации виден per-center, недоступный центр получает
  retry-состояние и не маскируется общим зелёным статусом.

Recovery принимает три masked shares из пяти только в памяти операции. Система
выбирает самый новый `FINALIZED` anchor без открытого incident, проверяет
`ciphertextHash`, расшифровывает snapshot, пересчитывает `plaintextHash` и
`MerkleRoot`, затем ждёт отдельный `chief_admin` approval, связанный с
`snapshotId`, root и target. Любая ошибка завершает операцию fail-closed.

Пять локальных центров доказывают только bounded MVP control plane; они не
доказывают географическую или административную независимость production
custodians и не закрывают release gate 7.

## 4. MVP acceptance criteria

1. Admin создаёт или импортирует synthetic-запись; marker и schema validation
   выполняются до операций с данными, а UI показывает canonical preview.
2. Devnet-транзакция сначала проходит simulation; review показывает полный
   набор блокирующих полей, подпись до simulation не запрашивается.
3. Повторный click/reload не создаёт второй batch или transaction; expired
   blockhash возвращает flow к preparation/simulation.
4. Certificate не выдаётся до `finalized`; после него доступны package,
   `certificateHash`, QR и signature/slot.
4a. Certificate QR выдаётся и принимается только для рабочего registry:
    `RegistryConfig` существует и имеет `paused = false`; при pause issuance,
    QR endpoints и verifier возвращают `REGISTRY_PAUSED`.
5. Camera/image/manual QR flow в fresh browser context даёт `VERIFIED`;
   cross-device scan проверяется только на отдельно разрешённом HTTPS staging.
6. QR/package/field tampering даёт `INVALID`, direct synthetic DB tampering —
   `DISPUTED`; stale/unavailable incident index — `VERIFIED_NO_INCIDENT_CHECK`;
   есть fixtures для `VERIFIED_HISTORICAL` и `SUPERSEDED`.
7. UI адаптивен для desktop/mobile, управляется клавиатурой, имеет camera
   fallback и не выражает status только цветом.
8. Локальный детерминированный E2E сохраняет screenshot/trace; guarded live
   evidence создаётся отдельно `OL-C-34`.
9. Admin и OneLayer используют один набор design tokens/status components и
   доступную high-contrast тему.
10. `auditor` может читать, но не может подготовить batch, запросить подпись
    или выдать certificate; это проверяется на Admin API.
11. Deploy/CLI publish требуют собственных approval digests; browser publish
    требует reviewed intent, wallet prompt и signed-transaction validation.
12. Default CI проходит IDL→Codama drift check и локальный browser E2E без
    SOL; `OL-C-34` запускается только с отдельным подтверждением.
13. Preflight на clean host либо подтверждает зависимости, либо выходит до
    mutation с точной remediation; fixture reset не затрагивает чужие
    процессы или данные.
14. JSON/CSV принимает валидный сертификат пользователя и отклоняет unknown
    field, неверный type, decimal scale, дробной timestamp и пустое обязательное
    поле с отчётом строки/пути; dry-run не меняет БД.
15. `fieldRoot`, `recordCommitment`, batch leaf и `merkleRoot` строятся из
    фактических полей; повторный `internalRecordId` создаёт новую версию,
    прежний сертификат становится `SUPERSEDED`.
16. `SELECTIVE_FIELDS` даёт `VERIFIED` для подмножества путей; package не
    содержит значения/соли нераскрытых путей, а root/proofs совпадают с
    `FULL_RECORD` той же версии.
17. Public certificate detail показывает ровно поля из проверенного package и
    не читает значения в обход package.
18. Все сценарии `docs/use-cases-ru.md`, кроме явных CLI-only исключений,
    доступны из UI; dashboard показывает фактические API-метрики.
19. Backup Admin показывает пять стартовых центров, folders, health и
    per-center status; создание добавляет шестой или следующий пустой центр.
20. `Обновить копии` создаёт одну immutable-копию полного state во всех
    активных центрах; недоступный центр получает `PENDING_RETRY`, частичный
    успех виден явно.
21. Ни один центр не хранит более 12 snapshots; retention сохраняет хотя бы
    одну `FINALIZED` версию.
22. Backup включает полный перечисленный state, а plaintext не покидает
    encrypted package при репликации.
23. Recovery автоматически выбирает последний `FINALIZED` anchor без incident,
    принимает `3-of-5`, отклоняет `2-of-5`, не сохраняет shares и останавливается
    при любом hash/root mismatch.
24. Только `chief_admin` подписывает `Approve restore`; `operator` не может
    удалить backup вручную, `auditor` остаётся read-only.
25. Локальный E2E покрывает пять центров, дополнительный центр, active
    replicas, retry, retention, damaged package, `2-of-5`/`3-of-5`, root
    mismatch и успешный restore. Это evidence bounded MVP, не release gate 7.

## 5. MVP-структура и транспорт

```text
spec/                         # frozen protocol documents and vectors
onchain/programs/onelayer-registry/
crates/canonical/
crates/merkle/
packages/canonical-ts/
packages/merkle-ts/
packages/onchain-client/      # checked-in Codama/Kit client
packages/snapshot-ts/         # SnapshotPackageV1 и threshold recovery
apps/pilot-pipeline/          # один процесс с логическими модулями
apps/demo-api/                # Admin HTTP runtime и backup/recovery
apps/mvp-web/                 # Admin + public OneLayer
apps/verifier/                # REST verifier
tests/e2e/                    # integration smoke
tests/e2e-web/                # deterministic browser E2E
db/migrations/
deploy/devnet-demo/           # native demo
docs/adr/
```

Транспорт MVP:

| Граница | Механизм |
|---|---|
| Pipeline | вызовы функций в одном процессе, PostgreSQL transactions |
| Pipeline → Publisher | `publish_queue` с claim/lease |
| Browser → `mvp-web` | same-origin HTTPS; точный loopback HTTP только для demo |
| `mvp-web` → API/verifier | server-side same-origin proxy, loopback HTTP |
| Publisher → Solana | allowlisted devnet JSON-RPC |
| Public verifier | REST |

В MVP не вводятся gRPC/protobuf и новые процессы без подтверждённой границы
развёртывания или владения. WORM используется для immutable manifest/evidence,
но не для очереди.

Целевые MVP-сущности БД:

- `anchor_batch` и `batch_leaf` с составным ключом `(registry_id,
  batch_sequence)`;
- `publish_queue` и immutable `publish_attempt`, где подписанные bytes не
  заменяются, а terminal outcome разрешается только один раз;
- `backup_center`, `snapshot`, `snapshot_replica`, `restore_attempt`;
- `snapshot_replica` уникальна для пары `(snapshot_id, center_id)`;
- `copy_status=VERIFIED` разрешён только после проверки ciphertext hash;
- `FINALIZED` требует совпадения с выбранным finalized anchor без открытого
  incident;
- shares и plaintext не сохраняются в backup tables.

## 6. Тестовая стратегия

Критерий — покрытые инварианты, а не количество тестов.

### On-chain

Для каждой инструкции обязательны негативные проверки её account constraints и
state invariants: авторизация и принадлежность реестру, роли, pause/resume,
сегменты capacity 46, непрерывность `batch_sequence`, previous anchor hash,
schema/hash/tree algorithm, sealed/чужие/переполненные ledger-и, incident open/
resolve и повторные операции.

Пирамида: быстрые property/invariant tests в LiteSVM или Mollusk, integration в
Surfpool с synthetic fixtures, browser E2E с mock Wallet Standard, regression
gate по CU `publish_anchor` и fuzz instruction data. Live devnet — только
guarded `OL-C-34`.

### Off-chain и browser

Обязательны focused tests для Unicode NFC, decimal, сортировки, RFC 6962 proofs,
CDC cursor/restart, deterministic `manifestHash`, duplicate publish и
`UNKNOWN → FINALIZED` без изменения signed bytes; tampering commitments,
field/batch proofs, root, program, segment PDA; finalized incident lifecycle;
`confirmed` вместо `finalized`; simulation/signing/expiry/reload/double-click;
camera fallback, invalid QR/package, `DISPUTED` и stale incident index.

Для selective disclosure отдельно проверяется, что:

- package не содержит `record_field_key`;
- соли присутствуют только для раскрытых путей;
- API не возвращает `record_field_key` или
  `record_field_key_encrypted`;
- подмена соли ломает field proof.

Не являются MVP-критериями квоты тестов, 95% coverage как самоцель, live-devnet
в default CI или массовые нагрузочные прогоны на 10⁶ записей.

## 7. Выход Gate C

Gate C считается готовым только если одновременно выполнены следующие условия:

- сквозной flow работает 72 часа на synthetic-нагрузке без ручного
  вмешательства;
- `anchor_sequence_gap_total = 0`;
- повторная сборка диапазона даёт идентичный `manifestHash`;
- incident index обрабатывает finalized open/resolve и watermark;
- локальный browser flow `OL-C-29` и отдельно approved `OL-C-34` доходят до
  QR → `VERIFIED`, а tampering даёт `INVALID`/`DISPUTED`;
- backup flow создаёт копию во всех активных центрах, соблюдает retention 12 и
  восстанавливает state только после root match и chief approval.

## 8. Что явно не входит в этот MVP-план

Mainnet, production credentials, реальные кадастровые данные, внешний IdP и
production SSO/RBAC, HSM/hardware custody, внешний backup registration,
географически независимые custodians, Monitor Gate D, будущая recovery
hardening, настоящий restore drill, два RPC, multisig/timelock, Kubernetes, SIEM, banking
SDK, bulk issuance, OCR/PDF parsing, mobile app, PWA/offline mode, push/email,
analytics, локализация и внешняя публикация.

Fixture-only recovery остаётся demo/prototype-частью и не заменяет
`SnapshotPackageV1`, threshold recovery или production release gate 7.

## 9. Связанные документы

- `IMPLEMENTATION_PLAN.md` — исходный общий план; оставлен без изменений.
- `CONTEXT.md` — термины Certificate Package, Record Version, Anchor, Snapshot,
  BackupCenter, Recovery Share и Restore Approval.
- `docs/adr/0003-visual-mvp-boundaries.md` — границы и отклонения визуального
  MVP.
- `docs/adr/0004-certificate-data-boundary.md` — полный JSON в
  `CertificatePackageV1`, не в Solana.
- `docs/adr/0005-mvp-backup-centers-and-recovery.md` — пять локальных центров и
  threshold recovery.
- `docs/use-cases-ru.md` — пользовательские сценарии MVP.
- `docs/presentation-ru.md` — объяснение потока и границ для презентации.
- `deploy/devnet-demo/README.md` — запуск native demo-контура.
