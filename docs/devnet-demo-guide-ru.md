# Инструкция: synthetic devnet demo

Практическое руководство по `deploy/devnet-demo/demo`: запуск, что происходит на каждом
шаге, как данные хешируются и попадают в Solana devnet, и как добавить новые синтетические
записи/сертификаты.

Границы демо: только Solana **devnet**, только синтетические записи (`SYNTHETIC-*`),
только БД `onelayer_demo` в Compose-проекте `onelayer-devnet-demo`, порты только на
loopback, ключи только в tmpfs `/dev/shm/onelayer-devnet-demo`. Реальные кадастровые
данные в этот стенд не загружаются и загружаться не должны.

---

## 1. Предусловия

`deploy/devnet-demo/scripts/preflight` проверяет версии жёстко, поэтому нужны именно они:

| Компонент | Версия |
|---|---|
| Node.js | `v24.*` |
| Solana CLI | `3.1.10` |
| Anchor CLI | `1.1.2` |
| Docker + `docker compose` | демон доступен, пользователь в группе `docker` |
| Rust / cargo | по `rust-toolchain.toml` |
| прочее | `git`, `curl`, `sha256sum` |

Проверка:

```bash
node --version && solana --version && anchor --version && docker info >/dev/null && echo ok
```

Занятые порты: `127.0.0.1:8090` (demo-api), `127.0.0.1:8080` (verifier),
`127.0.0.1:55432` (PostgreSQL).

---

## 2. Полный сценарий показа

### Шаг 1. `plan` — ничего не отправляется в сеть

```bash
./deploy/devnet-demo/demo plan
```

Что делает:
1. `anchor build` — сборка программы `onelayer-registry`;
2. `initialize-runtime` — генерирует в `/dev/shm/onelayer-devnet-demo` пароль Postgres,
   internal-токен, тестовый payer-keypair, buffer-keypair, копирует program-keypair;
3. `devnet_demo_fixture prepare` — детерминированно собирает batch из фикстуры и печатает
   `merkleRoot` / `manifestHash`;
4. `program-deploy plan` → `artifacts/program-plan.txt` с `approval_digest`;
5. `devnet_demo_chain plan` → `artifacts/chain-plan.txt` с `approval_digest`.

Ни одной транзакции не отправляется. Артефакты — в `deploy/devnet-demo/artifacts/`
(в Git игнорируются).

### Шаг 2. Согласование двух дайджестов

Это approval-барьер: без точного совпадения дайджестов ни деплой программы, ни publish
не выполнятся.

```bash
grep approval_digest deploy/devnet-demo/artifacts/program-plan.txt
grep approval_digest deploy/devnet-demo/artifacts/chain-plan.txt
```

- `program-plan` дайджест = SHA-256 от (метка `ONELAYER_SYNTHETIC_DEVNET_PROGRAM_V1`, RPC,
  program id, pubkey плательщика, sha256 бинаря `.so`, лимит airdrop).
  Меняется при любой пересборке программы.
- `chain-plan` дайджест = SHA-256 от (метка `ONELAYER:SYNTHETIC:DEVNET:DEMO:APPROVAL:V1`,
  RPC, program id, payer, PDA конфига, PDA роли, PDA сегмента, merkle root, manifest hash).
  Меняется при изменении фикстуры **и при смене UTC-даты** (PDA сегмента содержит `day_utc`).

Практический вывод: `plan` и `happy-path` нужно выполнять в один UTC-день, иначе дайджест
устареет — тогда просто перезапустите `plan`.

### Шаг 3. `happy-path` — реальная девнет-транзакция и VERIFIED

```bash
ONELAYER_DEVNET_DEPLOY_APPROVED=<program-approval-digest> \
ONELAYER_DEVNET_TX_APPROVED=<chain-approval-digest> \
./deploy/devnet-demo/demo happy-path
```

Последовательность:
1. `preflight` — версии, права `0600` на payer-ключ, отсутствие закоммиченных ключей в Git;
2. `program-deploy apply` — при необходимости airdrop (до 3 попыток по 2 SOL) и
   `solana program deploy` в devnet с commitment `finalized`. Если программа уже
   задеплоена — шаг печатает `deploy=already-finalized` и пропускается;
3. `devnet_demo_chain apply` — идемпотентно создаёт `RegistryConfig`, `OperatorRole`,
   `DailyAnchorLedgerSegment` и публикует anchor. Каждая транзакция сначала
   **симулируется**, затем подтверждается на `finalized`;
4. результат (`transaction_signature`, `anchor_slot`, `anchor_hash`, `ledger_segment`)
   сохраняется в `artifacts/finalized-anchor.env` — повторный запуск `happy-path`
   переиспользует его и не платит за новую транзакцию;
5. `devnet_demo_fixture certificate` — выпускает сертификат со ссылкой на finalized-якорь;
6. поднимаются `postgres`, `migrate`, `demo-api`, `verifier`; сертификат регистрируется
   через `POST /internal/register` (Bearer-токен из tmpfs);
7. `snapshot` — дамп чистой фикстуры для сценария recovery;
8. проверка: пакет сертификата отправляется верификатору, ожидается `VERIFIED`;
9. сохраняется QR: `artifacts/certificate-qr.svg`.

Идентификатор демонстрационного сертификата фиксирован:
`08080808080808080808080808080808`.

### Шаг 4. Показ проверки

- QR из `artifacts/certificate-qr.svg` ведёт на
  `http://127.0.0.1:8090/c/<certificate_id>?h=<base64url(certificate_hash)>`.
  Страница сама тянет пакет и отправляет его верификатору с требованием `finalized`.
- Повторная проверка из терминала:

```bash
./deploy/devnet-demo/demo verify
cat deploy/devnet-demo/artifacts/verification.json
```

### Шаг 4a. Визуальный MVP: две панели вместо CLI

```bash
./deploy/devnet-demo/demo ui
```

Команда поднимает тот же guarded Compose-проект и добавляет один UI-порт.
Печатаются два адреса и путь к сгенерированным demo-логинам:

- Admin-панель — `http://127.0.0.1:8091/admin`;
- публичная OneLayer-панель — `http://127.0.0.1:8091/verify`;
- логины `operator` и `auditor` — `/dev/shm/onelayer-devnet-demo/admin-credentials.json`.

Полный путь в браузере:

1. **Records** — ввести сертификат в форме, построенной из схемы `land-registry-v1`,
   либо импортировать JSON/CSV (кнопка *Validate (dry run)* проверяет без записи и
   показывает отклонённые строки с номером строки и путём). Ниже сразу показывается
   canonical preview: `recordIdCommitment`, `fieldRoot`, `recordCommitment`, batch leaf,
   `merkleRoot` и `manifestHash`; «Details» у записи открывает `field_commitment` каждого
   пути. `certificateHash` здесь отсутствует — он появляется только после выдачи пакета.
2. **Prepare & publish** → *Connect wallet*. Нужен кошелёк Wallet Standard с
   аккаунтом `solana:devnet` и выданной ролью оператора. Панель не принимает
   keypair-файлы, приватные ключи и seed-фразы.
3. *Prepare and simulate* — сервер строит транзакцию, симулирует её и
   фиксирует intent hash, idempotency key и срок действия blockhash.
4. **Transaction review** — блокирующий шаг: cluster, program ID, инструкция,
   все аккаунты с флагами signer/writable, registry, segment PDA, batch,
   `merkleRoot`, `manifestHash`, `previousAnchorHash`, fee payer и логи симуляции.
   Кнопка подписи активна только после успешной симуляции.
5. *Request wallet signature* — кошелёк подписывает ровно подготовленные байты;
   backend перед отправкой заново сверяет подписанную транзакцию с сохранённым intent.
6. *Check finalization* — состояние идёт `SUBMITTED → FINALIZED`. Кнопки выдачи
   сертификата до `FINALIZED` не существует.
7. *Issue certificate package* — сертификат, `certificateHash`, QR (SVG),
   подпись транзакции, слот и ссылка на Solana Explorer.
8. Открыть QR-ссылку в публичной панели — результат `VERIFIED` с показом
   incident index: watermark, finalized head и лаг.

Повторный клик и перезагрузка не создают второй batch: idempotency key
возвращает тот же intent. Протухший blockhash даёт `EXPIRED` и возврат к
подготовке, отказ кошелька — `SIGNING_REJECTED`, неуспешная симуляция —
`SIMULATION_FAILED` без запроса подписи.

Роль `auditor` видит записи, сертификаты и timeline, но не может подготовить
batch, запросить подпись или выдать сертификат — запрет реализован в Admin API,
а не скрытием кнопок.

### Шаг 5. `incident` — инцидент подмены данных

```bash
./deploy/devnet-demo/demo incident
```

Прямой `UPDATE` в PostgreSQL меняет `status` записи `SYNTHETIC-1` на `TAMPERED` в обход
пайплайна. Затем `POST /internal/reconcile` пересчитывает корень из содержимого БД,
сравнивает с корнем зафиксированного якоря, открывает `integrity_incident`
(`DIRECT_DB_TAMPERING`, `CRITICAL`) и переводит сертификат в `DISPUTED`. Проверка
возвращает `DISPUTED` — при том, что якорь в Solana не менялся.

### Шаг 6. `recovery` — восстановление в чистой среде (опционально)

```bash
./deploy/devnet-demo/demo recovery
```

Поднимает отдельную БД `clean-room-db`, восстанавливает дамп фикстуры, пересчитывает
merkle root из восстановленных данных и сравнивает с `merkle_root` из finalized-якоря.
Расхождение → выход с кодом 72.

### Шаг 7. `reset` — возврат к чистой фикстуре

```bash
./deploy/devnet-demo/demo reset
```

`TRUNCATE` четырёх демо-таблиц и повторная загрузка `db/fixtures/devnet-demo.sql`.
Контейнеры, тома, образы и состояние в Solana **не** удаляются: якорь в devnet
неизменяем по определению. После `reset` нужно снова прогнать `happy-path`, чтобы
зарегистрировать сертификат (транзакция переиспользуется из `finalized-anchor.env`).

Полная остановка стенда:

```bash
docker compose -p onelayer-devnet-demo -f deploy/devnet-demo/compose.yaml down
```

---

## 3. Как данные хешируются и попадают в Solana

Цепочка от поля записи до слота в devnet (реализация: `crates/canonical`,
`apps/pilot-pipeline`, `onchain/programs/onelayer-registry`):

1. **Поле → field commitment.** Значение приводится к каноническому CBOR (RFC 8949, NFC),
   солится `field_salt`, выведенным из `record_field_key` записи:
   `field_commitment(path, value, salt)`.
2. **Поля → field root.** Коммитменты полей складываются в дерево записи (`FieldTree`).
   Именно это даёт selective disclosure: раскрыть можно одно поле, показав proof до
   `field_root`, не раскрывая остальные.
3. **Запись → record commitment.**
   `record_commitment(registry_id_hash, record_id_commitment, record_version, field_root)`,
   где `record_id_commitment` — HMAC-подобный коммитмент внутреннего id (сам id на цепь
   не попадает).
4. **Записи → merkle root пакета.** Листья — `batch_leaf_hash(record_commitment)`,
   дерево по RFC 6962 (непарный узел не дублируется), записи упорядочены по
   `record_id_commitment`, затем по `record_version`.
5. **Манифест.** `merkle_root`, диапазон курсоров, версии, `previous_anchor_hash`,
   URI листьев подписываются ключом оператора → `manifest_hash`.
6. **Транзакция.** `AnchorEntryInputV1 { batch_sequence, registry_version,
   source_cursor_start/end, merkle_root, manifest_hash, snapshot_hash,
   previous_anchor_hash, leaf_count, schema_version, flags, hash_algorithm,
   tree_algorithm }` уходит инструкцией `publish_anchor`.
7. **Куда пишется.** Аккаунт `DailyAnchorLedgerSegment` — PDA с сидами
   `["ledger", registry_config, day_utc(BE), segment_index(LE)]`, ёмкость 46 записей,
   размер 10 040 байт. `registry_config` = PDA `["registry", registry_id_hash]`,
   права оператора — PDA `["operator", config, operator_pubkey]`.
8. **anchor_hash считает программа**, а не клиент: SHA-256 над доменным префиксом,
   `registry_id_hash` и всеми полями записи *плюс* `operator` и `published_at` —
   то есть в хеш связываются значения, которые контролирует цепь.
9. **Финализация.** Клиент ждёт `finalized`, читает аккаунт сегмента, находит запись по
   `batch_sequence` и фиксирует `slot` и `anchor_hash`.
10. **Сертификат.** В пакет входят раскрытые поля с солями, merkle proof листа до
    `merkle_root`, ссылка на якорь (`program_id`, `segment_pda`, `batch_sequence`,
    подпись транзакции, слот) и подпись эмитента.
11. **Проверка** (`apps/verifier`): пересобрать field root → record commitment → лист →
    прогнать proof и сравнить с `merkle_root`; независимо прочитать аккаунт сегмента
    через Solana RPC (два источника, сравнение голов цепи) и убедиться, что тот же
    `merkle_root`/`manifest_hash` действительно опубликован и финализирован;
    проверить подпись эмитента; запросить индекс инцидентов. Итог:
    `VERIFIED` / `VERIFIED_NO_INCIDENT_CHECK` / `DISPUTED` / `INVALID`.

Ключевое для презентации: **на цепь не уходят ни персональные данные, ни значения полей,
ни внутренние идентификаторы** — только 32-байтовые хеши и метаданные пакета.

---

## 4. Как добавить новые синтетические записи и сертификаты

Прямо сейчас загрузить новый сертификат «снаружи» нельзя: демо детерминировано и
фиксировано по построению. `POST /internal/register` принимает только уже выпущенный
пакет и жёстко валидирует `registryId = gov.registry.land`, форматы хешей, соответствие
хеша в QR-URL хешу сертификата. Сам набор записей задан в двух местах, которые обязаны
совпадать байт в байт по смыслу:

| Источник истины | Файл | Роль |
|---|---|---|
| Rust-пайплайн | `apps/pilot-pipeline/src/demo.rs` → `build_demo_batch()` | строит batch и merkle root, который уходит в Solana |
| Фикстура БД | `db/fixtures/devnet-demo.sql` | «состояние реестра», из которого reconcile пересчитывает корень |

Пересчёт на стороне БД — `apps/demo-api/src/reconcile.ts` (`fixtureRoot`). Он принимает
только `internal_record_id` вида `SYNTHETIC-<n>` и берёт набор полей у `fieldsOf`
(`apps/demo-api/src/admin-batch.ts`) — той же функции, которой пользуется batch builder:
`status` из колонки записи плюс всё, что лежит в `synthetic_record_field`.
Если эти три места разойдутся — reconcile выдаст `DISPUTED` уже на чистой фикстуре.

Сказанное выше относится к **фикстуре и CLI happy path**. Записи, введённые или
импортированные через Admin-панель (`origin='ADMIN_UI'`), править в этих файлах не нужно:
их поля приходят из сертификата пользователя и хранятся в `synthetic_record_field`.

### Рецепт: добавить запись `SYNTHETIC-3`

1. `apps/pilot-pipeline/src/demo.rs`, массив в `build_demo_batch`:

```rust
for (cursor, record_id, field_key) in [
    (1, "SYNTHETIC-1", [1; 32]),
    (2, "SYNTHETIC-2", [2; 32]),
    (3, "SYNTHETIC-3", [3; 32]),
]
```

2. `db/fixtures/devnet-demo.sql` — та же запись с тем же курсором, версией `1`,
   статусом `ACTIVE` и тем же `record_field_key_hex` (`repeat('03', 32)`).

3. В `apps/pilot-pipeline/src/bin/devnet_demo_chain.rs` `leaf_count` берётся из
   `batch.records.len()` — править не нужно. `cursor_start`/`cursor_end` тоже считаются
   из пакета.

4. Пересобрать и заново согласовать дайджесты: merkle root изменится, значит
   `chain-plan.txt` даст новый `approval_digest`.

```bash
cargo test -p onelayer-pilot-pipeline
cd apps/demo-api && npm test && cd -
./deploy/devnet-demo/demo reset          # если стенд уже поднят
rm -f deploy/devnet-demo/artifacts/finalized-anchor.env   # нужен новый якорь для нового корня
./deploy/devnet-demo/demo plan
```

Затем `happy-path` с двумя новыми дайджестами.

**Важно про повторную публикацию.** Новый merkle root требует новой транзакции
`publish_anchor`, а программа проверяет цепочку жёстко
(`onchain/programs/onelayer-registry/src/lib.rs`):

- `batch_sequence` обязан быть ровно `config.current_batch_sequence + 1`, иначе
  `BadSequence`;
- `previous_anchor_hash` обязан равняться `config.last_anchor_hash`, иначе
  `BrokenAnchorChain`;
- сегмент обязан соответствовать текущему UTC-дню, иначе `WrongLedgerDay`.

Смена UTC-дня здесь не помогает — счётчик `current_batch_sequence` живёт в
`RegistryConfig`, а не в сегменте. Поэтому есть два пути:

1. **Демонстрационный (проще):** оставить `batch_sequence = 1` и опубликовать новую
   фикстуру на **новый registry** — сменить `DEMO_REGISTRY_ID` в `demo.rs` (например,
   `gov.registry.land.demo2`). Это даёт другой `registry_id_hash` → другой PDA конфига →
   чистую цепочку с `genesis_anchor_hash`. Но `REGISTRY_ID` захардкожен в
   `apps/demo-api/src/main.ts` и `reconcile.ts`, а в `main.ts` ещё и regex-валидация
   `/^gov\.registry\.land$/` — их придётся править синхронно.
2. **Честный (продолжение цепочки):** поднять `batch_sequence` до `2` в
   `demo.rs` (`BatchBuildRequest`) и в `devnet_demo_chain.rs`
   (`AnchorEntryInputV1 { batch_sequence: 1, ... }` и строка `println!("batch_sequence=1")`),
   а `previous_anchor_hash` заменить с `genesis_anchor_hash(&registry_hash)` на
   `anchor_hash` предыдущего пакета (он лежит в `artifacts/finalized-anchor.env` как
   `ONELAYER_ANCHOR_HASH`). Сегмент для нового дня создастся автоматически.

Если стенд разворачивается «с нуля» на свежем devnet-registry (config ещё не
инициализирован), ничего из этого не нужно — обычный `plan` + `happy-path`.

### Рецепт: выпустить второй сертификат

`apps/pilot-pipeline/src/bin/devnet_demo_fixture.rs`:

```rust
let certificate_id = [8; 16];                         // → 08080808...08
    .issue_certificate(CertificateRequest {
        internal_record_id: "SYNTHETIC-1",            // на какую запись
        disclosed_paths: &["status"],                 // какие поля раскрываются
        disclosure_mode: DisclosureMode::FullRecord,  // или SelectiveFields
        ...
```

Чтобы выпустить сертификат на другую запись: сменить `internal_record_id` и
`certificate_id` (16 байт → 32 hex-символа). Для выпуска нескольких сертификатов за
прогон бинарь нужно расширить — сейчас он печатает ровно один JSON-объект.

Учтите, что id `08080808080808080808080808080808` захардкожен в `deploy/devnet-demo/demo`
(функция `verify_certificate` и получение QR). При смене id правьте и его.

### Селективное раскрытие вместо полного

`DisclosureMode::SelectiveFields` + `disclosed_paths` с подмножеством путей даёт пакет,
который несёт значения, соли и field proof **только** этих путей; `fieldRoot`, batch proof
и якорь остаются теми же. Верификатор проверяет оба режима (`apps/verifier/src/verify.ts`).

В CLI-фикстуре у записи одно поле `status`, поэтому для демонстрации через CLI сначала
добавьте записи с несколькими полями в `build_demo_batch`. **Через браузер этого не
требуется:** импортируйте сертификат с несколькими полями на экране Records, а при выдаче
снимите отметки с тех путей, которые раскрывать не нужно, — режим переключится на
`SELECTIVE_FIELDS` автоматически.

---

## 4a. Браузерные проверки

```bash
# детерминированный E2E: без Docker, валидатора и расхода SOL
npm --prefix tests/e2e-web test

# guarded live-devnet smoke перед показом или релизом (отдельное подтверждение)
APPROVE_ONELAYER_LIVE_DEVNET_SMOKE=yes \
ONELAYER_DEVNET_DEPLOY_APPROVED=<program-approval-digest> \
ONELAYER_DEVNET_TX_APPROVED=<chain-approval-digest> \
./deploy/devnet-demo/scripts/live-smoke
```

Live smoke проверяет сертификат, заякоренный guarded CLI publish, поэтому
ключевой материал в браузер не попадает. Артефакты — в
`deploy/devnet-demo/artifacts/live-smoke/`.

## 5. Типовые проблемы

| Симптом | Причина / действие |
|---|---|
| `ONELAYER_DEVNET_TX_APPROVED must equal approval_digest` | дайджест устарел (пересборка, изменение фикстуры, смена UTC-дня) → перезапустить `plan` |
| `Docker daemon is not accessible` (код 41) | пользователь не в группе `docker`; скрипт сам пробует `sg docker` |
| `Solana CLI 3.1.10 is required` (34/35) | версии CLI зафиксированы preflight-ом |
| `test payer needs at least 3 devnet SOL` (43) | девнет-фаусет исчерпан, повторить позже |
| `tracked credential-like file detected` (39) | в Git попал `*keypair.json`/`id.json`/`.env` — убрать из индекса |
| `finalized anchor output is invalid` (80) | публикация не дошла до finalized, проверить `artifacts/chain-apply.txt` |
| `synthetic fixture marker missing` | БД без фикстуры → `demo reset` или повторный `migrate` |
| проверка даёт `DISPUTED` на чистом стенде | разошлись `demo.rs`, `devnet-demo.sql` и `reconcile.ts` |
| `BadSequence` / `BrokenAnchorChain` при publish | повторная публикация в уже инициализированный registry — см. §4 |
| `WrongLedgerDay` | сегмент создан в другой UTC-день; удалить `finalized-anchor.env` и прогнать `plan` заново |
