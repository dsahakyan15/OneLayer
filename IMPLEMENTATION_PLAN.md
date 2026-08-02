# OneLayer — план имплементации

**Базовый документ:** `OneLayer_Solana_Technical_Spec_RU.md` (v0.9, историческая проектная версия)
**Источник истины протокола:** versioned-документы в `spec/` заморожены для Gate B и имеют приоритет над этим планом и v0.9; любое нормативное изменение требует ADR и новой версии schema/account/package
**Статус плана:** v2.6, 2026-08-02
**Структура:** gate-ы A, B, C, D, E0, E — каждый с явным выходным решением
**Горизонт:** Gate A–C (pilot + визуальный MVP на devnet) ≈ 6–8 месяцев; Gate D–E (production go-live) ≈ +10–12 месяцев; Phase 3 — отдельный горизонт после go-live

> План покрывает инженерную реализацию. Юридические решения (§17 спецификации) — отдельный трек, блокирующий Gate E.

---

## 0. Рабочие ограничения

**Proportional Engineering.** Минимальный поддерживаемый scope. Только доказательно необходимые проверки и security controls. Без спекулятивного hardening. Инфраструктура и абстракции добавляются после подтверждения потребности, а не заранее.

**Следствия для этого плана:**
- количество тестов не является acceptance criterion; критерий — покрытые инварианты; добавляются только те проверки, что доказывают изменённое поведение или предотвращают наблюдавшуюся регрессию;
- сервис выделяется в отдельный процесс только при подтверждённой границе развёртывания или владения;
- транспорт, оркестрация, storage-абстракции добавляются, когда появляется второй потребитель;
- всё, что не нужно для проверки следующей гипотезы, откладывается до gate-а, где оно нужно;
- security-работа пропорциональна фактической границе доверия: обязательные safeguards сохраняются, уязвимости, внесённые или открытые задачей, устраняются, но новые защитные фреймворки без подтверждённой модели угроз не вводятся;
- расширение scope требует названного acceptance criterion, наблюдавшегося отказа или зафиксированного риска. Если его нет — работа не делается; если расширение меняет решение по существу — решение принимает владелец.

Эти правила не отменяют проверки, обязательные по контрактам репозитория и release gates, применимым к изменённому поведению.

**Явно вне scope до Gate E:** Kubernetes/Helm/Terraform/OPA, SIEM, мультисиг и timelock, threshold-церемонии, три независимых storage, два RPC-провайдера, banking SDK, algorithm transition, массовая выдача сертификатов.

**HSM.** До Gate E не выполняется продуктовая HSM-интеграция: в основном коде нет HSM-абстракции, pipeline подписывает software-ключом. В Gate A разрешён изолированный feasibility spike (`OL-A-03`) — вне основного кода, без production credentials, результат spike-а в продукт не переносится.

---

## 1. История ревизий

Текущая версия — **v2.6**. Изменения относительно v2.5:

- визуальный MVP доведён до полного пользовательского контура: запись больше не является одним полем `status`, а строится из сертификата, который даёт пользователь (структурированный JSON или CSV по схеме реестра);
- зафиксирована demo-схема реестра `land-registry-v1` — единственный перечень допустимых путей полей и их типов; поле вне схемы отклоняется как `CANONICALIZATION_FAILED` (§4 `spec/canonical-record-v1.md`), а не игнорируется;
- метаданные, canonical preview, field tree, сертификат и QR строятся динамически из фактического набора полей записи; хардкод одного поля удалён из всех трёх мест, где он был (batch builder, reconcile, fixture);
- добавлена выдача в режиме `SELECTIVE_FIELDS` с field proofs: оператор выбирает раскрываемые пути, соли остальных путей в пакет не попадают;
- добавлены документы `docs/use-cases-ru.md` (сценарии использования) и `docs/presentation-ru.md` (ролевые модели, разбор потока, FAQ) — они описывают систему, но нормативной силы не имеют;
- публикация хэшей в devnet остаётся guarded wallet-контуром §5.4 без изменений: server-side one-click подписи не вводится.

Сохранённая история v2.5:

- источник истины приведён к фактическому статусу: `spec/*.md` уже frozen для Gate B, E0 и E;
- исправлен incident-index contract: индекс обрабатывает finalized `IncidentOpened` и `IncidentResolved`, а Gate C проверяет текущий, а не недоказуемый исторический статус;
- визуальный MVP привязан к существующему guarded devnet-контуру, но разводит CLI approval digests и интерактивную Wallet Standard подпись;
- `certificateHash` перенесён на этап после finalized anchor; transaction flow дополнен failure/expiry/unknown states, IDL→Codama client и доказуемым Admin API contract;
- детерминированный browser E2E отделён от guarded live-devnet smoke; понятие clean room оставлено только recovery-сценарию;
- схема БД, QR/HTTPS-граница, on-chain negative cases, testing pyramid и Gate E access-control scope сверены с frozen specs и текущими migrations.

Сохранённая история v2.4:

- в Gate C добавлен визуальный MVP: Admin-панель для synthetic-записей, devnet anchor и выдачи сертификатов; OneLayer-панель для QR-сканирования и верификации;
- визуальный flow разводит `certificateHash` и on-chain anchor: в Solana публикуются `merkleRoot` / `manifestHash`, а связь сертификата доказывается package-подписью и Merkle proof;
- в MVP зафиксированы Wallet Standard, simulation-before-signing, явный transaction review и запрет выдачи сертификата до `finalized`.

Сохранённая история v2.3:

- `record_id_commitment` включён в `record_commitment`: Merkle proof теперь связывает содержимое с конкретной записью (§2.1);
- контракт incident index scoped по `registryId`; индекс, не дошедший до anchor slot, получает `STALE` (§2.3);
- результат `OL-A-04` принят в план: segmented ledger C′, 46 entries на сегмент (§8.2);
- `publish_attempt` хранит неизменяемые байты подписанной попытки, но допускает однократное разрешение outcome (§6.2);
- `SnapshotPackageV1` получил deterministic CBOR, однозначные AAD, DEK wrapping и lifecycle test KEK (§10.1);
- удалена недоказательная проверка «соль нельзя вывести»; сохранены только проверяемые границы раскрытия (§7.2).

---

## 2. P0-решения: криптографический протокол

Решения этого раздела уже внесены в frozen-документы и golden vectors Gate B. Раздел сохраняет обоснования; при расхождении побеждает `spec/`, а изменение протокола идёт через ADR и новую версию.

### 2.1. Disclosure protocol — соли полей отделены от record nonce

**Проблема v1.0.** `field_nonce(path) = HMAC(record_nonce, path)` при том, что `record_nonce` включён в сертификат: держатель вычисляет соль любого скрытого поля и перебирает значения из малого множества (`status`, тип права, флаги).

**Проблема промежуточного варианта v2.0.** Вывод `record_field_key` из вечно хранимого `field_salt_key_vN` соседствовал с хранением самого `record_field_key` в зашифрованном виде — два механизма для одной цели, плюс `record_leaf_nonce` без отдельного места хранения.

**Решение v2.1 — одна модель: случайный ключ на версию записи.**

```text
На версию записи:
  record_field_key = random_32_bytes()              // CSPRNG, хранится зашифрованно

Промежуточные байты (определены до вычисления любых длин):
  path_bytes = UTF-8( NFC(path) )              // нормализация ДО измерения длины
  value_cbor = deterministic_cbor(value)       // RFC 8949

На поле:
  field_salt(path)  = HMAC-SHA256(record_field_key,
                                  "ONELAYER:FIELDSALT:V1" || path_bytes)

  field_commitment(path) = SHA256("ONELAYER:FIELD:V1" ||
                                  u16_be(byte_len(path_bytes)) || path_bytes ||
                                  u32_be(byte_len(value_cbor)) || value_cbor ||
                                  field_salt(path))

  field_tree_leaf_hash(path) = SHA256(0x00 || field_commitment(path))   // RFC 6962 leaf
  field_node_hash(l, r)      = SHA256(0x01 || l || r)                   // RFC 6962 node

  field_root = корень RFC6962-дерева по field_tree_leaf_hash,
               листья отсортированы по path (байтово)

Внешнее дерево:
  record_commitment  = SHA256("ONELAYER:RECORD:V1" || registry_id_hash ||
                              record_id_commitment ||
                              u64_be(record_version) || field_root)

  batch_leaf_hash    = SHA256(0x00 || record_commitment)                // RFC 6962 leaf
  batch_node_hash    = SHA256(0x01 || left || right)

  merkle_root = корень RFC6962-дерева по batch_leaf_hash,
                листья отсортированы по (record_id_commitment, record_version)
```

`record_id_commitment` входит в хэшируемый preimage, а не только задаёт порядок листьев. Иначе две записи одного реестра с одинаковыми `record_version` и `field_root` дали бы один `record_commitment`, и batch-proof не связывал бы содержимое с заявленным record ID. Frozen `spec/leaf-v1.md`, `crates/canonical` и vectors содержат golden vector и differential case: одинаковые `registry_id_hash` / `record_version` / `field_root`, разные `record_id_commitment` → разные `record_commitment`.

**Двойное хэширование намеренное.** `*_commitment` — доменно-разделённое обязательство к содержимому; `*_leaf_hash` — RFC 6962-обёртка, отделяющая листья от внутренних узлов. Термины различаются нормативно, чтобы исключить неоднозначность при генерации golden vectors. Ни один вектор не использует слово «leaf» без префикса `field_tree_` или `batch_`.

**Длина — всегда в байтах.** Правило действует во всём протоколе, включая `audit_preimage` (§2.6):
- `len(·)` в формулах означает `byte_len` после кодирования, никогда не число code points и не число символов;
- строка нормализуется (NFC) и кодируется в UTF-8 **до** измерения длины;
- значение сериализуется в deterministic CBOR **до** измерения длины: считается длина `value_cbor`, а не исходного значения;
- `byte_len(path_bytes) <= 65535` проверяется явно, превышение → `CANONICALIZATION_FAILED`;
- сортировка путей (§2.1) выполняется по `path_bytes`, а не по строкам в исходной кодировке.

Причина: `"ы".length` в JavaScript равно 1, в UTF-8 это 2 байта. Без явного правила Rust и TypeScript дают разные commitment на одних и тех же данных, и differential-тесты поймали бы это только при наличии не-ASCII вектора.

**`record_leaf_nonce` удалён.** При секретных `field_salt` величина `field_root` уже неотличима от случайной для того, кто не знает солей, поэтому отдельный nonce не добавляет свойств. Спецификация v0.9 — проектная, развёрнутого протокола нет, обратная совместимость не требуется. Следствия — правки спецификации:
- §4.4: `payload_hash` → `field_root`, `nonce_32` из формулы leaf убирается;
- §8.1: поле `nonce` в `CertificatePackageV1` заменяется на `fieldSalts: Record<path, base64url>` — соли **только** раскрытых полей.

**Что попадает в сертификат:**

| Режим | Содержимое |
|---|---|
| `SELECTIVE_FIELDS` | `record_id_commitment`, значения раскрываемых полей, `field_salt` **только этих** путей, field-proof каждого, `field_root`, batch-proof |
| `FULL_RECORD` | `record_id_commitment`, все значения и все `field_salt`, batch-proof (`field_root` пересчитывается) |

`record_field_key` не попадает в сертификат и не отдаётся ни одним API **никогда**. Раскрытие одной соли не даёт вычислить другие: HMAC с секретным ключом невосстановим по своим выходам.

**Хранение:**

```sql
-- в canonical_record_version, вместо nonce_encrypted из §7.1 спецификации
record_field_key_encrypted BYTEA NOT NULL,
key_encryption_version     TEXT  NOT NULL   -- версия KEK/KMS-ключа, не ключа записи
```

Одно поле, один механизм. В production — envelope encryption через KMS; в pilot — software KEK, не коммитится и не пишется в логи. Ротация касается только KEK: перешифровать `record_field_key_encrypted` можно массово, не трогая ни сертификаты, ни якоря. Вечное хранение старых версий master-ключа больше не требуется — этого требования у v2.1 нет.

**Оговорка.** Множество путей полей само по себе утечка структуры: при `SELECTIVE_FIELDS` число листьев field-дерева видно из proof-а. Для frozen v1 решено **не** дополнять дерево до фиксированной степени двойки; возврат к padding требует ADR и новой версии `leaf-v*`.

`OL-SPEC-01` (Gate B, блокирующая)

### 2.2. Одна нормативная сериализация `anchor_hash`

**Проблема v1.0.** §1.3 использовал Borsh (`try_to_vec`), §5.5 — физический layout (`bytemuck::bytes_of`). Второе делает публичный криптографический протокол зависимым от порядка полей и padding в storage-структуре: перестановка полей ради выравнивания молча меняет anchor chain.

**Решение.** Явная конкатенация фиксированной ширины, независимая от обоих:

```text
anchor_preimage = "ONELAYER:ANCHOR:V1"            (18 байт, без терминатора)
               || registry_id_hash                (32)
               || u64_be(batch_sequence)          (8)
               || u64_be(registry_version)        (8)
               || u64_be(source_cursor_start)     (8)
               || u64_be(source_cursor_end)       (8)
               || merkle_root                     (32)
               || manifest_hash                   (32)
               || snapshot_hash                   (32, нули = отсутствует)
               || previous_anchor_hash            (32)
               || u32_be(leaf_count)              (4)
               || u16_be(schema_version)          (2)
               || u16_be(flags)                   (2)
               || u8(hash_algorithm)              (1)
               || u8(tree_algorithm)              (1)
               || operator_pubkey                 (32)
               || i64_be(published_at)            (8)

anchor_hash = SHA-256(anchor_preimage)            // preimage ровно 260 байт
```

Правила:
- zero-copy layout используется **только** для хранения в аккаунте и может меняться между версиями программы без влияния на протокол;
- Borsh используется только для instruction data;
- `anchor_preimage` — единственный нормативный формат для хэширования, реализуется в Rust и TypeScript независимо, покрывается golden vectors;
- поля `_pad` в storage-структуре в preimage не входят.

`OL-SPEC-02` (Gate B, блокирующая)

### 2.3. Обнаружение `IncidentNotice` — зафиксированный контракт

**Проблема v1.0.** PDA адресуется по `incident_sequence`, верификатор знает только `batch_sequence`. Перечисления нет.

**Решение для pilot (Gate C):**
- `incident_sequence` назначает программа из монотонного счётчика `RegistryConfig.incident_count` — это необходимо для корректности назначения, а не индекс;
- верификатор использует off-chain **incident index** (`GET /v1/incidents?registryId=&batchSequence=`), построенный из finalized on-chain событий `IncidentOpened` **и** `IncidentResolved`; `registryId` обязателен, потому что `batch_sequence` монотонен только внутри реестра;
- пустой ответ индекса сам по себе не является доказательством отсутствия инцидентов: индекс мог потерять событие, отстать от finalized head или остановиться на старом слоте. Поэтому индекс обязан публиковать **watermark полноты**.

**Индекс сообщает только `indexedThroughSlot`. Голову цепочки верификатор берёт сам.** Если бы индекс отдавал и то, и другое, зависший или скомпрометированный индекс объявлял бы устаревшую цепочку актуальной — самозаверение полноты.

```text
indexedThroughSlot   ← от incident index
rpcFinalizedHeadSlot ← verifier.getSlot(commitment = "finalized"), собственный запрос
indexLagSlots        = rpcFinalizedHeadSlot − indexedThroughSlot
```

Ответ индекса:

```json
{ "registryId": "gov.registry.land", "indexedThroughSlot": 412345999, "incidents": [] }
```

Ответ верификатора:

```json
{
  "incidentIndexStatus": "CHECKED",
  "indexedThroughSlot": 412345999,
  "rpcFinalizedHeadSlot": 412346040,
  "indexLagSlots": 41
}
```

Правило статуса:

| Статус | Условие | Влияние на итог |
|---|---|---|
| `CHECKED` | `0 <= indexLagSlots <= maxIndexLagSlots` **и** `indexedThroughSlot >= anchor_slot` | итог может быть `VERIFIED` |
| `STALE` | индекс доступен, но `indexLagSlots > maxIndexLagSlots` **или** `indexedThroughSlot < anchor_slot` | понижение до `VERIFIED_NO_INCIDENT_CHECK` |
| `UNAVAILABLE` | индекс недоступен или ответ без `indexedThroughSlot` | понижение до `VERIFIED_NO_INCIDENT_CHECK` |
| `INDEX_INCONSISTENT` | `indexedThroughSlot > rpcFinalizedHeadSlot` — индекс утверждает, что обогнал finalized-голову | понижение до `VERIFIED_NO_INCIDENT_CHECK`, событие в лог как аномалия |
| `RPC_DISAGREEMENT` | два RPC разошлись по высоте finalized-головы сильнее `maxRpcHeadDifference` (только при двух источниках, Gate E) | понижение до `VERIFIED_NO_INCIDENT_CHECK` |

`maxIndexLagSlots` — конфигурируемый параметр верификатора, по умолчанию 300 слотов (≈2 минуты). Ответ без watermark трактуется как `UNAVAILABLE`, а не как `CHECKED`. Условие `indexedThroughSlot < anchor_slot` проверяется отдельно от lag: индекс может укладываться в 300 слотов от head, но ещё не покрывать конкретный новый anchor.

**Правило двух RPC (Gate E).** В pilot `rpcFinalizedHeadSlot` берётся у единственного RPC. При двух источниках консервативным является **больший** head: `indexLagSlots = head − indexedThroughSlot`, поэтому меньший head уменьшает измеренный лаг и может ошибочно перевести `STALE` в `CHECKED`.

```text
rpcHeadDifference = abs(rpcA.finalizedHead − rpcB.finalizedHead)

если rpcHeadDifference <= maxRpcHeadDifference:
    effectiveFinalizedHead = max(rpcA.finalizedHead, rpcB.finalizedHead)
    indexLagSlots          = effectiveFinalizedHead − indexedThroughSlot
иначе:
    incidentIndexStatus    = RPC_DISAGREEMENT
    verificationStatus     = VERIFIED_NO_INCIDENT_CHECK
```

Пример ошибки, которую это устраняет: при `indexedThroughSlot = 1000` и головах 1100 / 1200 выбор 1100 даёт лаг 100 вместо 200 — индекс выглядит свежее, чем он есть.

Завышение head скомпрометированным RPC уводит статус в `STALE`, то есть в сторону отказа от проверки, а не ложного `CHECKED`; грубое завышение отсекается порогом `maxRpcHeadDifference`.

Расхождение RPC **по данным** finalized-слота (разное содержимое аккаунта или разные транзакции на одной высоте) — другой случай: он не понижает incident-статус, а даёт `ANCHOR_DISPUTED` по §9.5 спецификации. `RPC_DISAGREEMENT` относится только к расхождению высот при проверке свежести индекса.

**Что именно проверяется в Gate C:** существует ли **сейчас** открытый инцидент, покрывающий batch. Инцидент может быть открыт спустя месяцы после публикации якоря, поэтому индекс должен быть близок к текущему finalized head, а не только к слоту anchor; `indexedThroughSlot >= anchor_slot` — необходимое, но недостаточное условие для `CHECKED`.

Определение исторического состояния «инцидент был открыт в момент anchor» текущий контракт `{ range, status }` не доказывает: для этого API должен вернуть проверяемые `opened_slot` / `resolved_slot` либо ссылки на finalized события. Такое расширение требует отдельной версии контракта. Статусы сертификата `VERIFIED_HISTORICAL` и `SUPERSEDED` при этом остаются частью frozen verifier contract и вычисляются по lifecycle самого сертификата, а не подменяются incident-index эвристикой.

**Открытое решение владельца.** Полностью автономная проверка (без backend) требует одного из:
- перебора всех PDA `0..incident_count` через `getMultipleAccounts` — работает при десятках инцидентов, деградирует при тысячах, и это лишь смягчение, а не полноценный индекс;
- отдельной on-chain структуры «batch range → incident» — существенное расширение формата.

Ни то, ни другое не реализуется, пока автономное обнаружение инцидентов не станет явным acceptance criterion. Пункт зафиксирован в §12 как решение владельца.

`OL-SPEC-03`, `OL-DEC-01`

### 2.4. Непрерывность source cursor — граница ответственности

**Проблема v1.0.** Текст создавал впечатление, что anchor chain гарантирует непрерывность источника. Не гарантирует: программа проверяет только `start <= end`, поэтому Publisher с корректной `batch_sequence` и `previous_anchor_hash` может пропустить диапазон событий.

**Решение для pilot:**

> Solana-программа гарантирует **только**: непрерывность последовательности anchor (`batch_sequence`), связность цепочки (`previous_anchor_hash`), авторизацию публикующего и неизменность опубликованных entries. Непрерывность и полноту потока source events она не гарантирует и не может гарантировать — эти свойства проверяются Integrity Monitor путём независимого сравнения `source_cursor` диапазонов последовательных манифестов с собственным чтением источника.

Формулировка вносится нормативно в `spec/anchor-chain-v1.md` и в раздел «границы гарантий» пользовательской документации.

**Отложенная опция.** Добавление `RegistryConfig.last_source_cursor_end` и проверки `input.source_cursor_start == last_source_cursor_end + 1` переносит гарантию on-chain. Стоимость: 8 байт состояния, одна проверка, но жёсткая связка с семантикой курсора источника — при любой нештатной операции (пропуск заведомо мусорного диапазона, переиндексация источника) потребуется governance-инструкция для сдвига курсора. Решение принимается после Gate A, когда известна фактическая семантика курсора реестра.

`OL-SPEC-04`, `OL-DEC-02`

### 2.5. Пустые batch не создаются

Позиция v1.0 («публикация пустого batch разрешена») удалена. Для v1:

- batch создаётся только при наличии ≥1 canonical record version в диапазоне;
- `batch_sequence` инкрементируется только при фактической публикации;
- интервал без событий не порождает ни batch, ни транзакцию;
- SLO `Maximum unanchored window` измеряется от появления **события**, а не от начала интервала.

Если внешний аудит потребует доказательства «в интервале ничего не происходило», это отдельный sentinel-контракт с собственной семантикой курсора — вносится как решение владельца, не реализуется по умолчанию.

`OL-SPEC-05`, `OL-DEC-03`

### 2.6. Audit journal: hash-chain выведена из Gate C

**Проблема v1.0.** `audit_hash = SHA256(prev || event)` без определения владельца цепочки, порядка записи и сериализуемых байтов: конкурентные writer-ы создают fork, а `JSONB` не является криптографической сериализацией.

**Решение v2.1 по пропорциональности: в Gate C hash-chain не реализуется.**

Внутренний журнал нужен для расследования, и для этого достаточно append-only таблицы:

```sql
CREATE TABLE audit_event (
  registry_id    TEXT   NOT NULL,
  audit_sequence BIGINT NOT NULL,           -- монотонный per-registry
  audit_id       UUID   NOT NULL UNIQUE,
  event_type     TEXT   NOT NULL,
  actor          TEXT   NOT NULL,
  object_type    TEXT   NOT NULL,
  object_id      TEXT   NOT NULL,
  event_payload  JSONB  NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (registry_id, audit_sequence)
);
```

Только запрет UPDATE/DELETE на уровне grants и монотонная нумерация. Криптографической доказуемости журнала на pilot нет, и план этого не утверждает.

**Hash-chain включается при появлении требования** доказывать целостность журнала внешней стороне (`OL-DEC-07`). Её контракт определён заранее, чтобы включение не потребовало пересмотра:

```text
// все строки: UTF-8(NFC(·)); все длины — byte_len, см. правило в §2.1
audit_preimage = "ONELAYER:AUDIT:V1"
              || u16_be(byte_len(registry_id))  || registry_id
              || u64_be(audit_sequence)
              || u16_be(byte_len(event_type))   || event_type
              || u16_be(byte_len(actor))        || actor
              || u16_be(byte_len(object_type))  || object_type
              || u16_be(byte_len(object_id))    || object_id
              || u32_be(byte_len(payload_cbor)) || payload_cbor
              || i64_be(created_at_unix)
              || previous_audit_hash            // 32 нулевых байта для genesis

где payload_cbor = deterministic_cbor(event_payload)
audit_hash = SHA-256(audit_preimage)
```

Защита от fork при включении цепочки (все три условия обязательны):
- цепочка **per-registry**, не глобальная;
- единственный сериализованный writer: `SELECT ... FOR UPDATE` по строке `audit_chain_head(registry_id, last_sequence, last_hash)` в той же транзакции, что и вставка;
- `UNIQUE (registry_id, previous_audit_hash)` — второй параллельный writer получает нарушение ограничения, а не молчаливый fork.

`JSONB` никогда не хэшируется напрямую — только через `deterministic_cbor`. Якорение цепочки в batch — отдельное решение, в критический путь не входит.

`OL-SPEC-06`

### 2.7. Сохранённые решения v1.0 (без изменений)

| # | Решение |
|---|---|
| 1 | `internalRecordId` исключён из canonical payload; в записи только `recordIdCommitment` |
| 2 | `AnchorEntryInputV1` (instruction data) отделён от `AnchorEntryV1` (storage); `operator` и `published_at` заполняет программа |
| 3 | Составной ключ `(registry_id, batch_sequence)` во всех таблицах |
| 4 | `max_entries_per_day` в config — источник истины; `capacity` в ledger — снимок на момент создания |
| 5 | В Gate C `governance_authority` и `emergency_authority` — отдельные test pubkey; в Gate E они переводятся на multisig/timelock по процедуре key ceremony |
| 6 | `day_utc` = день публикации, не день событий; backlog обрабатывается coalescing-ом |
| 7 | Genesis `last_anchor_hash = SHA256("ONELAYER:GENESIS:V1" || registry_id_hash)` |
| 8 | `record_id_commitment = HMAC-SHA256(id_key_vN, registry_id \|\| 0x00 \|\| internal_record_id)` — разделитель обязателен |
| 9 | Deterministic CBOR по RFC 8949 (не RFC 7049 — другие правила сортировки ключей) |

---

## 3. Gate A — feasibility (2–4 недели)

**Единственная цель:** выяснить, реализуема ли система на существующем реестре. Кода продукта не пишется, кроме spike-ов.

| ID | Задача | Результат |
|---|---|---|
| `OL-A-01` | Аудит workflow-системы: подписываются ли операции персонально, чем, есть ли неотказуемость, есть ли внешние ссылки на дела | Отчёт: реализуем ли `authorized_workflow_event` без доработки реестра |
| `OL-A-02` | Аудит источника: механизм CDC (logical replication / audit log / триггеры), семантика курсора, монотонность, объёмы, качество данных | Отчёт: какой курсор является источником истины и непрерывен ли он |
| `OL-A-03` | Ed25519 HSM spike: подписать тестовую Solana-транзакцию ключом из HSM, замерить латентность и пропускную способность | Подписанная транзакция в devnet или отказ вендора |
| `OL-A-04` | **Закрыто:** large PDA allocation spike на локальном валидаторе | ADR-0002: C′, сегменты по 46 entries, seed с `segment_index`; прямой `init` 47+ entries отвергнут runtime (§8.2) |
| `OL-A-05` | Disclosure design: закрыть §2.1, включая решение по padding field-дерева | Подписанный раздел `spec/leaf-v1.md` |
| `OL-A-06` | Threat model v1 по **подтверждённым** trust boundaries (не по гипотетическим) | Документ + формальный sign-off по текущим границам (release gate 3, первое закрытие) |
| `OL-A-07` | Ограничения целевой среды: что доступно (оркестрация, storage, сеть, KMS), а не что хотелось бы | Список ограничений, вход для Gate E |
| `OL-A-08` | Data classification и запуск DPIA | Начатое заключение (gate 1 закрывается позже) |

**Выход Gate A:** решение `go / redesign / stop`.

Критерии `redesign`: workflow-события не подписываются персонально (модель §11.3 нереализуема — OneLayer вырождается в «детект без атрибуции»); курсор источника не монотонен (нужна другая модель батчинга); HSM без Ed25519 (нужен внешний signing appliance, меняется §13.2).

Инфраструктура Gate A: локальная воспроизводимая сборка, один CI workflow, каталоги только под перечисленные spike-и.

---

## 4. Gate B — protocol freeze (2–3 недели)

**Цель:** зафиксировать криптографический протокол так, чтобы две независимые реализации давали идентичный результат.

### 4.1. Нормативные документы

| Документ | Содержание |
|---|---|
| `spec/canonical-record-v1.md` | Deterministic CBOR (RFC 8949), Unicode NFC, RFC 3339 UTC без дробной части, decimal как строка с фиксированным scale, различение отсутствующего ключа и `null`, сортировка `rights`/`encumbrances`/`subjectCommitments`, полный перечень путей полей, отклонение полей вне схемы |
| `spec/leaf-v1.md` | §2.1 полностью: `record_field_key`, `field_salt`, `field_commitment`, `field_tree_leaf_hash`, `field_root`, `record_commitment` с обязательным `record_id_commitment`, `batch_leaf_hash` |
| `spec/merkle-tree-v1.md` | RFC 6962: `leaf_hash=SHA256(0x00\|\|commitment)`, `node=SHA256(0x01\|\|left\|\|right)`, непарный узел поднимается без хэширования (дублирование запрещено), порядок листьев для обоих деревьев |
| `spec/onchain-state-v1.md` | **Заморозка on-chain ABI и state:** все PDA seeds; поля и порядок в `RegistryConfig`, `OperatorRole`, `DailyAnchorLedgerSegment`, `IncidentNotice`, `AnchorEntryV1`; `segment_index`, capacity 46 и порядок sealing сегментов; endianness и фиксированные размеры; `AnchorEntryInputV1` (instruction data, Borsh); поля, заполняемые программой (`operator`, `published_at`, `incident_sequence`); события и их поля; правило версионирования аккаунтов; семантика `incident_count`; genesis-значения |
| `spec/batch-manifest-v1.md` | Байтовая сериализация для подписи, `manifestHash` от манифеста без подписи, Ed25519 |
| `spec/anchor-chain-v1.md` | §2.2 `anchor_preimage`, genesis, §2.4 границы гарантий |
| `spec/certificate-package-v1.md` | CBOR-кодирование, что подписывает issuer, состав по режимам раскрытия (§2.1: `fieldSalts` только раскрытых путей, поле `nonce` спецификации удалено), `recordIdCommitment`, `segmentIndex` и segment PDA, формат QR |
| `spec/error-codes.md` | Коды §9.5 спецификации + on-chain коды; полный verifier contract `VERIFIED/VERIFIED_HISTORICAL/VERIFIED_NO_INCIDENT_CHECK/SUPERSEDED/DISPUTED/INVALID` и `incidentIndexStatus` `CHECKED/STALE/UNAVAILABLE/INDEX_INCONSISTENT/RPC_DISAGREEMENT`; единый источник для обеих реализаций |

### 4.2. Golden vectors — около 50–70 суммарно

| Набор | Количество | Что покрывает |
|---|---:|---|
| canonical | 20–30 | по одному на класс: Unicode NFC (кириллица/армянский с комбинирующими), surrogate pair, RTL-маркер, `0.10` vs `0.1`, отрицательный decimal, `-0`, отсутствующий ключ vs `null`, пустой массив, порядок массива, високосная секунда, граничная дата, поле вне схемы (отклонение) |
| leaf / field tree | 8–12 | одно поле, все поля, selective с одним раскрытым, selective с несколькими, вложенное поле, отсутствующее поле, пара одинаковых roots/versions с разными `record_id_commitment`. Каждый вектор содержит **раздельно** `field_commitment`, `field_tree_leaf_hash`, `field_root`, `record_commitment`, `batch_leaf_hash` — двойное хэширование и привязка ID фиксируются явно |
| merkle | 10–15 | 1, 2, 3, 4, 5, 7, 8 листьев (непарные узлы на разных уровнях), proof для первого/последнего/среднего |
| manifest / anchor | 5–8 | `anchor_preimage`, genesis, snapshot_hash = нули и не-нули |
| certificate | 5 | FULL_RECORD, SELECTIVE_FIELDS, повреждённая подпись, неподдерживаемая схема, подменённое раскрытое поле/proof |

Векторы выбираются по классам эквивалентности, а не по количеству. Каждый вектор в `spec/vectors/` содержит вход, промежуточные значения и итоговый хэш.

### 4.3. Две реализации

Независимость нужна там, где Monitor должен обнаружить ошибку Builder-а: общая библиотека дала бы одинаковый неверный результат в обоих контурах.

| Контур | Язык |
|---|---|
| Pipeline (canonicalize → batch → publish → issue) | Rust |
| Monitor, Verifier | TypeScript |

Обе пишутся по нормативным документам, а не друг по другу. Обе прогоняют один и тот же набор векторов.

**Differential testing — пропорционально:**
- в PR: небольшой differential corpus (~1000 сгенерированных записей), быстро;
- перед релизом: расширенный прогон;
- ежедневных прогонов на 10⁶ записей нет.

**Выход Gate B:** заморожены и криптографический протокол, и on-chain ABI/state (release gate 2), обе реализации проходят все векторы, ADR приняты.

`spec/onchain-state-v1.md` фиксирует уже принятое решение `OL-A-04`: segmented ledger C′ с capacity 46 и seed `["ledger", config, day_utc, u16_le(segment_index)]`. Инструкции роста в ABI нет. Возврат к realloc-варианту B возможен только через новый ADR, если `OL-A-02` докажет обязательность единого дневного аккаунта.

Изменение любого замороженного документа после Gate B требует ADR и инкремента версии схемы — молчаливых правок layout-а или preimage быть не может.

---

## 5. Gate C — вертикальный pilot

**Цель:** один сквозной поток, работающий на synthetic-данных и devnet.

```text
synthetic change → canonicalize → batch → manifest → devnet anchor → certificate → verifier
```

### 5.1. Состав

| ID | Задача |
|---|---|
| `OL-C-01` | On-chain: `initialize_registry`, `grant_operator`, `revoke_operator` |
| `OL-C-02` | On-chain: `create_ledger_segment` по ADR-0002, capacity 46, монотонный `segment_index` внутри дня |
| `OL-C-03` | On-chain: `publish_anchor` (§8.4), `anchor_hash` по §2.2, события |
| `OL-C-04` | On-chain: `seal_daily_ledger` запечатывает все сегменты дня; `entries_hash` считается по `segment_index` |
| `OL-C-05` | On-chain: `pause_registry` / `resume_registry` |
| `OL-C-06` | On-chain: `open_incident` / `resolve_incident`, счётчик `incident_count`; resolve обязан проверять `incident.registry == config.key()` |
| `OL-C-10` | `crates/canonical` + `crates/merkle`: реализация по Gate B |
| `OL-C-11` | `apps/pilot-pipeline`: чтение synthetic-источника, сопоставление с workflow-событием, canonical version, batch, манифест |
| `OL-C-12` | `apps/pilot-pipeline`: единый builder/publisher для devnet, отслеживание `finalized` и durable queue в PostgreSQL; 72-часовой pilot подписывает tmpfs software test key, визуальный MVP — Wallet Standard test operator |
| `OL-C-13` | `apps/pilot-pipeline`: выдача сертификата, оба режима раскрытия, `recordIdCommitment`, `segmentIndex` и segment PDA, QR (основной формат: URL + id + hash) |
| `OL-C-14` | `apps/verifier`: алгоритм §8.3 спецификации, один RPC, проверка segment PDA, lifecycle-статусы `VERIFIED_HISTORICAL` / `SUPERSEDED`, event-backed incident index scoped по `registryId` с watermark (§2.3), REST по §9.1 |
| `OL-C-15` | Схема БД (§6.2): durable queue + неизменяемые подписанные данные `publish_attempt` с однократным разрешением outcome, append-only audit journal без hash-chain (§2.6) |
| `OL-C-20` | Детерминированный integration smoke: synthetic change → `VERIFIED` в verifier на локальной Solana-среде |
| `OL-C-21` | `apps/mvp-web`: один Next.js App Router client с двумя route groups — закрытая Admin-панель и публичная OneLayer-панель; общие design tokens/status components и разные trust boundaries |
| `OL-C-22` | Admin: список и детали synthetic-сертификатов; wizard ручного ввода/JSON-импорта; до anchor показывает canonical payload, disclosed fields, `recordIdCommitment`, `fieldRoot`, `recordCommitment` и batch leaf; `certificateHash` появляется только после finalized anchor и выдачи package |
| `OL-C-23` | Admin: review подготовленной транзакции показывает program ID, instruction, все accounts с signer/writable flags, registry, segment PDA, batch, roots, fee payer, fee/rent и simulation logs; RPC accounts проверяются по owner, длине и discriminator |
| `OL-C-24` | Wallet Standard через `@solana/kit-plugin-wallet` + `@solana/react`; только browser test operator в `solana:devnet`, без keypair/seed в UI; browser подписывает точное prepared message, backend повторно проверяет intent/signature и передаёт signed wire transaction единственному durable publisher |
| `OL-C-25` | Transaction state machine: `DRAFT → PREPARED → SIMULATED → SIGNED → SUBMITTED → FINALIZED → ISSUED` с ветками `SIMULATION_FAILED`, `SIGNING_REJECTED`, `EXPIRED`, `UNKNOWN`, `FAILED`; `UNKNOWN` только reconciles известную signature, `ISSUED` запрещён до finalized checks |
| `OL-C-26` | Admin: выдача certificate package после `FINALIZED`, QR SVG/PNG, copy/download URL, transaction signature и Solana Explorer devnet link; timeline операции без секретов в logs |
| `OL-C-27` | OneLayer: QR из камеры, image upload и manual URL/package input; проверка QR hash binding, issuer signature, field/batch proof, program/account ownership, finalized transaction и incident index |
| `OL-C-28` | OneLayer: отдельные result views `VERIFIED`, `VERIFIED_HISTORICAL`, `SUPERSEDED`, `INVALID`, `DISPUTED`, `VERIFIED_NO_INCIDENT_CHECK`; причина, cluster, slot, signature, index lag и раскрытые поля без скрытых данных |
| `OL-C-29` | Детерминированный browser E2E на локальном Surfpool с mock Wallet Standard: happy path до QR → `VERIFIED`, package/QR tampering → `INVALID`, direct synthetic DB tampering → `DISPUTED`; live devnet не является обычным CI-тестом |
| `OL-C-30` | `apps/mvp-web` расширяет существующий Compose-проект `deploy/devnet-demo`: сохраняет labels/networks, synthetic marker, tmpfs server keys и loopback-only binding, добавляя один UI-port. Program deploy остаётся CLI-only с deploy approval digest; CLI publish сохраняет tx digest, а UI publish требует reviewed click + wallet prompt и exact-intent validation |
| `OL-C-31` | Admin: runtime-generated test credentials в tmpfs, короткая server-side session с `HttpOnly`/`SameSite` cookie и CSRF-защитой mutation; `operator` может публиковать, `auditor` только читать; роль берётся только из server session, не из client state |
| `OL-C-32` | Anchor IDL → Codama → checked-in Kit-native TypeScript client; CI регенерирует его и ломается при drift. Ручная Borsh-сериализация, PDA seeds и account layout во frontend запрещены |
| `OL-C-33` | Versioned Admin API: idempotency key, immutable intent hash + expiry, server-session role checks и повторная валидация signed wire transaction перед сохранением/отправкой |
| `OL-C-34` | Один guarded live-devnet browser smoke перед презентацией/release: отдельное явное approval, synthetic fixture/test keys, finalized transaction → certificate → QR → `VERIFIED`; в default CI не запускается |
| `OL-C-35` | Presentation preflight проверяет Docker daemon/socket access, Compose, toolchain, devnet-only RPC, test-key balance/rent, ports и synthetic marker; отсутствие `rg` использует portable fallback, а недоступный обязательный dependency завершает запуск до создания новых demo artifacts |
| `OL-C-36` | Demo-схема реестра `land-registry-v1`: закрытый перечень путей полей, типы (text/decimal-строка/timestamp/bool/enum/hex), обязательные пути, ограничения длины; поле вне схемы → `CANONICALIZATION_FAILED`. Схема — единственный источник и для preview, и для issuance, и для reconcile |
| `OL-C-37` | Импорт сертификата пользователя: JSON-объект (`internalRecordId` + `fields`) или CSV (первая строка — пути полей), построчная валидация по `OL-C-36`, dry-run preview без записи, отчёт об ошибках с указанием строки и пути, идемпотентный upsert новой версии записи |
| `OL-C-38` | Динамические canonical-метаданные: field tree строится по фактическому набору полей записи; preview показывает per-field `field_commitment`, `fieldRoot`, `recordCommitment` и batch leaf; хардкод единственного поля удалён из batch builder, reconcile и fixture-пути |
| `OL-C-39` | Выдача в режиме `SELECTIVE_FIELDS`: оператор выбирает раскрываемые пути, пакет содержит field proof и соль **только** этих путей, `fieldRoot` остаётся прежним; `FULL_RECORD` остаётся значением по умолчанию |
| `OL-C-40` | Динамический QR и публичная карточка сертификата: QR SVG/PNG строится из выданного пакета, публичная страница рендерит только раскрытые поля пакета, показывает cluster/slot/signature и не запрашивает скрытые значения |
| `OL-C-41` | Полный UI-контур: dashboard с фактическими метриками, детали записи и сертификата, incident-панель, публичная страница «как это работает»; навигация покрывает все сценарии `docs/use-cases-ru.md` |

### 5.2. Чего в Gate C нет

HSM, durable nonce, два RPC, мультисиг, три хранилища манифестов (одно + локальная копия), Monitor, snapshots, recovery, algorithm transition, SIEM, Kubernetes, banking SDK.

Существующие `clean-fixture.dump` и `deploy/recovery-lab` — demo/prototype artifacts. Fixture-only reset/recovery в Gate C не является нормативным `SnapshotPackageV1`, threshold recovery или доказательством выхода Gate E0.

В Gate C используется свежий blockhash, полученный непосредственно перед simulation/signing, вместе с `lastValidBlockHeight`. Интерактивный review может пережить окно валидности; в таком случае flow завершается `EXPIRED` и возвращается в `PREPARED` с новой simulation — старую транзакцию не отправляет. Durable nonce остаётся Gate E для offline/HSM-signing и длинных очередей.

### 5.3. Модель развёртывания pilot

Один процесс `pilot-pipeline` с логическими модулями-библиотеками внутри (`cdc`, `workflow`, `canonicalizer`, `batch`, `publisher`, `issuer`). Отдельный процесс `verifier` — потому что у него другая граница доверия (единственный компонент с входящим публичным трафиком), а не потому что «микросервисы».

Разделение на отдельные сервисы происходит при появлении подтверждённой границы: Publisher выносится, когда появляется HSM в изолированной подсети (Gate E); Monitor изначально отдельный процесс с отдельными credentials (Gate D) — это требование модели угроз, а не архитектурная эстетика.

### 5.4. Визуальный MVP

**Цель:** превратить технический Gate C flow в два понятных пользовательских контура, не меняя замороженный криптографический протокол. После однократного guarded deploy программы и выдачи test operator role полный путь от synthetic-записи до публичной проверки сертификата выполняется через UI. Monitor (Gate D) и recovery-консоль (Gate E0) в MVP не входят.

```text
Admin panel
  сертификат пользователя: JSON / CSV по схеме land-registry-v1
    → schema validation (поле вне схемы отклоняется)
      → canonical preview
      → batch + Merkle root + manifest hash
        → simulate devnet transaction
          → explicit wallet review/sign
            → finalized anchor
              → signed certificate package + QR

OneLayer panel
  camera / image / URL
    → QR hash binding
      → certificate + Merkle proof
        → finalized Solana anchor + incident index
          → VERIFIED / VERIFIED_HISTORICAL / SUPERSEDED
            / INVALID / DISPUTED / VERIFIED_NO_INCIDENT_CHECK
```

**Граница on-chain.** Admin-панель не записывает отдельный `certificateHash` в Solana и не создаёт второй протокол. Программа якорит batch `merkleRoot` и `manifestHash`; certificate package содержит Merkle proof и связывает сертификат с finalized anchor. UI показывает эти две величины раздельно.

**Сертификат пользователя — вход, а не результат (`OL-C-36`…`OL-C-38`).** До v2.6 запись MVP имела ровно одно поле `status`, и все метаданные были константой. Теперь исходные данные даёт пользователь: JSON-объект или CSV по demo-схеме реестра `land-registry-v1`. Схема — часть Gate C artefacts, а не `spec/`: она описывает **конкретный** реестр, тогда как frozen-документы описывают протокол, одинаковый для любого реестра.

```text
land-registry-v1 (перечень путей закрыт)
  status              enum text   обязателен   ACTIVE | ARCHIVED | PENDING | DISPUTED
  cadastralNumber     text        обязателен   NFC, byte_len <= 64
  parcelAddress       text                     NFC, byte_len <= 256
  areaSquareMeters    decimal-строка           фиксированный scale 2: "1250.50"
  landCategory        enum text                AGRICULTURAL | SETTLEMENT | INDUSTRIAL | FOREST | WATER | RESERVE
  permittedUse        text                     NFC, byte_len <= 128
  rightType           enum text                OWNERSHIP | LEASE | EASEMENT | MORTGAGE
  rightRegisteredAt   timestamp                RFC 3339, UTC, без дробной части
  encumbered          bool
  holderCommitment    hex(64)                  обязательство к личности правообладателя, не сама личность
  documentHash        hex(64)                  SHA-256 исходного документа, если он есть
```

Правила импорта:

- поле вне схемы — отказ `CANONICALIZATION_FAILED` с указанием пути; молчаливое отбрасывание запрещено (§4 `spec/canonical-record-v1.md`);
- decimal и timestamp принимаются **строками**: `"0.10" ≠ "0.1"` семантически значимо, а float в канонический CBOR не попадает вообще;
- ПДн правообладателя в записи не хранятся: схема принимает `holderCommitment`, а не ФИО. Это граница, а не оформление demo;
- импорт идемпотентен: повторная загрузка того же `internalRecordId` создаёт **новую версию** записи, а не второй объект; старый сертификат этой записи после нового anchor становится `SUPERSEDED`;
- CSV — первая строка задаёт пути полей, каждая последующая строка — одна запись; ошибка в строке отклоняет **строку**, а не молча импортирует часть файла; отчёт указывает строку и путь;
- dry-run обязателен: до записи в БД показываются канонические значения и типы каждой строки и полный список отклонений. Commitments в dry-run не показываются: `field_salt` выводится из `record_field_key`, который создаётся вместе с версией записи, — показывать «предварительный» commitment, не равный итоговому, значило бы показывать неверное число. `field_commitment`, `fieldRoot`, `recordCommitment` и batch leaf появляются в canonical preview сразу после сохранения и до подготовки batch.

Одна и та же схема применяется в трёх местах, где раньше был хардкод одного поля: batch builder Admin API, reconcile-проверка прямого вмешательства в БД и fixture-путь CLI. Расхождение любого из трёх дало бы ложный `DISPUTED` — это инвариант, а не деталь реализации.

**Хранение полей в demo-контуре.** `status` остаётся колонкой `synthetic_registry_record` — на неё опираются seeded fixture и Rust CLI happy path, и менять их формат ради UI незачем. Остальные пути хранятся в `synthetic_record_field` (миграция `0004`), по строке на путь текущей версии записи: уникальность пути и его тип проверяются схемой БД, а не только кодом. История значений в demo-БД не хранится — прежние версии доказываются выданными пакетами, которые содержат свои значения и свой `fieldRoot`. Целевая схема (§6.2) хранит поля в canonical payload версии записи; demo-таблица её не заменяет.

**Раскрытие полей при выдаче (`OL-C-39`).** `FULL_RECORD` остаётся значением по умолчанию. Дополнительно оператор может выбрать раскрываемые пути и выдать `SELECTIVE_FIELDS`: пакет содержит значения, соли и field proof **только** выбранных путей, `fieldRoot` при этом не меняется, поэтому batch proof и anchor остаются теми же. Соль нераскрытого пути не выводится из раскрытых (§2.1), но число листьев field-дерева видно из proof — оговорка §2.1 действует и здесь.

**Динамические метаданные и QR (`OL-C-40`).** QR по-прежнему кодирует `URL + certificateId + certificateHash` (`spec/certificate-package-v1.md`) и не содержит данных записи: сами значения приходят из пакета после проверки hash binding. Публичная карточка сертификата рендерит ровно те поля, что раскрыты пакетом, — не список схемы и не запрос в БД. Для нераскрытых путей карточка не показывает ни значения, ни плейсхолдера «скрыто по конкретному пути»: раскрытая структура — то, что доказано, всё остальное отсутствует.

**Архитектура UI.** Одно приложение `apps/mvp-web` на Next.js App Router, один сгенерированный Solana Kit client и общие визуальные primitives. Admin и OneLayer — разные route groups и access policies, но не два frontend-репозитория. Wallet hooks живут только в client leaf-components; публичная верификация не требует wallet. Browser обращается к Admin API и verifier через same-origin `/api/admin/*` и `/api/verify/*` proxy; Compose-сервисы остаются во внутренней сети, новый широкий CORS не открывается.

**Среда исполнения — существующий demo-контур.** MVP разворачивается в guarded Compose-проекте `deploy/devnet-demo` (`OL-C-30`): synthetic marker, tmpfs server keys, labels/networks и loopback-only binding сохраняются; добавляется только UI-port. Program deploy/upgrade остаётся CLI-only и требует deploy approval digest. CLI automated publish сохраняет tx approval digest; browser publish использует отдельную интерактивную границу — reviewed click, Wallet Standard prompt и server-side exact-intent validation. Эти механизмы не подменяют друг друга.

Текущий fixture incident endpoint годится только для demo-сценария и не закрывает `OL-C-14`: выход Gate C требует индекса, построенного из finalized `IncidentOpened` / `IncidentResolved` с watermark. CLI-runner `deploy/devnet-demo/demo` остаётся воспроизводимым параллельным happy path, но browser E2E работает через UI/API, а не запускает shell-команды из браузера.

CLI сохраняет one-command сценарии `demo happy-path`, `demo incident` и опциональный `demo recovery`. `demo reset` удаляет/пересоздаёт только явно названные fixture resources после label + synthetic-marker checks; broad Docker cleanup запрещён. Preflight обязан fail closed при недоступном Docker socket, а не оставлять certificate/QR от старого запуска как результат нового.

**Design system.** Один документированный набор design tokens (цвет, типографика, spacing, radius, focus) и общие status components. Статус выражается парой «иконка + текст», никогда одним цветом. Для MVP обязательна одна доступная high-contrast тема; вторая тема опциональна только без дублирования state/layout logic.

**Роли Admin.** `operator` — подготовка batch, simulation, запрос подписи, выдача сертификата; `auditor` — read-only список, детали и timeline. Runtime-generated test credentials живут в tmpfs; сервер выдаёт короткую `HttpOnly`/`SameSite` session cookie и требует CSRF token для mutations. Роль берётся из server session, а не из `localStorage`, query/body или скрытия кнопок. Это demo access separation; внешний IdP, production SSO/RBAC и аудит доступа — Gate E.

**Админские экраны:** dashboard с фактическими метриками (записи, версии, батчи, последний finalized anchor, выданные сертификаты, открытые инциденты); record list и record detail с полями, версиями и commitments; create/import wizard (форма, JSON, CSV) с dry-run отчётом; canonical/disclosure preview; batch preparation; transaction review + simulation; publish progress; выбор раскрываемых полей; issued certificate + QR; certificate list/detail; append-only operation timeline. Admin API — тонкий HTTP-адаптер в `pilot-pipeline`, а не новый сервис.

**Экраны OneLayer:** scan; camera permission/fallback; image upload; manual input; checking progress; result; public certificate detail с раскрытыми полями; страница «как это работает» (границы гарантий, что попадает в Solana, что нет). Камера — progressive enhancement: отказ permission никогда не блокирует image/manual flow.

**Полнота контура (`OL-C-41`).** Требование «через UI выполним весь путь» проверяется навигацией: каждый сценарий `docs/use-cases-ru.md` достижим из интерфейса без curl, psql и shell. Исключения названы явно и остаются CLI-only: deploy/upgrade программы, выдача operator role, fixture reset и guarded live smoke — у них отдельные approval digests (§5.4, `OL-C-30`).

**Transaction review — блокирующий шаг.** До wallet prompt UI показывает cluster `devnet`, program ID, instruction, accounts с signer/writable flags, registry, segment PDA, batch sequence, `merkleRoot`, `manifestHash`, `previousAnchorHash`, fee payer, fee/rent и simulation logs. RPC account data считается недоверенным и проверяется по owner, длине и discriminator. Любой endpoint/wallet не на devnet отклоняется до подписи.

Admin API создаёт typed intent, строит message, фиксирует `intentHash`, idempotency key, expiry и simulation result. Browser подписывает именно эти байты. Backend до broadcast проверяет wallet signature и соответствие signed wire transaction сохранённому intent, атомарно создаёт `publish_attempt`, затем передаёт её единственному durable publisher. Второго client-side publisher нет; `UNKNOWN` reconciles известную signature и никогда не вызывает слепую пересборку.

**Test identity.** Browser test wallet имеет только operator role и отделён от governance/upgrade authority. Issuer software test key остаётся server-side в tmpfs и никогда не попадает в browser. Operator role выдаётся однократной guarded devnet-операцией с отдельным явным подтверждением. Browser не принимает keypair files, private keys и seed phrases.

**QR transport.** Нормативный QR использует HTTPS. Единственное исключение MVP — точный loopback origin (`http://127.0.0.1`/`http://localhost`), визуально помеченный `DEVNET SYNTHETIC DEMO`; любой другой HTTP URL отклоняется. Телефон не может открыть loopback хоста Docker, поэтому responsive/mobile и camera flow проверяются в fresh browser context/emulator на том же host. Cross-device phone scan требует отдельно разрешённого HTTPS staging и не входит в локальный DoD.

**Вне scope MVP:** mainnet, production credentials, реальные кадастровые данные, внешний IdP и production SSO/RBAC (демо-роли `OL-C-31` их не заменяют), локализация интерфейса, PWA/офлайн-режим, формальная сертификация доступности, bulk issuance, native mobile app, push/email, внешняя публикация и analytics. Внешний staging и HTTPS-хостинг требуют отдельного разрешения; loopback demo остаётся базовым контуром.

Импорт **не** включает: OCR и парсинг PDF/сканов, автоматическое извлечение полей из произвольного документа, загрузку файлов сертификатов на сервер, справочники и нормализацию адресов. Вход — структурированный JSON/CSV; связь с внешним документом возможна только через `documentHash`, посчитанный вне системы.

**Acceptance criteria визуального MVP:**

1. Admin создаёт или импортирует synthetic-запись; UI показывает canonical preview и не принимает запись без marker/schema validation.
2. Devnet-транзакция симулируется; review показывает все поля из блокирующего шага; подпись запрашивается только после успеха simulation.
3. Повторный click/reload не создаёт второй batch или вторую транзакцию; протухший blockhash возвращает flow к preparation/simulation.
4. Сертификат не выдаётся до `finalized`; после `finalized` Admin получает certificate package, `certificateHash`, QR и signature/slot.
5. QR, прочитанный камерой или загруженный как image в fresh browser context на demo-host, даёт OneLayer `VERIFIED`; manual input даёт тот же результат. Cross-device scan проверяется только на отдельно разрешённом HTTPS staging.
6. Подмена QR hash/package/field даёт `INVALID`; direct synthetic DB tampering даёт `DISPUTED`; stale/unavailable incident index не показывает зелёный `VERIFIED`, а даёт `VERIFIED_NO_INCIDENT_CHECK`; fixtures покрывают также `VERIFIED_HISTORICAL` и `SUPERSEDED`.
7. UI адаптивен для desktop и mobile scan, управляется с клавиатуры, не полагается только на цвет для status и имеет camera fallback.
8. Fresh browser context проходит локальный детерминированный flow `OL-C-29` и сохраняет screenshot/trace; guarded live-devnet evidence создаётся отдельно задачей `OL-C-34`.
9. Оба контура собраны из одного набора design tokens/status components; обязательная high-contrast тема читается без опоры на цвет.
10. Пользователь с ролью `auditor` видит данные, но не может подготовить batch, запросить подпись или выдать сертификат; ограничение проверяется на Admin API, а не только скрытием элементов UI.
11. Synthetic marker проверяется до data operations. Deploy и CLI publish не проходят без своих approval digests; browser publish не проходит без reviewed intent, wallet prompt и server-side signed-transaction validation.
12. Default CI проходит IDL→Codama drift check и детерминированный Surfpool/browser E2E без расхода SOL; один `OL-C-34` live-devnet smoke запускается только с отдельным подтверждением перед презентацией/release.
13. На clean host preflight либо подтверждает все зависимости, либо сообщает точную remediation и выходит до mutation; one-command CLI happy path воспроизводим, а fixture-only reset не затрагивает другие Compose projects, containers, images или volumes.
14. Импорт JSON и CSV принимает валидный сертификат пользователя и отклоняет: поле вне схемы (`CANONICALIZATION_FAILED`), неверный тип, decimal с чужим scale, timestamp с дробной частью, обязательное поле без значения. Отчёт называет строку и путь; dry-run не меняет БД; ошибка в одной строке CSV не импортирует остальные молча.
15. `fieldRoot`, `recordCommitment`, batch leaf и `merkleRoot` пересчитываются из фактического набора полей записи; повторный импорт того же `internalRecordId` даёт новую версию, а не второй объект, и после нового anchor прежний сертификат этой записи становится `SUPERSEDED`.
16. Выдача в режиме `SELECTIVE_FIELDS` даёт `VERIFIED` при раскрытии подмножества путей; пакет не содержит значений и солей нераскрытых путей; `fieldRoot`, batch proof и anchor совпадают с `FULL_RECORD` той же версии записи.
17. Публичная карточка сертификата показывает ровно раскрытые пакетом поля; ни одно значение не берётся из БД в обход проверенного пакета.
18. Каждый сценарий `docs/use-cases-ru.md`, кроме явно названных CLI-only операций, выполним из UI; dashboard-метрики совпадают с данными API, а не являются статикой.

### 5.5. Состояние реализации Gate C

| Блок | Состояние |
|---|---|
| `OL-C-01`…`OL-C-06` on-chain | реализованы в `onchain/programs/onelayer-registry` |
| `OL-C-10`…`OL-C-13` pipeline | реализованы в `crates/*` и `apps/pilot-pipeline` |
| `OL-C-14` verifier | реализован, включая `VERIFIED_HISTORICAL`/`SUPERSEDED` и event-backed incident index с watermark |
| `OL-C-15` схема БД | `db/migrations/0001`–`0003` |
| `OL-C-20` smoke | `tests/e2e/synthetic-smoke.test.ts` |
| `OL-C-21`…`OL-C-28` UI | `apps/mvp-web`: Admin и публичная OneLayer route groups, общие design tokens и status components |
| `OL-C-29` browser E2E | `tests/e2e-web`, 19 сценариев × desktop/mobile; вместо Surfpool — фикстурный backend (ADR-0003) |
| `OL-C-30` Compose | `deploy/devnet-demo` расширен одним UI-портом; labels, networks, tmpfs и loopback сохранены |
| `OL-C-31` роли | server-session, `HttpOnly`/`SameSite` cookie, CSRF, `operator`/`auditor` на уровне API |
| `OL-C-32` IDL→Codama | `packages/onchain-client` + drift check в CI |
| `OL-C-33` Admin API | idempotency key, immutable intent hash, expiry, повторная валидация signed wire transaction |
| `OL-C-34` live smoke | `deploy/devnet-demo/scripts/live-smoke`, отдельное подтверждение, публичный путь без ключей в браузере |
| `OL-C-35` preflight | Docker/Compose/toolchain, devnet-only RPC, баланс test key, занятость портов, portable fallback вместо `rg` |
| `OL-C-36` схема реестра | `apps/demo-api/src/record-schema.ts` (`land-registry-v1`), отдаётся UI через `GET /v1/admin/schema` |
| `OL-C-37` импорт | `POST /v1/admin/records/import` (JSON/CSV, dry-run, построчный отчёт) + wizard в `apps/mvp-web` |
| `OL-C-38` динамические поля | `db/migrations/0004`, `fieldsOf` в `admin-batch.ts` — общий источник для builder, preview и reconcile |
| `OL-C-39` selective disclosure | `issueCertificate(..., disclosedPaths)`, field proofs; verifier возвращает раскрытые поля только после успешных проверок |
| `OL-C-40` QR и карточка | `GET /v1/certificates/:id/metadata`, QR в SVG и PNG, публичная карточка из проверенного пакета |
| `OL-C-41` полный контур | dashboard на фактических метриках, карточка записи, деталь сертификата, публичная страница `/how-it-works` |

Отклонения от буквы плана и их обоснование зафиксированы в
`docs/adr/0003-visual-mvp-boundaries.md`. Сценарии использования — в
`docs/use-cases-ru.md`, разбор потока для презентации — в `docs/presentation-ru.md`.
Незакрытым остаётся сам выход Gate C: 72-часовой прогон под synthetic-нагрузкой
не выполнялся.

**Выход Gate C:** сквозной поток работает 72 часа на synthetic-нагрузке без ручного вмешательства; `anchor_sequence_gap_total = 0`; повторная сборка одного диапазона даёт идентичный `manifestHash`; event-backed incident index обрабатывает open/resolve; локальный browser flow `OL-C-29` и отдельный approved smoke `OL-C-34` заканчиваются QR → `VERIFIED`, а tampering — `INVALID`/`DISPUTED` без ложного зелёного статуса.

---

## 6. Репозиторий, схема БД, транспорт

### 6.1. Структура — минимальная, растущая по факту

```text
onelayer/
├── spec/
│   ├── *.md                 # нормативные документы (Gate B)
│   └── vectors/             # golden vectors
├── onchain/
│   ├── programs/onelayer-registry/
│   └── tests/
├── crates/
│   ├── canonical/           # Rust-реализация канонизации и leaf
│   └── merkle/
├── packages/
│   ├── canonical-ts/        # независимая TS-реализация
│   ├── merkle-ts/
│   └── onchain-client/       # Codama-generated Kit client; checked in + drift check
├── apps/
│   ├── pilot-pipeline/      # Rust, один процесс, модули-библиотеки внутри
│   ├── mvp-web/             # Next.js App Router, Admin + public OneLayer route groups
│   └── verifier/            # TS, REST
├── tests/e2e/
├── db/migrations/
├── deploy/devnet-demo/       # guarded Compose-контур Gate C: фикстура, approval digests, CLI-runner
└── docs/adr/
```

Появляется позже, по факту потребности: `apps/monitor` (Gate D), `crates/hsm` + вынесенный publisher (Gate E), `tools/recovery` (Gate E), production-топология в `deploy/` (Gate E, после `OL-A-07`).

### 6.2. Схема БД — целевой вид

Даётся результирующая схема, а не миграции от §7.1 спецификации: рабочей базы ещё нет, писать `ALTER` не к чему (существующие FK всё равно заблокировали бы смену PK).

Отличия от §7.1 спецификации:

```sql
-- составной ключ и все зависимые FK
CREATE TABLE anchor_batch (
  registry_id     TEXT   NOT NULL,
  batch_sequence  BIGINT NOT NULL,
  registry_version BIGINT NOT NULL,
  cursor_start    BIGINT NOT NULL,
  cursor_end      BIGINT NOT NULL,
  leaf_count      INTEGER NOT NULL,
  merkle_root     BYTEA  NOT NULL,
  manifest_hash   BYTEA  NOT NULL,
  previous_anchor_hash BYTEA NOT NULL,
  anchor_hash     BYTEA,                    -- появляется после on-chain publish
  snapshot_hash   BYTEA,
  status          TEXT   NOT NULL CHECK (status IN
                    ('PREPARED','SIGNED','SUBMITTED','FINALIZED','DISPUTED','FAILED')),
  solana_signature TEXT,
  solana_slot     BIGINT,
  prepared_at     TIMESTAMPTZ NOT NULL,
  finalized_at    TIMESTAMPTZ,
  CHECK (anchor_hash IS NULL OR octet_length(anchor_hash) = 32),
  CHECK (status <> 'FINALIZED' OR anchor_hash IS NOT NULL),
  PRIMARY KEY (registry_id, batch_sequence)
);

CREATE TABLE batch_leaf (
  registry_id       TEXT   NOT NULL,
  batch_sequence    BIGINT NOT NULL,
  leaf_index        INTEGER NOT NULL,
  record_version_id UUID   NOT NULL REFERENCES canonical_record_version(id),
  leaf_hash         BYTEA  NOT NULL,
  proof_object_key  TEXT,
  PRIMARY KEY (registry_id, batch_sequence, leaf_index),
  FOREIGN KEY (registry_id, batch_sequence) REFERENCES anchor_batch(registry_id, batch_sequence)
);

-- аналогично: certificate, snapshot, integrity_incident ссылаются на (registry_id, batch_sequence)

-- durable queue публикации (не WORM): текущее состояние, одна строка на batch
CREATE TABLE publish_queue (
  registry_id     TEXT   NOT NULL,
  batch_sequence  BIGINT NOT NULL,
  attempt_count   INT    NOT NULL DEFAULT 0,
  claimed_by      TEXT,                     -- lease: идентификатор воркера
  claimed_until   TIMESTAMPTZ,              -- lease: срок
  status          TEXT NOT NULL CHECK (status IN
                    ('QUEUED','CLAIMED','SUBMITTED','FINALIZED','EXPIRED','FAILED')),
  last_error      TEXT,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (registry_id, batch_sequence)
);

-- история попыток: подписанные байты неизменяемы; outcome разрешается один раз
CREATE TABLE publish_attempt (
  registry_id     TEXT   NOT NULL,
  batch_sequence  BIGINT NOT NULL,
  attempt_no      INT    NOT NULL,
  transaction_b64 TEXT   NOT NULL,          -- точные signed wire bytes попытки
  signature       TEXT   NOT NULL,          -- подпись этой попытки
  recent_blockhash TEXT  NOT NULL,
  submitted_to    TEXT[] NOT NULL DEFAULT '{}',
  outcome         TEXT   NOT NULL CHECK (outcome IN
                    ('SUBMITTED','FINALIZED','EXPIRED','FAILED','UNKNOWN')),
  error_code      TEXT,                     -- внутренний bounded код, не текст провайдера
  error_message   TEXT,                     -- санитизированное сообщение, <=512 символов
  error_payload_hash BYTEA,                 -- SHA-256 сырого ответа, для корреляции
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at     TIMESTAMPTZ,
  PRIMARY KEY (registry_id, batch_sequence, attempt_no),
  FOREIGN KEY (registry_id, batch_sequence) REFERENCES publish_queue(registry_id, batch_sequence)
);

-- курсор источника: единственная точка истины о прогрессе
CREATE TABLE source_cursor_state (
  registry_id    TEXT PRIMARY KEY,
  last_processed BIGINT NOT NULL,
  last_anchored  BIGINT NOT NULL,
  updated_at     TIMESTAMPTZ NOT NULL
);

-- audit_event — по §2.6 (append-only журнал, без hash-chain в Gate C)
```

**Ошибки не хранятся сырыми.** Ответ RPC-провайдера может содержать внутренние endpoint URL, идентификаторы провайдера и служебные заголовки. В `publish_attempt` пишутся: внутренний код из закрытого перечня, санитизированное сообщение и хэш сырого ответа для корреляции с логами провайдера. Сырой payload по умолчанию не сохраняется — при необходимости расследования он берётся из временных логов с коротким retention.

**Почему `publish_attempt` не удаляется и не заменяется.** Каждая попытка — это подписанная транзакция, отправленная в сеть. Исход части попыток принципиально неопределён (`UNKNOWN`): RPC не ответил, но транзакция могла быть принята. В этом состоянии Publisher обязан **опрашивать статус по известной signature**, а не пересобирать транзакцию, — значит все предыдущие signature должны сохраняться.

Неизменяемы `transaction_b64`, `signature`, `recent_blockhash`, `submitted_to`, `created_at` и ключ попытки. Разрешено ровно одно обновление результата из `SUBMITTED` или `UNKNOWN` в терминальный `FINALIZED` / `EXPIRED` / `FAILED` с заполнением `resolved_at` и санитизированной ошибки. Повторный или обратный переход запрещён. Этого достаточно для provenance; отдельная таблица наблюдений появится только при явном требовании хранить каждое status-poll событие.

`audit_chain_head` в Gate C не создаётся — появляется вместе с включением hash-chain (`OL-DEC-07`).

Партиционирование `registry_change_event` и `canonical_record_version` добавляется при подтверждённых объёмах из `OL-A-02`, не заранее.

### 6.3. Транспорт

| Что | Механизм |
|---|---|
| Внутри pipeline | вызовы функций в одном процессе; состояние — транзакции PostgreSQL |
| Pipeline → Publisher | `publish_queue` с claim/lease |
| Browser → `mvp-web` | same-origin HTTPS; exact loopback HTTP разрешён только для devnet demo |
| `mvp-web` → Admin API / verifier | server-side same-origin proxy; внутренний HTTP в Compose network, без публичного CORS |
| Publisher → Solana | JSON-RPC только к allowlisted devnet endpoint в Gate C |
| Публичный verifier | REST |
| Monitor → источники | прямое чтение (реплика, Solana RPC, хранилище манифестов) |

gRPC и protobuf не вводятся, пока не появится вызов через сетевую границу с независимым масштабированием. Схемы данных описываются в `spec/`, а не в `.proto`.

**WORM** используется по назначению: неизменяемая копия подписанного манифеста и evidence bundle. Не как очередь.

---

## 7. Тестовая стратегия

Критерий — покрытые инварианты, не количество тестов.

### 7.1. On-chain

Для каждой инструкции — минимальный набор негативных тестов, соответствующий её уникальным account constraints и state invariants.

`publish_anchor` (больше всего инвариантов):
неавторизованный signer · отозванная роль · истёкшая роль · роль без `PERM_PUBLISH_ANCHOR` · роль чужого реестра · пустой batch · `batch_sequence` повтор/пропуск · неверный `previous_anchor_hash` · `registry_version` назад · `cursor_start > cursor_end` · несовпадение schema/hash/tree algorithm · sealed ledger · переполненный ledger · ledger чужого дня · ledger чужого реестра · `paused`.

`create_ledger_segment`: повторное создание · чужой реестр · неавторизованная роль · неверный следующий `segment_index` · capacity не равна 46 · paused registry · неверный `day_utc`.
`seal_daily_ledger`: повторный seal · чужой сегмент · пропуск сегмента дня · пустой день · неавторизованная роль.
`grant_operator` / `revoke_operator`: не-governance signer · повторный grant.
`pause` / `resume`: не-emergency signer на pause · не-governance на resume.
`open_incident` / `resolve_incident`: роль без `PERM_REPORT_INCIDENT` · неверный/пустой batch range · resolve не-governance · повторный resolve · incident чужого registry.

Пирамида: быстрые property/invariant tests в LiteSVM или Mollusk; integration в Surfpool с synthetic fixtures; browser E2E с mock Wallet Standard. Плюс property-тест стабильности zero-copy layout, замер CU по `publish_anchor` с regression gate и fuzz instruction data перед release. Live devnet запускается только guarded smoke `OL-C-34`, не на каждый PR.

### 7.2. Off-chain

Focused property tests: Unicode NFC, decimal, сортировка массивов, RFC 6962 proof (построение → проверка, для 1..16 листьев).

Обязательные сценарии (по одному на инвариант):
- дубликат CDC-события, событие вне порядка, пропуск курсора, рестарт посреди обработки;
- изменение без workflow-события; workflow-событие без изменения;
- повторная сборка диапазона → идентичный `manifestHash`;
- параллельная попытка опубликовать один batch дважды; `UNKNOWN → FINALIZED` разрешается один раз без изменения подписанных байтов попытки;
- сертификат с подменёнными: `recordIdCommitment`, значением поля, солью, field-proof, batch-proof, `merkleRoot`, `programId`, `segmentIndex`, segment PDA;
- сертификат для batch с открытым инцидентом;
- incident index недоступен / отдаёт лаг выше `maxIndexLagSlots` / не дошёл до `anchor_slot` / отдаёт ответ без watermark → `VERIFIED_NO_INCIDENT_CHECK`, статусы `UNAVAILABLE`/`STALE`/`STALE`/`UNAVAILABLE` соответственно; запрос без совпадающего `registryId` отвергается;
- lifecycle fixtures для `VERIFIED_HISTORICAL` и `SUPERSEDED`; finalized `IncidentOpened` / `IncidentResolved` меняют текущий результат индекса без попытки вывести недоступное историческое состояние;
- RPC вернул `confirmed` вместо `finalized`;
- Admin UI: mainnet endpoint/wallet, неуспешная simulation, wallet rejection, blockhash expiry, reload/double-click в каждом transaction state; ни один сценарий не выдаёт certificate до `finalized`;
- OneLayer UI: camera denied/unavailable, QR image без payload, неверный QR hash, подменённый package, `DISPUTED`, устаревший incident index; все статусы проверяются browser E2E и не сводятся к цвету.

**Проверка изоляции солей (§2.1)** — вместо недоказуемого «восстановить соль невозможно» тестируется конкретный контракт:
- сериализованный selective-сертификат не содержит `record_field_key` (поиск по байтам ключа в готовом пакете);
- сертификат содержит соли ровно тех путей, что раскрыты, и ни одной другой;
- ни один эндпоинт API не возвращает `record_field_key` и `record_field_key_encrypted` — проверка на сериализаторах ответов, а не на конкретных ручках;
- подмена соли раскрытого поля ломает field-proof.

### 7.3. Что не делается

Квоты «N тестов на инструкцию», 95%-покрытие как самоцель, 100 повторных сборок (достаточно 3), ежедневные прогоны на 10⁶ записей и live-devnet транзакции в default CI. Детерминированный локальный E2E выполняется в CI; guarded devnet smoke — один раз перед презентацией/release.

---

## 8. On-chain: расчёты (сохранено из v1.0)

### 8.1. Zero-copy вместо `Vec`

Единый `Vec<AnchorEntryV1>` на целевые 96 записей занял бы ~20 КБ и не создаётся прямым `init` через CPI. Решение — `#[account(zero_copy)]` с фиксированным массивом на 46 entries и явным padding; день состоит из последовательных сегментов.

Entry: 216 байт (`repr(C)`, align 8, все padding-поля явные и обнуляемые — иначе `Pod` не выводится). Header ledger-а: 96 байт + 8 дискриминатор.

**Важно (§2.2):** этот layout — деталь хранения. Для `anchor_hash` используется `anchor_preimage`, а не байты аккаунта.

### 8.2. Размеры и rent

| unit | capacity | entries | + header | итого | rent-exempt* |
|---|---:|---:|---:|---:|---:|
| один сегмент C′ | 46 | 9 936 | 104 | 10 040 | 0.07076928 SOL |
| три сегмента/день | 138 | 29 808 | 312 | 30 120 | 0.21230784 SOL |

\* `(128 + size) × 3480 × 2` lamports.

`OL-A-04` эмпирически подтвердил: прямой `init` ограничен 10 240 байтами; 46 entries дают 10 040 байт и проходят, 47 entries дают 10 256 байт и отвергаются. Принят **C′**:

```text
seed: ["ledger", config, day_utc, u16_le(segment_index)]
capacity: 46 entries
```

Три сегмента покрывают 138 entries в сутки против целевых 96 без realloc-инструкции и промежуточного состояния «ledger создан, но не доращён». Если аккаунты хранятся навсегда, rent-exempt капитал растёт примерно на 77.49 SOL в год. Перед mainnet измерение повторяется на актуальном validator runtime как вход в program audit и budget review; само измерение release gate 4 не закрывает.

### 8.3. Модель хранения ledger — решение владельца

| Вариант | Rent/год | Верификация |
|---|---:|---|
| A. Полные entries навсегда | +~77.5 SOL rent-exempt капитала/год | чтение segment PDA, указанного в сертификате |
| B. Только rolling `entries_hash` | ~0.6 SOL | entry из транзакции, PDA подтверждает целостность |
| C. Hot window 90 дней + закрытие после | ~19.1 SOL steady-state для hot segments + ~0.6 SOL/год для digest | последние 90 дней — segment PDA, старше — digest + архив |

Для pilot реализуется **A** (простейшая, соответствует §8.3 спецификации буквально). Переход на C не меняет формат entries и возможен в Gate E. Решение — за владельцем до go-live.

`OL-DEC-04`

### 8.4. `publish_anchor` — инварианты

Порядок проверок: не приостановлен → роль принадлежит этому реестру и этому signer → роль активна по времени и не отозвана → есть право публикации → `batch_sequence == current + 1` → `registry_version` не назад → `cursor_start <= cursor_end` → `previous_anchor_hash == config.last_anchor_hash` → schema/hash/tree algorithm совпадают с config → segment принадлежит реестру, день и `segment_index` верны, segment не sealed, есть место.

Затем: entry записывается с `operator` и `published_at` от программы; `anchor_hash` считается по §2.2; обновляются `last_anchor_hash`, `current_batch_sequence`, `current_registry_version`; эмитится событие `AnchorPublished`.

Бюджет: < 30 000 CU, замер в тесте, регресс > 10% ломает CI.

**Не проверяется программой:** непрерывность source cursor (§2.4), корректность кадастровых данных, наличие workflow-события.

---

## 9. Gate D — независимый Monitor

Запускается только после стабильного детерминированного pipeline (выход Gate C).

| ID | Задача |
|---|---|
| `OL-D-01` | Независимое чтение источника — отдельная read-only реплика, отдельные credentials, отдельный процесс |
| `OL-D-02` | Независимое чтение workflow-потока |
| `OL-D-03` | Загрузка манифестов и anchors напрямую с Solana |
| `OL-D-04` | Повторный расчёт canonical records и leaf на TS-реализации, сравнение с anchored root |
| `OL-D-05` | Детект: изменение без workflow-события; workflow-событие без изменения; разрыв `source_cursor` между манифестами (§2.4) |
| `OL-D-06` | Merkle diff для локализации расходящейся записи |
| `OL-D-07` | Один incident flow: evidence bundle → `open_incident` on-chain → карантин batch → остановка публикаций |
| `OL-D-08` | Focused tampering exercise: прямой `UPDATE` в источнике → измеренное время детекта |

**Требование к владению:** код Monitor не ревьюится разработчиками pipeline; учётные записи Monitor недоступны администратору основного контура. Это требование модели угроз (§2.3 спецификации), а не организационное пожелание.

**Выход Gate D:** SLO `Out-of-process detection p95 < 15 минут` измерен на synthetic-нагрузке.

---

## 10. Gate E0 — Recovery Lab (Docker)

Подэтап между Gate D и Gate E. Цель — проверить **программную корректность** recovery-протокола до того, как разворачиваются реальные custodian environments, ведутся переговоры с организациями-хранителями и проводится настоящая threshold-церемония. Ошибка в схеме шифрования или в процедуре восстановления должна обнаружиться здесь, а не на первом реальном restore drill.

### 10.1. Топология

```text
docker compose (recovery-lab)
├── source-db              PostgreSQL, synthetic-данные
├── snapshot-coordinator   создаёт и шифрует snapshot
├── custodian-a │
├── custodian-b │          MinIO, у каждого свой volume и свой credential
├── custodian-c │
├── key-holder-1..5        только тестовые threshold shares
└── clean-room-restore     отдельный PostgreSQL, без доступа к source-db
```

SoftHSM подключается **только** если нужно проверить интерфейс доступа к ключу. Общая HSM-абстракция в основном коде не создаётся — она появляется в Gate E вместе с реальным устройством.

### 10.1.1. Предусловие: `spec/snapshot-package-v1.md`

Acceptance criteria требуют AES-256-GCM, уникального DEK, AAD и ciphertext hash — но без байтового формата пакета проверять нечего. До начала Gate E0 пишется один versioned формат (не универсальный backup-фреймворк):

```text
SnapshotPackageV1
├── format_version               // u16, значение 1
├── registry_id                  // NFC UTF-8, byte_len <= 65535
├── snapshot_id                  // UUID, ровно 16 байт
├── snapshot_version             // u64
├── encryption_algorithm        // "AES-256-GCM"
├── chunk_size                  // u32, фиксирован для пакета
├── total_chunks                // u32
├── chunks[]
│   ├── chunk_index             // u32, строго 0..total_chunks-1
│   ├── nonce                   // 12 байт, уникален в пределах DEK
│   ├── ciphertext
│   └── auth_tag                // 16 байт
├── key_wrap_algorithm          // "AES-256-GCM"
├── wrapped_dek                 // ciphertext, ровно 32 байта
├── wrapped_dek_nonce           // 12 байт
├── wrapped_dek_auth_tag        // 16 байт
├── key_encryption_version      // NFC UTF-8, byte_len <= 65535
├── plaintext_hash              // SHA-256 всего plaintext
└── ciphertext_hash             // SHA-256 canonical CBOR пакета без этого поля

registry_id_bytes = UTF-8(NFC(registry_id))
key_version_bytes = UTF-8(NFC(key_encryption_version))

AAD каждого chunk =
    "ONELAYER:SNAPSHOT:CHUNK:V1"
 || u16_be(byte_len(registry_id_bytes)) || registry_id_bytes
 || snapshot_id || u64_be(snapshot_version)
 || u32_be(chunk_size) || u32_be(chunk_index) || u32_be(total_chunks)
 || plaintext_hash

AAD для wrapped_dek =
    "ONELAYER:SNAPSHOT:DEKWRAP:V1"
 || u16_be(byte_len(registry_id_bytes)) || registry_id_bytes
 || snapshot_id || u64_be(snapshot_version)
 || u16_be(byte_len(key_version_bytes)) || key_version_bytes
```

Правила:
- пакет кодируется deterministic CBOR по тому же RFC 8949 profile, что и остальные нормативные документы; map keys, числовые диапазоны и кратчайшее кодирование integer, byte strings и порядок `chunks` фиксируются в `spec/snapshot-package-v1.md`;
- `ciphertext_hash` считается от canonical CBOR всего пакета без поля `ciphertext_hash`; это единственный формат, который записывается custodian-ам и хэшируется после чтения;
- chunking обязателен: одно монолитное GCM-сообщение непригодно для ретраев и локализации повреждения; `plaintext_hash` считается до шифрования и затем входит в AAD каждого chunk;
- `chunk_size > 0`, `total_chunks > 0`; массив содержит каждый `chunk_index` ровно один раз в порядке `0..total_chunks-1`, все chunks кроме последнего имеют plaintext-длину `chunk_size`;
- пара `(DEK, nonce)` уникальна глобально; nonce выводится как `u32_be(chunk_index)` в 12-байтовом поле с нулевым префиксом, поскольку DEK уникален на snapshot — счётчик не может повториться;
- `chunk_index` и `total_chunks` входят в AAD: это защищает от перестановки, усечения и подмены chunk-ов между пакетами;
- `wrapped_dek_nonce` генерируется CSPRNG для каждого snapshot; повтор пары `(KEK, wrapped_dek_nonce)` запрещён;
- ошибка проверки auth tag завершает restore **fail-closed**: частично расшифрованные данные не используются и не сохраняются;
- `plaintext_hash` проверяется после сборки всех chunk-ов, независимо от успешных тегов.

### 10.1.2. Что именно делится threshold-схемой

Иерархия ключей фиксируется явно, иначе неясно, к чему относятся 3-of-5:

```text
DEK   — уникален на snapshot, шифрует chunk-и
KEK   — шифрует DEK (wrapped_dek)
3-of-5 shares — восстанавливают KEK (recovery wrapping key)
```

Shamir-разделение применяется **только к KEK**. Отдельно делить каждый DEK не нужно: это множит церемонии пропорционально числу снимков и усложняет lifecycle без выигрыша — компрометация KEK и так раскрывает все DEK, а разделение DEK не защищает от неё.

**Lifecycle в Gate E0:** test KEK генерируется один раз при инициализации lab, разделяется на пять shares и передаётся coordinator-у отдельным Compose secret только на фазу создания snapshot. Coordinator не получает ни одного share. После записи и перепроверки трёх replicas coordinator и его secret удаляются; recovery начинается только после этого. `clean-room-restore` получает выбранные shares через одноразовые файлы в `tmpfs`, восстанавливает KEK при 3-of-5, unwrap-ит DEK и уничтожается после drill. В Gate E место live KEK занимает подтверждённый `OL-A-07` KMS/HSM; threshold shares остаются recovery-копией этого KEK, а не механизмом на каждый штатный snapshot.

### 10.2. Изоляция внутри lab

- отдельные Docker networks для storage, key holders и restore;
- отдельный volume и отдельный credential у каждого custodian; общего bucket-credential нет;
- custodian не имеет доступа к KEK и shares;
- key holder не имеет доступа к backup storage;
- restore-контейнер не имеет доступа к `source-db`;
- coordinator не имеет доступа ни к одному share; KEK присутствует у него только во время создания snapshot;
- clean-room получает shares только после удаления coordinator и потери primary fixture;
- production credentials отсутствуют полностью; только synthetic-данные и test keys.

**Ключевой материал не передаётся через environment.** `environment:` и `.env` видны в `docker inspect` и регулярно попадают в диагностические выгрузки. Для shares, KEK и DEK используются: Compose secrets или одноразовые read-only файлы в `tmpfs`, доступные только на время реконструкции; после drill контейнер и ephemeral volume уничтожаются.

Формулировка о стирании ключей — честная: **key material не записывается в persistent volume; временные secret-файлы лежат в tmpfs; процесс best-effort зануляет доступные буферы; после drill контейнер и ephemeral volume уничтожаются.** Обещать надёжный secure erase поверх Docker overlayfs и SSD с wear leveling нельзя, и план этого не утверждает.

### 10.3. Acceptance criteria

| # | Сценарий | Критерий |
|---|---|---|
| 1 | Создание snapshot | plaintext hash посчитан; deterministic CBOR; AES-256-GCM; уникальный DEK на snapshot; chunk AAD однозначно содержит registry ID, snapshot ID, version, chunk size, indexes и plaintext hash; DEK wrapping имеет отдельный domain и auth tag |
| 2 | Размещение | ciphertext записан в три MinIO с разными credentials и volume; ciphertext hash перепроверен **после** записи у каждого |
| 3 | Threshold | после удаления coordinator: `2-of-5` — восстановление KEK **отказывает**; `3-of-5` — успешно; coordinator не видел shares; shares не появляются в логах, артефактах и `docker inspect`; после drill ephemeral volume и контейнеры уничтожены |
| 4 | Отказ custodian | один MinIO остановлен или его volume удалён → восстановление из оставшихся успешно |
| 5 | Повреждение replica | изменён один байт → ciphertext hash не совпал → replica исключена, попытки расшифровать её как корректную нет |
| 6 | Потеря primary | контейнер `source-db` удалён вместе с volume; clean-room поднимается с нуля; восстановление идёт только по документированной процедуре |
| 7 | Криптографическая сверка | после restore пересчитаны canonical records, field roots и batch merkle root; сравнение с сохранённым Solana anchor; расхождение хотя бы одной записи = drill неуспешен |
| 8 | Гигиена артефактов | автоматическая проверка: в образах нет shares; `.env` с ключами не в репозитории; в логах нет DEK, KEK, shares и plaintext backup; в отчётах нет ключевого материала |

Пункт 7 — главный: он проверяет, что восстановленная база даёт тот же корень, что был заякорен, то есть что recovery действительно восстанавливает **доказуемое** состояние, а не просто рабочую БД.

### 10.4. Границы применимости — что lab не доказывает

Несколько контейнеров на одной машине — это не несколько дата-центров. У них общий host, ядро, физический диск, Docker daemon и один администратор, то есть одна точка компрометации.

| Проверяется | Не проверяется |
|---|---|
| Корректность snapshot, шифрования и AAD | Географическая независимость |
| Работа threshold-логики | Разные административные организации |
| Обнаружение повреждения | Защита от компрометации host |
| Воспроизводимость restore | Реальный Object Lock провайдера |
| Совпадение root после restore | Production HSM ceremony |
| Переносимость потери одной replica | Cross-border compliance |
| Полнота документированной процедуры | Устойчивость реального дата-центра |

**Успешный Gate E0 — предварительное условие Gate E, но release gate 7 он не закрывает.** Gate 7 закрывается только restore drill на реальной инфраструктуре, где роли отображены на настоящие границы: три custodian в разных identity domains без общего root/admin, реальные KMS/HSM, включённый Object Lock, независимые credentials и раздельные audit logs, key holders — разные люди с hardware-идентичностями, и формальная threshold-церемония.

### 10.5. Guards для разрушительных скриптов

`destroy-primary` и `corrupt-replica` удаляют данные. Они допустимы только потому, что работают на изолированной fixture, — и это должно проверяться самим скриптом, а не дисциплиной запускающего. Обязательные предохранители, без которых скрипт не выполняется:

- фиксированное имя Compose-проекта `onelayer-recovery-lab`; всё вне него игнорируется;
- проверка label `com.onelayer.fixture=true` на каждом контейнере и volume перед удалением;
- проверка synthetic-маркера внутри самой БД (таблица-маркер с известным значением);
- отказ при обнаружении production-подобного hostname или credential;
- удаление **только** явно поименованных volume; `docker system prune` и широкий `docker volume prune` запрещены;
- confirmation token в окружении запуска: `DESTROY_ONELAYER_FIXTURE=yes`;
- вывод только имён тестовых ресурсов, без credentials.

Проверки выполняются последовательно, любая непрошедшая — немедленный выход с ненулевым кодом. Это требование безопасности, а не дополнительный hardening: скрипт с `docker volume rm` в репозитории проекта будет запущен на машине разработчика с другими проектами.

### 10.6. Артефакты

Каталог `deploy/recovery-lab/` уже существует как prototype. Его наличие не означает прохождение Gate E0: при наступлении gate-а он обязан удовлетворить контрактам §10.1–10.5 и пройти полный acceptance drill.

```text
deploy/recovery-lab/
├── compose.yaml
├── networks/
├── minio/
├── key-holders/
├── scripts/
│   ├── create-snapshot
│   ├── corrupt-replica
│   ├── destroy-primary
│   ├── restore-clean-room
│   └── reconcile-anchor
└── README.md
```

Gate E0 выполняется на synthetic-данных и потому **не требует** законченного legal approval — в отличие от shadow pilot (§11).

---

## 11. Gate E — production hardening

Всё, что требует подтверждённой целевой среды и юридических решений.

| Блок | Состав |
|---|---|
| Ключи | HSM-интеграция (operator, issuer), durable nonce, разделение fee payer / operator, мультисиг + timelock на governance и upgrade authority, key ceremony, ротация с перекрытием (UC-15) |
| Надёжность | Два независимых RPC + правило разрешения расхождений, три независимых хранилища манифестов, backlog coalescing (§2.7 п.6) |
| Recovery | Snapshot Coordinator, custodian replicas с Object Lock, threshold 3-of-5, Recovery Toolkit (воспроизводимая офлайн-сборка), **обязательный restore drill** (release gate 7) |
| Доступ | Реальный IdP/SSO, production RBAC, CSRF/session policy, least privilege и аудит административных действий |
| Аудит | Внешний аудит программы (gate 4); penetration test (gate 5) охватывает backend, Admin/OneLayer web, API/proxy, wallet intent/signing flow; security exercises §15.3 спецификации |
| Развёртывание | Топология по результатам `OL-A-07`, изоляция Publisher, DMZ для verifier, наблюдаемость и алерты по §14.1 спецификации |
| Протокол | `transition_algorithm`, `rotate_governance` |
| Pilot | 60-дневный shadow pilot на боевых данных без юридических последствий (gate 6), FP rate < 0.1% |
| Юридическое | Статус сертификата, incident authority, порядок correction, DPIA-заключение (gate 1) |

### 11.1. Обязательный порядок

После Gate D идут **две независимые ветки** — Gate E0 не ждёт юристов, реальные данные не ждут ничего другого:

```text
Gate D
├── Gate E0: Docker Recovery Lab      (synthetic-данные, test keys — legal approval не требуется)
└── DPIA / legal approval             (gate 1)

Gate E0 PASSED  +  legal approval
  → production-like recovery infrastructure
    → security baseline: code/config freeze → program audit → backend pentest
      → закрытие critical/high findings
        → реальный restore drill              (gate 7)
          → shadow pilot на разрешённых данных (gate 6)
            → targeted re-review изменений, сделанных по итогам pilot
              → go-live decision              (gate 9)
```

**Почему аудит и pentest стоят до shadow pilot.** Shadow pilot работает на боевых данных реестра. Загружать их в непроверенную production-like систему — значит создавать trust boundary раньше, чем она проверена. Поэтому до pilot закрываются critical/high находки на замороженном коде; полное финальное закрытие gates 4 и 5 может произойти после pilot, но baseline — до него.

**Почему DPIA стоит до боевых данных.** Без закрытого DPIA shadow pilot — это обработка персональных данных без основания.

Gate E0 — единственный блок, выполнимый до завершения legal approval, и только потому, что он целиком на synthetic-данных и test keys.

**Минимум для go-live** по recovery: одна рабочая схема snapshot + threshold + один успешный полный restore drill на реальной инфраструктуре. Масштабирование числа custodians, географическое распределение и регулярные квартальные учения — **после** go-live, отдельный горизонт (Phase 3 спецификации), в этот план не входят.

**Выход Gate E:** решение go-live (gate 9).

---

## 12. Открытые решения владельца

Не реализуются, пока не станут явным acceptance criterion.

| ID | Решение | Стоимость реализации | Когда нужно |
|---|---|---|---|
| `OL-DEC-01` | Автономное обнаружение инцидентов без backend (§2.3) | перебор PDA — низкая; on-chain индекс — высокая | до Gate C, если автономность обязательна |
| `OL-DEC-02` | `last_source_cursor_end` on-chain (§2.4) | низкая, но жёсткая связка с семантикой курсора | после Gate A |
| `OL-DEC-03` | Sentinel-контракт для пустых интервалов (§2.5) | средняя | если требует внешний аудит |
| `OL-DEC-04` | Модель хранения ledger A/B/C (§8.3) | C — средняя | до go-live |
| `OL-DEC-06` | Immutable program vs governed upgrades после аудита | — | Gate E |
| `OL-DEC-07` | Audit hash-chain и её якорение в batch (§2.6) | низкая, контракт определён заранее | при требовании доказывать целостность журнала внешней стороне |
| `OL-DEC-08` | `maxRpcHeadDifference` для incident index (§2.3); `maxIndexLagSlots = 300` уже зафиксирован как Gate C default | — | Gate E, вместе со вторым RPC |

---

## 13. Риски

| # | Риск | Влияние | Митигация |
|---|---|---|---|
| R1 | Workflow-события не подписываются персонально | критическое | `OL-A-01` в первую неделю; при подтверждении — `redesign` на выходе Gate A |
| R2 | HSM без Ed25519 | высокое | `OL-A-03`; запасной вариант — внешний signing appliance, меняет §13.2 спецификации |
| R3 | Расхождение двух реализаций найдено поздно | высокое | общие векторы с Gate B, differential corpus в каждом PR |
| R4 | Rent-нагрузка ledger не согласована с бюджетом | среднее | `OL-A-04` зафиксировал C′ и реальную стоимость allocation; `OL-DEC-04` выбирает retention до go-live по измеренному rent-exempt капиталу (§8.2–8.3) |
| R5 | Физическое вмешательство в файлы primary DB в обход WAL | критическое | **Не устраняется сканированием реплики.** Реплика может не получить такое изменение и показать старое внутренне согласованное состояние. Periodic replica scan обнаруживает пропущенные и повреждённые CDC-события, но не гарантирует обнаружение произвольного физического вмешательства в primary. Для этого требуется независимый канал к primary, независимо созданный snapshot primary или storage-level attestation — вводится только при подтверждении такой модели угроз в `OL-A-06` |
| R6 | Ложноположительные инциденты парализуют операции | среднее | 60-дневный shadow pilot с разбором каждого случая |
| R7 | Компрометация upgrade authority | критическое | Gate E: multisig + timelock; после аудита — рассмотреть `authority = None` (`OL-DEC-06`) |
| R8 | Деградация или цензура RPC | среднее | Gate E: два независимых провайдера; durable queue сохраняет backlog |
| R9 | Регулятор признаёт linkability по хэшам недостаточной | высокое | `OL-A-08` в Gate A; per-field соли из секретного ключа уже заложены (§2.1) |
| R10 | Смена схемы после production | высокое | `transition_algorithm` в Gate E; репетиция перехода — обязательное условие Phase 3 |
| R11 | Преждевременная декомпозиция замедляет pilot | среднее | §5.3: один процесс до подтверждённой границы развёртывания |
| R12 | UI показывает «успех» после signature, но до finalization, или повторно публикует batch | высокое | §5.4: явная transaction state machine, simulation-before-signing, idempotency key, account/transaction checks и `ISSUED` только после `finalized` |
| R13 | Демо-логин `OL-C-31` воспринимается как готовый контроль доступа | среднее | §5.4: роли ограничивают Admin API, но не заменяют SSO/RBAC; MVP работает только на loopback и synthetic-данных, реальный access control — Gate E |
| R14 | Импорт произвольного JSON/CSV принимается за подтверждённые данные реестра | высокое | Система доказывает неизменность того, что ей дали, а не истинность содержимого. Импорт помечает записи `origin='ADMIN_UI'`, synthetic marker проверяется до операций, схема `land-registry-v1` отклоняет поля вне перечня. В презентации и в UI это названо прямо: якорь фиксирует состояние на момент публикации, источник данных остаётся ответственностью реестра (§2.4) |
| R15 | Расхождение набора полей между batch builder, reconcile и fixture даёт ложный `DISPUTED` | среднее | Один модуль схемы на все три пути (`OL-C-36`), тест на совпадение `merkleRoot` builder-а и reconcile на записи с несколькими полями |

---

## 14. Первая неделя

1. `OL-A-01` — signed workflow events: есть или нет. Критический путь всего проекта.
2. `OL-A-02` — CDC и семантика курсора.
3. `OL-A-03` — Ed25519 HSM spike.
4. `OL-A-05` — закрыть disclosure design по §2.1: случайный `record_field_key` на версию записи, соли только раскрытых полей в сертификате, разведённые термины commitment/leaf_hash.
5. `OL-A-04` — **закрыто**: принят segmented ledger C′, capacity 46; результат уже учтён в §8.2 и Gate B.
6. Минимальный CI и только те каталоги, что нужны этим spike-ам: `spec/`, `onchain/`, `crates/canonical/`.

Skeleton M1–M12 в первую неделю не создаётся.

---

## 15. Соответствие release gates спецификации

| Gate (§16.3 спецификации) | Где закрывается |
|---|---|
| 1. Legal/privacy approval | Gate A (запуск) → Gate E (заключение) |
| 2. Schema and canonicalization freeze | Gate B |
| 3. Threat model sign-off | Gate A (v1 по подтверждённым границам) → после Gate D (targeted update: Monitor, его trust boundary) → Gate E (подтверждение отсутствия незакрытых критических изменений) |
| 4. Program audit | Gate E |
| 5. Backend penetration test | Gate E |
| 6. 60-day shadow pilot | Gate E |
| 7. Restore drill | Gate E (Gate E0 — предварительное условие, gate **не** закрывает: контейнеры на одном host не являются независимыми дата-центрами) |
| 8. Governance/key ceremony approval | Gate E |
| 9. Mainnet go-live decision | выход Gate E |
