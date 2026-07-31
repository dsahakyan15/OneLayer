# OneLayer — план имплементации

**Базовый документ:** `OneLayer_Solana_Technical_Spec_RU.md` (v0.9)
**Статус плана:** v2.2, 2026-07-31 · история версий — `CHANGELOG_IMPLEMENTATION_PLAN.md`
**Структура:** gate-ы A, B, C, D, E0, E — каждый с явным выходным решением
**Горизонт:** Gate A–C (pilot на devnet) ≈ 5–7 месяцев; Gate D–E (production go-live) ≈ +10–12 месяцев; Phase 3 — отдельный горизонт после go-live

> План покрывает инженерную реализацию. Юридические решения (§17 спецификации) — отдельный трек, блокирующий Gate E.

---

## 0. Рабочие ограничения

**Proportional Engineering.** Минимальный поддерживаемый scope. Только доказательно необходимые проверки и security controls. Без спекулятивного hardening. Инфраструктура и абстракции добавляются после подтверждения потребности, а не заранее.

**Следствия для этого плана:**
- количество тестов не является acceptance criterion; критерий — покрытые инварианты;
- сервис выделяется в отдельный процесс только при подтверждённой границе развёртывания или владения;
- транспорт, оркестрация, storage-абстракции добавляются, когда появляется второй потребитель;
- всё, что не нужно для проверки следующей гипотезы, откладывается до gate-а, где оно нужно.

**Явно вне scope до Gate E:** Kubernetes/Helm/Terraform/OPA, SIEM, мультисиг и timelock, threshold-церемонии, три независимых storage, два RPC-провайдера, banking SDK, algorithm transition, массовая выдача сертификатов.

**HSM.** До Gate E не выполняется продуктовая HSM-интеграция: в основном коде нет HSM-абстракции, pipeline подписывает software-ключом. В Gate A разрешён изолированный feasibility spike (`OL-A-03`) — вне основного кода, без production credentials, результат spike-а в продукт не переносится.

---

## 1. История ревизий

Текущая версия — **v2.2**. Изменения относительно v2.1:

- байтовые длины в `field_commitment` и `audit_preimage`: `byte_len` после UTF-8/CBOR-кодирования (§2.1);
- `finalizedHeadSlot` верификатор запрашивает у RPC сам; при двух RPC берётся **больший** head, при большом расхождении — `RPC_DISAGREEMENT` (§2.3);
- добавлен Gate E0 — Docker Recovery Lab: `spec/snapshot-package-v1.md`, иерархия DEK/KEK/shares, обращение с ключевым материалом, guards для разрушительных скриптов (§10);
- Gate E0 и DPIA — параллельные ветки; security baseline (audit + pentest) до shadow pilot с боевыми данными (§11.1);
- `publish_attempt`: сырые ответы RPC не хранятся (§6.2).

Полная история v1.0 → v2.2 с обоснованиями — `CHANGELOG_IMPLEMENTATION_PLAN.md`.

---

## 2. P0-решения: криптографический протокол

Всё в этом разделе фиксируется **до** написания golden vectors и является предметом Gate B.

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
                              u64_be(record_version) || field_root)

  batch_leaf_hash    = SHA256(0x00 || record_commitment)                // RFC 6962 leaf
  batch_node_hash    = SHA256(0x01 || left || right)

  merkle_root = корень RFC6962-дерева по batch_leaf_hash,
                листья отсортированы по (record_id_commitment, record_version)
```

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
| `SELECTIVE_FIELDS` | значения раскрываемых полей, `field_salt` **только этих** путей, field-proof каждого, `field_root`, batch-proof |
| `FULL_RECORD` | все значения и все `field_salt`, batch-proof (`field_root` пересчитывается) |

`record_field_key` не попадает в сертификат и не отдаётся ни одним API **никогда**. Раскрытие одной соли не даёт вычислить другие: HMAC с секретным ключом невосстановим по своим выходам.

**Хранение:**

```sql
-- в canonical_record_version, вместо nonce_encrypted из §7.1 спецификации
record_field_key_encrypted BYTEA NOT NULL,
key_encryption_version     TEXT  NOT NULL   -- версия KEK/KMS-ключа, не ключа записи
```

Одно поле, один механизм. В production — envelope encryption через KMS; в pilot — software KEK, не коммитится и не пишется в логи. Ротация касается только KEK: перешифровать `record_field_key_encrypted` можно массово, не трогая ни сертификаты, ни якоря. Вечное хранение старых версий master-ключа больше не требуется — этого требования у v2.1 нет.

**Оговорка.** Множество путей полей само по себе утечка структуры: при `SELECTIVE_FIELDS` число листьев field-дерева видно из proof-а. Скрытие требует дополнения дерева до фиксированной степени двойки. Решение владельца (`OL-DEC-05`), по умолчанию **не** реализуется.

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
- верификатор использует off-chain **incident index** (`GET /v1/incidents?batchSequence=`), построенный из on-chain событий `IncidentOpened`;
- пустой ответ индекса сам по себе не является доказательством отсутствия инцидентов: индекс мог потерять событие, отстать от finalized head или остановиться на старом слоте. Поэтому индекс обязан публиковать **watermark полноты**.

**Индекс сообщает только `indexedThroughSlot`. Голову цепочки верификатор берёт сам.** Если бы индекс отдавал и то, и другое, зависший или скомпрометированный индекс объявлял бы устаревшую цепочку актуальной — самозаверение полноты.

```text
indexedThroughSlot   ← от incident index
rpcFinalizedHeadSlot ← verifier.getSlot(commitment = "finalized"), собственный запрос
indexLagSlots        = rpcFinalizedHeadSlot − indexedThroughSlot
```

Ответ индекса:

```json
{ "indexedThroughSlot": 412345999, "incidents": [] }
```

Ответ верификатора:

```json
{
  "incidentIndexStatus": "CHECKED",
  "indexedThroughSlot": 412345999,
  "rpcFinalizedHeadSlot": 412346040,
  "indexLagSlots": 41,
  "checkedAt": "2026-07-31T00:00:00Z"
}
```

Правило статуса:

| Статус | Условие | Влияние на итог |
|---|---|---|
| `CHECKED` | `0 <= indexLagSlots <= maxIndexLagSlots` **и** `indexedThroughSlot >= anchor_slot` | итог может быть `VERIFIED` |
| `STALE` | индекс доступен, но `indexLagSlots > maxIndexLagSlots` | понижение до `VERIFIED_NO_INCIDENT_CHECK` |
| `UNAVAILABLE` | индекс недоступен или ответ без `indexedThroughSlot` | понижение до `VERIFIED_NO_INCIDENT_CHECK` |
| `INDEX_INCONSISTENT` | `indexedThroughSlot > rpcFinalizedHeadSlot` — индекс утверждает, что обогнал finalized-голову | понижение до `VERIFIED_NO_INCIDENT_CHECK`, событие в лог как аномалия |
| `RPC_DISAGREEMENT` | два RPC разошлись по высоте finalized-головы сильнее `maxRpcHeadDifference` (только при двух источниках, Gate E) | понижение до `VERIFIED_NO_INCIDENT_CHECK` |

`maxIndexLagSlots` — конфигурируемый параметр верификатора, по умолчанию 300 слотов (≈2 минуты). Ответ без watermark трактуется как `UNAVAILABLE`, а не как `CHECKED`.

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

**Что именно проверяется — оба состояния:**
1. был ли открыт инцидент, покрывающий диапазон batch, на момент anchor;
2. открыт ли такой инцидент **сейчас**.

Второе — основной пользовательский вопрос: инцидент может быть открыт спустя месяцы после публикации якоря. Поэтому индекс должен быть близок к текущему finalized head, а не только к слоту anchor, и `indexedThroughSlot >= anchor_slot` — необходимое, но недостаточное условие для `CHECKED`.

**Открытое решение владельца.** Полностью автономная проверка (без backend) требует одного из:
- перебора всех PDA `0..incident_count` через `getMultipleAccounts` — работает при десятках инцидентов, деградирует при тысячах, и это лишь смягчение, а не полноценный индекс;
- отдельной on-chain структуры «batch range → incident» — существенное расширение формата.

Ни то, ни другое не реализуется, пока автономное обнаружение инцидентов не станет явным acceptance criterion. Пункт вносится в §10 как решение владельца.

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
| 5 | `governance_authority` и `emergency_authority` — адреса мультисига; проверка **не** on-chain, а процедурная (ceremony gate) |
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
| `OL-A-04` | Large PDA allocation spike: создание аккаунта 20 840 байт через `init` и через `init` + `realloc` на локальном валидаторе | ADR: схема ledger A / B / C (§5.2) |
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
| `spec/leaf-v1.md` | §2.1 полностью: `record_field_key`, `field_salt`, `field_commitment`, `field_tree_leaf_hash`, `field_root`, `record_commitment`, `batch_leaf_hash`, `record_id_commitment` |
| `spec/merkle-tree-v1.md` | RFC 6962: `leaf_hash=SHA256(0x00\|\|commitment)`, `node=SHA256(0x01\|\|left\|\|right)`, непарный узел поднимается без хэширования (дублирование запрещено), порядок листьев для обоих деревьев |
| `spec/onchain-state-v1.md` | **Заморозка on-chain ABI и state:** все PDA seeds; поля и порядок в `RegistryConfig`, `OperatorRole`, `DailyAnchorLedger`, `IncidentNotice`, `AnchorEntryV1`; endianness и фиксированные размеры; `AnchorEntryInputV1` (instruction data, Borsh); поля, заполняемые программой (`operator`, `published_at`, `incident_sequence`); события и их поля; правило версионирования аккаунтов; семантика `incident_count`; семантика `capacity` и её неизменности; genesis-значения |
| `spec/batch-manifest-v1.md` | Байтовая сериализация для подписи, `manifestHash` от манифеста без подписи, Ed25519 |
| `spec/anchor-chain-v1.md` | §2.2 `anchor_preimage`, genesis, §2.4 границы гарантий |
| `spec/certificate-package-v1.md` | CBOR-кодирование, что подписывает issuer, состав по режимам раскрытия (§2.1: `fieldSalts` только раскрытых путей, поле `nonce` спецификации удалено), формат QR |
| `spec/error-codes.md` | Коды §9.5 спецификации + on-chain коды + добавленные статусы верификатора (`VERIFIED_NO_INCIDENT_CHECK`, `incidentIndexStatus` со значениями `CHECKED/STALE/UNAVAILABLE/INDEX_INCONSISTENT/RPC_DISAGREEMENT`), единый источник для обеих реализаций |

### 4.2. Golden vectors — около 50–70 суммарно

| Набор | Количество | Что покрывает |
|---|---:|---|
| canonical | 20–30 | по одному на класс: Unicode NFC (кириллица/армянский с комбинирующими), surrogate pair, RTL-маркер, `0.10` vs `0.1`, отрицательный decimal, `-0`, отсутствующий ключ vs `null`, пустой массив, порядок массива, високосная секунда, граничная дата, поле вне схемы (отклонение) |
| leaf / field tree | 8–12 | одно поле, все поля, selective с одним раскрытым, selective с несколькими, вложенное поле, отсутствующее поле. Каждый вектор содержит **раздельно** `field_commitment`, `field_tree_leaf_hash`, `field_root`, `record_commitment`, `batch_leaf_hash` — двойное хэширование фиксируется явно |
| merkle | 10–15 | 1, 2, 3, 4, 5, 7, 8 листьев (непарные узлы на разных уровнях), proof для первого/последнего/среднего |
| manifest / anchor | 5–8 | `anchor_preimage`, genesis, snapshot_hash = нули и не-нули |
| certificate | 5 | FULL_RECORD, SELECTIVE_FIELDS, повреждённая подпись, неподдерживаемая схема |

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

`spec/onchain-state-v1.md` пишется после `OL-A-04` — схема ledger (A/B/C) должна быть известна до заморозки layout-а. Если Gate A даёт вариант B (доращивание аккаунта), Gate B удлиняется на неделю: добавляется инструкция роста и её место в ABI.

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
| `OL-C-02` | On-chain: `create_daily_ledger` по схеме из `OL-A-04` |
| `OL-C-03` | On-chain: `publish_anchor` (§5.4), `anchor_hash` по §2.2, события |
| `OL-C-04` | On-chain: `seal_daily_ledger`, `entries_hash` |
| `OL-C-05` | On-chain: `pause_registry` / `resume_registry` |
| `OL-C-06` | On-chain: `open_incident` / `resolve_incident`, счётчик `incident_count` |
| `OL-C-10` | `crates/canonical` + `crates/merkle`: реализация по Gate B |
| `OL-C-11` | `apps/pilot-pipeline`: чтение synthetic-источника, сопоставление с workflow-событием, canonical version, batch, манифест |
| `OL-C-12` | `apps/pilot-pipeline`: публикация в devnet (обычный blockhash, software-ключ), отслеживание `finalized`, durable queue в PostgreSQL |
| `OL-C-13` | `apps/pilot-pipeline`: выдача сертификата, оба режима раскрытия, QR (основной формат: URL + id + hash) |
| `OL-C-14` | `apps/verifier`: алгоритм §8.3 спецификации, один RPC, incident index с watermark и правилом статуса (§2.3), REST по §9.1 |
| `OL-C-15` | Схема БД (§6.2): durable queue + append-only `publish_attempt`, append-only audit journal без hash-chain (§2.6) |
| `OL-C-20` | E2E smoke: synthetic change → VERIFIED в верификаторе |

### 5.2. Чего в Gate C нет

HSM, durable nonce, два RPC, мультисиг, три хранилища манифестов (одно + локальная копия), Monitor, snapshots, recovery, algorithm transition, SIEM, Kubernetes, banking SDK.

Обоснование по durable nonce: он решает протухание blockhash при медленной HSM-подписи (100–2000 мс + очередь). С software-ключом подпись занимает микросекунды, 150 слотов хватает с запасом. Механизм добавляется вместе с HSM в Gate E.

### 5.3. Модель развёртывания pilot

Один процесс `pilot-pipeline` с логическими модулями-библиотеками внутри (`cdc`, `workflow`, `canonicalizer`, `batch`, `publisher`, `issuer`). Отдельный процесс `verifier` — потому что у него другая граница доверия (единственный компонент с входящим публичным трафиком), а не потому что «микросервисы».

Разделение на отдельные сервисы происходит при появлении подтверждённой границы: Publisher выносится, когда появляется HSM в изолированной подсети (Gate E); Monitor изначально отдельный процесс с отдельными credentials (Gate D) — это требование модели угроз, а не архитектурная эстетика.

**Выход Gate C:** сквозной поток работает 72 часа на synthetic-нагрузке без ручного вмешательства; `anchor_sequence_gap_total = 0`; повторная сборка одного диапазона даёт идентичный `manifestHash`.

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
│   └── merkle-ts/
├── apps/
│   ├── pilot-pipeline/      # Rust, один процесс, модули-библиотеки внутри
│   └── verifier/            # TS, REST
├── tests/e2e/
├── db/migrations/
└── docs/adr/
```

Появляется позже, по факту потребности: `apps/monitor` (Gate D), `crates/hsm` + вынесенный publisher (Gate E), `tools/recovery` (Gate E), `deploy/` (Gate E, после `OL-A-07`).

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
  anchor_hash     BYTEA  NOT NULL,          -- §2.2, для сверки с on-chain
  snapshot_hash   BYTEA,
  status          TEXT   NOT NULL CHECK (status IN
                    ('PREPARED','SIGNED','SUBMITTED','FINALIZED','DISPUTED','FAILED')),
  solana_signature TEXT,
  solana_slot     BIGINT,
  prepared_at     TIMESTAMPTZ NOT NULL,
  finalized_at    TIMESTAMPTZ,
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

-- история попыток: append-only, ничего не перезаписывается
CREATE TABLE publish_attempt (
  registry_id     TEXT   NOT NULL,
  batch_sequence  BIGINT NOT NULL,
  attempt_no      INT    NOT NULL,
  transaction_b64 TEXT   NOT NULL,          -- построенная транзакция
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

**Почему `publish_attempt` append-only.** Каждая попытка — это подписанная транзакция, отправленная в сеть. Исход части попыток принципиально неопределён (`UNKNOWN`): RPC не ответил, но транзакция могла быть принята. В этом состоянии Publisher обязан **опрашивать статус по известной signature**, а не пересобирать транзакцию, — значит все предыдущие signature должны сохраняться. Перезапись строки уничтожила бы и эту возможность, и provenance-доказательство того, что именно публиковалось.

`audit_chain_head` в Gate C не создаётся — появляется вместе с включением hash-chain (`OL-DEC-07`).

Партиционирование `registry_change_event` и `canonical_record_version` добавляется при подтверждённых объёмах из `OL-A-02`, не заранее.

### 6.3. Транспорт

| Что | Механизм |
|---|---|
| Внутри pipeline | вызовы функций в одном процессе; состояние — транзакции PostgreSQL |
| Pipeline → Publisher | `publish_queue` с claim/lease |
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
неавторизованный signer · отозванная роль · истёкшая роль · роль без `PERM_PUBLISH_ANCHOR` · роль чужого реестра · `batch_sequence` повтор/пропуск · неверный `previous_anchor_hash` · `registry_version` назад · `cursor_start > cursor_end` · sealed ledger · переполненный ledger · ledger чужого дня · ledger чужого реестра · `paused`.

`create_daily_ledger`: повторное создание · чужой реестр · неавторизованная роль.
`seal_daily_ledger`: повторный seal · чужой ledger · неавторизованная роль.
`grant_operator` / `revoke_operator`: не-governance signer · повторный grant.
`pause` / `resume`: не-emergency signer на pause · не-governance на resume.
`open_incident` / `resolve_incident`: роль без `PERM_REPORT_INCIDENT` · resolve не-governance · повторный resolve.

Плюс: property-тест стабильности zero-copy layout (размер и смещения не менялись), замер CU по `publish_anchor` с регресс-гейтом, один fuzz-прогон instruction data перед релизом.

### 7.2. Off-chain

Focused property tests: Unicode NFC, decimal, сортировка массивов, RFC 6962 proof (построение → проверка, для 1..16 листьев).

Обязательные сценарии (по одному на инвариант):
- дубликат CDC-события, событие вне порядка, пропуск курсора, рестарт посреди обработки;
- изменение без workflow-события; workflow-событие без изменения;
- повторная сборка диапазона → идентичный `manifestHash`;
- параллельная попытка опубликовать один batch дважды;
- сертификат с подменёнными: значением поля, солью, field-proof, batch-proof, `merkleRoot`, `programId`, ledger PDA;
- сертификат для batch с открытым инцидентом;
- incident index недоступен / отдаёт лаг выше `maxIndexLagSlots` / отдаёт ответ без watermark → во всех трёх случаях `VERIFIED_NO_INCIDENT_CHECK`, статусы `UNAVAILABLE`/`STALE`/`UNAVAILABLE` соответственно;
- RPC вернул `confirmed` вместо `finalized`.

**Проверка изоляции солей (§2.1)** — вместо недоказуемого «восстановить соль невозможно» тестируется конкретный контракт:
- сериализованный selective-сертификат не содержит `record_field_key` (поиск по байтам ключа в готовом пакете);
- сертификат содержит соли ровно тех путей, что раскрыты, и ни одной другой;
- ни один эндпоинт API не возвращает `record_field_key` и `record_field_key_encrypted` — проверка на сериализаторах ответов, а не на конкретных ручках;
- `field_salt(path)`, вычисленная из всех публичных входов сертификата, не совпадает с фактической солью скрытого поля;
- подмена соли раскрытого поля ломает field-proof.

### 7.3. Что не делается

Квоты «N тестов на инструкцию», 95%-покрытие как самоцель, 100 повторных сборок (достаточно 3), ежедневные прогоны на 10⁶ записей, ежедневный полный devnet E2E (достаточно одного smoke-теста в CI и полного прогона перед релизом).

---

## 8. On-chain: расчёты (сохранено из v1.0)

### 8.1. Zero-copy вместо `Vec`

`Vec<AnchorEntryV1>` на 96 записей — ~20 КБ, десериализуемых в 32-килобайтный BPF heap при каждом `publish_anchor`. Решение — `#[account(zero_copy)]` с фиксированным массивом и явным padding.

Entry: 216 байт (`repr(C)`, align 8, все padding-поля явные и обнуляемые — иначе `Pod` не выводится). Header ledger-а: 96 байт + 8 дискриминатор.

**Важно (§2.2):** этот layout — деталь хранения. Для `anchor_hash` используется `anchor_preimage`, а не байты аккаунта.

### 8.2. Размеры и rent

| capacity | entries | + header | итого | rent-exempt* | в год |
|---:|---:|---:|---:|---:|---:|
| 96 | 20 736 | 104 | 20 840 | 0.1459 SOL | 53.3 SOL (365) |
| 192 | 41 472 | 104 | 41 576 | 0.2903 SOL | 105.9 SOL (365) |
| 48 (полудневной) | 10 368 | 104 | 10 472 | 0.0738 SOL | 53.9 SOL (730) |

\* `(128 + size) × 3480 × 2` lamports.

Прирост данных аккаунта за инструкцию ограничен 10 240 байтами. Поведение `init` для аккаунта >10 КБ через CPI проверяется эмпирически (`OL-A-04`), результат определяет схему:
**A** — прямой `init`, capacity 192, запас на backlog;
**B** — `init` 10 240 + доращивание отдельной инструкцией до первого anchor;
**C** — полудневной ledger, seed `["ledger", config, day_utc, half]`, capacity 96.

При равенстве предпочтителен **C**: нет realloc-логики, тот же годовой rent, естественный запас на backlog.

### 8.3. Модель хранения ledger — решение владельца

| Вариант | Rent/год | Верификация |
|---|---:|---|
| A. Полные entries навсегда | 53–106 SOL | одно чтение PDA |
| B. Только rolling `entries_hash` | ~0.6 SOL | entry из транзакции, PDA подтверждает целостность |
| C. Hot window 90 дней + закрытие после | ~1.5 SOL | последние 90 дней — PDA, старше — digest + архив |

Для pilot реализуется **A** (простейшая, соответствует §8.3 спецификации буквально). Переход на C не меняет формат entries и возможен в Gate E. Решение — за владельцем до go-live.

`OL-DEC-04`

### 8.4. `publish_anchor` — инварианты

Порядок проверок: не приостановлен → роль принадлежит этому реестру и этому signer → роль активна по времени и не отозвана → есть право публикации → `batch_sequence == current + 1` → `registry_version` не назад → `cursor_start <= cursor_end` → `previous_anchor_hash == config.last_anchor_hash` → schema/hash/tree algorithm совпадают с config → ledger принадлежит реестру, день верный, не sealed, есть место.

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
├── format_version
├── registry_id
├── snapshot_id
├── snapshot_version
├── encryption_algorithm        // "AES-256-GCM"
├── chunk_size                  // фиксирован для пакета
├── total_chunks
├── chunks[]
│   ├── chunk_index
│   ├── nonce                   // 12 байт, уникален в пределах DEK
│   ├── ciphertext
│   └── auth_tag                // 16 байт
├── wrapped_dek                 // DEK, зашифрованный KEK
├── key_encryption_version      // версия KEK
├── plaintext_hash              // SHA-256 всего plaintext
└── ciphertext_hash             // SHA-256 сериализованного пакета без этого поля

AAD каждого chunk =
    "ONELAYER:SNAPSHOT:V1"
 || registry_id || snapshot_id || u64_be(snapshot_version)
 || u32_be(chunk_index) || u32_be(total_chunks)
 || plaintext_hash
```

Правила:
- chunking обязателен: одно монолитное GCM-сообщение непригодно для streaming, ретраев и локализации повреждения на снимках реального размера;
- пара `(DEK, nonce)` уникальна глобально; nonce выводится как `u32_be(chunk_index)` в 12-байтовом поле с нулевым префиксом, поскольку DEK уникален на snapshot — счётчик не может повториться;
- `chunk_index` и `total_chunks` входят в AAD: это защищает от перестановки, усечения и подмены chunk-ов между пакетами;
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

### 10.2. Изоляция внутри lab

- отдельные Docker networks для storage, key holders и restore;
- отдельный volume и отдельный credential у каждого custodian; общего bucket-credential нет;
- custodian не имеет доступа к KEK и shares;
- key holder не имеет доступа к backup storage;
- restore-контейнер не имеет доступа к `source-db`;
- coordinator ни в одной точке не держит все пять shares;
- production credentials отсутствуют полностью; только synthetic-данные и test keys.

**Ключевой материал не передаётся через environment.** `environment:` и `.env` видны в `docker inspect` и регулярно попадают в диагностические выгрузки. Для shares, KEK и DEK используются: Compose secrets или одноразовые read-only файлы в `tmpfs`, доступные только на время реконструкции; после drill контейнер и ephemeral volume уничтожаются.

Формулировка о стирании ключей — честная: **key material не записывается в persistent volume; временные secret-файлы лежат в tmpfs; процесс best-effort зануляет доступные буферы; после drill контейнер и ephemeral volume уничтожаются.** Обещать надёжный secure erase поверх Docker overlayfs и SSD с wear leveling нельзя, и план этого не утверждает.

### 10.3. Acceptance criteria

| # | Сценарий | Критерий |
|---|---|---|
| 1 | Создание snapshot | plaintext hash посчитан; AES-256-GCM; уникальный DEK на snapshot; AAD содержит registry ID, snapshot ID, version, plaintext hash |
| 2 | Размещение | ciphertext записан в три MinIO с разными credentials и volume; ciphertext hash перепроверен **после** записи у каждого |
| 3 | Threshold | `2-of-5` — восстановление KEK **отказывает**; `3-of-5` — успешно; shares не появляются в логах, артефактах и `docker inspect`; после drill ephemeral volume и контейнеры уничтожены |
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

Каталог создаётся **при наступлении Gate E0**, не раньше:

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
| Аудит | Внешний аудит программы (gate 4), penetration test (gate 5), security exercises §15.3 спецификации |
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
| `OL-DEC-05` | Padding field-дерева до степени двойки (скрытие числа полей, §2.1) | низкая | до Gate B, если утечка структуры неприемлема |
| `OL-DEC-06` | Immutable program vs governed upgrades после аудита | — | Gate E |
| `OL-DEC-07` | Audit hash-chain и её якорение в batch (§2.6) | низкая, контракт определён заранее | при требовании доказывать целостность журнала внешней стороне |
| `OL-DEC-08` | `maxIndexLagSlots` (по умолчанию 300 слотов) и `maxRpcHeadDifference` для incident index (§2.3) | — | `maxIndexLagSlots` — до Gate C; `maxRpcHeadDifference` — до Gate E, вместе со вторым RPC |

---

## 13. Риски

| # | Риск | Влияние | Митигация |
|---|---|---|---|
| R1 | Workflow-события не подписываются персонально | критическое | `OL-A-01` в первую неделю; при подтверждении — `redesign` на выходе Gate A |
| R2 | HSM без Ed25519 | высокое | `OL-A-03`; запасной вариант — внешний signing appliance, меняет §13.2 спецификации |
| R3 | Расхождение двух реализаций найдено поздно | высокое | общие векторы с Gate B, differential corpus в каждом PR |
| R4 | Rent-нагрузка ledger не согласована с бюджетом | среднее | `OL-DEC-04` до go-live; вариант C снижает в ~35 раз |
| R5 | Физическое вмешательство в файлы primary DB в обход WAL | критическое | **Не устраняется сканированием реплики.** Реплика может не получить такое изменение и показать старое внутренне согласованное состояние. Periodic replica scan обнаруживает пропущенные и повреждённые CDC-события, но не гарантирует обнаружение произвольного физического вмешательства в primary. Для этого требуется независимый канал к primary, независимо созданный snapshot primary или storage-level attestation — вводится только при подтверждении такой модели угроз в `OL-A-06` |
| R6 | Ложноположительные инциденты парализуют операции | среднее | 60-дневный shadow pilot с разбором каждого случая |
| R7 | Компрометация upgrade authority | критическое | Gate E: multisig + timelock; после аудита — рассмотреть `authority = None` (`OL-DEC-06`) |
| R8 | Деградация или цензура RPC | среднее | Gate E: два независимых провайдера; durable queue сохраняет backlog |
| R9 | Регулятор признаёт linkability по хэшам недостаточной | высокое | `OL-A-08` в Gate A; per-field соли из секретного ключа уже заложены (§2.1) |
| R10 | Смена схемы после production | высокое | `transition_algorithm` в Gate E; репетиция перехода — обязательное условие Phase 3 |
| R11 | Преждевременная декомпозиция замедляет pilot | среднее | §5.3: один процесс до подтверждённой границы развёртывания |

---

## 14. Первая неделя

1. `OL-A-01` — signed workflow events: есть или нет. Критический путь всего проекта.
2. `OL-A-02` — CDC и семантика курсора.
3. `OL-A-03` — Ed25519 HSM spike.
4. `OL-A-05` — закрыть disclosure design по §2.1: случайный `record_field_key` на версию записи, соли только раскрытых полей в сертификате, разведённые термины commitment/leaf_hash.
5. `OL-A-04` — large PDA allocation spike.
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
