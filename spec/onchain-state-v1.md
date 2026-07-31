# onchain-state-v1

**Статус:** frozen (Gate B)
**Решение allocation:** ADR-0002, сегменты по 46 entries

Документ является источником истины для ABI и state программы
`onelayer_registry`. Все integer в Borsh account/instruction data кодируются
little-endian. Исключения в PDA seeds указаны явно.

## 1. PDA seeds

| Account | Seeds |
|---|---|
| `RegistryConfig` | `["registry", registry_id_hash]` |
| `OperatorRole` | `["operator", registry_config_pubkey, operator_pubkey]` |
| `DailyAnchorLedgerSegment` | `["ledger", registry_config_pubkey, u32_be(day_utc), u16_le(segment_index)]` |
| `IncidentNotice` | `["incident", registry_config_pubkey, u64_be(incident_sequence)]` |

`day_utc` имеет форму `YYYYMMDD`. Первый сегмент дня имеет индекс `0`, каждый
следующий — предыдущий индекс + 1. Пропуски запрещены.

## 2. Константы

```text
ACCOUNT_VERSION_V1       = 1
LEDGER_CAPACITY          = 46
PERM_PUBLISH_ANCHOR      = 1 << 0
PERM_CREATE_LEDGER       = 1 << 1
PERM_SEAL_LEDGER         = 1 << 2
PERM_REPORT_INCIDENT     = 1 << 3

INCIDENT_OPEN            = 1
INCIDENT_CONFIRMED       = 2
INCIDENT_FALSE_POSITIVE  = 3
INCIDENT_RESOLVED        = 4
```

Неизвестная версия account отклоняется. Поля `reserved` должны быть нулевыми
при создании и игнорируются при чтении версии 1.

## 3. Accounts

Порядок полей нормативен.

```rust
pub struct RegistryConfig {
    pub version: u8,
    pub bump: u8,
    pub registry_id_hash: [u8; 32],
    pub governance_authority: Pubkey,
    pub emergency_authority: Pubkey,
    pub current_batch_sequence: u64,
    pub current_registry_version: u64,
    pub last_anchor_hash: [u8; 32],
    pub incident_count: u64,
    pub schema_version: u16,
    pub hash_algorithm: u8,
    pub tree_algorithm: u8,
    pub anchor_interval_seconds: u32,
    pub max_entries_per_day: u16,
    pub paused: bool,
    pub created_at: i64,
    pub reserved: [u8; 96],
}

pub struct OperatorRole {
    pub version: u8,
    pub bump: u8,
    pub registry: Pubkey,
    pub operator: Pubkey,
    pub permissions: u32,
    pub valid_from: i64,
    pub valid_until: i64,
    pub revoked_at: i64, // 0 = не отозвана
    pub key_id_hash: [u8; 32],
    pub reserved: [u8; 32],
}
```

`valid_until = 0` означает отсутствие верхней границы. Активная роль:
`revoked_at == 0 && now >= valid_from && (valid_until == 0 || now <= valid_until)`.

### 3.1. Zero-copy entry и segment

```rust
#[repr(C)]
pub struct AnchorEntryV1 {
    pub batch_sequence: u64,
    pub registry_version: u64,
    pub source_cursor_start: u64,
    pub source_cursor_end: u64,
    pub merkle_root: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub snapshot_hash: [u8; 32],
    pub previous_anchor_hash: [u8; 32],
    pub leaf_count: u32,
    pub schema_version: u16,
    pub flags: u16,
    pub hash_algorithm: u8,
    pub tree_algorithm: u8,
    pub _pad0: [u8; 6],
    pub operator: Pubkey,
    pub published_at: i64,
} // 216 bytes, align 8

#[repr(C)]
pub struct DailyAnchorLedgerSegment {
    pub version: u8,
    pub bump: u8,
    pub sealed: u8,
    pub _pad0: u8,
    pub registry: Pubkey,
    pub day_utc: u32,
    pub segment_index: u16,
    pub entry_count: u16,
    pub capacity: u16,
    pub _pad1: [u8; 2],
    pub created_at: i64,
    pub sealed_at: i64,
    pub entries_hash: [u8; 32],
    pub entries: [AnchorEntryV1; 46],
} // 10_032 bytes + 8-byte discriminator = 10_040
```

Все padding bytes нулевые. `capacity` всегда `46`; значение хранится как
проверяемый снимок принятого allocation-контракта, а не как настройка.

### 3.2. IncidentNotice

```rust
pub struct IncidentNotice {
    pub version: u8,
    pub bump: u8,
    pub registry: Pubkey,
    pub incident_sequence: u64,
    pub first_suspect_batch: u64,
    pub last_suspect_batch: u64,
    pub incident_type: u16,
    pub status: u8,
    pub evidence_manifest_hash: [u8; 32],
    pub opened_by: Pubkey,
    pub opened_at: i64,
    pub resolved_at: i64,
    pub resolution_hash: [u8; 32],
}
```

`incident_sequence` присваивает программа из `RegistryConfig.incident_count`,
после успешного создания счётчик увеличивается на один. Диапазон включителен,
`first_suspect_batch <= last_suspect_batch`.

## 4. Instruction data

```rust
pub struct AnchorEntryInputV1 {
    pub batch_sequence: u64,
    pub registry_version: u64,
    pub source_cursor_start: u64,
    pub source_cursor_end: u64,
    pub merkle_root: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub snapshot_hash: [u8; 32],
    pub previous_anchor_hash: [u8; 32],
    pub leaf_count: u32,
    pub schema_version: u16,
    pub flags: u16,
    pub hash_algorithm: u8,
    pub tree_algorithm: u8,
}
```

`operator` и `published_at` отсутствуют во входе: программа берёт signer и
`Clock.unix_timestamp`.

| Instruction | Аргументы |
|---|---|
| `initialize_registry` | `registry_id_hash`, authorities, schema/hash/tree, interval, max entries |
| `grant_operator` | `permissions`, validity, `key_id_hash` |
| `revoke_operator` | нет |
| `create_ledger_segment` | `day_utc`, `segment_index`, `capacity` |
| `publish_anchor` | `AnchorEntryInputV1` |
| `seal_daily_ledger` | `day_utc` + все сегменты дня в порядке индекса |
| `pause_registry` / `resume_registry` | нет |
| `open_incident` | batch range, type, evidence hash |
| `resolve_incident` | final status, resolution hash |

Инструкций `grow`/`realloc`, `transition_algorithm` и `rotate_governance` в ABI
pilot нет.

## 5. Genesis и переходы

При `initialize_registry`:

```text
current_batch_sequence    = 0
current_registry_version  = 0
incident_count            = 0
last_anchor_hash           = SHA256("ONELAYER:GENESIS:V1" || registry_id_hash)
paused                     = false
```

`publish_anchor` применяет порядок проверок из §8.4 плана и записывает entry
только после прохождения всех проверок. Затем атомарно обновляет config и
эмитит событие.

## 6. Sealing hash

`seal_daily_ledger` получает все существующие сегменты дня строго в порядке
`segment_index = 0..n-1`; пропуск, лишний сегмент, другой registry/day или уже
sealed segment отклоняется. Пустой день не seal-ится.

```text
day_entries_preimage = "ONELAYER:DAYENTRIES:V1"
                    || registry_config_pubkey
                    || u32_be(day_utc)
                    || u16_be(segment_count)
                    || для каждого segment по segment_index:
                         u16_le(segment_index)
                      || u16_be(entry_count)
                      || anchor_hash(entry[0]) ... anchor_hash(entry[n-1])

entries_hash = SHA256(day_entries_preimage)
```

Одинаковый `entries_hash` записывается во все сегменты дня вместе с
`sealed = 1` и единым `sealed_at` из Clock. `anchor_hash(entry)` считается по
`anchor-chain-v1.md`, не по zero-copy bytes.

## 7. Events

| Event | Поля |
|---|---|
| `RegistryInitialized` | registry, registry_id_hash, governance, emergency |
| `OperatorGranted` | registry, operator, permissions, valid_from, valid_until |
| `OperatorRevoked` | registry, operator, revoked_at |
| `LedgerSegmentCreated` | registry, day_utc, segment_index, capacity |
| `AnchorPublished` | registry, batch_sequence, segment_index, entry_index, anchor_hash, manifest_hash |
| `DailyLedgerSealed` | registry, day_utc, segment_count, entries_hash |
| `RegistryPaused` / `RegistryResumed` | registry, authority, occurred_at |
| `IncidentOpened` | registry, incident_sequence, batch range, incident_type, evidence hash |
| `IncidentResolved` | registry, incident_sequence, status, resolution_hash |

## 8. Версионирование

Изменение seeds, порядка/типа полей, fixed sizes или instruction data после
Gate B требует ADR и новой версии account/schema. Существующий account версии
1 не интерпретируется по новому layout. Zero-copy bytes не используются как
публичный hash preimage.
