# OneLayer — техническая документация Solana

**Статус:** проектная спецификация v0.9  
**Назначение:** криптографический слой доказуемости и восстановления для государственного земельного реестра  
**Целевая сеть:** Solana Mainnet Beta  
**Язык on-chain программы:** Rust + Anchor  
**Язык сервисов:** TypeScript/Node.js или Rust; примеры API приведены в JSON/SQL  

> Документ описывает целевую архитектуру. Он не утверждает, что система уже внедрена, и не заменяет юридическое заключение, аудит исходного реестра, threat modeling и независимый security review.

---

## 1. Цели и границы системы

### 1.1. Цели

OneLayer должен обеспечивать:

1. неизменяемую фиксацию криптографического состояния реестра;
2. независимое обнаружение изменений вне штатного регистрационного процесса;
3. выдачу переносимого доказательства владельцу;
4. проверку документа при недоступности backend государственного реестра;
5. проверку резервной копии перед восстановлением;
6. сохранение истории версий и переходов между алгоритмами;
7. отсутствие открытых персональных и кадастровых данных в публичной сети.

### 1.2. Не-цели

OneLayer не должен:

- заменять государственный реестр или становиться юридическим источником права;
- записывать право собственности непосредственно в Solana;
- хранить на chain имена, адреса, кадастровые номера, геометрию или документы;
- автоматически решать юридические споры;
- автоматически откатывать государственную базу;
- считать корректной любую запись только потому, что она была anchored;
- заменять резервные копии, MFA, PAM, SIEM, EDR и стандартную защиту.

### 1.3. Основные гарантии

Система доказывает, что конкретное состояние данных существовало не позднее определённого Solana slot и было включено в определённый пакет. Она не доказывает законность первоначального ввода. Это ограничение `garbage in — garbage out` является фундаментальным.

---

## 2. Модель угроз

### 2.1. Защищаемые активы

- история состояний записей;
- связь записи с регистрационным workflow;
- Merkle roots и manifests;
- signing keys оператора;
- salts/nonces сертификатов;
- зашифрованные snapshots;
- ключи расшифрования и threshold shares;
- upgrade authority Solana-программы;
- журналы инцидентов и восстановления.

### 2.2. Противники

- внешний атакующий с украденным логином/паролем администратора;
- администратор БД с прямым SQL-доступом;
- скомпрометированный оператор Anchoring Service;
- скомпрометированный RPC-провайдер;
- insider с правом подписывать workflow;
- ransomware, уничтожающий production и connected backups;
- коалиция custodian + key holders;
- атакующий, подменяющий certificate или QR;
- разработчик, получивший upgrade authority программы.

### 2.3. Ключевой принцип разделения полномочий

Доступ к БД, право подтверждать юридическую операцию, право публиковать anchor, право обновлять программу и право восстанавливать backup должны принадлежать разным ключам и ролям. Один логин администратора не должен позволять создать юридически подтверждённое изменение.

---

## 3. Высокоуровневая архитектура

```text
Государственный реестр
  ├─ Primary DB
  ├─ Signed Workflow Event Stream
  └─ Change Data Capture / Transaction Log
          │ read-only, mTLS
          ▼
Canonicalization + Policy Engine
          ├─ сопоставляет запись и разрешённое событие
          ├─ создаёт RecordVersion
          └─ отправляет несоответствия в Incident Queue
          │
          ▼
Batch Builder / Merkle Service
          ├─ canonical payload hashes
          ├─ Merkle leaves/tree
          ├─ signed batch manifest
          └─ certificate proofs
          │
          ▼
HSM-backed Anchor Publisher ──────► Solana Program
          │                           ├─ RegistryConfig PDA
          │                           ├─ DailyAnchorLedger PDA
          │                           └─ IncidentNotice PDA
          │
          ├─► Independent RPC provider A
          └─► Independent RPC provider B

Independent Integrity Monitor
  ├─ отдельный read replica / snapshot reader
  ├─ authorized workflow stream
  ├─ anchored manifests
  └─ alerting/SIEM

Recovery Plane
  ├─ encrypted snapshots in independent trust boundaries
  ├─ immutable object storage
  ├─ threshold key holders
  └─ Recovery Toolkit

Public Plane
  ├─ Certificate Issuer
  ├─ QR / certificate package
  ├─ Public Verifier
  └─ API for banks/notaries
```

### 3.1. Компоненты

| Код | Компонент | Ответственность |
|---|---|---|
| M1 | CDC Adapter | Чтение изменений реестра без прав записи |
| M2 | Workflow Adapter | Получение подписанных разрешённых операций |
| M3 | Canonicalization Service | Детерминированное представление записи |
| M4 | Batch/Merkle Service | Leaves, tree, root, manifest, proofs |
| M5 | Anchor Publisher | HSM signing и отправка Solana-транзакции |
| M6 | Solana Program | Проверка роли, sequence и запись root metadata |
| M7 | Certificate Issuer | Подписанный certificate package и QR |
| M8 | Public Verifier | Проверка certificate, proof и on-chain anchor |
| M9 | Integrity Monitor | Независимое обнаружение out-of-process изменений |
| M10 | Snapshot Coordinator | Создание и распределение encrypted replicas |
| M11 | Recovery Toolkit | Проверка snapshots и восстановленных records |
| M12 | Audit/Incident Service | Неизменяемая история инцидентов и решений |

---

## 4. Детерминированная канонизация данных

### 4.1. Почему нельзя hash-ировать обычный JSON

Порядок ключей, Unicode normalization, формат дат, пробелы, `null`, числа и порядок массивов могут отличаться при одинаковом смысловом содержании. Поэтому вводится versioned canonical schema.

### 4.2. Правила Canonical Record v1

- UTF-8;
- Unicode NFC;
- ключи в лексикографическом порядке;
- даты в UTC RFC 3339;
- decimal значения — строки с фиксированным scale;
- отсутствующее значение и `null` различаются;
- массивы прав/обременений сортируются по стабильному идентификатору;
- геометрия не включается в citizen proof по умолчанию; для неё создаётся отдельный commitment;
- все идентификаторы имеют namespace;
- PII не используется как публичный идентификатор.

### 4.3. CanonicalRecordV1

```ts
interface CanonicalRecordV1 {
  schemaVersion: 1;
  registryId: string;              // например "AM.CADASTRE.RIGHTS"
  internalRecordId: string;        // только off-chain
  recordIdCommitment: string;      // hex32
  recordVersion: bigint;
  effectiveAt: string;             // RFC3339 UTC
  workflowEventId: string;
  parcelCommitment: string;        // hex32
  subjectCommitments: string[];    // владельцы/правообладатели, hex32
  rights: CanonicalRightV1[];
  encumbrances: CanonicalEncumbranceV1[];
  sourceTransactionId: string;
  previousVersionHash: string | null;
}

interface CanonicalRightV1 {
  rightId: string;
  rightType: string;
  shareNumerator: string;
  shareDenominator: string;
  validFrom: string;
  validTo: string | null;
  status: "ACTIVE" | "SUPERSEDED" | "CANCELLED";
}

interface CanonicalEncumbranceV1 {
  encumbranceId: string;
  type: string;
  beneficiaryCommitment: string;
  validFrom: string;
  validTo: string | null;
  status: "ACTIVE" | "RELEASED" | "EXPIRED";
}
```

### 4.4. Commitments

Рекомендуемый алгоритм leaf v1:

```text
payload_hash = SHA-256(canonical_cbor(record))
leaf = SHA-256(
  "ONELAYER:RECORD:V1" ||
  registry_id_hash ||
  u64_be(record_version) ||
  payload_hash ||
  nonce_32
)
```

`nonce_32` — 256-битное случайное значение, уникальное для версии записи. На chain nonce не публикуется. Он хранится зашифрованно у Issuer и может включаться в certificate владельца. Это препятствует словарному подбору по публичному root.

Для внутренних идентификаторов:

```text
record_id_commitment = HMAC-SHA-256(id_key_vN, registry_id || internal_record_id)
```

`id_key_vN` не передаётся пользователю и хранится в HSM/KMS.

---

## 5. Merkle-модель

### 5.1. Дерево пакета

- hash: SHA-256;
- leaves сортируются по `(record_id_commitment, record_version)`;
- непарный последний узел дублируется либо используется RFC6962-style tree — правило фиксируется в `treeAlgorithm`;
- domain separation для leaf и node обязательна.

```text
leaf_hash = SHA256(0x00 || leaf)
node_hash = SHA256(0x01 || left || right)
```

### 5.2. BatchManifestV1

```ts
interface BatchManifestV1 {
  manifestVersion: 1;
  registryIdHash: string;          // hex32
  batchSequence: bigint;
  registryVersion: bigint;
  sourceCursorStart: bigint;
  sourceCursorEnd: bigint;
  createdAt: string;
  schemaVersion: number;
  hashAlgorithm: "SHA256";
  treeAlgorithm: "RFC6962_SHA256_V1";
  leafCount: number;
  merkleRoot: string;
  previousAnchorHash: string;
  snapshotHash: string | null;
  leavesObjectUri: string;         // internal URI
  leavesObjectHash: string;
  builderVersion: string;
  operatorKeyId: string;
  manifestSignature: string;       // Ed25519/HSM
}
```

Manifest хранится минимум в трёх независимых off-chain хранилищах. На Solana публикуются `merkleRoot`, `manifestHash`, sequence и минимальная metadata.

### 5.3. ProofV1

```ts
interface MerkleProofV1 {
  treeAlgorithm: "RFC6962_SHA256_V1";
  leafIndex: number;
  leafHash: string;
  siblings: Array<{
    side: "LEFT" | "RIGHT";
    hash: string;
  }>;
  expectedRoot: string;
}
```

---

## 6. Solana on-chain программа

### 6.1. Основные решения

- программа stateless; mutable state хранится в PDA accounts;
- Anchor используется для IDL и account constraints;
- финальная проверка anchor выполняется на commitment `finalized`;
- транзакции не содержат PII;
- один anchor каждые 15 минут — базовая конфигурация;
- roots группируются в дневной PDA ledger, чтобы не создавать account на каждый batch;
- опубликованные entries не изменяются; исправления оформляются отдельным IncidentNotice.

Solana programs хранят mutable state в отдельных accounts, а PDA являются детерминированными адресами без приватного ключа; подписывать за PDA может только соответствующая программа. Официальная документация: [Accounts](https://solana.com/docs/core/accounts), [Programs](https://solana.com/docs/core/programs), [PDA](https://solana.com/docs/core/pda).

### 6.2. PDA seeds

```text
RegistryConfig:
  ["registry", registry_id_hash]

OperatorRole:
  ["operator", registry_config_pubkey, operator_pubkey]

DailyAnchorLedger:
  ["ledger", registry_config_pubkey, day_utc_u32_be]

IncidentNotice:
  ["incident", registry_config_pubkey, incident_seq_u64_be]

AlgorithmTransition:
  ["algorithm", registry_config_pubkey, transition_seq_u64_be]
```

### 6.3. RegistryConfig account

```rust
#[account]
pub struct RegistryConfig {
    pub version: u8,
    pub bump: u8,
    pub registry_id_hash: [u8; 32],
    pub governance_authority: Pubkey,
    pub emergency_authority: Pubkey,
    pub current_batch_sequence: u64,
    pub current_registry_version: u64,
    pub last_anchor_hash: [u8; 32],
    pub schema_version: u16,
    pub hash_algorithm: u8,
    pub tree_algorithm: u8,
    pub anchor_interval_seconds: u32,
    pub max_entries_per_day: u16,
    pub paused: bool,
    pub created_at: i64,
    pub reserved: [u8; 96],
}
```

### 6.4. OperatorRole account

```rust
#[account]
pub struct OperatorRole {
    pub version: u8,
    pub bump: u8,
    pub registry: Pubkey,
    pub operator: Pubkey,
    pub permissions: u32,
    pub valid_from: i64,
    pub valid_until: i64,
    pub revoked_at: i64, // 0 = active
    pub key_id_hash: [u8; 32],
    pub reserved: [u8; 32],
}

pub const PERM_PUBLISH_ANCHOR: u32 = 1 << 0;
pub const PERM_CREATE_LEDGER: u32 = 1 << 1;
pub const PERM_SEAL_LEDGER: u32 = 1 << 2;
pub const PERM_REPORT_INCIDENT: u32 = 1 << 3;
```

### 6.5. AnchorEntryV1

```rust
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct AnchorEntryV1 {
    pub batch_sequence: u64,
    pub registry_version: u64,
    pub source_cursor_start: u64,
    pub source_cursor_end: u64,
    pub merkle_root: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub snapshot_hash: [u8; 32], // zero = отсутствует
    pub previous_anchor_hash: [u8; 32],
    pub leaf_count: u32,
    pub schema_version: u16,
    pub flags: u16,
    pub hash_algorithm: u8,
    pub tree_algorithm: u8,
    pub operator: Pubkey,
    pub published_at: i64,
}
```

### 6.6. DailyAnchorLedger account

```rust
#[account]
pub struct DailyAnchorLedger {
    pub version: u8,
    pub bump: u8,
    pub registry: Pubkey,
    pub day_utc: u32,               // YYYYMMDD
    pub entry_count: u16,
    pub capacity: u16,              // обычно 96
    pub sealed: bool,
    pub created_at: i64,
    pub sealed_at: i64,
    pub entries_hash: [u8; 32],     // hash всех entries при seal
    pub entries: Vec<AnchorEntryV1>,
}
```

Ожидаемый режим: 96 anchors/day при интервале 15 минут. Размер и rent должны быть рассчитаны после фиксации Borsh layout. Capacity запрещено менять после создания ledger.

### 6.7. IncidentNotice account

```rust
#[account]
pub struct IncidentNotice {
    pub version: u8,
    pub bump: u8,
    pub registry: Pubkey,
    pub incident_sequence: u64,
    pub first_suspect_batch: u64,
    pub last_suspect_batch: u64,
    pub incident_type: u16,
    pub status: u8,                 // OPEN/CONFIRMED/FALSE_POSITIVE/RESOLVED
    pub evidence_manifest_hash: [u8; 32],
    pub opened_by: Pubkey,
    pub opened_at: i64,
    pub resolved_at: i64,
    pub resolution_hash: [u8; 32],
}
```

IncidentNotice не удаляет и не переписывает anchor. Он сообщает, что определённый диапазон требует расследования.

### 6.8. Инструкции программы

| Instruction | Кто подписывает | Действие |
|---|---|---|
| `initialize_registry` | governance | Создаёт RegistryConfig |
| `grant_operator` | governance | Создаёт OperatorRole |
| `revoke_operator` | governance | Отзывает роль |
| `create_daily_ledger` | operator | Создаёт ledger дня |
| `publish_anchor` | authorised operator | Добавляет следующий entry |
| `seal_daily_ledger` | operator/governance | Закрывает ledger от добавления |
| `pause_registry` | emergency authority | Останавливает публикации |
| `resume_registry` | governance | Возобновляет после проверки |
| `open_incident` | monitor/governance | Публикует notice |
| `resolve_incident` | governance quorum | Добавляет resolution hash |
| `transition_algorithm` | governance | Регистрирует смену schema/hash |
| `rotate_governance` | current governance | Меняет authority по процедуре |

### 6.9. Проверки `publish_anchor`

```rust
require!(!config.paused, ErrorCode::RegistryPaused);
require!(role.is_active(clock.unix_timestamp), ErrorCode::OperatorInactive);
require!(role.can_publish(), ErrorCode::MissingPermission);
require!(entry.batch_sequence == config.current_batch_sequence + 1, ErrorCode::BadSequence);
require!(entry.registry_version >= config.current_registry_version, ErrorCode::RegistryVersionRollback);
require!(entry.source_cursor_start <= entry.source_cursor_end, ErrorCode::InvalidCursorRange);
require!(entry.previous_anchor_hash == config.last_anchor_hash, ErrorCode::BrokenAnchorChain);
require!(ledger.day_utc == utc_day(clock.unix_timestamp), ErrorCode::WrongLedgerDay);
require!(!ledger.sealed, ErrorCode::LedgerSealed);
require!(ledger.entries.len() < ledger.capacity as usize, ErrorCode::LedgerFull);
```

On-chain программа не проверяет правильность кадастровых данных — только полномочия, последовательность и целостность anchor chain.

### 6.10. Upgrade authority

На pilot программа может быть upgradeable. Upgrade authority должна находиться в multisig с временной задержкой и независимыми участниками. После production-аудита возможны два режима:

1. immutable program — authority устанавливается в `None`;
2. governed upgrades — multisig + timelock + публичный hash bytecode + обязательный независимый аудит.

Solana допускает отзыв upgrade authority, после чего программу невозможно обновить: [Program deployment](https://solana.com/docs/core/programs/program-deployment).

---

## 7. Off-chain модель данных

### 7.1. Основные таблицы PostgreSQL

```sql
CREATE TABLE registry_change_event (
  event_id UUID PRIMARY KEY,
  registry_id TEXT NOT NULL,
  source_cursor BIGINT NOT NULL,
  source_tx_id TEXT NOT NULL,
  internal_record_id TEXT NOT NULL,
  operation TEXT NOT NULL CHECK (operation IN ('INSERT','UPDATE','DELETE')),
  observed_at TIMESTAMPTZ NOT NULL,
  raw_payload_encrypted BYTEA NOT NULL,
  raw_payload_hash BYTEA NOT NULL,
  UNIQUE (registry_id, source_cursor)
);

CREATE TABLE authorized_workflow_event (
  workflow_event_id TEXT PRIMARY KEY,
  registry_id TEXT NOT NULL,
  internal_record_id TEXT NOT NULL,
  operation_type TEXT NOT NULL,
  case_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  actor_signature BYTEA NOT NULL,
  external_approval_refs JSONB NOT NULL DEFAULT '[]',
  approved_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('AUTHORIZED','REVOKED','REJECTED'))
);

CREATE TABLE canonical_record_version (
  id UUID PRIMARY KEY,
  registry_id TEXT NOT NULL,
  internal_record_id TEXT NOT NULL,
  record_id_commitment BYTEA NOT NULL,
  record_version BIGINT NOT NULL,
  workflow_event_id TEXT REFERENCES authorized_workflow_event(workflow_event_id),
  schema_version SMALLINT NOT NULL,
  canonical_payload_encrypted BYTEA NOT NULL,
  payload_hash BYTEA NOT NULL,
  nonce_encrypted BYTEA NOT NULL,
  leaf_hash BYTEA NOT NULL,
  source_cursor BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  UNIQUE (registry_id, internal_record_id, record_version)
);

CREATE TABLE anchor_batch (
  batch_sequence BIGINT PRIMARY KEY,
  registry_id TEXT NOT NULL,
  registry_version BIGINT NOT NULL,
  cursor_start BIGINT NOT NULL,
  cursor_end BIGINT NOT NULL,
  leaf_count INTEGER NOT NULL,
  merkle_root BYTEA NOT NULL,
  manifest_hash BYTEA NOT NULL,
  previous_anchor_hash BYTEA NOT NULL,
  snapshot_hash BYTEA,
  status TEXT NOT NULL CHECK (status IN ('PREPARED','SIGNED','SUBMITTED','FINALIZED','DISPUTED','FAILED')),
  solana_signature TEXT,
  solana_slot BIGINT,
  prepared_at TIMESTAMPTZ NOT NULL,
  finalized_at TIMESTAMPTZ
);

CREATE TABLE batch_leaf (
  batch_sequence BIGINT REFERENCES anchor_batch(batch_sequence),
  leaf_index INTEGER NOT NULL,
  record_version_id UUID REFERENCES canonical_record_version(id),
  leaf_hash BYTEA NOT NULL,
  proof_object_key TEXT,
  PRIMARY KEY (batch_sequence, leaf_index)
);

CREATE TABLE certificate (
  certificate_id UUID PRIMARY KEY,
  record_version_id UUID NOT NULL REFERENCES canonical_record_version(id),
  batch_sequence BIGINT NOT NULL REFERENCES anchor_batch(batch_sequence),
  certificate_version SMALLINT NOT NULL,
  certificate_hash BYTEA NOT NULL,
  issuer_key_id TEXT NOT NULL,
  signature BYTEA NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ACTIVE','SUPERSEDED','REVOKED')),
  issued_at TIMESTAMPTZ NOT NULL,
  superseded_by UUID
);

CREATE TABLE integrity_incident (
  incident_id UUID PRIMARY KEY,
  incident_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  internal_record_id TEXT,
  expected_leaf_hash BYTEA,
  observed_leaf_hash BYTEA,
  first_suspect_batch BIGINT,
  status TEXT NOT NULL,
  evidence_object_key TEXT NOT NULL,
  opened_at TIMESTAMPTZ NOT NULL,
  resolved_at TIMESTAMPTZ,
  resolution TEXT
);

CREATE TABLE snapshot (
  snapshot_id UUID PRIMARY KEY,
  registry_id TEXT NOT NULL,
  registry_version BIGINT NOT NULL,
  snapshot_type TEXT NOT NULL CHECK (snapshot_type IN ('FULL','INCREMENTAL')),
  plaintext_hash BYTEA NOT NULL,
  ciphertext_hash BYTEA NOT NULL,
  encryption_algorithm TEXT NOT NULL,
  encryption_key_version TEXT NOT NULL,
  object_size BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  anchor_batch_sequence BIGINT REFERENCES anchor_batch(batch_sequence)
);

CREATE TABLE custodian_replica (
  snapshot_id UUID REFERENCES snapshot(snapshot_id),
  custodian_id TEXT NOT NULL,
  storage_object_id TEXT NOT NULL,
  object_lock_until TIMESTAMPTZ NOT NULL,
  verified_ciphertext_hash BYTEA NOT NULL,
  last_verified_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL,
  PRIMARY KEY (snapshot_id, custodian_id)
);

CREATE TABLE audit_event (
  audit_id UUID PRIMARY KEY,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  event_payload JSONB NOT NULL,
  previous_audit_hash BYTEA,
  audit_hash BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);
```

### 7.2. Хранилища объектов

В object storage сохраняются:

- encrypted raw CDC events;
- canonical payloads;
- manifests;
- leaves and Merkle nodes;
- proofs;
- incident evidence bundles;
- encrypted snapshots;
- signed recovery reports.

Для объектов включаются versioning, WORM/Object Lock, retention policy, cross-account replication и hash verification.

---

## 8. Certificate и QR

### 8.1. CertificatePackageV1

```ts
interface CertificatePackageV1 {
  format: "ONELAYER_CERTIFICATE";
  version: 1;
  certificateId: string;
  registryId: string;
  issuedAt: string;
  recordVersion: string;
  disclosureMode: "FULL_RECORD" | "SELECTIVE_FIELDS";
  disclosedRecord: Record<string, unknown>;
  nonce: string;                   // base64url 32 bytes
  payloadHash: string;
  leafHash: string;
  proof: MerkleProofV1;
  anchor: {
    batchSequence: string;
    registryVersion: string;
    merkleRoot: string;
    manifestHash: string;
    solanaProgramId: string;
    dailyLedgerPda: string;
    transactionSignature: string;
    commitmentRequired: "finalized";
  };
  issuer: {
    keyId: string;
    publicKey: string;
    signatureAlgorithm: "Ed25519";
  };
  issuerSignature: string;
}
```

### 8.2. QR-форматы

**Рекомендуемый основной формат:** QR содержит короткий HTTPS URL + certificate ID + certificate hash. Полный package загружается с verifier и проверяется цифровой подписью.

**Автономный формат:** animated QR или несколько QR-частей содержат compressed CBOR certificate. Он нужен для сценариев без доступа к Issuer, но всё равно требуется доступ к Solana RPC либо локальный архив anchors.

QR не должен содержать открытые PII по умолчанию.

### 8.3. Алгоритм проверки

```text
1. Decode certificate package.
2. Verify issuer Ed25519 signature.
3. Canonicalize disclosed record under certificate schema version.
4. Recompute payload_hash and leaf using nonce.
5. Verify Merkle proof → expected root.
6. Fetch DailyAnchorLedger PDA and transaction from two RPC sources.
7. Require finalized commitment.
8. Verify program ID, registry PDA, batch sequence, manifest hash and root.
9. Check IncidentNotice for referenced batch range.
10. Return VERIFIED / VERIFIED_HISTORICAL / SUPERSEDED / DISPUTED / INVALID.
```

### 8.4. Результат verifier

```json
{
  "status": "VERIFIED_HISTORICAL",
  "certificateId": "8db6...",
  "anchoredAt": "2026-03-14T11:42:00Z",
  "batchSequence": "18421",
  "solanaSlot": "412345678",
  "currentStatusChecked": false,
  "incidentStatus": "NONE",
  "warnings": [
    "Доказательство подтверждает состояние на дату anchor, но не текущий юридический статус."
  ]
}
```

---

## 9. API

### 9.1. Public API

| Method | Endpoint | Назначение |
|---|---|---|
| `POST` | `/v1/verify` | Проверить certificate package |
| `GET` | `/v1/anchors/{batchSequence}` | Получить anchor metadata |
| `GET` | `/v1/incidents?batchSequence=` | Проверить incident notices |
| `GET` | `/v1/certificates/{id}/status` | Проверить статус certificate |
| `GET` | `/v1/health` | Health endpoint без чувствительных данных |

### 9.2. Government/Internal API

| Method | Endpoint | Назначение |
|---|---|---|
| `POST` | `/internal/v1/batches/prepare` | Построить batch |
| `POST` | `/internal/v1/batches/{seq}/sign` | Подписать manifest через HSM |
| `POST` | `/internal/v1/batches/{seq}/publish` | Отправить Solana tx |
| `POST` | `/internal/v1/certificates/issue` | Выдать certificate |
| `POST` | `/internal/v1/snapshots/register` | Зарегистрировать snapshot |
| `POST` | `/internal/v1/incidents/open` | Открыть инцидент |
| `POST` | `/internal/v1/recovery/verify` | Запустить проверку backup |

### 9.3. Verify request

```json
{
  "certificatePackage": "base64url(cbor)",
  "checkCurrentRegistryStatus": false,
  "requiredCommitment": "finalized"
}
```

### 9.4. Prepare batch request

```json
{
  "registryId": "AM.CADASTRE.RIGHTS",
  "cursorStart": "99100001",
  "cursorEnd": "99100450",
  "expectedPreviousBatch": "18420",
  "schemaVersion": 1
}
```

### 9.5. Ошибки API

| Код | Значение |
|---|---|
| `CERT_SIGNATURE_INVALID` | Подпись issuer неверна |
| `CANONICALIZATION_FAILED` | Невозможно воспроизвести canonical payload |
| `MERKLE_PROOF_INVALID` | Proof не приводит к root |
| `ANCHOR_NOT_FOUND` | Anchor не найден у независимых RPC |
| `ANCHOR_NOT_FINALIZED` | Транзакция недостаточно подтверждена |
| `ANCHOR_DISPUTED` | Для batch опубликован incident notice |
| `SCHEMA_UNSUPPORTED` | Verifier не поддерживает schema version |
| `RECORD_SUPERSEDED` | Certificate исторически верен, но есть новая версия |
| `CURRENT_STATUS_UNAVAILABLE` | Нельзя проверить актуальное состояние реестра |

---

## 10. Резервные копии и дата-центры

### 10.1. Модель

Не рекомендуется sharding единственной backup-копии между дата-центрами. Базовая модель — несколько полных зашифрованных replicas в независимых trust boundaries:

- daily incremental;
- weekly full;
- immutable storage;
- отдельные identity domains;
- отсутствие общего administrator account;
- регулярная hash verification;
- quarterly restore drills.

### 10.2. Шифрование

- data encryption: AES-256-GCM либо утверждённый государством алгоритм;
- уникальный DEK на snapshot;
- DEK зашифрован KEK;
- KEK управляется threshold/HSM policy;
- AAD включает registry ID, snapshot ID, version и plaintext hash;
- custodian хранит ciphertext, но не ключ.

### 10.3. Threshold ceremony

Пример policy `3-of-5`. Key holders не совпадают с storage custodians. Каждая reconstruction ceremony требует case ID, подписанное разрешение, присутствие независимого аудитора и неизменяемый audit bundle. Условия должны быть закреплены юридически до production.

### 10.4. Процедура восстановления

1. определить последний доверенный anchor перед compromise;
2. выбрать snapshot и проверить ciphertext hash;
3. собрать threshold quorum;
4. расшифровать в clean-room environment;
5. проверить plaintext snapshot hash;
6. пересчитать canonical records и Merkle roots;
7. применить только подтверждённые post-snapshot events;
8. изолировать несовпадающие records;
9. получить юридическое разрешение на возврат в production;
10. опубликовать recovery anchor и signed report.

---

## 11. Integrity Monitor

### 11.1. Три независимых входа

Monitor сравнивает:

1. фактическое состояние DB/read replica;
2. поток подписанных authorised workflow events;
3. manifests и anchors предыдущих batch.

### 11.2. Direct SQL tampering

Если запись изменилась без workflow event:

- change виден в CDC или при periodic scan;
- отсутствует соответствующее разрешённое событие;
- record leaf расходится с expected leaf;
- hierarchical Merkle diff локализует запись;
- batch помещается в quarantine;
- создаётся incident и при необходимости `pause_registry`.

### 11.3. Скомпрометированный администратор

Если атакующий создаёт формально корректное workflow event, одной blockchain-проверки недостаточно. Нужны:

- person-specific digital signature;
- MFA/PAM;
- HSM-backed workflow signing;
- dual approval для критических операций;
- external case/notary references;
- behavioral anomaly detection;
- separation DB admin и legal approver.

### 11.4. Вредоносный anchor уже опубликован

Предыдущий anchor остаётся неизменным. Новый batch маркируется incident notice. Система сравнивает manifests и определяет переход между последней подтверждённой и подозрительной версиями. Автоматический rollback запрещён; correction выполняется новым юридически разрешённым событием и новым anchor.

---

## 12. Use cases

### UC-01. Обычная регистрация права

**Actors:** государственный реестр, регистратор, Anchoring Service.  
**Flow:** workflow подписан → DB изменена → CDC и workflow сопоставлены → canonical version → batch → finalized anchor → certificate.  
**Acceptance:** запись попала в anchor не позднее SLA; sequence непрерывен; proof проходит проверку.

### UC-02. Проверка QR владельцем

**Actors:** владелец, Public Verifier.  
**Flow:** scan QR → load/decode certificate → issuer signature → canonical hash → Merkle proof → Solana finalized anchor → incident check.  
**Result:** historical validity и отдельный признак current status.

### UC-03. Проверка при недоступном государственном backend

Verifier использует certificate и два Solana RPC/локальный архив. Возвращает `VERIFIED_HISTORICAL`; актуальный юридический статус помечает как непроверенный.

### UC-04. Прямое изменение записи администратором БД

Monitor видит изменение без signed workflow event, локализует leaf, блокирует публикацию либо открывает incident. Последняя подтверждённая версия остаётся доступной.

### UC-05. Компрометация workflow-аккаунта

Система проверяет HSM signature, dual approval, case references и anomalies. Если все внешние подтверждения также скомпрометированы, OneLayer сохраняет историю, но не может самостоятельно определить незаконность исходного решения.

### UC-06. Компрометация Anchor Publisher

Атакующий не может изменить старые anchors. Новая публикация ограничена sequence и previous anchor hash. Independent Monitor открывает incident; governance отзывает OperatorRole и ротирует ключ.

### UC-07. Недоступность Solana

Anchoring queue сохраняется в WORM storage; государственный реестр продолжает работу. После восстановления сети batches публикуются последовательно. SLA фиксирует максимальное unanchored window.

### UC-08. RPC-провайдер возвращает ложные данные

Verifier сравнивает ответы минимум двух независимых RPC и при конфликте использует собственный archival node/третьего провайдера. Для аудита требуется `finalized`.

### UC-09. Восстановление из replica

Snapshot hash проверяется, threshold key собирается, база пересчитывается и reconciles с anchors. Несовпадения изолируются для ручной проверки.

### UC-10. Исправление законной ошибки

Старая версия не удаляется. Создаётся новый signed workflow event с reason code, новая record version и новый certificate. Старый certificate получает статус `SUPERSEDED`, оставаясь исторически проверяемым.

### UC-11. Смена schema/hash algorithm

Governance публикует AlgorithmTransition, одновременно рассчитываются старый и новый root в transition window. После подтверждения verifier принимает новый algorithm version.

### UC-12. Массовый импорт

Import разбивается на deterministic batches, каждый имеет source cursor range, import job ID и signed manifest. До production выполняется полный reconciliation и sampling юридических дел.

### UC-13. Банк проверяет объект

Банк получает consent/authorisation, отправляет certificate или selective proof, получает signed verification response. API не раскрывает больше данных, чем требуется цели проверки.

### UC-14. Открытие и закрытие инцидента

Monitor создаёт evidence bundle → on-chain IncidentNotice → investigation → governance resolution → signed resolution report → corrective batch. Anchor history не переписывается.

### UC-15. Отзыв ключа оператора

Governance отзывает OperatorRole, создаёт новую роль для HSM key, публикует rotation record и проверяет, что batches после cutoff подписаны только новым ключом.

---

## 13. Безопасность

### 13.1. Identity и network

- mTLS service-to-service;
- workload identity вместо static secrets;
- OIDC для операторов;
- PAM/JIT access;
- separate admin workstations;
- egress allowlist для Publisher;
- Publisher не имеет inbound-доступа из public network;
- DB credentials read-only и ограничены schema/view.

### 13.2. Keys

- HSM для operator и issuer signing;
- multisig/timelock для upgrade authority;
- rotation минимум ежегодно и после incident;
- key IDs входят в manifests;
- backup keys разделены от anchor keys;
- secrets никогда не пишутся в logs.

### 13.3. Supply chain

- pinned Rust/Anchor/Solana versions;
- reproducible builds;
- SBOM;
- signed container images;
- dependency audit;
- static analysis, fuzzing, property tests;
- независимый аудит программы и сервисов;
- bytecode hash публикуется перед upgrade.

### 13.4. Privacy

Hash не объявляется анонимным автоматически. Необходимы DPIA/регуляторное заключение, анализ linkability, retention salts, selective disclosure, обработка запросов субъектов данных и отдельный анализ cross-border replicas.

---

## 14. Наблюдаемость и SLO

### 14.1. Метрики

- `cdc_lag_seconds`;
- `workflow_match_failure_total`;
- `unanchored_events_total`;
- `batch_prepare_duration_seconds`;
- `solana_submit_latency_seconds`;
- `solana_finalization_latency_seconds`;
- `anchor_sequence_gap_total`;
- `integrity_discrepancy_total`;
- `certificate_verify_duration_ms`;
- `snapshot_replica_verified_total`;
- `restore_reconciliation_records_per_second`.

### 14.2. Целевые SLO

| SLO | Цель |
|---|---:|
| Out-of-process detection p95 | <15 минут |
| Anchored authorised events | ≥99,9% |
| Unresolved sequence gaps | 0 |
| Certificate verification p95 | <3 секунды online |
| Maximum unanchored window | ≤15 минут, кроме network incident |
| Snapshot replica hash verification | 100% по расписанию |
| False-positive incidents после pilot | <0,1% events |

---

## 15. Тестирование

### 15.1. On-chain

- unit tests instruction constraints;
- sequence replay/skip tests;
- unauthorized signer tests;
- ledger capacity/seal tests;
- pause/resume tests;
- incident lifecycle tests;
- account substitution tests;
- property-based tests для serialization;
- fuzzing instruction data;
- local validator integration;
- devnet end-to-end;
- upgrade migration tests.

### 15.2. Off-chain

- golden canonicalization vectors;
- Unicode/date/decimal edge cases;
- Merkle proof vectors;
- CDC duplicate/out-of-order events;
- workflow mismatch;
- HSM unavailable;
- Solana RPC disagreement;
- expired blockhash/retry/idempotency;
- certificate tampering;
- snapshot corruption;
- disaster recovery exercise;
- load test at 10× expected peak.

### 15.3. Security exercises

- stolen DB admin credential;
- stolen operator credential without HSM;
- compromised RPC;
- malicious insider with workflow signing;
- ransomware destroying primary and connected backups;
- attempted unauthorised threshold ceremony;
- compromised upgrade authority simulation.

---

## 16. Deployment

### 16.1. Environments

- local validator;
- Solana devnet + synthetic registry;
- isolated shadow pilot;
- mainnet pre-production with non-PII synthetic batches;
- mainnet production.

### 16.2. Recommended topology

- Kubernetes/OpenShift in government environment;
- separate namespace/account for Monitor;
- HSM-backed Publisher in isolated subnet;
- PostgreSQL HA for metadata;
- S3-compatible immutable object storage;
- two external RPC providers + optional own archival RPC;
- SIEM integration;
- no public access to internal APIs.

### 16.3. Release gates

1. legal/privacy approval;
2. schema and canonicalization freeze;
3. threat model sign-off;
4. program audit;
5. backend penetration test;
6. 60-day shadow pilot;
7. restore drill;
8. governance/key ceremony approval;
9. mainnet go-live decision.

---

## 17. Открытые проектные решения

До production необходимо утвердить:

- точный состав canonical record;
- юридически значимый authorised workflow event;
- anchor interval;
- daily ledger capacity и rent budget;
- необходимость SPL Account Compression или достаточно собственного batch Merkle tree;
- issuer certificate disclosure model;
- HSM vendor и multisig governance;
- RPC/archive strategy;
- custodian organisations;
- threshold policy;
- допустимость cross-border replicas;
- статус certificate в суде;
- incident authority и порядок correction;
- immutable или governed-upgrade Solana program;
- secondary anchor network.

**Рекомендация:** для первой версии не использовать SPL Account Compression без необходимости. OneLayer не управляет миллионами independently mutable on-chain assets; он публикует один root на batch. Собственный простой Anchor program с дневным ledger легче аудировать. SPL Concurrent Merkle Tree следует рассматривать только если появится требование обновлять и доказывать отдельные leaves непосредственно on-chain.

---

## 18. План реализации

### Phase 0 — 2–3 месяца

- аудит source DB/change log/workflow;
- data classification и DPIA;
- canonical schema v1;
- threat model;
- prototype Merkle/QR/verifier;
- Solana devnet program;
- решение по custodian model.

### Phase 1 — 3–4 месяца

- shadow CDC adapter;
- workflow matching;
- batch builder;
- independent monitor;
- devnet/mainnet synthetic anchors;
- 60-дневная проверка discrepancies.

### Phase 2 — 4–6 месяцев

- audited program;
- HSM publisher;
- mainnet anchors;
- public verifier;
- certificate issuance on request;
- incident workflow;
- production observability.

### Phase 3 — 6–12 месяцев

- mass certificates;
- bank/notary API;
- encrypted custodian replicas;
- threshold ceremonies;
- full restore drill;
- algorithm transition rehearsal.

---

## 19. Источники по Solana

- [Solana core concepts](https://solana.com/docs/core)
- [Accounts](https://solana.com/docs/core/accounts)
- [Programs](https://solana.com/docs/core/programs)
- [Program Derived Addresses](https://solana.com/docs/core/pda)
- [Transactions](https://solana.com/docs/core/transactions)
- [Fees](https://solana.com/docs/core/fees)
- [RPC and commitment levels](https://solana.com/docs/rpc)
- [getTransaction](https://solana.com/docs/rpc/http/gettransaction)
- [getSignatureStatuses](https://solana.com/docs/rpc/http/getsignaturestatuses)
- [Program deployment and upgrades](https://solana.com/docs/programs/deploying)
- [Anchor framework](https://www.anchor-lang.com/)
- [Anchor account constraints](https://www.anchor-lang.com/docs/references/account-constraints)

---

## 20. Итоговое техническое решение

Минимально безопасная production-архитектура OneLayer — это не «hash базы в Solana». Это связанная система из:

1. независимого signed workflow stream;
2. детерминированной канонизации;
3. versioned record commitments;
4. Merkle batches и independently stored manifests;
5. HSM-backed публикации последовательных roots;
6. простой auditable Solana-программы;
7. independent integrity monitor;
8. переносимых certificates;
9. encrypted replicas в разных trust boundaries;
10. юридически определённого incident и recovery governance.

Только совокупность этих компонентов отвечает на главный риск: если администраторский доступ скомпрометирован, система должна не просто сохранить новый hash, а сопоставить изменение с независимым разрешённым событием, локализовать расхождение, сохранить последнюю подтверждённую версию и предоставить проверяемое доказательство для расследования и восстановления.
