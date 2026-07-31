# batch-manifest-v1

**Статус:** frozen (Gate B)
**Реализации:** `crates/canonical`, `packages/canonical-ts`
**Векторы:** `spec/vectors/manifest.json`

## 1. Неподписанный манифест

`BatchManifestV1` кодируется deterministic CBOR по профилю
`canonical-record-v1.md`. Имена полей ниже — text keys CBOR map; hash-значения
кодируются byte string, целые — unsigned integer, `snapshotHash` — byte string
ровно 32 байта либо CBOR `null`.

| Поле | Тип |
|---|---|
| `manifestVersion` | unsigned, только `1` |
| `registryIdHash` | bytes(32) |
| `batchSequence` | u64 |
| `registryVersion` | u64 |
| `sourceCursorStart` / `sourceCursorEnd` | u64 |
| `createdAt` | RFC 3339 UTC без дробной части |
| `schemaVersion` | u16 |
| `hashAlgorithm` | text, только `SHA256` |
| `treeAlgorithm` | text, только `RFC6962_SHA256_V1` |
| `leafCount` | u32, больше нуля |
| `merkleRoot` / `previousAnchorHash` | bytes(32) |
| `snapshotHash` | bytes(32) или `null` |
| `leavesObjectUri` | NFC text |
| `leavesObjectHash` | bytes(32) |
| `builderVersion` / `operatorKeyId` | NFC text |

Поля вне этого перечня запрещены. `manifestSignature` и публичный ключ не входят
в неподписанный CBOR.

## 2. Hash и подпись

```text
unsigned_manifest_cbor = deterministic_cbor(BatchManifestV1 без подписи)
manifest_hash           = SHA-256(unsigned_manifest_cbor)
manifest_signature      = Ed25519.sign(operator_secret_key, manifest_hash)
```

Подпись проверяется над 32 байтами `manifest_hash`, не над hex-строкой.
Публичный ключ — 32 байта Ed25519, подпись — 64 байта. `manifest_hash`,
публикуемый в anchor, обязан совпадать с пересчитанным значением.

## 3. Инварианты

- `sourceCursorStart <= sourceCursorEnd`;
- `leafCount > 0`: пустые batch запрещены;
- повторная сборка одинаковых входов даёт идентичный unsigned CBOR и hash;
- изменение любого поля ломает hash, изменение hash ломает подпись;
- URI не загружается до успешной проверки hash и подписи манифеста.
