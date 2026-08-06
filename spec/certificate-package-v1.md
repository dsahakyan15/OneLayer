# certificate-package-v1

**Статус:** frozen (Gate B)
**Кодирование:** deterministic CBOR по `canonical-record-v1.md`
**Векторы:** `spec/vectors/certificate.json`

## 1. Подписываемое тело

`CertificateBodyV1` — CBOR map с точным набором ключей:

| Поле | Тип |
|---|---|
| `format` | text, `ONELAYER_CERTIFICATE` |
| `version` | unsigned, `1` |
| `certificateId` | bytes(16), UUID |
| `registryId` | NFC text |
| `issuedAt` | RFC 3339 UTC без дробной части |
| `recordIdCommitment` | bytes(32) |
| `recordVersion` | u64 |
| `schemaVersion` | u16 |
| `disclosureMode` | `FULL_RECORD` или `SELECTIVE_FIELDS` |
| `disclosedFields` | map `path → canonical value` |
| `fieldSalts` | map `path → bytes(32)` |
| `fieldRoot` | bytes(32) |
| `fieldProofs` | array `FieldProofV1` |
| `batchProof` | `MerkleProofV1` |
| `anchor` | `AnchorReferenceV1` |
| `issuer` | `IssuerV1` |

Поля вне списка запрещены.

### 1.1. FieldProofV1

```text
{
  path: text,
  leafIndex: u32,
  siblings: [{ side: "LEFT" | "RIGHT", hash: bytes(32) }]
}
```

Proof строится от `field_tree_leaf_hash` раскрытого поля к `fieldRoot`.

### 1.2. MerkleProofV1

```text
{
  treeAlgorithm: "RFC6962_SHA256_V1",
  leafIndex: u32,
  leafHash: bytes(32),
  siblings: [{ side: "LEFT" | "RIGHT", hash: bytes(32) }],
  expectedRoot: bytes(32)
}
```

`leafHash` — `batch_leaf_hash`, `expectedRoot` — anchored `merkleRoot`.

### 1.3. AnchorReferenceV1

```text
{
  batchSequence: u64,
  registryVersion: u64,
  merkleRoot: bytes(32),
  manifestHash: bytes(32),
  solanaProgramId: bytes(32),
  segmentIndex: u16,
  segmentPda: bytes(32),
  transactionSignature: bytes(64),
  anchorSlot: u64,
  commitmentRequired: "finalized"
}
```

Verifier заново выводит segment PDA из seeds и сверяет program owner,
discriminator, account version и entry. Адрес из package не считается
доверенным.

### 1.4. IssuerV1

```text
{
  keyId: text,
  publicKey: bytes(32),
  signatureAlgorithm: "Ed25519"
}
```

## 2. Режимы раскрытия

| Режим | Инвариант |
|---|---|
| `FULL_RECORD` | `disclosedFields` содержит все поля, `fieldSalts` содержит те же пути, `fieldProofs` пуст; verifier пересчитывает полный `fieldRoot` |
| `SELECTIVE_FIELDS` | `disclosedFields`, `fieldSalts` и `fieldProofs` содержат один и тот же непустой набор путей; verifier проверяет proof каждого поля |

`record_field_key` и `record_field_key_encrypted` отсутствуют в package при
любом режиме. `recordIdCommitment` присутствует всегда и входит в
`record_commitment`.

## 3. Hash, подпись и package

```text
certificate_body_cbor = deterministic_cbor(CertificateBodyV1)
certificate_hash      = SHA-256(certificate_body_cbor)
issuer_signature      = Ed25519.sign(issuer_secret_key, certificate_hash)

CertificatePackageV1 = CertificateBodyV1 + {
  issuerSignature: bytes(64)
}
```

Подпись проверяется над 32 raw bytes `certificate_hash`. После декодирования
package verifier обязан повторно сериализовать тело и получить те же bytes;
альтернативное CBOR-кодирование отклоняется как `CERTIFICATE_FORMAT_INVALID`.

## 4. Порядок проверки

1. Проверить canonical CBOR, format/version/schema и issuer signature.
2. Проверить равенство наборов раскрытых путей по правилам режима.
3. Пересчитать `field_commitment` каждого раскрытого поля.
4. Получить `fieldRoot`: полная пересборка либо field proofs.
5. Пересчитать `record_commitment` с `recordIdCommitment`, затем
   `batch_leaf_hash`; проверить `batchProof`.
6. Получить finalized segment account, проверить PDA/program/entry и совпадение
   root, manifest hash, sequence и slot.
7. Проверить incident index по `registryId`, watermark и собственному
   finalized RPC head.

Любая криптографическая ошибка даёт `INVALID`; недоступный/устаревший incident
index понижает только до `VERIFIED_NO_INCIDENT_CHECK`.

## 5. QR pilot

Основной QR содержит один HTTPS URL:

```text
https://<verifier-host>/c/<lowercase-uuid>?h=<base64url(certificate_hash)>
```

Base64url без padding. PII, disclosed fields и package в QR не помещаются.
Animated/offline QR не входит в pilot.

Operational policy: the QR path is available only while the referenced on-chain
registry has an existing `RegistryConfig` with `paused = false`. This guard is
outside the frozen QR wire format: issuance, public QR endpoints and the
independent verifier must all fail closed with `REGISTRY_PAUSED` when the
registry is paused.
