# leaf-v1

**Статус:** frozen (Gate B; owner sign-off `OL-A-05` учитывается отдельно)
**Реализация:** `crates/canonical/src/commit.rs`
**Векторы:** `spec/vectors/leaf.json`, `spec/vectors/batch.json`

Документ фиксирует §2.1 плана: обязательства к полям, дерево полей,
обязательство к записи и лист batch-дерева.

## 1. Термины

`*_commitment` — доменно-разделённое обязательство к содержимому.
`*_leaf_hash` — RFC 6962-обёртка, отделяющая листья от внутренних узлов.

Это **разные** значения, и оба присутствуют в векторах раздельно. Слово
«leaf» не употребляется без префикса `field_tree_` или `batch_`.

## 2. Ключ солей

```text
record_field_key = random_32_bytes()    // CSPRNG, на версию записи
```

Хранится только в зашифрованном виде (`record_field_key_encrypted`,
envelope encryption; версия KEK — в `key_encryption_version`). **Не
попадает в сертификат и не возвращается ни одним API никогда.**
Ротации подлежит KEK, не ключ записи.

## 3. Обязательства

```text
path_bytes  = UTF-8( NFC(path) )         // нормализация ДО измерения длины
value_cbor  = deterministic_cbor(value)  // RFC 8949, см. canonical-record-v1

field_salt(path) = HMAC-SHA256(record_field_key,
                               "ONELAYER:FIELDSALT:V1" || path_bytes)

field_commitment(path) = SHA-256("ONELAYER:FIELD:V1" ||
                                 u16_be(byte_len(path_bytes)) || path_bytes ||
                                 u32_be(byte_len(value_cbor)) || value_cbor ||
                                 field_salt(path))

field_tree_leaf_hash(path) = SHA-256(0x00 || field_commitment(path))

field_root = корень дерева (merkle-tree-v1) по field_tree_leaf_hash,
             листья отсортированы по path_bytes

record_commitment = SHA-256("ONELAYER:RECORD:V1" || registry_id_hash ||
                            record_id_commitment ||
                            u64_be(record_version) || field_root)

batch_leaf_hash   = SHA-256(0x00 || record_commitment)

merkle_root = корень дерева по batch_leaf_hash,
              листья отсортированы по (record_id_commitment, record_version)
```

Вспомогательные значения:

```text
registry_id_hash     = SHA-256( UTF-8(NFC(registry_id)) )
record_id_commitment = HMAC-SHA256(id_key_vN,
                                   registry_id || 0x00 || internal_record_id)
genesis_anchor_hash  = SHA-256("ONELAYER:GENESIS:V1" || registry_id_hash)
```

Разделитель `0x00` в `record_id_commitment` обязателен: без него пары
`("ab", "c")` и `("a", "bc")` дают одно обязательство.

`record_id_commitment` входит в preimage обязательства к записи. Поэтому две
записи с одинаковыми `registry_id_hash`, `record_version` и `field_root`, но
разными `record_id_commitment`, дают разные `record_commitment`.

Префиксы длины в `field_commitment` обязательны по той же причине.

## 4. Длина — всегда в байтах

`len(·)` во всех формулах означает `byte_len` после кодирования:

* строка нормализуется (NFC) и кодируется в UTF-8 **до** измерения;
* значение сериализуется в deterministic CBOR **до** измерения — считается
  длина `value_cbor`, а не исходного значения;
* `byte_len(path_bytes) <= 65535`, превышение → `CANONICALIZATION_FAILED`;
* сортировка путей выполняется по `path_bytes`.

Причина: `"ы".length` в JavaScript равно 1, в UTF-8 это 2 байта. Без явного
правила Rust и TypeScript дают разные commitment на одних данных.

## 5. Состав сертификата

| Режим | Содержимое |
|---|---|
| `SELECTIVE_FIELDS` | `record_id_commitment`, значения раскрываемых полей, `field_salt` **только этих** путей, field-proof каждого, `field_root`, batch-proof |
| `FULL_RECORD` | `record_id_commitment`, все значения и все `field_salt`, batch-proof (`field_root` пересчитывается) |

Раскрытие одной соли не даёт вычислить другие: HMAC с секретным ключом
невосстановим по своим выходам.

`record_leaf_nonce` в протоколе отсутствует: при секретных `field_salt`
величина `field_root` уже неотличима от случайной для того, кто не знает
солей.

## 6. Известная утечка

Множество путей полей — утечка структуры: при `SELECTIVE_FIELDS` число
листьев field-дерева видно из proof. Скрытие требует дополнения дерева до
фиксированной степени двойки — решение владельца `OL-DEC-05`, по умолчанию
**не** реализуется.
