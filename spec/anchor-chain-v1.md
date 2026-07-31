# anchor-chain-v1

**Статус:** draft (замораживается на выходе Gate B)
**Реализация:** `crates/canonical/src/anchor.rs`
**Векторы:** `spec/vectors/anchor.json`

## 1. `anchor_preimage`

Единственный нормативный формат для хэширования якоря. Явная конкатенация
фиксированной ширины, независимая и от Borsh, и от layout аккаунта.

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

`published_at` — знаковое, кодируется в дополнительном коде big-endian.

Правила:

* zero-copy layout используется **только** для хранения в аккаунте и может
  меняться между версиями программы без влияния на протокол;
* Borsh используется только для instruction data;
* поля `_pad` storage-структуры в preimage не входят;
* `operator_pubkey` и `published_at` заполняет программа, не Publisher.

Все поля фиксированной ширины, поэтому префиксы длины не нужны: границы
полей не сдвигаются ни при каких значениях.

## 2. Genesis

```text
last_anchor_hash(genesis) = SHA-256("ONELAYER:GENESIS:V1" || registry_id_hash)
```

Первый якорь реестра несёт это значение в `previous_anchor_hash`.

## 3. Границы гарантий (нормативно)

> Solana-программа гарантирует **только**: непрерывность последовательности
> anchor (`batch_sequence`), связность цепочки (`previous_anchor_hash`),
> авторизацию публикующего и неизменность опубликованных entries.
> Непрерывность и полноту потока source events она не гарантирует и не
> может гарантировать — эти свойства проверяются Integrity Monitor путём
> независимого сравнения диапазонов `source_cursor` последовательных
> манифестов с собственным чтением источника.

Программа проверяет только `source_cursor_start <= source_cursor_end`.
Publisher с корректными `batch_sequence` и `previous_anchor_hash` способен
пропустить диапазон событий, и это не будет отвергнуто on-chain.

Перенос гарантии on-chain (`RegistryConfig.last_source_cursor_end` и
проверка `source_cursor_start == last_source_cursor_end + 1`) — решение
`OL-DEC-02`, принимается после Gate A.

## 4. Пустые batch

Batch создаётся только при наличии ≥ 1 canonical record version в
диапазоне. Интервал без событий не порождает ни batch, ни транзакцию.
`batch_sequence` инкрементируется только при фактической публикации.
