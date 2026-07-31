# error-codes

**Статус:** frozen (Gate B; Gate E коды добавлены аддитивно)

Единый словарь ошибок программы, pipeline и verifier. Публичные ответы содержат
только код и bounded message; сырой provider payload не возвращается и не
сохраняется.

## 1. On-chain

| Код | Условие |
|---|---|
| `ACCOUNT_VERSION_UNSUPPORTED` | account version не равна 1 |
| `UNAUTHORIZED_GOVERNANCE` | signer не governance authority |
| `UNAUTHORIZED_EMERGENCY` | signer не emergency authority |
| `OPERATOR_MISMATCH` | role принадлежит другому signer или registry |
| `OPERATOR_INACTIVE` | роль ещё не активна, истекла или отозвана |
| `MISSING_PERMISSION` | отсутствует требуемый permission bit |
| `REGISTRY_PAUSED` | публикация/создание segment запрещено pause-флагом |
| `REGISTRY_NOT_PAUSED` | операция требует предварительно приостановленный registry |
| `BAD_SEQUENCE` | batch sequence не равна current + 1 |
| `REGISTRY_VERSION_ROLLBACK` | registry version уменьшилась |
| `INVALID_CURSOR_RANGE` | source cursor start больше end |
| `BROKEN_ANCHOR_CHAIN` | previous anchor hash не равен config head |
| `SCHEMA_MISMATCH` | schema version не равна config |
| `HASH_ALGORITHM_MISMATCH` | hash algorithm не равен config |
| `TREE_ALGORITHM_MISMATCH` | tree algorithm не равен config |
| `INVALID_LEDGER_CAPACITY` | capacity не равна 46 |
| `BAD_SEGMENT_INDEX` | segment index не является следующим для дня |
| `WRONG_LEDGER_DAY` | segment не относится к текущему UTC day |
| `LEDGER_REGISTRY_MISMATCH` | segment принадлежит другому registry |
| `LEDGER_SEALED` | segment/day уже запечатан |
| `LEDGER_FULL` | entry count достиг capacity |
| `SEGMENT_GAP` | sealing получил неполную/непоследовательную цепочку segments |
| `EMPTY_LEDGER_DAY` | sealing вызван без entries |
| `EMPTY_BATCH` | anchor input не содержит ни одного leaf |
| `INVALID_INCIDENT_RANGE` | first suspect batch больше last |
| `INCIDENT_ALREADY_RESOLVED` | повторный resolve |
| `INVALID_INCIDENT_STATUS` | финальный status не разрешён ABI v1 |
| `INVALID_ALGORITHM_TRANSITION` | schema не увеличена, алгоритм не изменён или identifier равен нулю |
| `INVALID_GOVERNANCE_AUTHORITY` | новая governance authority совпадает с текущей |

## 2. Pipeline и canonicalization

| Код | Условие |
|---|---|
| `CANONICALIZATION_FAILED` | поле вне schema, path > 65535 bytes, CBOR integer/type invalid |
| `MERKLE_EMPTY` | дерево без листьев |
| `MERKLE_INDEX_OUT_OF_RANGE` | proof index отсутствует |
| `SOURCE_CURSOR_GAP` | независимая проверка обнаружила разрыв source cursor |
| `WORKFLOW_EVENT_MISSING` | change не сопоставлен с подписанным workflow event |
| `PUBLISH_ATTEMPT_CONFLICT` | конкурентная попытка нарушила уникальность batch/attempt |
| `PUBLISH_OUTCOME_FINAL` | повторное или обратное разрешение terminal outcome |
| `RPC_RESPONSE_INVALID` | RPC payload не прошёл schema/owner/length/discriminator checks |

## 3. Verifier status

Итоговый `verificationStatus`:

| Статус | Значение |
|---|---|
| `VERIFIED` | signature, proofs, finalized anchor и incident check успешны |
| `VERIFIED_HISTORICAL` | certificate доказан, существует более новая record version |
| `VERIFIED_NO_INCIDENT_CHECK` | криптографическая проверка успешна, incident index не доказал полноту |
| `SUPERSEDED` | certificate заменён и policy требует отдельного статуса |
| `DISPUTED` | batch покрыт открытым/подтверждённым incident |
| `INVALID` | криптографическая или schema-проверка не прошла |

`incidentIndexStatus`:

| Статус | Условие |
|---|---|
| `CHECKED` | lag в пределах threshold и watermark дошёл до anchor slot |
| `STALE` | lag выше threshold или watermark ниже anchor slot |
| `UNAVAILABLE` | index недоступен либо watermark отсутствует |
| `INDEX_INCONSISTENT` | watermark выше собственного finalized RPC head |
| `RPC_DISAGREEMENT` | два RPC head расходятся сверх threshold (Gate E) |

## 4. Verifier errors

| Код | Условие |
|---|---|
| `CERT_SIGNATURE_INVALID` | issuer signature неверна |
| `CERTIFICATE_FORMAT_INVALID` | deterministic CBOR/package shape нарушены |
| `CANONICALIZATION_FAILED` | disclosed value не воспроизводится по schema |
| `FIELD_PROOF_INVALID` | field proof не приводит к field root |
| `MERKLE_PROOF_INVALID` | batch proof не приводит к anchored root |
| `RECORD_ID_MISMATCH` | record commitment не связан с заявленным record ID commitment |
| `ANCHOR_NOT_FOUND` | segment/entry отсутствует |
| `ANCHOR_NOT_FINALIZED` | commitment ниже finalized |
| `ANCHOR_ACCOUNT_INVALID` | owner, discriminator, PDA, layout или program ID неверны |
| `ANCHOR_DISPUTED` | независимые RPC вернули разные finalized данные |
| `SCHEMA_UNSUPPORTED` | schema version не поддерживается |
| `RECORD_SUPERSEDED` | существует более новая record version |
| `CURRENT_STATUS_UNAVAILABLE` | актуальное состояние реестра недоступно |
| `INCIDENT_INDEX_REGISTRY_MISMATCH` | ответ index относится к другому registry ID |

HTTP mapping минимален: malformed input → `400`, cryptographically invalid
package → `422`, missing certificate/anchor → `404`, unavailable dependency →
`503`, internal invariant violation → `500`. `DISPUTED` и
`VERIFIED_NO_INCIDENT_CHECK` — успешные `200` ответы со статусом, не transport
errors.
