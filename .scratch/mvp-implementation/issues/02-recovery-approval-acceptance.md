# 02 — Recovery, Restore Approval и acceptance E2E

**What to build:** оператор должен пройти bounded recovery flow от выбранного
центра и Snapshot до восстановления полного рабочего state, а `chief_admin`
должен отдельно подписать разрешение. Весь пользовательский flow и его
ошибочные ветки должны быть проверены через существующий browser acceptance
seam.

**Blocked by:** `01 — BackupCenter и полный Snapshot lifecycle`.

**Status:** implemented

- [x] `operator` может выбрать `BackupCenter` и Snapshot folder и ввести три
      masked `Recovery Share` только в памяти операции.
- [x] Две доли (`2-of-5`) отклоняются; три доли (`3-of-5`) восстанавливают KEK
      только для текущей операции, без сохранения shares в БД, browser storage,
      logs или replica storage.
- [x] Система автоматически выбирает самый новый `FINALIZED` anchor без
      открытого incident и явно показывает выбранный anchor/root.
- [x] До approval проверяются `ciphertextHash`, расшифрованный
      `plaintextHash` и `Merkle Root` Snapshot; mismatch любого значения
      останавливает flow fail-closed.
- [x] После успешной threshold/hash/root-проверки операция переходит в
      состояние ожидания `Restore Approval`, не выполняя restore автоматически.
- [x] Только `chief_admin` может подписать approval, связанный с `snapshotId`,
      `Merkle Root` и target; `operator` и `auditor` не могут обойти это
      требование прямым API-вызовом.
- [x] Подписанный approval не заменяет `Recovery Share` и не позволяет
      восстановить другой Snapshot, другой root или другой target.
- [x] После approval полный Snapshot восстанавливается в bounded local demo
      target; plaintext доступен только внутри операции восстановления и
      корректно очищается после завершения.
- [x] Любая ошибка выбора anchor, incident status, share count, decryption,
      hash/root check или approval завершает операцию без частичного restore и
      без ложного success status.
- [x] Browser acceptance E2E покрывает пять стартовых центров, дополнительный
      центр, replication, offline retry, 13-ю копию и retention, повреждённый
      ciphertext, `2-of-5` отказ, `3-of-5` успех, root mismatch, role separation,
      chief approval и успешный restore.
- [x] UI показывает доступные причины отказа и не раскрывает shares, plaintext
      или приватные ключи в DOM, API-ответах и timeline.
