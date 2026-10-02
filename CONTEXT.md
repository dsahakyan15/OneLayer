# OneLayer Domain Context

OneLayer делает состояния реестра проверяемыми и восстанавливаемыми. Этот словарь фиксирует язык сертификатов, доказательств и backup-восстановления для MVP.

## Certificate and proof

**Certificate Package**:
Подписанный пакет, содержащий раскрытые данные объекта и доказательства их связи с finalized anchor. Пакет является источником возвращаемых данных сертификата; blockchain хранит его доказательный anchor.
_Avoid_: on-chain certificate, raw certificate JSON

**Record Version**:
Отдельное неизменяемое состояние одного объекта реестра в момент публикации. Новое состояние получает новую версию, даже если объект уже имел сертификат.
_Avoid_: overwrite, current row

**Anchor**:
Зафиксированное в blockchain состояние batch с `merkleRoot` и служебными ссылками. `FINALIZED` anchor — единственный anchor, который может быть принят как завершённый для проверки и восстановления.
_Avoid_: certificate hash, database snapshot

**Merkle Root**:
Короткое обязательство ко всему batch записей, с которым сравниваются Merkle proofs отдельных сертификатов и snapshots.
_Avoid_: data hash, QR hash

**Merkle Proof**:
Доказательство, что конкретный record commitment входит в batch, чей `merkleRoot` опубликован в finalized anchor.
_Avoid_: QR signature

**Full Record**:
Режим сертификата, в котором пакет раскрывает все разрешённые поля выбранной версии записи. Он не означает, что поля записаны в blockchain.
_Avoid_: on-chain record

## Backup and recovery

**Backup Center**:
Отдельное место хранения зашифрованных snapshots. Центр хранит ciphertext, но не является держателем recovery share.
_Avoid_: key holder, recovery key

**Snapshot**:
Зафиксированный пакет полного рабочего state OneLayer: records, record versions, certificate packages, QR metadata, proofs, roots, manifests, anchor references и история операций.
_Avoid_: database dump, folder copy

**Finalized Snapshot**:
Snapshot, чей `MerkleRoot` совпал с выбранным finalized anchor без открытого incident. Такой snapshot защищён retention-политикой как минимально необходимая доверенная копия.
_Avoid_: latest file, newest backup

**Recovery Share**:
Одна из пяти долей recovery key. Любые три доли восстанавливают ключ расшифрования, а две доли недостаточны.
_Avoid_: backup password, center key

**Restore Approval**:
Отдельное подписанное разрешение `chief_admin` на восстановление конкретного snapshot, его root и target. Оно не заменяет recovery shares.
_Avoid_: operator confirmation, fourth share

**Retention Window**:
Правило, по которому каждый BackupCenter хранит не более 12 snapshots и сохраняет хотя бы один Finalized Snapshot. Старейшие не-finalized snapshots удаляются первыми.
_Avoid_: arbitrary cleanup, manual delete

## Roles

**Operator**:
Администратор ежедневного контура: создаёт backup centers и запускает создание новых копий, но не может один восстановить state.
_Avoid_: recovery admin, key holder

**Auditor**:
Read-only участник, который просматривает centers, folders, statuses, roots и историю операций.
_Avoid_: backup operator

**Chief Admin**:
Роль, которая отдельно подписывает Restore Approval после предоставления трёх Recovery Shares.
_Avoid_: one-person recovery, operator

**Key Holder**:
Участник, который хранит собственную Recovery Share и предоставляет её для конкретной операции восстановления. Он не получает полномочий на изменение реестра или Restore Approval только в силу владения долей.
_Avoid_: backup center, sole recovery admin

## Product language

User decision, 2026-10-01: the application interface is English. Launcher and
workspaces use English navigation, labels, status explanations, accessibility
text and errors. Protocol identifiers and registry/user-provided values retain
their original bytes; this does not translate or rewrite record contents.
Internal project documentation and discussion may remain Russian.

## Implementation boundary — 2026-10-02

The definitions above describe intended domain semantics. Current demo Snapshot capture omits newer workflow/publication state; RESTORED records a validated digest/summary without importing a usable target database. A finalized anchor does not establish current document suitability. The normal launcher has no usable login or role workspace. See [current implementation status](docs/implementation-status-2026-10-02.md) before interpreting these terms as delivered behavior.
