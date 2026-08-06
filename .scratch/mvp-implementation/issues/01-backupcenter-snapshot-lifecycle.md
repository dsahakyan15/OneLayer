# 01 — BackupCenter и полный Snapshot lifecycle

**What to build:** оператор должен управлять bounded backup-контуром из Admin:
видеть пять стартовых локальных `BackupCenter`-ов, добавлять новые центры,
создавать полный immutable `SnapshotPackageV1`, реплицировать его во все
активные центры и понимать per-center результат. Retention Window должна
автоматически удерживать не более 12 snapshots на центр.

**Blocked by:** None — can start immediately.

**Status:** implemented

- [x] После инициализации Admin показывает пять локальных `BackupCenter`-ов с
      отдельными volume/credentials, folders, health и replica status.
- [x] `operator` может создать шестой и последующие локальные центры;
      `auditor` и `chief_admin` могут только просматривать их, а внешняя
      production-регистрация не появляется в MVP.
- [x] `Обновить копии` создаёт один полный immutable `SnapshotPackageV1`,
      включающий records, `Record Version`-ы, `Certificate Package`-ы, QR
      metadata, proofs, roots, manifests, anchor references и operation history.
- [x] Snapshot шифруется существующим AES-256-GCM/DEK/KEK-контуром; plaintext и
      `Recovery Share` не сохраняются в persistence, browser storage или logs.
- [x] Одна и та же Snapshot replica отправляется во все active centers, не
      перезаписывает предыдущие folders и получает явный per-center status:
      `COPIED`, `PENDING_RETRY` или ошибка.
- [x] Повторное нажатие `Обновить копии` идемпотентно в рамках операции и не
      создаёт две replica для одной пары snapshot/center.
- [x] Offline/unavailable center не скрывает partial success: после
      восстановления доступности его replica можно безопасно повторить.
- [x] Retention Window ограничивает каждый center 12 snapshots; после 13-й
      валидной копии удаляется старейшая не-`FINALIZED`, а единственный
      `Finalized Snapshot` сохраняется.
- [x] Ручное удаление backup недоступно для всех ролей, а retention сохраняет
      provenance старых immutable folders.
- [x] Admin API enforce-ит role/session/CSRF boundaries, а deterministic browser
      E2E покрывает bootstrap пяти центров, создание дополнительного центра,
      snapshot happy path, replication, retry и retention.
