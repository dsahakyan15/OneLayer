# 03 — Gate C exit evidence и synthetic soak
**What to build:** владелец release должен получить воспроизводимое evidence
закрытия Gate C: стабильный synthetic pilot, корректный incident index,
проверенный browser/public flow, approved devnet smoke и полный bounded
backup/recovery сценарий. Ticket фиксирует только evidence MVP и не объявляет
production recovery готовым.

**Blocked by:** `02 — Recovery, Restore Approval и acceptance E2E`; baseline
`OL-C-01`…`OL-C-41` считается уже завершённым и отдельными tickets не
переиздаётся.

**Status:** ready-for-agent

- [ ] Synthetic flow работает 72 часа без ручного вмешательства и формирует
      воспроизводимый soak report.
- [ ] За soak-период `anchor_sequence_gap_total = 0`, а повторная сборка одного
      source range даёт идентичный `manifestHash`.
- [ ] Finalized `IncidentOpened` и `IncidentResolved` корректно меняют
      incident index и watermark; stale/unavailable index не выдаёт ложный
      `VERIFIED`.
- [ ] Deterministic browser flow проходит import, canonical preview,
      transaction review, mock Wallet Standard signing, finalized package, QR и
      `VERIFIED`, включая `INVALID`/`DISPUTED` tampering branches.
- [ ] Guarded live-devnet smoke с отдельным approval проходит
      `QR → finalized anchor → VERIFIED` и не передаёт ключи в браузер.
- [ ] Backup/recovery acceptance evidence подтверждает replication во все
      active centers, retry, retention 12, `2-of-5` отказ, `3-of-5` успех,
      повреждённый package, root mismatch и chief approval.
- [ ] Evidence явно помечено как bounded synthetic MVP и не заявляет
      географическую независимость центров, production restore drill или
      закрытие release gate 7.
- [ ] Все обязательные acceptance results, traces/screenshots и remediation
      для неуспешного preflight собраны в воспроизводимом release report.
