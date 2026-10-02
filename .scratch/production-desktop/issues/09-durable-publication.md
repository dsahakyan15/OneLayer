# 09 — Надежный publication и signer flow

Status: ready-for-agent
Execution: in-review
Owner: publication agent
Role: Backend/Identity + Protocol/Trust
Phase: P2
Blocked by: 02, 03, 04, 08

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Durable worker/intent/journal/reconciliation реализованы и тестируются отдельно.
- Осталось: Runtime consumer, signer UI, wf_version → finalized anchor → certificate issuance.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Связать согласованные версии с finalized anchor и корректной выдачей Certificate Package.

## Scope и источники

apps/pilot-pipeline/; apps/demo-api/src/admin-batch.ts; admin-transaction.ts; transaction-state.ts; onchain client

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Builder детерминирован; независимый расчет сверяет commitment; durable queue не теряет попытки и сохраняет ordering.
- [ ] Signer подтверждает разрешенное действие и точные bytes после simulation; payload/blockhash changes требуют повторной предусмотренной проверки.
- [ ] UNKNOWN/expired/crash/double click проходят reconciliation без повторного логического anchor; leases/attempt transitions защищены от двух workers.
- [ ] Certificate выдаётся только после подтвержденного FINALIZED и согласно disclosure policy; повтор команды идемпотентен, версия/отзыв поступают в lifecycle source.

## Проверка

Real PostgreSQL + local chain pipeline; timeout-after-send, worker crash, two publishers, expired blockhash, signing rejection, paused registry.

## Evidence и handoff

При исполнении создать `../evidence/09/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.

## Partial implementation — 2026-09-24

Durable PostgreSQL workflow handoff implemented: immutable membership, exclusive expiring leases, fenced reclaim preserving operation identity, payload verification, append-only attempt journal. Real PostgreSQL negative/concurrency/crash tests pass. [Evidence](../evidence/09/report.md). This is an internal queue foundation; no trusted Builder/signer/finalized-chain completion or Certificate Package issuance is claimed. Acceptance remains unchecked; coordinator review and dependencies remain outstanding.

## Partial implementation — intent, attempt journal, trusted completion (2026-09-24)

Added deterministic publication intent from immutable membership (existing canonical-ts/merkle-ts builders, new `ONELAYER:WORKFLOW:FIELDMAP:V1`), exact intent bytes/hash stored before any attempt and re-verified every step; append-only fenced attempt journal with exact signed bytes, signature, blockhash and lastValidBlockHeight stored before send; reconciliation (UNKNOWN/timeout/crash/expired/double step) without a second logical anchor; trusted completion that alone sets FINALIZED after matching the finalized ledger entry with the intent; DB guards against generic FINALIZED transitions. Migration `0013_workflow_publication_chain.sql`. Real PostgreSQL negative tests and a live local-validator test (registry program from source) pass. [Evidence](../evidence/09/report.md).

Still open: Certificate Package issuance + disclosure policy + lifecycle hand-off, native signer approval, independent verifier review of FIELDMAP/intent protocol, key custody, conflict/mismatch operator procedure. Found: legacy `admin.ts` segment `dayUtc` uses days-since-epoch while the program expects YYYYMMDD. Execution stays in-review; acceptance boxes remain unchecked.

## Review fixes — 2026-09-24

Independent review (5 MAJOR, 5 MINOR, 8 evidence overclaims) addressed: context-slot-aware reconciliation with landing search before any new attempt or conflict (EXPIRED→FINALIZED only with proof), confirmed-read ANCHOR_MISMATCH, two-person fenced ABANDONED maintenance exit with successor via superseded_by, `__proto__`-safe CBOR and workflow contract V1.1 (safe integers, no `__proto__`, NFC-distinct keys), hardened 0013 triggers (TRUNCATE, fence, event sequence, anchor↔intent), PREPARED reservation before signing, chain-time ledger day with midnight guard, FAILED retry limit. Evidence rewritten with a findings/disposition table. Still open: certificate issuance/disclosure/lifecycle, native signer approval, authenticated maintenance identities, DB role separation, chain re-check at issuance, protocol review of FIELDMAP/intent. Execution stays in-review.

## Review round 2 fixes — 2026-09-24

Round 2 (N1–N10, INFO) addressed: terminal LANDED_DISCREPANCY procedure for our own landed-but-mismatched anchor (no completion loop, no successor), ledger-entry proof when status history is pruned, typed PUBLICATION_UNPUBLISHABLE_VERSION with documented queue stop (quarantine options for the owner), stale-slot fix after EXPIRED, FAILED recording on abandonment, own-landing-first classification, OPEN-only/creation-transaction membership guards and locked lease check, transaction-scoped step lock, identity normalization, abandonment gated on block or force. Evidence updated with a round-2 disposition table. Open: issuance/disclosure/lifecycle, native signer, authenticated maintenance principals (07), DB roles, custody exits on verify failure (16), protocol review. Execution stays in-review.


## ADR-0009 archival safety continuation — 2026-10-01

Owner for this bounded slice: publication_safety agent. Existing archival reconciliation/approval implementation inspected and exercised with real disposable PostgreSQL and synthetic chain/archive. Forced abandonment of a pruned own landing is rejected in worker and SQL; archival recovery distinguishes FINALIZED from LANDED_DISCREPANCY without a successor. Added regression coverage for incomplete/lagging archive, live blockhash, exact/newest evidence binding, independent approvals and approved foreign cancellation. Fixed SQL three-valued-logic bypass: FOREIGN_PROVEN evidence with a missing/null proof is rejected. See [evidence](../evidence/09/report.md). Execution remains in-review; no acceptance checkbox is closed by this bounded slice.
