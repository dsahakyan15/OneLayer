# 14 — Full-state checkpoint и согласованный Snapshot

Status: ready-for-agent
Execution: not-started
Owner: unassigned
Role: Recovery/Storage + Protocol/Trust
Phase: P5
Blocked by: 03, 04, 05, 09, 12

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Legacy snapshot capture; не включает новый workflow/publication state.
- Осталось: Полная inventory, consistent checkpoint, schema-versioned restore.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Закрыть S2/S7: FINALIZED Snapshot должен быть доказательством полного восстанавливаемого состояния.

## Scope и источники

spec/snapshot/checkpoint новая версия; apps/demo-api/src/admin.ts snapshot code; packages/snapshot-ts/; db/migrations/

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Versioned checkpoint связывает plaintext hash, artifact inventory, source boundary, schema/key versions и trusted finalized reference; нет циклического self-hash.
- [ ] Полный payload содержит необходимые versions/packages/proofs/history/cursors/pending state и recovery key references; исключены shares/управляющие private keys.
- [ ] Capture консистентен при параллельном publish; реальный пересчет отвергает tampered payload даже с прежними DB root labels.
- [ ] NON_FINALIZED/UNVERIFIED не превращается в FINALIZED до chain/incident/completeness checks; V1 migration/compatibility описаны.

## Проверка

Concurrency capture/publish, changed DB root, missing artifact, wrong schema/key version; cross-language vectors для нового protocol и recovery inventory check.

## Evidence и handoff

При исполнении создать `../evidence/14/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.
