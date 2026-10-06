# 13 — Audit, evidence и восстановление projections

Status: ready-for-agent
Execution: not-started
Owner: unassigned
Role: Backend/Identity + Monitor
Phase: P4
Blocked by: 07, 08, 12

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Частичные audit events и legacy Timeline.
- Осталось: Scoped search/export, evidence bundles и восстановление projections.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Сделать действия и восстановление индексов прослеживаемыми вне одной mutable DB.

## Scope и источники

audit module; db/migrations/; incident/lifecycle projections; external evidence sink

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Критические действия имеют actor/device/action/resource/scope/outcome/time/operation ID и integrity references.
- [ ] Журнал не содержит tokens, shares, keys или лишние раскрытые поля; read/export ограничены правами.
- [ ] Независимый append-only/защищенный destination позволяет обнаружить удаление/rollback локальной audit projection.
- [ ] Index rebuild из проверенного источника воспроизводим, сохраняет completeness и не дает false current во время rebuild.

## Проверка

Rollback/delete локального журнала, повтор delivery, rebuild после crash, forbidden audit export и secret-redaction assertions.

## Evidence и handoff

При исполнении создать `../evidence/13/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.
