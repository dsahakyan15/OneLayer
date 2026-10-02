# 12 — Независимый Monitor и доказательства вмешательства

Status: ready-for-agent
Execution: in-progress
Owner: monitor-agent (Claude, coordinator-assigned 2026-09-28)
Role: Monitor
Phase: P4
Blocked by: 04, 08, 09

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Есть исходный monitor и тестовые harness; полная runtime готовность этим ревью не подтверждена.
- Осталось: Независимый запуск, полномочия, tamper detection/projection repair и сквозная приемка.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Обнаруживать изменения source вне утвержденного процесса, даже если переписан локальный root.

## Scope и источники

apps/monitor/; crates/canonical/; source adapter; evidence storage; incident contracts

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Monitor имеет отдельный процесс/credentials, read-only source и независимый расчет относительно Builder.
- [ ] Эталон загружается из доверенной chain/checkpoint boundary, не из редактируемой таблицы рядом с records.
- [ ] Tampering/gap/missing artifacts/backlog дают scoped evidence и policy-controlled реакцию; Monitor не получает право незаметно исправить source.
- [ ] Измерен out-of-process detection p95 на workload; цель <15 минут не объявлена выполненной без injected failures.

## Проверка

Изменить source поля, version, rows и локальный root в disposable environment; доказать alert/affected range даже при неисправном Builder.

## Evidence и handoff

При исполнении создать `../evidence/12/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.
