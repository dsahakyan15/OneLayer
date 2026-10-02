# 01 — Baseline, модель угроз и обязательные контракты

Status: ready-for-agent
Execution: in-progress
Owner: Codex
Role: Coordinator
Phase: P0
Blocked by: none

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Ведутся спецификация, ADR и permission contracts.
- Осталось: Завершить и принять все контракты, threat model и acceptance.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Зафиксировать фактический baseline и контракты, на которых безопасно строить рабочее приложение.

## Scope и источники

AGENTS.md; CONTEXT.md; docs/adr/; spec/; review; действующие MVP и implementation plans

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Перепроверены F1–F5 и S1–S7 review: для каждого есть воспроизведение либо аргументированное изменение вывода, приоритет и владелец.
- [ ] Определены threat actors, trusted dependencies, failure domains; permission matrix и запреты self-approval/самоповышения зафиксированы с примерами.
- [ ] API operations, domain errors, idempotency, совместимость versions и source-of-truth описаны; будущие protocol changes перечислены отдельно от V1.
- [ ] Production ОС, IdP/device enrollment, signer, source, storage, workload и RPO/RTO имеют выбранное значение либо ответственного и точный зависимый gate; baseline checks записаны.

## Проверка

Docs review + запуск существующих тестов по областям. Не помечать неизвестные infrastructure решения принятыми.

## Evidence и handoff

При исполнении создать `../evidence/01/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.

2026-09-19: работа начата. Частичные результаты и незакрытые критерии: [evidence](../evidence/01/report.md). Задача целиком не закрыта.
