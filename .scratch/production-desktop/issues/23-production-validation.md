# 23 — Независимые проверки, реальный restore drill и shadow pilot

Status: ready-for-human
Execution: not-started
Owner: unassigned
Role: Владелец системы + независимые reviewers
Phase: P8
Blocked by: 21, 22

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Не выполнено.
- Осталось: Независимые проверки, restore drill и shadow pilot.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Закрыть обязательные production gates старого плана на реальной инфраструктуре.

## Scope и источники

IMPLEMENTATION_PLAN.md release gates; audit/pentest reports; shadow pilot; recovery evidence

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Program audit и backend penetration test завершены независимыми проверяющими; критические findings устранены и перепроверены.
- [ ] Restore drill выполнен в реальных независимых custodian environments с hardware identities/custody; проверены old QR и продолжение публикации.
- [ ] 60-day shadow pilot с разрешенными реальными данными завершен после legal/privacy допуска; SLO/RPO/RTO измерены.
- [ ] Governance/key ceremony, threat model и legal/privacy approvals получены; остаточные риски имеют владельцев и допустимый disposition.

## Проверка

Отдельные отчеты и signatures/digests evidence; локальный harness и self-review агента не закрывают независимый аудит.

## Evidence и handoff

При исполнении создать `../evidence/23/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.
