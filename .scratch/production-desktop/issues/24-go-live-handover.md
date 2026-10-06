# 24 — Go-live, ограниченный rollout и передача эксплуатации

Status: ready-for-human
Execution: not-started
Owner: unassigned
Role: Владелец системы + Release/Ops
Phase: P8
Blocked by: 23

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Не выполнено.
- Осталось: Принятые gates, управляемый rollout и передача эксплуатации.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Запустить согласованную production версию и передать систему ответственным операторам.

## Scope и источники

Release manifest; installers/backend artifacts; runbooks; training; rollback plan

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Все девять release gates старого плана имеют проверенное evidence; явное go-live решение относится к конкретным digests/config/cluster.
- [ ] Ограниченный rollout проходит health/role/publication/verification smoke; расширение выполняется только при выполненных thresholds.
- [ ] Проверены fencing/rollback и совместимость migrations/client; rollback не переписывает законную finalized историю.
- [ ] Ролевые инструкции и обучение operator/auditor/holder/chief завершены; назначены on-call, доступ к evidence и расписание повторных restore drills.

## Проверка

Production smoke в разрешенном scope с approved dataset, rollout log и ownership handoff. Выполнять deployment только по конкретному разрешению, не автоматически из плана.

## Evidence и handoff

При исполнении создать `../evidence/24/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.
