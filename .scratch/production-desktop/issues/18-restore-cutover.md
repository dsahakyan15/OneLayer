# 18 — Полный restore в новую target и управляемый cutover

Status: ready-for-agent
Execution: not-started
Owner: unassigned
Role: Recovery/Storage + Backend
Phase: P6
Blocked by: 09, 12, 17

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Demo сохраняет digest/summary и ставит RESTORED.
- Осталось: Настоящий target import, validation, writer fencing, cutover и rollback.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Закрыть F5: после RESTORED должна существовать проверенная работающая target DB.

## Scope и источники

apps/recovery/; import adapters; migrations; writer fencing; desktop recovery progress

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Полный state импортирован в пустую target из независимого storage при недоступной primary DB и остановленных старых процессах.
- [ ] Проверены schema/references/counts/commitments, старый QR, lifecycle и новая версия/publication; summary-only запись не дает RESTORED.
- [ ] Pending sends и external side effects отключены до cutover; chain reconciliation не повторяет уже finalized операции.
- [ ] Отдельный cutover approval, writer fencing и catch-up boundary предотвращают split brain; partial failure/rollback policy испытаны.

## Проверка

Clean-room drill на известном dataset с old host shutdown, поврежденным одним storage, двумя недоступными holders и отказом посреди import; измерить RPO/RTO.

## Evidence и handoff

При исполнении создать `../evidence/18/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.
