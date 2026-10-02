# 15 — Реальные Backup Centers, read-back и retention

Status: ready-for-agent
Execution: not-started
Owner: unassigned
Role: Recovery/Storage
Phase: P5
Blocked by: 14

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Локальная demo модель copies/read-back/retention.
- Осталось: Реальные независимые storage adapters/centers и scoped custodian UI.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Закрыть S3/S5/S6: копия должна существовать в выбранном независимом storage.

## Scope и источники

backup storage adapters; apps/demo-api/src/backup.ts; snapshot catalog; retention/GC

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Lab использует пять реальных volumes/credentials; ciphertext читается из выбранного центра, а не central PostgreSQL.
- [ ] COPIED требует read-back hash; partial failure и retry видны per-center; catalog доступен без primary DB.
- [ ] Retention сохраняет доверенную копию, учитывает active recovery/Object Lock и удаляет разрешенные orphan envelopes; логические 12 и физический объем различаются.
- [ ] Есть quotas/capacity alert и отказ при нехватке места; поврежденная replica не маскируется здоровым central package.

## Проверка

Отключение credentials/volume, corruption отдельного replica, недоступная DB, 13+ snapshots, immutable object и единственная доверенная копия.

## Evidence и handoff

При исполнении создать `../evidence/15/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.
