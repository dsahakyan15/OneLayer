# 20 — Deployment, наблюдаемость и runbooks

Status: ready-for-agent
Execution: claimed
Owner: MiMo V2.6 Pro (high)
Role: Release/Ops
Phase: P7
Blocked by: 06, 12, 13, 15, 18, 19

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Native devnet script, private state guards и отдельный readiness CLI.
- Осталось: Runtime wiring всех контуров, operational observability, runbooks и RPO/RTO.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Обеспечить работу системы при деградациях без ложного успеха.

## Scope и источники

deploy/; configs/secrets references; metrics/logging; runbooks; health endpoints

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Deployment разделяет application/monitor/signer/recovery/storage identities; startup проверяет environment/trust/cluster/schema.
- [ ] Readiness отличается от liveness; upstream timeouts, parse limits, backpressure и capacity quotas имеют измеримые значения.
- [ ] Metrics/alerts отражают publication backlog, index completeness, monitor latency, per-center trusted age, recovery и authz/update failures.
- [ ] Runbooks loss RPC/DB/issuer/holder/storage/device и rollback/cutover испытаны в lab; RPO/RTO измеряются на согласованной нагрузке.

## Проверка

Restart/failover/disk-full/network-partition exercises, stale index, compromised test issuer revoke и observability assertions без secrets.

## Evidence и handoff

При исполнении создать `../evidence/20/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.


2026-10-06: текущий ограниченный срез выполняется в `feat/pipeline-live-demo-20261006` через T3 orchestration. Полные acceptance и зависимости остаются открытыми; итоги и evidence будут опубликованы после интеграционной проверки.
