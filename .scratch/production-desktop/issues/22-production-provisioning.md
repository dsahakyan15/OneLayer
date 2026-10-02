# 22 — Production provisioning и ответственные за доверенные контуры

Status: ready-for-human
Execution: not-started
Owner: unassigned
Role: Владелец инфраструктуры + Release/Ops
Phase: P8
Blocked by: 01, 02, 15, 16, 19

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Не выполнено; нужны решения и инфраструктура владельца.
- Осталось: IdP, ingress, signer, storage, keys, release authority и ответственные.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Заменить lab assumptions реальными IdP/device/storage/signing/custody границами.

## Scope и источники

Организационные решения; production configs; inventory; custody и access policies

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Назначены владельцы IdP/device fleet, registry source, signer/governance/upgrade authority, release signing и incident response.
- [ ] Подтверждены поддерживаемые ОС, реальные private ingress/device admission и scopes; accounts provisioned без self-elevation.
- [ ] Backup Centers имеют доказанные независимые failure/identity domains, отдельные credentials и retention; Key Holders отдельны от Storage Custodians.
- [ ] KMS/HSM/key ceremony и подписанные trust profiles выполнены уполномоченными лицами; RPO/RTO/workload/privacy требования утверждены.

## Проверка

Агент готовит manifests/checklists и проверяет несекретные evidence. Люди выполняют реальные enrollment/custody решения; secrets в ticket не сохранять.

## Evidence и handoff

При исполнении создать `../evidence/22/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.
