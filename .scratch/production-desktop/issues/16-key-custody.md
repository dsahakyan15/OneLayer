# 16 — Provisioning, 3-of-5 custody и ротация ключей

Status: ready-for-agent
Execution: in-review
Owner: Boole (explicit software lab key configuration)
Role: Recovery/Storage
Phase: P5
Blocked by: 01, 14

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Explicit software writer key config и immutable version binding.
- Осталось: Provisioning/custody/rotation, индивидуальные shares; default demo не provisioned автоматически.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Закрыть S4 и исключить сохранение пяти shares в обычном API-процессе.

## Scope и источники

key provisioning tools; snapshot writer KEK access; key versions; recovery interfaces

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] KEK не генерируется заново без миграции при каждом API startup; immutable key version references имеют provisioning lifecycle.
- [ ] Shares выдаются отдельным holders с подтверждением получения; writer не получает shares, ordinary renderer/API не получает все пять.
- [ ] Production KMS/HSM policy или явно ограниченный lab adapter проверяет identities; software KEK fallback не объявляется криптографической изоляцией.
- [ ] Rotation сохраняет восстановимость старых snapshots; потеря двух holders/restart работает, потеря нужной key version дает честную блокировку.

## Проверка

Restart/rotation drill и 2-of-5/3-of-5, duplicate indices, wrong version, expiry; secret leakage checks. Production ceremony отдельно в 22/23.

## Evidence и handoff

При исполнении создать `../evidence/16/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.

2026-10-01: начат ранний bounded срез explicit restart-stable software lab KEK с version binding; исправляется implicit per-startup generation и issuer-key fallback. Production custody/HSM и isolated Recovery Controller не заявляются, dependencies остаются открытыми.

2026-10-01: explicit writer configuration и durable immutable version binding (0018) реализованы; [evidence](../evidence/16/report.md). Full custody/HSM/Recovery Controller acceptance остается открытым.
