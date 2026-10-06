# 17 — Изолированный Recovery Controller и Restore Approval

Status: ready-for-agent
Execution: not-started
Owner: unassigned
Role: Recovery/Storage
Phase: P6
Blocked by: 07, 14, 15, 16

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Обычный API имеет bounded demo ceremony и software approval.
- Осталось: Изолированный controller, отдельные holder sessions и внешняя точная approval подпись.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Организовать сбор отдельных долей и отдельное полномочное разрешение на точную recovery operation.

## Scope и источники

apps/recovery/; recovery API/contracts; desktop holder/chief views; recovery state store

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Operation связывает registry/snapshot/checkpoint/target/key version/nonce/expiry; controller доступен по отдельной policy.
- [ ] Каждый holder отправляет только свою share; три различных корректных contributions дают проверку payload, два не дают.
- [ ] Chief Admin approval подписан отдельным credential и связан со всеми критическими полями; replay/target swap/expired approval отвергаются.
- [ ] State transitions durable, cancellation/timeout очищает временные материалы; обычный audit не содержит shares/plaintext.

## Проверка

Real identity/controller flow: operator + три holders + chief; self-approval restrictions, replay, altered target/root, controller crash и cleanup.

## Evidence и handoff

При исполнении создать `../evidence/17/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.
