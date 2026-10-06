# 06 — Private ingress и закрытие сетевой утечки demo

Status: ready-for-agent
Execution: in-progress
Owner: Codex
Role: Backend/Identity
Phase: P1
Blocked by: 01

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Локальные сервисы слушают loopback.
- Осталось: Managed-device private ingress и доказанная deployment boundary.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Закрыть S1 и исключить обход доступа через прямые backend/package endpoints.

## Scope и источники

apps/demo-api/src/main.ts; apps/verifier/src/main.ts; deploy/devnet-demo/native; будущий ingress config

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Native demo API/verifier реально bind на loopback; проверены listening sockets, а не только переменные URL.
- [ ] Deployment recipe закрывает прямые backend ports; доступ возможен только через предусмотренный private ingress.
- [ ] Device identity принимается только от проверенного ingress; spoofed forwarded headers не создают доверенное устройство.
- [ ] Package/QR/metadata/verify paths включены в общий access contract; отсутствие public ingress доказано в test topology.

## Проверка

Network allow/deny tests и test reverse proxy. Production device-provider provisioning относится к 22; local proof не заменяет его.

## Evidence и handoff

При исполнении создать `../evidence/06/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.

2026-09-19: работа начата. Частичные результаты и незакрытые критерии: [evidence](../evidence/06/report.md). Задача целиком не закрыта.
