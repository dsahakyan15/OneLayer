# 21 — Сквозная приемка установленного приложения и 72-hour soak

Status: ready-for-agent
Execution: not-started
Owner: unassigned
Role: QA/Security Reviewer
Phase: P8
Blocked by: 11, 18, 19, 20

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Есть ограниченные unit/integration/browser-fixture проверки.
- Осталось: Installed-app happy/deny для 8 ролей, full restore и 72-hour soak.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Получить воспроизводимое evidence полного приложения на synthetic данных.

## Scope и источники

tests/acceptance/; installed client; real backend/local chain/storage; .scratch evidence

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Все роли проходят свои реальные потоки и forbidden direct API cases; backup/recovery UI подключен к реальным 15–18, нет fixture-only success.
- [ ] Negative matrix review F1–F5/S1–S7 покрыта и пройдена; screenshots/traces не содержат secrets/PII.
- [ ] 72-hour synthetic soak измеряет gaps/backlog/errors/recovery, а не только uptime; сбои не требуют скрытой ручной починки.
- [ ] Evidence указывает commit/OS/runtime/dataset hashes/commands и ограничения; независимый reviewer проверил результаты.

## Проверка

План §11 целиком, native install/SSO/signer/update, complete clean-room restore, restart/reconnect и permission matrix. Это не 60-day real shadow pilot.

## Evidence и handoff

При исполнении создать `../evidence/21/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.
