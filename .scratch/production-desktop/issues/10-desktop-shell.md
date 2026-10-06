# 10 — Устанавливаемая программа, вход и ролевой каркас

Status: ready-for-agent
Execution: claimed
Owner: MiMo V2.6 Pro (high)
Role: Desktop
Phase: P3
Blocked by: 02, 07

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: English Overview/Connection и ручные health probes.
- Осталось: Настройка профиля, обычный вход, реальный workspace, credential/session integration.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Поставить рабочий desktop shell с настоящим входом, безопасным bridge и server-driven permissions.

## Scope и источники

apps/desktop/; выделяемые packages/ui и api-contracts; существующий apps/mvp-web

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Есть installer/launch для первой целевой production-конфигурации Linux Mint 22.1 x86_64, подписанный environment profile и заметное различие demo/staging/production.
- [ ] Вход/refresh/logout/device revoke работают с настоящим test IdP/backend; renderer не хранит refresh/keys.
- [ ] Navigation отражает разрешенный scope; direct deep link не обходит backend authorization; native commands минимальны и явно ограничены.
- [ ] Есть offline/error/expired session/loading states, keyboard accessibility, масштабирование и restart с восстановлением operation IDs.

## Проверка

Installed-app smoke, PKCE callback hijack/replay negative case в test harness, logout/revoke/offline; browser component tests только дополняют native evidence.

## Evidence и handoff

При исполнении создать `../evidence/10/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.

2026-09-21: inspected prerequisites and recorded [handoff](../evidence/10/report.md). No production shell acceptance claimed: candidate platform gate 02 and real IdP/backend device lifecycle 07 remain incomplete. Ticket02 callback transport advanced independently; ticket10 production integration awaits those contracts.

2026-09-24: по решению пользователя первый выпуск ориентирован на Linux, целевая конфигурация — Linux Mint 22.1 x86_64. Installed-app acceptance выполняется на ней; Windows/macOS отложены за пределы первого выпуска. Выбор ОС больше не открыт, зависимости 02/07 и Execution blocked сохраняются до их приемки.

## Первый UI лаунчера — 2026-10-01

В Linux GTK lab реализован Demo launcher: обзор/подключение, состояние сессии, три карточки доступности и явная фоновая проверка с deadline. Entry point: `apps/desktop/launcher`. Финальные Python/GTK 27/27 и installed smoke PASS; synthetic IdP session integration PASS. [Evidence, screenshot и review disposition](../evidence/10/launcher-ui-2026-10-01.md). Это постепенное развитие установленного harness; основной кандидат Tauri 2 + React, production dependencies 02/07 и полный Execution blocked сохраняются.

2026-10-01: Boole (DeepSeek v4.1 Flash, max reasoning) переводит весь launcher UI на английский; production dependencies и Execution blocked сохраняются.


2026-10-06: текущий ограниченный срез выполняется в `feat/pipeline-live-demo-20261006` через T3 orchestration. Полные acceptance и зависимости остаются открытыми; итоги и evidence будут опубликованы после интеграционной проверки.
