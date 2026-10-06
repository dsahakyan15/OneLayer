# 02 — Desktop spike: установка, SSO и signer

Status: ready-for-agent
Execution: blocked
Owner: desktop-agent
Role: Desktop
Phase: P0
Blocked by: 01

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: GTK lab harness; отдельные callback/broker/install эксперименты.
- Осталось: Собрать выбранный desktop runtime с настоящими login/signer/update flows.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Доказать пригодность desktop stack на настоящем окне/установке и выбрать путь подписания.

## Scope и источники

apps/mvp-web/; apps/mvp-web/lib/wallet.ts; будущий apps/desktop/; ADR-0007

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Минимальное приложение собирается и устанавливается на первой целевой production-конфигурации Linux Mint 22.1 x86_64; ограничения поддержки записаны. Windows/macOS и другие Linux-дистрибутивы не входят в первый выпуск.
- [ ] OIDC через внешний браузер с PKCE/callback и native credential store проверен на test identity; secrets не попадают в renderer storage.
- [ ] Проверен реальный signer flow: browser extension не предполагается доступным в WebView; выбран и испытан внешний browser или device/service путь с exact-byte binding.
- [ ] Определен перенос React UI без Next.js server routes в desktop; signed update lab flow и permissions/custom command scope проверены.

## Проверка

Native smoke с версиями ОС/WebView, test signer и ошибками callback/signing. Решение о Tauri подтверждено или заменено обоснованным ADR, spike не выдается за production UI.

## Evidence и handoff

При исполнении создать `../evidence/02/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.

2026-09-19: работа начата. Частичные результаты и незакрытые критерии: [evidence](../evidence/02/preflight.md). Задача целиком не закрыта.

2026-09-20: desktop-agent реализовал executable Linux GTK runtime lab (не новый production stack), disposable installer, PKCE/callback и approval-binding experiments, Secret Service fail-closed adapter. 7 tests и реальный native smoke PASS; [report](../evidence/02/report.md), screenshot (локальный артефакт: `../evidence/02/native-smoke.png`; не включён в документационный PR). Полная acceptance заблокирована отсутствием Tauri/Qt dev toolchains, test IdP/backend integration, реального signer/review и signed updater; dependency 01 остается открытой. Independent review pending.

2026-09-21: added actual ephemeral loopback callback transport and six TCP adversarial tests; fixed empty duplicate state/code acceptance. 13 tests PASS and repeated installed GTK smoke PASS (approved local socket/display access), [continuation evidence](../evidence/02/report.md). Production candidate/IdP/signer/updater gates remain open; independent review pending.

2026-09-24: пользователь выбрал Linux для первой production-версии. Текущая ОС подтверждена через `/etc/os-release` и `uname -m`: Linux Mint 22.1 x86_64. Это целевая конфигурация spike и приемки; Windows/macOS отложены. Развилка выбора ОС снята; выбор Tauri/Qt и оставшиеся acceptance-проверки открыты, Execution остается blocked. Решение записано в ADR-0007; исторические отчеты Linux lab не являются подтверждением production-поддержки.
