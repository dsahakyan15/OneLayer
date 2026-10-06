# 19 — CI, installers, signed updates и supply chain

Status: ready-for-agent
Execution: claimed
Owner: Codex coordinator
Role: Release/Ops
Phase: P7
Blocked by: 02, 10

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: GTK CI/installed harness smoke; не пользовательская приемка.
- Осталось: Bundled installer, signed updates/rollback, compatibility и supply-chain gates.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Сделать поставку desktop/backend воспроизводимой и проверяемой.

## Scope и источники

.github/workflows/; build scripts; desktop bundling/updater; artifact manifest

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] CI включает scope-appropriate Rust/TS/contracts/migrations/local-chain и native build gates; новые команды реально существуют и документированы.
- [ ] Artifacts имеют SBOM/digest/provenance; signing secrets недоступны недоверенным PR jobs; production signing отдельно от lab keys.
- [ ] Installer/update для каждой заявленной ОС испытан; неверная подпись/несовместимый version отклоняются.
- [ ] Server-client version handshake и downgrade/rollback policy позволяют безопасный rollout; проверенный artifact продвигается по digest.

## Проверка

Rebuild/provenance check, signed test update/tampered update, install/uninstall/upgrade smoke на каждой поддерживаемой ОС; dependency/secrets scan evidence.

## Evidence и handoff

При исполнении создать `../evidence/19/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.

2026-10-01: добавлен отдельный Linux GTK CI job с live virtual display, unit/interaction tests и installed smoke artifact. Запуск на GitHub не заявлен; production bundling/signing/updates остаются открытыми.

2026-10-01: локальные команды GTK CI (virtual display) 27 tests + installed smoke PASS; [evidence](../evidence/19/gtk-ci-2026-10-01.md). GitHub-run, Tauri bundle и signed updates остаются открытыми.


2026-10-06: текущий ограниченный срез выполняется в `feat/pipeline-live-demo-20261006` через T3 orchestration. Полные acceptance и зависимости остаются открытыми; итоги и evidence будут опубликованы после интеграционной проверки.
