# 11 — Все рабочие кабинеты и сквозные ролевые действия

Status: ready-for-agent
Execution: claimed
Owner: MiMo V2.6 Pro (high)
Role: Desktop
Phase: P3
Blocked by: 05, 08, 09, 10

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Отдельный English web workflow кабинет; часть legacy web screens.
- Осталось: Все native кабинеты, полный happy/deny pipeline каждой роли, reconnect/restart acceptance.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Дать участникам полные пользовательские потоки, а не декоративный dashboard.

## Scope и источники

apps/desktop/; packages/ui/; typed API client; accessibility tests

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Records/diff/approvals/publication/certificates/verify/incidents/access/audit экраны используют реальные API и разрешения.
- [ ] Все длинные операции показывают phase/operation ID и переживают reconnect/restart; accepted не отображается как finalized.
- [ ] Verification различает current/historical/revoked/unknown/disputed и freshness; QR/package disclosure следует field scope.
- [ ] Backup/recovery экраны имеют contract и подключаются к реальной реализации 15–18 в acceptance 21; отсутствующие возможности честно помечены недоступными, не показывают fake success.

## Проверка

По одному полному happy и deny flow для каждой роли; exact signing review; export permissions; записи без утечек в search/autocomplete. Итоговое recovery E2E выполняется в 21.

## Evidence и handoff

При исполнении создать `../evidence/11/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.

2026-10-01: реализован bounded RegistryWorkflow кабинет на английском и реальный OIDC HTTP-сценарий. [Evidence](../evidence/11/report.md). Остальные ролевые/native/recovery/publication acceptance остаются открытыми.

2026-10-02 continuation: English web workflow workspace gains pending-attempt
recovery, explicit cancellation and draft discovery without UUID hand-off.
Production browser validation PASS; real GTK smoke and local services startup
PASS. The GTK shell remains a lab/demo, and native password-demo login does not
provision scoped workflow/OIDC access. This is not completion of all eight role
workspaces or full native signer/recovery flows. See
[evidence](../evidence/workflow-recovery-2026-10-02.md).


2026-10-06: текущий ограниченный срез выполняется в `feat/pipeline-live-demo-20261006` через T3 orchestration. Полные acceptance и зависимости остаются открытыми; итоги и evidence будут опубликованы после интеграционной проверки.

### 2026-10-07 — guided live scenario

The visible GTK create/submit/different-approver/commit/exact-plan publication/
selective certificate/QR/verify/export path passed against the real local
validator and a clean PR-source demo API. Rejection/correction, worker approval
refusal and tampered-copy refusal also passed. Evidence:
[evidence/11/guided-live-scenario-2026-10-07.md](../evidence/11/guided-live-scenario-2026-10-07.md).
This is one accepted service-backed business walkthrough, not acceptance of the
entire eight-role recovery/audit desktop matrix or signed installed release.
