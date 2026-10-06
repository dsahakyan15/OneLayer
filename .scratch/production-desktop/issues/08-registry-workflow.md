# 08 — Записи, версии и независимое согласование

Status: ready-for-agent
Execution: in-review
Owner: workflow-agent
Role: Backend/Identity
Phase: P2
Blocked by: 07

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Draft/revision/submit/independent approval/commit/outbox; recovery receipts и draft discovery в web/API.
- Осталось: Единый Records/import workflow, native screens и полный publication handoff.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Сделать изменения реестра управляемыми, воспроизводимыми и защищенными от гонок.

## Scope и источники

apps/demo-api/src/admin.ts; record-schema.ts; db/migrations/; Registry Workflow module

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Draft, submit, approve/reject связаны с точным payload hash и исходной версией; правка draft аннулирует прежнее approval.
- [ ] Изменение утверждает другой человек; сочетание ролей не позволяет self-approval.
- [ ] Immutable Record Version, audit и outbox фиксируются атомарно; optimistic concurrency отклоняет потерянное обновление.
- [ ] Source adapter определяет signed workflow evidence/cursor полноту; duplicate/gap/reorder/delete/tombstone имеют явное поведение.

## Проверка

Concurrent edits, approve-then-edit, self-approval, outbox crash и повтор source event; synthetic source с полноценным contract, без доверия к boolean authorized.

## Evidence и handoff

При исполнении создать `../evidence/08/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.

2026-09-20 — workflow-agent: backend synthetic slice implemented in Registry Workflow V1; exact hash/revision/base binding, contributor self-approval denial, concurrent CAS, immutable version/audit/outbox transactions and three-signature contiguous source ingestion. Disposable PostgreSQL integration: 2 PASS, 0 skip; typecheck PASS. [Evidence](../evidence/08/report.md). Acceptance remains open until independent review, coordinator HTTP integration and prerequisite07 completion; production source integration/high-watermark and desktop flow are not claimed.

2026-09-21 — workflow-agent: продолжение закрывает два воспроизведенных trust-boundary дефекта: replay авторизует историческую revision и base payload; source ingestion сохраняет snapshot подписанного envelope до первого await. Добавлены source cursor failure rollback, concurrent duplicate и revoked approver replay проверки. Dependency07, production source high-watermark, native flow и независимый review остаются открыты.

2026-10-01 — ADR-0009 exclusion backend verified with 3 real PostgreSQL tests (fresh queue and claimed-operation supersession, two independent scoped approvals, exact correction binding, immutable history). Contract updated; production implementation already present. Evidence records separate existing concurrent-edit 404/409 defect. Issuance/UI/verifier lifecycle excluded from this slice; independent review pending.

2026-10-01: Poincare (DeepSeek v4.1 Flash, max reasoning) выполняет bounded correction concurrent-edit CAS 404/409; полный acceptance остаётся in-review на prerequisites.

2026-10-01 — workflow-agent (continuation): закрыт записанный concurrent-edit дефект [200,404]→[200,409]. Причина: единый запрос `JOIN wf_revision … FOR UPDATE OF d` терял новую revision при lock recheck; ветка теперь берёт блокировку строки draft отдельным statement, затем читает связанную revision с новым snapshot. Новый детерминированный adversarial тест `apps/demo-api/integration/workflow-concurrency.test.ts` на disposable PostgreSQL: `pg_sleep`-триггер удерживает победителя, `pg_locks` подтверждает ожидание; проверены stale revision → 409 `REVISION_CONFLICT`, отсутствующий draft → 404 `DRAFT_NOT_FOUND`, CAS-гонка коммитов через admin-диспетчер → [200,409] `BASE_VERSION_CONFLICT`, отсутствие lost update, audit/outbox/idempotency-следов у отказа и сохранность payload-hash привязки approval. Репро-проверка: на временно возвращённом старом shape тест падает с [200,404]. Типчек PASS, unit 124/124, полный integration 72/72. [Evidence](../evidence/08/report.md). Ограничения: dispatcher-level, не live HTTP; prerequisite 07, production source high-watermark, native flow и независимый review открыты; коммита нет.

2026-10-02 continuation: server-owned durable attempts now survive browser/API
restart, including safe fenced cancellation and scoped paged draft discovery.
English UI and 110 affected browser checks pass; live scoped OIDC workflow and
focused PostgreSQL negative/restart cases pass. See
[evidence](../evidence/workflow-recovery-2026-10-02.md). Native password-demo
identities remain outside scoped v2 workflow access; no role/permission fallback
has been added. Production identity and publication gates remain open.
