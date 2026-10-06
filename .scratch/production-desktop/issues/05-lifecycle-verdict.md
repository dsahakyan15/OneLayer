# 05 — Проверяемая актуальность и честный verification result

Status: ready-for-agent
Execution: in-review
Owner: coordinator (V2 contract and client integration)
Role: Protocol/Trust
Phase: P1
Blocked by: 03, 04, 09

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: V2 contract/client честно возвращают UNKNOWN без доказанной актуальности.
- Осталось: Authenticated complete lifecycle source и CURRENT.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Закрыть F4: историческое включение не должно подменять текущую пригодность записи.

## Scope и источники

apps/verifier/src/verify.ts; http-adapters.ts; server.ts; lifecycle projection; spec/

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Versioned result отдельно возвращает proofs, registry, incidents, lifecycle, checkedAt и observed slots.
- [ ] Null/error/stale lifecycle не дает CURRENT; REVOKED, HISTORICAL, DISPUTED и UNKNOWN различаются в API.
- [ ] Утвержден и реализован проверяемый lifecycle source: state proof/checkpoint либо независимо контролируемый журнал с доказательством полноты; ответ mutable DB сам себя не удостоверяет.
- [ ] Compatibility mapping не позволяет старому VERIFIED трактоваться новым клиентом как доказанная актуальность; отзыв/новая версия из реального workflow видны корректно.

## Проверка

Real-backend flow: v1 issue → v2 publish/revoke → lifecycle outage/rollback → verification; чужой certificate ID не получает current result.

## Evidence и handoff

При исполнении создать `../evidence/05/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.

2026-10-01: начата интеграция уже существующего `/v2/verify` с английским UI. Независимый authenticated complete lifecycle source остаётся открытой dependency; CURRENT не вводится на основе mutable projection.

2026-10-01: V2 contract, English client, no-fallback/unknown/malformed-result regressions и real API→verifier evidence реализованы. [Evidence](../evidence/05/v2-contract-and-client-2026-10-01.md). CURRENT не заявляется; полный authenticated lifecycle acceptance остается открытым.
