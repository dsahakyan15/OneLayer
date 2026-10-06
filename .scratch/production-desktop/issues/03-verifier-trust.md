# 03 — Закрепить доверие verifier к issuer, program и registry

Status: ready-for-agent
Execution: in-review
Owner: Codex
Role: Protocol/Trust
Phase: P1
Blocked by: 01

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Локальные trust-policy/anti-rollback проверки и harness.
- Осталось: Принять полный trust acceptance, provisioned roots и независимый review.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Устранить F1: корректная математическая подпись от произвольного ключа не должна давать доверенный сертификат.

## Scope и источники

apps/verifier/src/verify.ts; apps/verifier/src/solana-rpc.ts; packages/canonical-ts/; spec/

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Trust policy поступает извне package и закрепляет registry/config, cluster/program, issuer keys, versions и алгоритмы.
- [ ] Чужой issuer, program, ledger другого registry и неправильный config PDA отвергаются, даже если proofs структурно корректны.
- [ ] Есть проверяемый lifecycle trust policy: expiry/rotation/revocation и защита от rollback; легальная история после ротации проверяется по явной политике.
- [ ] Versioned конфигурация и migration не меняют frozen certificate encoding молча; недоступный trust material дает fail-closed.

## Проверка

Regression переподписи ID/issuer + отрицательные chain binding tests; positive тест доверенного issuer после ротации; реальные account constraints в локальном chain harness.

## Evidence и handoff

При исполнении создать `../evidence/03/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.

2026-09-19: работа начата. Частичные результаты и незакрытые критерии: [evidence](../evidence/03/report.md). Задача целиком не закрыта.

2026-09-24 (Protocol/Trust agent): continuation. Добавлены durable anti-rollback watermark (revision + sha256 digest, atomic tmp+fsync+rename, fail-closed на missing/corrupt/unavailable state, явный bootstrap), опциональная authenticated distribution (Ed25519 signed envelope, trust-root ключи из `ONELAYER_TRUST_ROOT_KEYS`), rotation lifecycle тест через durable store (legal history, interval limits, revocation нельзя откатить) и opt-in live harness на solana-test-validator (`npm --prefix apps/verifier run test:local-chain`, PASS). `npm test` 35 PASS, typecheck PASS. Открыто: native-bind e2e fixture нужно дополнить `ONELAYER_TRUST_STATE_BOOTSTRAP=1` (владелец tests/e2e); signed policy не включена по умолчанию, trust-root custody/rotation — ticket 16; внешний монотонный источник против удаления state; backdated `issuedAt` скомпрометированным ключом; foreign deployed program live не проверен; найдено расхождение demo-api `dayUtc` (epoch days) и on-chain `utc_day` (YYYYMMDD). Execution `in-review`: complete только после независимого review и закрытия открытых пунктов. [Evidence](../evidence/03/report.md#continuation-2026-09-24).

2026-09-24 (Protocol/Trust agent, post-review): исправлены все findings независимого review (3 major, 6 minor, evidence). Deployment pin для signed policy; обязательный приватный state path (lstat/perm/uid, отдельно от policy); `authenticated` в watermark и запрет downgrade; явный `ONELAYER_TRUST_POLICY_UNSIGNED=1`; O_EXCL lock; digest-pinned bootstrap; demo revision = watermark+1 и шаг ротации; лимит шага revision; пропуск испорченных подписей; строгий MIN_REVISION. Обновлены `tests/e2e/native-bind.test.ts` и `deploy/devnet-demo/native` (смена bootstrap, согласовано координатором); `deploy/devnet-demo/README.md` не обновлён. Результаты: verifier 39 PASS, typecheck PASS, local-chain 1 PASS, native-bind 3 PASS. Execution остаётся `in-review` до повторного review. [Disposition](../evidence/03/report.md#review-findings--disposition).

2026-09-24 (Protocol/Trust agent, review round 2): закрыты N1–N6 и лимит первого bootstrap. Строгая проверка state location (realpath disjointness, предки, O_NOFOLLOW/fstat); единое определение policy digest; одноразовый demo bootstrap; диагностика и процедура для stale lock; каноничный deployment pin. `deploy/devnet-demo/README.md` trust-раздел обновлён (предыдущая запись «README не обновлён» устарела); native-bind fixture перенесла state в отдельный каталог. verifier 42 PASS, typecheck PASS, native-bind 3 PASS; local-chain в этом раунде не перезапускался (проверяемый им код не менялся). Execution `in-review`. [Round 2](../evidence/03/report.md#second-review-round-2026-09-24).
