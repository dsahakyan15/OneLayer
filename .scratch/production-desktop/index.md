# Очередь реализации OneLayer

Обновлено: 2026-10-02. Полнофункциональный launcher не готов; полная приемка всех 24 задач остаётся открытой. Status — triage; Execution — состояние ограниченного среза, а не подтверждение завершения acceptance.

[Что работает и что осталось](../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](evidence/launcher-usage-pipeline-review-2026-10-02.md). История ниже сохраняет результаты отдельных проверок; актуальная сводка имеет приоритет.

[Спецификация](spec.md) · [Полный пайплайн](../../docs/application-pipeline-ru.md) · [Runbook](../../docs/agents/implementation-runbook.md)

| Ticket | Этап | Зависимости | Исполнитель | Triage | Execution |
|---|---|---|---|---|---|
| [01 — Baseline, модель угроз и обязательные контракты](issues/01-baseline-contracts.md) | P0 | — | Codex coordinator | ready-for-agent | claimed |
| [02 — Desktop spike: установка, SSO и signer](issues/02-desktop-platform-spike.md) | P0 | 01 | Desktop | ready-for-agent | blocked |
| [03 — Закрепить доверие verifier к issuer, program и registry](issues/03-verifier-trust.md) | P1 | 01 | Protocol/Trust | ready-for-agent | in-review |
| [04 — Полный и аутентифицированный incident index](issues/04-incident-index.md) | P1 | 01 | Protocol/Trust | ready-for-agent | in-review |
| [05 — Проверяемая актуальность и честный verification result](issues/05-lifecycle-verdict.md) | P1 | 03, 04, 09 | Protocol/Trust | ready-for-agent | in-review |
| [06 — Private ingress и закрытие сетевой утечки demo](issues/06-private-ingress.md) | P1 | 01 | Backend/Identity | ready-for-agent | in-progress |
| [07 — Identity, sessions и server-side permissions](issues/07-identity-authorization.md) | P2 | 01, 06 | Backend/Identity | ready-for-agent | in-review |
| [08 — Записи, версии и независимое согласование](issues/08-registry-workflow.md) | P2 | 07 | Backend/Identity | ready-for-agent | in-review |
| [09 — Надежный publication и signer flow](issues/09-durable-publication.md) | P2 | 02, 03, 04, 08 | DeepSeek V4.1 Flash (max) | ready-for-agent | claimed |
| [10 — Устанавливаемая программа, вход и ролевой каркас](issues/10-desktop-shell.md) | P3 | 02, 07 | MiMo V2.6 Pro (high) | ready-for-agent | claimed |
| [11 — Все рабочие кабинеты и сквозные ролевые действия](issues/11-desktop-workflows.md) | P3 | 05, 08, 09, 10 | MiMo V2.6 Pro (high) | ready-for-agent | claimed |
| [12 — Независимый Monitor и доказательства вмешательства](issues/12-independent-monitor.md) | P4 | 04, 08, 09 | Monitor | ready-for-agent | in-progress |
| [13 — Audit, evidence и восстановление projections](issues/13-audit-evidence.md) | P4 | 07, 08, 12 | Backend/Identity + Monitor | ready-for-agent | not-started |
| [14 — Full-state checkpoint и согласованный Snapshot](issues/14-snapshot-checkpoint.md) | P5 | 03, 04, 05, 09, 12 | Recovery/Storage + Protocol/Trust | ready-for-agent | not-started |
| [15 — Реальные Backup Centers, read-back и retention](issues/15-backup-centers-retention.md) | P5 | 14 | Recovery/Storage | ready-for-agent | not-started |
| [16 — Provisioning, 3-of-5 custody и ротация ключей](issues/16-key-custody.md) | P5 | 01, 14 | Recovery/Storage | ready-for-agent | in-review |
| [17 — Изолированный Recovery Controller и Restore Approval](issues/17-recovery-controller.md) | P6 | 07, 14, 15, 16 | Recovery/Storage | ready-for-agent | not-started |
| [18 — Полный restore в новую target и управляемый cutover](issues/18-restore-cutover.md) | P6 | 09, 12, 17 | DeepSeek V4.1 Flash (max) | ready-for-agent | claimed |
| [19 — CI, installers, signed updates и supply chain](issues/19-ci-signed-release.md) | P7 | 02, 10 | Codex coordinator | ready-for-agent | claimed |
| [20 — Deployment, наблюдаемость и runbooks](issues/20-deployment-operations.md) | P7 | 06, 12, 13, 15, 18, 19 | MiMo V2.6 Pro (high) | ready-for-agent | claimed |
| [21 — Сквозная приемка установленного приложения и 72-hour soak](issues/21-synthetic-acceptance.md) | P8 | 11, 18, 19, 20 | Codex coordinator | ready-for-agent | claimed |
| [22 — Production provisioning и ответственные за доверенные контуры](issues/22-production-provisioning.md) | P8 | 01, 02, 15, 16, 19 | Владелец инфраструктуры + Release/Ops | ready-for-human | not-started |
| [23 — Независимые проверки, реальный restore drill и shadow pilot](issues/23-production-validation.md) | P8 | 21, 22 | Владелец системы + независимые reviewers | ready-for-human | not-started |
| [24 — Go-live, ограниченный rollout и передача эксплуатации](issues/24-go-live-handover.md) | P8 | 23 | Владелец системы + Release/Ops | ready-for-human | not-started |

## Как читать граф

01 открывает baseline и contracts. После него параллельно возможны 02, 03, 04 и 06. Далее 07 → 08 → 09; 05 завершается после реального workflow/publication, поэтому границы этапов частично перекрываются. 10 начинает desktop после spike/identity; 11 связывает ролевые flows. 12 → 13 усиливают независимый контроль. 14 → 15/16 → 17 → 18 строят реальный recovery. 19 может выполняться параллельно backend после desktop shell. 20/21 собирают все интеграции; 22 идет отдельным организационным треком; 23/24 требуют людей и production evidence.

## Трассировка review

| Finding | Tickets |
|---|---|
| F1 — trust issuer/program/registry | 03, 09, 21 |
| F2 — источник incident event | 04, 21 |
| F3 — полнота индекса | 04, 12, 21 |
| F4 — неизвестная актуальность | 05, 11, 21 |
| F5 — summary вместо восстановления | 17, 18, 21, 23 |
| S1 — bind и ingress | 06, 07, 20, 22 |
| S2 — недоказанный snapshot root | 14, 18, 21 |
| S3 — одна БД вместо центров | 15, 18, 22, 23 |
| S4 — недолговечные ключи | 16, 17, 22, 23 |
| S5 — читается не выбранная replica | 15, 18, 21 |
| S6 — неограниченный storage | 15, 20, 21 |
| S7 — несогласованный snapshot | 14, 21 |

Evidence создается по мере выполнения; заранее сгенерированных PASS-отчетов нет.

[Отчет первого этапа реализации и результаты тестов](../../docs/implementation-progress-2026-09-19.md).

2026-09-20: [07 — admin permissions, registry scope и отзыв сессий](evidence/07/report.md). OIDC/device admission/object-field scope остаются открытыми.

2026-09-20: [07 — PostgreSQL accounts/sessions, restart и transactional revoke](evidence/07/durable-sessions.md). Следующий срез: OIDC с test IdP и device admission.

2026-09-24: параллельный раунд агентов по 03, 04, 07 и 09. На каждый срез проведено независимое ревью, найденное исправлено, для 03, 07 и 09 выполнено повторное ревью. Коммита нет.
- [03](evidence/03/report.md): durable anti-rollback watermark, signed policy с привязкой к deployment, lock между процессами, проверка размещения state, local-chain harness. Execution: in-review.
- [04](evidence/04/report.md): live-validator интеграция, миграция 0014 (u64 suspect range), recovery anchor только при полном и свежем индексе, закрыт fail-open для local incident без диапазона. Execution: in-review. Открыто: D2 (смысл RESOLVED), масштабируемость refresh.
- [07](evidence/07/service-principals.md): scoped service principals для `/internal/*` (миграция 0012), gate и rate limit, отдельный пул, audit окон отказов. Execution: in-review.
- [09](evidence/09/report.md): детерминированный intent, attempt journal до send, reconciliation с `minContextSlot`, доверенное завершение FINALIZED, maintenance-выходы, DB-guards (миграция 0013). Execution: in-review.
- Координатор: общий `ledger-day.ts`; исправлен legacy `dayUtc` в `admin.ts` (программа ожидает YYYYMMDD, а не дни от epoch).

Проверки после раунда: demo-api typecheck PASS, unit 118/118, verifier 42/42, packages 16/16, root e2e 9/9, e2e-web 66/66. Serial integration demo-api — 59/60 в первом прогоне: `admin-access` не дождался старта API за 10 с и отдельно проходит 3 из 3. Повторный serial прогон: 60/60 PASS, 0 skip. Validator-тесты входят в этот набор.

Открытые решения владельца: D2 (RESOLVED блокирует или нет), ANCHOR_MISMATCH_UNATTRIBUTED (нужен ли архивный RPC перед принудительной отменой), quarantine непубликуемой версии; выбор Tauri/Qt для 02/10 требует compatibility spike.

2026-09-24: пользователь выбрал Linux для первой production-версии. Целевая конфигурация — Linux Mint 22.1 x86_64 на текущем рабочем месте; Windows/macOS отложены за пределы первого выпуска. Обновлены ADR-0007, спецификация, пайплайн и acceptance 02/10. Развилка ОС снята; platform/identity/signer/update gates остаются открытыми.

2026-09-24: решения владельца зафиксированы: [ADR-0008](../../docs/adr/0008-incident-status-data-suitability.md) (RESOLVED блокирует, как CONFIRMED), [ADR-0009](../../docs/adr/0009-ambiguous-publication-and-version-exclusion.md) (без принудительной отмены неоднозначной публикации; непубликуемая версия исключается двумя независимыми согласованиями со ссылкой на исправление), дополнение [ADR-0007](../../docs/adr/0007-desktop-application-and-role-scoped-access.md) (Tauri 2 + React — основной кандидат, первая ОС остается Linux Mint 22.1). Порядок: D2, неоднозначная отмена, права 07 и ранняя часть 16 → spike 02 и issuance 09 → 05, 12, 13 → 14–18 → 19–21. Владельцев production IdP, устройств, RPC, ключей и подписи релизов (22–24) нужно подключить сейчас.

2026-10-01: bounded continuation 07 с субагентами DeepSeek v4.1 Flash, max reasoning: проверка checksum применённых миграций, атомарный SQL/checksum journal, отрицательные TTL/expiry проверки и исправление CLI-фикстур. PostgreSQL устанавливается в CI до root e2e. API typecheck и 120 unit-тестов PASS; regression runner 4/4, service store 10/10 и HTTP 2/2 PASS без skip. [Evidence и review disposition](evidence/07/migration-integrity-and-ttl.md). Полный acceptance 07 и production gates остаются открытыми.

2026-10-01: следующий раунд DeepSeek v4.1 Flash, max reasoning: [07 — scoped verifier reads](evidence/07/verifier-service-reads.md) и [10 — первый UI лаунчера](evidence/10/launcher-ui-2026-10-01.md). Точные service-read scopes, registry isolation и live revoke связаны с verifier; Linux Demo UI получил навигацию, состояние сессии и фоновые проверки доступности трёх сервисов. API: 124 unit PASS, read/principal HTTP по 2 PASS; verifier 68 PASS; composed API→verifier 1 PASS; Python/GTK 27 PASS и installed smoke PASS. Независимое review и его исправления отражены в evidence. Полные acceptance 07/10, native SSO и production installer остаются открытыми.

2026-10-01: ticket 08 — воспроизведён и закрыт записанный concurrent-edit дефект ([200,404]→[200,409]): блокировка строки draft отдельным statement перед join. Новый детерминированный adversarial тест на disposable PostgreSQL (удержание победителя триггером, подтверждение ожидания через pg_locks) плюс CAS-гонка коммитов через admin-диспетчер. Проверки: typecheck PASS, unit 124/124, полный demo-api integration 72/72 без skip. [Evidence](evidence/08/report.md). Dependency 07, production source и независимый review остаются открытыми.

2026-10-01: продолжение с требованием английского языка приложения, та же оркестрация DeepSeek v4.1 Flash / max reasoning. [10 — English launcher](evidence/10/launcher-english-2026-10-01.md), [05 — V2 contract/client](evidence/05/v2-contract-and-client-2026-10-01.md), [11 — RegistryWorkflow кабинет + real OIDC HTTP](evidence/11/report.md), [16 — explicit writer key + immutable version binding](evidence/16/report.md), [19 — GTK CI](evidence/19/gtk-ci-2026-10-01.md). Миграция 0018 добавлена; исторические SQL не изменялись этим срезом. UI получает реальные session permissions/registry scope. Финальные проверки и независимое review: [continuation report](evidence/continuation-2026-10-01.md). Все полные production acceptance остаются открытыми; ни test IdP, ни software key file, ни browser fixtures не заменяют production provisioning.

2026-10-02: завершение bounded continuation с DeepSeek v4.1 Flash / max reasoning и перекрёстным review. Исправлены повреждённые V2 ответы, lifecycle/disclosure противоречия, retry keys для unrelated draft reads, session/OIDC guards; additive 0019 закрывает runtime UPDATE/DELETE privileges. Affected browser suites 92/92 PASS, key/checksum 9/9 PASS, дополнительные disclosure/retry regressions PASS. Остаток: durable pending operation recovery после reload/restart и production gates. [Финальный отчёт](evidence/continuation-2026-10-01.md).

2026-10-02 — durable workflow attempt recovery and actual local startup:
[report](evidence/workflow-recovery-2026-10-02.md),
[local preflight](evidence/local-readiness-2026-10-02.md).
DeepSeek v4.1 Flash/max implementation + independent reviews. Server receipts,
restart recovery/cancellation, scoped draft discovery, English UI, real local
stack on private Unix state. 110 browser checks PASS; broad API integration
81/82 with one startup timeout, isolated final 7/7 PASS; migration 4/4 PASS;
readiness 27/27 PASS. This is local application evidence, not completion of
full-state/isolated-recovery/production-distribution or tickets 22–24.
