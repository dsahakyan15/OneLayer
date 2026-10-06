# 04 — Полный и аутентифицированный incident index

Status: ready-for-agent
Execution: in-review
Owner: Codex incident_semantics
Role: Protocol/Trust
Phase: P1
Blocked by: 01

## Текущий результат — 2026-10-02

Полная задача не завершена.

- Реализовано / проверенная граница: Event-backed index, freshness и проверки отказов.
- Осталось: Завершить полноту/масштабирование, operational evidence и UI инцидентов.
- [Сводный статус](../../../docs/implementation-status-2026-10-02.md) · [Личное ревью pipeline](../evidence/launcher-usage-pipeline-review-2026-10-02.md).

Исторические исполнители и PASS ниже описывают прошлые срезы; они не означают активный запуск агентов или готовность установленного приложения.

## Результат

Закрыть F2/F3 и сохранить семантику состояний incident.

## Scope и источники

apps/demo-api/src/incident-events.ts; incident-index.ts; incident-store.ts; solana-rpc.ts; onchain/

Общие требования: [полный пайплайн](../../../docs/application-pipeline-ru.md) и [runbook](../../../docs/agents/implementation-runbook.md).

## Acceptance

- [ ] Pagination проходит весь диапазон до сохраненного cursor; 101+ signatures и несколько страниц не теряют события.
- [ ] Watermark продвигается только при полной finalized истории; missing/pruned transaction, truncated logs и crash не создают ложный CLEAR.
- [ ] Parser проверяет программу-источник с учетом invocation stack/CPI и сверяет IncidentNotice; payload чужой программы не принимается.
- [ ] OPEN, CONFIRMED, FALSE_POSITIVE, RESOLVED различаются; policy пригодности данных после resolution явно определена и проверена.

## Проверка

Multi-page/crash/restart suite, события посторонней программы, resume после частичного scan; regression against fresh-but-incomplete watermark.

## Evidence и handoff

При исполнении создать `../evidence/04/report.md`: commit, environment, команды, negative cases, реальные integration/native результаты, ограничения и review. Обновить Execution после проверки; не объявлять synthetic evidence production-ready.

## Comments

Задача создана планом 2026-09-19. На момент создания реализация ещё не была начата; актуальный результат указан выше.

2026-09-19: работа начата. Частичные результаты и незакрытые критерии: [evidence](../evidence/04/report.md). Задача целиком не закрыта.

2026-09-24 (Protocol/Trust агент, chain integration срез): добавлен live-validator suite `apps/demo-api/integration/incident-chain.test.ts` (disposable solana-test-validator 3.1.10 + программа, собранная из исходников, + disposable PostgreSQL). Подтверждено на реальной цепочке: 132 notices, два scan по 117/121 signatures (multi-page), все 4 статуса и переходы, CPI через чужую программу, forged/failed/other-registry события отклоняются, crash (исключение и SIGKILL процесса) и pruned/missing/truncated дают откат без сдвига watermark, resume с cursor, unfinalized notice не покрывается watermark. Production код не менялся. Найден дефект D1: notice с `first_suspect_batch = 0` или `last_suspect_batch > i64::MAX` допустим программой, но не сохраняется схемой → индекс навсегда unavailable (fail-closed, не ложный CLEAR); нужна миграция/решение, зафиксировано regression-блоком. Не закрыто: D1, policy пригодности данных после resolution, review. Execution не complete. [Evidence](../evidence/04/report.md).

2026-09-24 (Protocol/Trust агент, D1 + policy): D1 закрыт по решению координатора (вариант a). Миграция `db/migrations/0014_incident_u64_suspect_range.sql` переводит suspect-диапазон в `numeric(20)`: CHECK `0..2^64-1`, `first <= last`, projection и watermark сохраняются (обоснование в evidence). `incident-store.ts` сравнивает через numeric. Добавлены проверки: применение 0014 поверх заполненной старой схемы, unit-тест границ; chain regression теперь требует успешного индексирования `first=0`, `last=u64::MAX` и `first=2^63` с точным round-trip. Policy статусов записана в `spec/error-codes.md`: OPEN/CONFIRMED → DISPUTED, FALSE_POSITIVE не блокирует. Трактовка RESOLVED — D2, требует решения владельца протокола; варианты A/B/C в evidence, не реализовано. Открыто: D2, тест маппинга статусов в `main.ts`, review. Execution не complete. [Evidence](../evidence/04/report.md).

2026-09-24 (Protocol/Trust агент, исправления по независимому review): исправлены MAJOR-1, MAJOR-2 и MINOR-1, 2, 4, 5, 6, 7.
- Recovery- и snapshot-anchor требуют, чтобы индекс был полон до `anchor_slot` и обновлён не более 2 минут назад, иначе `409 RECOVERY_ANCHOR_UNAVAILABLE`; добавлен фоновый refresh.
- Проверка «watermark только по finalized» сделана детерминированной: зафиксированный finalized head и unit-тест на commitment всех запросов индексера.
- Маршрут `/v1/incidents` вынесен в `incident-route.ts`, маппинг всех 4 статусов закреплён тестом.
- Добавлена точная сверка slots и счётчиков scan; harness убивает группу процессов validator и повторяет старт; soak-скрипт отдаёт ID строками.
- В 0014 добавлен lock_timeout, тест проверяет итоговый набор CHECK и повторный прогон.

Не реализовано: MAJOR-3 (D2 — решение владельца протокола), MINOR-3 (масштабируемость, описано в evidence).

Проверки: typecheck PASS, unit 116/116, integration incident-chain, incident-store и recovery-anchor 4/4.

Execution не complete: открыты D2, MINOR-3, порядок транзакций внутри slot, повторное review. [Evidence](../evidence/04/report.md).

2026-09-24 (Protocol/Trust агент): закрыт fail-open. Local finding без диапазона (NULL в first или last) теперь попадает в `/v1/incidents` как покрывающий весь u64 (`unscopedRange: true`), поэтому при OPEN verifier выдаёт DISPUTED. `selectRecoveryAnchor` блокирует и при NULL в last. Добавлены unit-тест и абзац в `spec/error-codes.md`. typecheck PASS, unit 117/117. e2e-web без devnet запускается, но не проверен: не установлены браузеры Playwright (66/66 FAIL на `browserType.launch`); сьют использует fixture-backend и `admin.ts` не импортирует. [Evidence](../evidence/04/report.md).

2026-10-01 (incident_semantics): ADR-0008 confirmed across existing incident wire API and verifier. Added V2 negative lifecycle matrix and disposable-PG recovery/snapshot/dashboard/local RESOLVED regressions; coordinator fixed remaining admin SQL predicates. Targeted suites 25/25 + 25/25 + PG 1/1 PASS, demo-api typecheck PASS. D2 decision is resolved; full verifier gate has a process-start timeout and coordinator-owned type narrowing check; whole ticket remains in-review, not complete. See [evidence](../evidence/04/report.md).
