# 04 — Полнота incident index, частичная реализация

2026-09-19, working tree поверх `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2`. Execution: in-progress до chain integration/нагрузочной приемки.

Реализованы pagination до cursor, проверка program invocation stack/CPI, отказ на missing transaction/logs/cursor, сверка всех notices с finalized accounts (owner/discriminator/PDA/bump/registry/sequence/status/context). Bootstrap не получает ложный complete при прерванной истории. CONFIRMED остается блокирующим. Refresh атомарен, writers сериализуются registry advisory lock.

`npm --prefix apps/demo-api test`: 11 файлов PASS; typecheck PASS. Покрыты 205 signatures, short/repeated pages, missing cursor, foreign CPI, truncated logs, partial rollback/replay, statuses, pruned bootstrap, несовпадающий snapshot. Wire account fixtures покрывают подмену идентичности и stale context. `npm --prefix apps/demo-api run test:integration`: PASS на отдельном настоящем PostgreSQL — migration 0007 сбрасывает старую недостоверную projection, rollback не оставляет partial progress, concurrent writers сериализуются, missing opening/config mismatch отклоняются.

Migration требует остановки старых writers. Повторный scan требует доступной полной истории; при pruned RPC индекс останется unavailable до подключения архивного источника. Live validator, RPC failover/chaos и нагрузка большого incident count не проверены. Сверка не заменяет доверие RPC и независимый monitor. [Общий отчет](../../../../docs/implementation-progress-2026-09-19.md).

---

# Evidence 04 — continuation: live validator chain integration (2026-09-24)

Commit: working tree поверх `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2` (uncommitted; изменения других агентов не затрагивались).

Environment / OS / versions: Linux 6.8.0-106-generic; Node v24.10.0; PostgreSQL 17.10 (Homebrew, disposable Unix-socket cluster из `integration/support/postgres.ts`); `solana-test-validator 3.1.10 (Agave, feat:1620780344)`; `cargo build-sbf 3.1.10`, platform-tools v1.52; anchor-lang 1.1.2. Sandbox не мешал: сборка и validator работали без отключения sandbox.

Dataset ID/hash: только synthetic. Registry ID `synthetic-chain-it-<random hex>` + `-other`, `-zero-first`, `-u64-max-last`; ключи governance/operator генерируются `generateKeyPairSigner()` на каждый прогон; foreign program ID случайный. `onelayer_registry.so` собирается из исходников в digest-keyed кэш (`$TMPDIR/onelayer-sbf-cache`), sha256 `db0c7203d771ed15b87fa418b810a555446fa991350f9dc7b0c2f39d36618ef9` — побайтно совпадает с `onchain/target/deploy/onelayer_registry.so` (детерминированная сборка текущего `lib.rs`). Foreign fixture sha256 `87e783238c81f1c356a2162417f310093ca335700d20447465cfef5bc3066ee5`. Никаких devnet/mainnet транзакций.

Проблема и invariant: закрыть «Live validator не проверен». Настоящие `SolanaIncidentRpc` + `refreshIncidentIndex` + `PostgresIncidentStore` на реальной цепочке: полная pagination до cursor, watermark = только finalized head и только после сверки с finalized accounts, откат при crash, resume с cursor, без ложного CLEAR, чужие/forged события не принимаются.

Измененный Interface: нет (production код `apps/demo-api/src/incident-*.ts`, `solana-rpc.ts` не менялся). Добавлены только тестовые файлы:
- `apps/demo-api/integration/incident-chain.test.ts` — chain integration suite;
- `apps/demo-api/integration/support/solana-validator.ts` — сборка SBF в digest-кэш, validator на случайных свободных TCP/UDP портах 127.0.0.1, ledger в `mkdtemp`, teardown через `context.after` + bash watchdog (убивает validator и удаляет ledger, если Node-процесс убит SIGKILL без hooks; [уточнено по review] проверено однократно вручную SIGKILL тестового процесса, автотестом не покрыто);
- `apps/demo-api/integration/support/incident-refresh-child.ts` — отдельный процесс-индексер для SIGKILL посреди scan;
- `apps/demo-api/integration/support/foreign-log-program/` — test-only native SBF программа (anchor-lang как библиотека): mode 0/1 пишет произвольный `Program data:` (forge, успех/провал), mode 2/3 делает CPI в целевую программу (успех/провал). Не workspace member, деплоится только в disposable validator.

Commands and results:

```bash
# сборка (выполняется и самим тестом, кэшируется по digest исходников)
CARGO_TARGET_DIR=<tmp> cargo build-sbf --manifest-path onchain/programs/onelayer-registry/Cargo.toml --sbf-out-dir <tmp>   # PASS, 3m18s cold
node --test --experimental-transform-types integration/incident-chain.test.ts integration/incident-store.test.ts          # PASS 2/2, 152 s
npm --prefix apps/demo-api run typecheck                                                                                   # PASS
npm --prefix apps/demo-api test                                                                                            # PASS 107/107 (baseline 99 + тесты других агентов)
```

Фактические цифры финального прогона: bootstrap scan — 117 finalized signatures (2 страницы по 100), 115 событий, watermark slot 113; resume с cursor — 121 signatures (2 страницы), 116 событий, watermark 221; итог 132 notices (+1 pending), все четыре статуса OPEN/CONFIRMED/FALSE_POSITIVE/RESOLVED присутствуют; projection совпадает с моделью отправленных транзакций и с finalized accounts. Confirmed-но-не-finalized notice (slot 258) не попал в индекс, watermark 227 < 258; после finalization — проиндексирован как OPEN.

Negative cases (все на реальной цепочке и реальной БД):
- crash (исключение) на 57-й транзакции bootstrap scan → ничего не закоммичено, state `{0, null}`, notices пусто;
- pruned/пустая история на bootstrap и на resume → `history is incomplete`, watermark не двигается;
- SIGKILL отдельного процесса-индексера внутри открытой DB транзакции (40-я транзакция resume scan) → rollback, state = прежний committed; [уточнено по review] освобождение advisory lock подтверждено косвенно: следующий refresh в том же тесте берёт lock (lock_timeout 15 s) и доходит до своей ошибки;
- исключение на 50-й транзакции resume, missing finalized transaction (null), truncated logs → reject, state неизменен; затем чистый resume проходит;
- forged `IncidentResolved(status=RESOLVED)` для OPEN incident и forged `IncidentOpened` (seq 999 и seq = следующий настоящий) от чужой программы в транзакциях, ссылающихся на наш config → игнорируются; OPEN incident остается OPEN (нет ложного CLEAR);
- forged event в упавшей транзакции; настоящий CPI `open_incident` внутри транзакции, упавшей после CPI → не индексируются;
- настоящее событие той же программы для другого registry в транзакции, ссылающейся на наш config → игнорируется;
- положительные: CPI-вызов `open_incident`/`resolve_incident` через foreign caller принимается [уточнено по review: глубины стека тестом не проверяются, выведены из структуры вызова]; open+resolve одного incident в одной транзакции (один slot) применяются в правильном порядке.

Найденные дефекты (расхождение мок ↔ цепочка):

- **D1 — finalized notice, который схема projection не может сохранить, навсегда блокирует индекс (liveness, fail-closed).** Программа принимает любой `first_suspect_batch <= last_suspect_batch` в u64, а `db/migrations/0003_mvp_web.sql` требует `first_suspect_batch > 0` и хранит u64 в signed `BIGINT`. Notice с `first_suspect_batch = 0` или `last_suspect_batch > 2^63-1` (любой operator с `PERM_REPORT_INCIDENT`, в т.ч. по ошибке) → `applyOpened` падает на CHECK/`out of range`, каждый refresh откатывается, verification для registry остается unavailable навсегда. Безопасность сохранена (watermark не двигается, частичной projection нет, CLEAR нет) — зафиксировано regression-блоком в конце `incident-chain.test.ts` (оба варианта, отдельные registries). Моки этого не ловили: unit-тесты используют in-memory store без схемных ограничений PostgreSQL, а существующий PG-тест — только диапазон 1..9. Исправление требует решения и миграции (вне scope этого среза, остановлено по инструкции). Варианты: (a) миграция: `first_suspect_batch >= 0` и `NUMERIC(20,0)` (или CHECK на u64 через NUMERIC) для обоих полей + сравнение в `listNotices`; (b) versioned изменение программы: `require!(first_suspect_batch >= 1)` и верхняя граница ≤ i64::MAX (уже созданные notices не исправит); (c) нормализация в индексере — не рекомендуется (меняет семантику и сверку со snapshot). После фикса regression-блок нужно перевернуть на ожидание успешного индексирования.
- Других расхождений с моками не найдено: реальный формат логов (`consumed`, `invoke [n]`, `failed: custom program error`), pagination `before` и `minContextSlot` совпали с допущениями адаптера. [исправлено по review] Порядок нескольких транзакций внутри одного slot НЕ проверен: проверен только порядок событий open+resolve внутри одной транзакции.

Real integration / native acceptance: live local validator + настоящая программа + настоящий PostgreSQL — да. Devnet/mainnet, RPC failover/chaos, реальный pruned archive RPC (прунинг эмулирован оберткой над настоящим адаптером), нагрузка тысяч incidents и длительные прогоны — нет.

Migration / rollback implications: этот срез миграций не добавляет. D1 требует миграции (см. выше) — не выполнялась.

Ограничения и что НЕ проверено:
- Suite занимает ~2.5 мин (+~3.5 мин холодная сборка программы) и выполняется в `npm run test:integration` вместе с остальными; требует `solana-test-validator`, `cargo build-sbf` и cargo registry cache (сборка `--offline`). При отсутствии toolchain тест падает, а не пропускается.
- Crash «исключением» и SIGKILL эмулированы через обертку/child над настоящим адаптером; реальное падение RPC-узла не моделировалось.
- [исправлено по review] Unfinalized-проверка была недетерминированной и могла вырождаться. Заменена: см. continuation 3 (pinned finalized head + unit на commitment).
- Policy пригодности данных после resolution (acceptance п.4, вторая половина) этим срезом не рассматривалась.
- Независимый monitor и доверие к RPC вне scope.

Reviewer / findings / disposition: review не проводился. Execution не complete.

Следующий ticket и передаваемые contracts: решение по D1 (владелец schema/migrations или протокола программы); после него — перевернуть regression в `incident-chain.test.ts`. Helper `integration/support/solana-validator.ts` можно переиспользовать для других chain integration тестов.

---

# Evidence 04 — continuation 2: D1 fix (migration 0014) и policy статусов (2026-09-24)

Commit: working tree поверх `3b93cd9`, uncommitted. Решение координатора: вариант (a) по D1, номер миграции 0014 закреплён за этим тикетом.

Проблема и invariant: finalized IncidentNotice с любым диапазоном u64, где `first <= last` (это единственное ограничение `open_incident` в `lib.rs`; `first >= 0` следует из типа u64), должен индексироваться с точным round-trip значений. Преобразований suspect batch через `Number` нет: только bigint и десятичные строки.

Изменённый Interface:
- `db/migrations/0014_incident_u64_suspect_range.sql`:
  - `first_suspect_batch` и `last_suspect_batch` переведены в `numeric(20)`;
  - старые безымянные CHECK удалены по определению, а не по сгенерированному имени;
  - добавлены именованные CHECK: `*_u64` (`0..18446744073709551615`) и `incident_index_notice_suspect_range_ordered` (`first <= last`);
  - индекс `incident_index_notice_range` перестраивается автоматически.
- `apps/demo-api/src/incident-store.ts`: фильтр `listNotices` сравнивает через `$2::numeric` вместо `$2::bigint`. Иначе запрос по batch больше i64::MAX падал бы на приведении типа.
- Другие изменения production-кода не нужны. События декодируются `getBigUint64`, snapshot читается u64-кодеками (bigint), в store значения пишутся строками, а читаются через `::text` → `BigInt`. `Number()` в `incident-*.ts` и `solana-rpc.ts` применяется только к slots/counts/stack depth (slots проверяются на `MAX_SAFE_INTEGER`).

Проверка потребителей колонок (`rg suspect_batch|incident_index_notice|firstBatchSequence`):
- `main.ts` `/v1/incidents`: получает bigint из `listNotices` и отдаёт `.toString()`. Совместим. [обновлено] Позже по review обработчик вынесен в `incident-route.ts`, см. continuation 3.
- `admin.ts`:
  - выбор recovery anchor сравнивает `numeric` с `bigint` `demo_anchor.batch_sequence`, PostgreSQL неявно приводит bigint→numeric;
  - счётчик `open_onchain` читает только status.
  - Совместим. [обновлено] По review изменены `selectRecoveryAnchor`/`latestSnapshotAnchor`, см. continuation 3.
- Verifier `http-adapters.ts`: парсит строки через `BigInt`, сравнивает bigint. Совместим.
- `apps/mvp-web`, `tests/e2e-web`: поля не читают.
- Вне scope, не менялось: `integrity_incident` (локальные findings монитора, таблица 0001/0002, BIGINT) — это отдельная таблица, а не projection. `deploy/devnet-demo/scripts/soak:58` использует `Number(...first_suspect_batch...)` только как fallback-идентификатор incident в soak-скрипте, verdict от него не зависит. Точность теряется выше 2^53 — передаю владельцу deploy.

Почему projection не сбрасывается, в отличие от 0007: все существующие строки удовлетворяли старым, более строгим CHECK, а их домен входит в новый. Конвертация `bigint→numeric(20)` точная, поэтому строки и watermark остаются верными относительно finalized state. Notice, который раньше не сохранялся, никогда не был закоммичен: refresh откатывался вместе с watermark и cursor. Поэтому никакое утверждение о покрытии от него не зависит. Первый refresh после миграции подхватывает его от неизменённого cursor, полная сверка со snapshot проходит. Rollback схемы вниз возможен только при отсутствии значений вне старого домена. Иначе нужен `DELETE` projection + сброс watermark, как в 0007.

Совместимость развёртывания:
- `ALTER COLUMN TYPE` переписывает таблицу под ACCESS EXCLUSIVE; писатели индекса на это время ждут (по review добавлен `SET LOCAL lock_timeout = '15s'`).
- [уточнено по review, не проверено тестом] Старые writers передают значения строками и должны продолжать работать; старый `listNotices` с `$2::bigint` должен работать для batch ≤ i64::MAX. Это вывод из кода, прогона старого бинарника против новой схемы не было.
- Native runner применяет миграцию одной транзакцией (`psql -1`).

Commands and results:

```bash
node --test --experimental-transform-types integration/incident-store.test.ts   # PASS 2/2
node --test --experimental-transform-types integration/incident-chain.test.ts   # PASS 1/1, 167 s
npm --prefix apps/demo-api run typecheck                                        # PASS
npm --prefix apps/demo-api test                                                 # 107/108: новые и все incident-тесты PASS;
#   1 FAIL в чужом tests/service-principal.test.ts ("explicit service registry IDs required",
#   src/service-principal.ts — файлы ticket 07 в работе, этим срезом не затрагивались)
```

Новые и изменённые проверки:
- `integration/incident-store.test.ts`, тест «0014 keeps an existing projection…»:
  - на disposable DB применены миграции 0001–0013; projection заполнена старой схемой (4 статуса, значение i64::MAX, watermark 500 + cursor);
  - на старой схеме отказы воспроизведены: first=0 → check constraint, u64::MAX → out of range;
  - после 0014 строки и watermark совпадают (сравнение результатов `listNotices`/`loadState`), тип колонок `numeric(20,0)`;
  - round-trip `[0,0]`, `[0,u64max]`, `[u64max,u64max]`, `[i64max+1,u64max-1]`, включая переход в FALSE_POSITIVE;
  - покрытие batch 0, i64::MAX, i64::MAX+1, u64::MAX;
  - отказы на u64::MAX+1, −1 и first>last по именованным constraints.
- Существующий тест 0007 переведён на общий disposable-хелпер. Каждая миграция применяется одной транзакцией, как в native runner.
- `tests/incident-index.test.ts`: unit-тест «u64 boundary suspect ranges decode and index exactly (D1)» — декодирование событий на границах (включая sequence = u64::MAX) и refresh с точным хранением.
- `integration/incident-chain.test.ts`: regression-блок D1 переписан на успех. Три реальных notice на validator: `[0,3]`, `[1,u64max]`, `[2^63,u64max]`. Каждый индексируется; точный round-trip проверяется и через bigint, и через сырой `::text` в БД; концы диапазона покрыты, соседние batch — нет.

Policy пригодности данных после resolution (acceptance п.4, вторая половина). Зафиксирована в контракте `spec/error-codes.md`, раздел 3 «Verifier status», по действующей реализации:

| Status | Verdict для batch в диапазоне | Recovery anchor | Основание |
|---|---|---|---|
| OPEN | DISPUTED | запрещён | spec error-codes «открытым», `main.ts` → wire OPEN, verifier `verify.ts`, `admin.ts` selectRecoveryAnchor |
| CONFIRMED | DISPUTED | запрещён | spec «подтверждённым», тот же код |
| FALSE_POSITIVE | не блокирует | разрешён | wire RESOLVED |
| RESOLVED | сейчас не блокирует | сейчас разрешён | wire RESOLVED — **не утверждено, D2** |

Индекс без доказанной полноты даёт только `VERIFIED_NO_INCIDENT_CHECK` или хуже. [уточнено по review] На chain проверено, что индекс хранит 4 статуса раздельно; отдача `status`/`resolutionStatus` в `/v1/incidents` проверена unit-тестом маршрута (continuation 3).

- **D2 — нужно решение владельца протокола (не реализовано).** `docs/application-pipeline-ru.md` §6.4: «закрытие расследования не означает очистку ошибочных данных». Семантика on-chain `RESOLVED` (4) нигде не определена, а MVP трактует её как очистку. Варианты:
  - (A) оставить: RESOLVED = устранено, данные в диапазоне снова пригодны. Риск: сертификаты из реально испорченных batch снова «зелёные».
  - (B) рекомендуемый fail-safe без изменения протокола: RESOLVED блокирует так же, как CONFIRMED (DISPUTED, recovery anchor запрещён); очищает только FALSE_POSITIVE. Пригодные данные перевыпускаются в новых batch вне диапазона. Требует правки маппинга в `main.ts` (wire V1: RESOLVED → OPEN или новый wire-статус с versioning) и запроса в `admin.ts` — файлы вне моего владения.
  - (C) versioned: RESOLVED с `resolution_hash` на подписанный remediation manifest, где перечислены batch, признанные пригодными. Остальные остаются DISPUTED. Требует spec и изменения протокола.
- [закрыто в continuation 3] Маппинг статусов `/v1/incidents` закреплён тестом `tests/incident-route.test.ts`.

Ограничения и что НЕ проверено:
- `incident_sequence` остаётся `BIGINT`: счётчик растёт на 1 за транзакцию, достичь 2^63 практически нельзя, при переполнении — fail-closed.
- `integrity_incident` не менялась. [обновлено] soak-скрипт изменён в continuation 3.
- Review не проводился. Execution не complete: открыты D2 и review.

---

# Evidence 04 — continuation 3: исправления по независимому review (2026-09-24)

Commit: working tree поверх `3b93cd9`, uncommitted. `main.ts` и `admin.ts` параллельно правит агент 07. Мои правки в них — только точечные замены в разрешённых местах: `/v1/incidents`, `refreshIndex`, `selectRecoveryAnchor`, `latestSnapshotAnchor` и импорт. Одна замена (`export` у `latestSnapshotAnchor`) сделана однострочным `sed -i` вместо Edit; содержимое файла в остальном не менялось, после правки файл перепроверен. Environment прежний.

## Review findings / disposition

| # | Finding | Disposition |
|---|---|---|
| MAJOR-1 | Recovery anchor не учитывает полноту и свежесть индекса | **Исправлено.** `selectRecoveryAnchor` принимает anchor только если `incident_index_state.indexed_through_slot >= anchor_slot` и последний успешный полный refresh (`updated_at`, пишется только в `saveState`) был не более 2 минут назад; иначе `409 RECOVERY_ANCHOR_UNAVAILABLE`. Код добавлен в `spec/error-codes.md` §5. `main.ts` делает фоновый refresh каждые 30 s (`setInterval(...).unref()`), чтобы критерий был достижим без verifier-трафика. Тест `integration/incident-recovery-anchor.test.ts` проверяет пять случаев: индекс не построен; watermark ниже slot последнего anchor (выбирается предыдущий); notice OPEN/CONFIRMED на batch N (выбирается N-1), FALSE_POSITIVE (выбирается N); застрявший индекс (возраст 10 мин) → 409. |
| MAJOR-2 | Тест «watermark только по finalized» вырождается | **Исправлено.** (1) `FaultyRpc.pinnedHead`: finalized head фиксируется на slot, finalized до отправки pending notice. Watermark обязан равняться этому head и быть меньше slot pending notice. Reject допускается только при неизменном state. (2) Live-вариант: если pending проиндексирован, требуется `confirmationStatus === "finalized"`; reject допускается при неизменном state. (3) Unit `tests/incident-rpc.test.ts` «every RPC request of a full refresh…» проверяет полный refresh через `SolanaIncidentRpc`: все 6 запросов (`getSlot`, 2×`getSignaturesForAddress`, `getTransaction`, `getAccountInfo`, `getMultipleAccounts`) идут с `commitment: "finalized"`, account reads — с `minContextSlot` = head, watermark = head. |
| MAJOR-3 (D2) | RESOLVED policy | **Не реализовано, решение за владельцем протокола.** Обработчик вынесен в `src/incident-route.ts` (`incidentsRoute`, `wireStatus`), `main.ts` его вызывает. `tests/incident-route.test.ts` фиксирует текущий маппинг всех 4 статусов (`status` и `resolutionStatus`), строка RESOLVED помечена как D2: изменение решения будет видно по падающему тесту. |
| MINOR-1 | `integrity_incident` сравнивается как bigint | **Исправлено**: `LOCAL_INCIDENT_SQL` сравнивает через `$2::numeric` (тест проверяет SQL и параметры). `batchSequence` валидируется как u64 (больше u64 → 400/TypeError). |
| MINOR-2 | `latestSnapshotAnchor` игнорирует on-chain notices и полноту | **Исправлено**: `finalized` требует ещё и `index_clear` — индекс полон через `anchor_slot` последнего anchor, свеж (≤ 2 мин) и не содержит OPEN/CONFIRMED notice на этот batch. Проверено тем же тестом recovery anchor. Прежнее условие по `integrity_incident` сохранено. |
| MINOR-3 | Масштабируемость | **Открыто, не реализовано.** Каждый refresh заново сверяет всю projection с цепочкой: `getMultipleAccounts` по всем notices пачками по 100 и `listNotices` целиком, то есть O(N incidents) RPC и DB на каждый refresh. Refresh выполняется под advisory lock в одной транзакции, фоновый refresh — раз в 30 s. При тысячах incidents нужны инкрементальная сверка (только изменённые PDA по signatures с последнего cursor и периодическая полная сверка) или сверка по checkpoint. Нагрузочные измерения не выполнялись. |
| MINOR-4 | Нет сверки slots и точных счётчиков | **Исправлено**: `openedSlot`/`resolvedSlot` каждого notice сверяются со slot соответствующей finalized транзакции (`getSignatureStatuses`). Bootstrap: `scannedSignatures === 2 + phaseA`, `appliedEvents === genuine(phaseA)`. Resume: `scannedSignatures === phaseB`, `appliedEvents === genuine(phaseB)`; forged, failed и other-registry транзакции дают 0 событий. Idle: `[0, 0]`. |
| MINOR-5 | Harness | **Исправлено**: teardown сигналит группу процессов по pgid независимо от состояния watchdog (SIGTERM → ожидание до 5 s → SIGKILL → ожидание), затем удаляет ledger. Старт повторяется до 3 раз на новых портах с очисткой ledger. Дедлайны переведены на монотонные часы (`performance.now()`): один прогон упал ложно после скачка wall clock / suspend хоста (06:1x → 19:08), повторный прогон прошёл. **PostgreSQL** (`integration/support/postgres.ts`, не мой файл) watchdog не имеет: при SIGKILL тестового процесса кластер остаётся жить (так было после ручной проверки 06:14, я его остановил). Предложение владельцу: такой же bash-watchdog вокруг `pg_ctl`/postmaster или `postgres` в foreground как child процесса. |
| MINOR-6 | ID incidents в `/v1/incidents` и soak | **Исправлено**: ONCHAIN — `source`, `incidentSequence` (строка); LOCAL_MONITOR — `source`, `incidentId` (uuid) и `incidentSequence`, если есть. `deploy/devnet-demo/scripts/soak` `incidentIds`: все ID — строки (без приведения к Number), ONCHAIN по `incidentSequence`, local — с префиксом `local:`, числовая сортировка через BigInt. Проверено `bash -n` и прогоном JS-фрагмента на u64::MAX: `["3","18446744073709551615","local:u-1"]`. |
| MINOR-7 | 0014: lock_timeout, CHECK set, повторный прогон, scale | **Исправлено**: `SET LOCAL lock_timeout = '15s'`. Тест проверяет точный итоговый набор CHECK и повторный прогон 0014 (тот же набор, те же строки и watermark). `numeric(20)` имеет scale 0, поэтому хранимые значения всегда целые; отдельный CHECK на scale был бы тавтологией. Дробный литерал PostgreSQL округлит при приведении до CHECK, поэтому защита — на границе приложения: запись только из bigint-строк. Это задокументировано в миграции. |

Уточнённые утверждения из continuation 1 и 2 помечены в тексте: «[исправлено по review]», «[уточнено по review]», «[обновлено]».

## Изменённые файлы (этот раунд)

- `apps/demo-api/src/incident-route.ts` — новый;
- `apps/demo-api/src/main.ts` — импорт, `/v1/incidents` → `incidentsRoute`, фоновый refresh;
- `apps/demo-api/src/admin.ts` — `selectRecoveryAnchor`, `latestSnapshotAnchor` (экспорт + критерий полноты и свежести);
- `db/migrations/0014_incident_u64_suspect_range.sql` — lock_timeout и комментарии;
- `spec/error-codes.md` — §5 `RECOVERY_ANCHOR_UNAVAILABLE`;
- `deploy/devnet-demo/scripts/soak` — `incidentIds`;
- тесты: новые `tests/incident-route.test.ts`, `integration/incident-recovery-anchor.test.ts`; изменены `tests/incident-rpc.test.ts`, `integration/incident-store.test.ts`, `integration/incident-chain.test.ts`, `integration/support/solana-validator.ts`.

## Commands and results

```bash
npx tsc --noEmit (npm --prefix apps/demo-api run typecheck)            # PASS, exit 0
npm --prefix apps/demo-api test                                         # PASS 116/116
node --test --experimental-transform-types integration/incident-chain.test.ts \
  integration/incident-store.test.ts integration/incident-recovery-anchor.test.ts   # PASS 4/4, 167 s
```

Финальный chain-прогон:
- bootstrap: 117 signatures (= 2 + 115), 115 событий, watermark 111;
- resume: 121 signatures, 116 событий, watermark 216;
- pinned head 217 < pending slot 249; live watermark 218, pending не индексирован (status confirmed).

После прогонов validator-процессов и ledger-директорий не осталось.

## Ограничения и что НЕ проверено

- Фоновый refresh в `main.ts` и путь HTTP → `incidentsRoute` в запущенном приложении не проверялись: демо-API требует devnet RPC. Маршрут покрыт unit-тестом.
- Изменение `latestSnapshotAnchor` делает snapshot non-finalized, пока индекс не свеж. Влияние на `tests/e2e-web` и native demo не прогонялось.
- **Наблюдение для владельца:** local finding (`integrity_incident`) с `first_suspect_batch IS NULL` блокирует recovery anchor, но не попадает в `/v1/incidents` (условие по диапазону). Для verifier это fail-open. Не исправлялось, запрос сохранён как был, только с numeric.
- Порядок нескольких транзакций внутри одного slot, MINOR-3 и D2 — открыты.
- Повторное review этих исправлений не проводилось. Execution не complete.

---

# Evidence 04 — continuation 4: unscoped local finding (fail-open) и e2e-web (2026-09-24)

Проблема: local finding (`integrity_incident`), у которого `first_suspect_batch` или `last_suspect_batch` = NULL, блокировал recovery anchor, но не попадал в `/v1/incidents`: SQL-условие по диапазону отбрасывало NULL. В результате verifier видел «чистый» batch и выдавал VERIFIED (fail-open).

Сверка с `apps/verifier/src/verify.ts`:
- `DISPUTED` = incident `OPEN` и `first <= batch <= last`, при статусе индекса CHECKED;
- `UNAVAILABLE` — ответ без watermark или ошибка адаптера;
- `http-adapters.ts` требует у каждого incident числовые строки `firstBatchSequence`/`lastBatchSequence`, NULL там был бы ошибкой.

Выбран вариант с сохранением формата ответа:
- `LOCAL_INCIDENT_SQL` отбирает finding при `first IS NULL OR last IS NULL OR (диапазон покрывает batch)`;
- `incidentsRoute` отдаёт такой finding как `firstBatchSequence: "0"`, `lastBatchSequence: "18446744073709551615"` и дополнительное поле `unscopedRange: true` (verifier игнорирует незнакомые поля);
- для `OPEN` это даёт DISPUTED для любого batch;
- `admin.ts` `selectRecoveryAnchor` (точечный Edit) теперь блокирует и при `last_suspect_batch IS NULL`; раньше проверялся только first.
- Контракт: абзац в `spec/error-codes.md` §3.
- Тест: `tests/incident-route.test.ts` «an unscoped local finding…» — варианты `[NULL,NULL]`, `[NULL,7]`, `[7,NULL]`; проверяются точный wire-ответ и то, что предикат verifier покрывает batch 0, 1 и u64::MAX.

Commands and results:
- `tsc --noEmit`: PASS.
- `npm --prefix apps/demo-api test`: PASS 117/117.

e2e-web: `npm --prefix tests/e2e-web test` (порты 38198/38199, отчёты в scratch) запускается локально без devnet: fixture-backend + `next start`, validator и SOL не нужны. Результат: 66/66 FAIL, все по причине среды — `browserType.launch: Executable doesn't exist … chromium_headless_shell-1234`: браузеры Playwright 1.62.1 не установлены. Нужна команда `npx --prefix tests/e2e-web playwright install chromium`. Я её не выполнял: это загрузка в пользовательский кэш, вне поручения. Поэтому тест НЕ проверен, а не PASS. По коду: `tests/e2e-web/fixture-backend.ts` — самостоятельный заменитель demo-api и verifier, `apps/demo-api/src/admin.ts` он не импортирует. Значит, требование свежести в `latestSnapshotAnchor` на этот сьют не влияет. Влияние на native demo (`deploy/devnet-demo/native`, живой devnet RPC) не проверялось.


## 2026-10-01 — ADR-0008 suitability continuation (synthetic/local)

Working tree over `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2`, Node v24.10.0, disposable PostgreSQL via `isolatedPostgres`; no external chain calls. Existing dirty incident-route/verifier implementation already preserves RESOLVED as blocking, explicit FALSE_POSITIVE as the only release, and legacy ambiguous RESOLVED as fail-closed. No additional production edits in those modules were needed. Coordinator fixed the remaining admin SQL predicates for on-chain and local RESOLVED; dashboard counts retain blocking resolved on-chain notices.

This agent's changes: `apps/verifier/tests/verify.test.ts` expands V2 regression to OPEN/CONFIRMED/RESOLVED × advisory ACTIVE/SUPERSEDED/REVOKED (all DISPUTED); `apps/demo-api/integration/incident-recovery-anchor.test.ts` asserts resolved on-chain notice prevents snapshot trust and falls back to an older recovery anchor, real dashboard returns blocking count 1 then 0 for FALSE_POSITIVE, and resolved unscoped local finding blocks all recovery anchors and snapshot trust. Existing immutable history is unchanged.

Checks:
- `node --test --experimental-transform-types apps/demo-api/tests/incident-{index,route,rpc}.test.ts`: PASS 25/25.
- `node --test --experimental-strip-types apps/verifier/tests/verify.test.ts`: PASS 25/25.
- `node --test --experimental-transform-types apps/demo-api/integration/incident-recovery-anchor.test.ts`: PASS 1/1 against disposable PostgreSQL (21.8 s total). Initial test-fixture credential/scope failures were corrected before this pass.
- `npm --prefix apps/demo-api run typecheck`: PASS.
- Full `npm --prefix apps/verifier test`: latest attempt 55/56; trust-state restart regression timed out waiting for process startup under concurrent load. This is not a passing full gate. Verifier typecheck initially found pre-existing TS narrowing at trust-state.test.ts:729; coordinator owns correction/recheck.

Limitations: no new live-validator/native acceptance, no production readiness claim. Unresolved whole-ticket concerns include scaling and within-slot transaction order from previous evidence. ADR-0008 decision D2 is resolved; broad acceptance/review remains open. Coordinator independently reviewed this slice; publication/exclusion reviews are separate. No migration or frozen protocol changes in this slice.
