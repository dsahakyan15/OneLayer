# Инструкция ИИ-агенту: реализация OneLayer Desktop и надежного backend

Дата: 2026-09-19. Применять вместе с [пайплайном](../application-pipeline-ru.md) и [spec](../../.scratch/production-desktop/spec.md). Это инструкция для будущего выполнения задач; она не означает, что перечисленные модули уже реализованы.

## 1. Вход в задачу

1. Прочитай root `AGENTS.md`, `CONTEXT.md`, релевантные `docs/adr/`, `spec/*` и ticket. Правила issue tracker находятся в `docs/agents/issue-tracker.md`.
2. Проверь `git status`, branch/commit и текущие изменения. Не затирай чужую работу. Если нужна изоляция — worktree; рабочий каталог всегда указывай явно.
3. Прочитай `Blocked by`. Dependency завершена, только если ее acceptance подтвержден evidence и она интегрирована в используемый commit. Наличие файла/PR или текста «готово» недостаточно.
4. Найди фактический Interface и потребителей через `rg`. Перечисли invariant, ожидаемый failure case и границу scope. Не начинай с глобального refactor.
5. Перед реализацией выясни только необходимые зависимости: для synthetic/local работы production secrets не нужны. Отсутствие HSM не блокирует строгий parse или отрицательный тест чужого issuer.

## 2. Жизненный цикл ticket

`Status:` использует ровно canonical triage labels: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. Не добавлять `done` или `in-progress` как шестую triage label.

Внутри ticket отдельно поддерживаются:

```text
Status: ready-for-agent
Execution: not-started | claimed | blocked | in-review | complete
Owner: имя агента/человека или unassigned
Blocked by: номера tickets или none
```

`Execution` — дополнительное поле этой очереди, не замена triage policy. Перед началом агент указывает Owner и claimed. При ожидании реального внешнего input — blocked с конкретной причиной; независимую часть выполняет. Complete ставится после acceptance и review. Человеческое решение имеет `ready-for-human`, а не фиктивную реализацию силами агента.

## 3. Контракт задания агенту

Coordinator передает конкретный ticket, а не «сделай все безопасно». Шаблон:

```text
Задача: .scratch/production-desktop/issues/<NN>-<slug>.md
Исходный commit/branch: <ref>
Scope/владение файлами: <перечень>
Dependencies с evidence: <tickets + refs>
Инварианты: <что не может стать неверным>
Failure scenario: <конкретный случай>
Interface/совместимость: <version, DTO, errors, migration constraints>
Разрешенная среда: <synthetic/local/staging>
Выход: минимальный diff + проверки + evidence + handoff
Не включать: <соседние задачи и несогласованные изменения протокола>
```

Агент сам выбирает обратимые implementation details внутри согласованного Interface. Смена frozen protocol, external access boundary, custody или юридически значимой semantics требует явного versioned решения; «нужно для теста» не оправдывает ослабление policy.

## 4. Цикл реализации

1. **Воспроизвести.** Для найденного дефекта — negative regression case, падающий на старом поведении. Для нового flow — пример входа, состояния и observable результата.
2. **Уточнить Interface.** В DTO включить operation ID, domain errors, scope, idempotency и concurrency expectations; серверные состояния являются источником истины для UI.
3. **Реализовать вертикальный срез.** Реальный backend/adapter и необходимый UI. Не выдавать fixture response за production implementation.
4. **Проверить инвариант.** Тесты через публичный Interface; разумный набор adverse cases, соответствующий конкретному риску. Не писать тесты, которые просто повторяют implementation.
5. **Проверить совместимость.** Golden vectors/IDL drift, migrations и API version только там, где их касается diff. Не менять frozen vectors ради прохождения неожиданно сломанного теста.
6. **Review.** Отдельно оценить соответствие spec и доверенным границам. Автор исправляет findings, reviewer проверяет результат, Coordinator интегрирует.
7. **Evidence и handoff.** Зафиксировать команды, среду, результаты, ограничения и unresolved dependencies. UI acceptance прилагает снимки/trace без секретов и реальных персональных данных.

Для криптографии, access control и state transitions обязательны существенные отрицательные проверки. Для текста, небольшого reversible UI изменения и документации не создавать искусственные тесты; достаточно подходящей проверки результата.

## 5. Параллельная работа

- Параллельные агенты допустимы при явном запуске Coordinator/пользователем и готовых независимых задачах. План не требует автоматического запуска агентов в каждом сеансе.
- Один ticket — один владелец. Общие contract/spec/migration файлы изменяет назначенный владелец; остальные присылают предложение Interface.
- Сначала интегрируется контракт, затем потребители. Agent Desktop может работать на mock Interface для разработки, но завершает ticket только на реальном backend.
- Protocol/Verifier и Monitor сохраняют независимый расчет криптографии. Не устранять различие копированием Builder кода в Monitor.
- Практичные первые ветки после 01: 02 desktop spike; 03 trust; 04 incident indexing; 06 private bind. Зависимости 05 lifecycle spec и 07 identity интегрируются до финальных UI flows.
- Reviewer может проверять готовый diff параллельно следующей независимой задаче, но автор не закрывает собственный gate без необходимого review.

## 6. Инструменты и доступ

| Инструмент | Для чего | Условия |
|---|---|---|
| `rg`, Git, редактор | Исследование, локальные изменения, diff | Учитывать uncommitted user changes |
| Cargo/Rust | Crypto, on-chain unit/integration, Monitor | Использовать repo toolchain и locks |
| Node/npm/TypeScript | Backend, verifier, desktop UI, contracts | Exact lockfile install; не обновлять все зависимости заодно |
| PostgreSQL CLI/test harness | Migrations, integration, recovery | Disposable DB; destructive тесты только на помеченной synthetic target |
| Local validator / chain harness | On-chain constraints и transaction flow | Фиксированная версия, отдельные test keys |
| Browser/native automation | UI, permissions, installer, callback, updater | Browser-only тест не доказывает native flow |
| Storage adapters | Replication/read-back/retention | Реальные bytes и отдельные credentials, не mock строка COPIED |
| CI и scanners | Gates, SBOM, secret/dependency checks | Signing secrets отсутствуют в недоверенных jobs |
| Official docs | Проверка изменчивых API и платформенной совместимости | Записать источник/дату/версию; не полагаться на память о версиях |

Development agents не получают production KEK/shares/private keys и не копируют dumps реальных персональных данных в prompts. Доступ к devnet/staging и публикация изменений выполняются в пределах конкретного поручения; план сам по себе не разрешает production deployment, сообщения третьим лицам или операции с реальными средствами.

## 7. Существующие проверки

Перед созданием или обновлением PR проверяй точный состав ветки в чистом checkout/worktree и выполняй относящиеся к изменению команды из текущего `.github/workflows/ci.yml`. Установленные зависимости соседнего локального проекта могут скрыть ошибки CI: verifier импортирует source `packages/onchain-client`, поэтому `npm ci` в этом package должен выполняться до verifier tests/typecheck. Не исправляй отсутствие зависимостей ослаблением strict TypeScript или ручной правкой generated client.

В PR укажи реально выполненные проверки и ограничения. После push проверь GitHub checks; локальный PASS и remote PASS фиксируй отдельно. Не объявляй CI успешным, пока есть failed или pending checks.

Выбирай команды по затронутому scope, затем обязательные CI gates. На дату плана существуют:

```bash
cargo test --all
cargo test --manifest-path onchain/Cargo.toml
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
npm --prefix apps/demo-api test
npm --prefix apps/demo-api run typecheck
npm --prefix apps/verifier test
npm --prefix apps/verifier run typecheck
npm --prefix packages/canonical-ts test
npm --prefix packages/merkle-ts test
npm --prefix packages/snapshot-ts test
npm --prefix packages/snapshot-ts run typecheck
npm --prefix packages/onchain-client run check-drift
npm --prefix packages/onchain-client test
npm --prefix apps/mvp-web run typecheck
npm --prefix tests/e2e-web test
```

Runtime requirements, installation и env брать из текущих manifests/CI. Отказ local socket из-за sandbox записать как ограничение среды и повторить в разрешенном test окружении; не маскировать skip как pass. Будущие desktop/acceptance команды ticket 19 добавит явно; сегодня они не считаются существующими.

## 8. Definition of Done для одного ticket

- Все перечисленные acceptance criteria проверены или явно оставлены незакрытыми; без этого Execution не complete.
- Есть краткое объяснение проблемы, итогового поведения и способа проверки.
- Права проверены backend, source of truth определен, ошибка не преобразуется в успешный status.
- При изменении protocol/API/migrations есть compatibility plan и versioned evidence.
- Synthetic/mock и real integration результаты различимы.
- Нет секретов/PII в diff, fixtures, logs, screenshots и report.
- Обязательные проверки прошли; оставшееся ограничение имеет владельца и влияние на gate.
- Связанные docs/ticket обновлены, изменение проверено review. Необоснованное расширение scope вынесено отдельно.

## 9. Evidence и отчет

Путь: `.scratch/production-desktop/evidence/<NN>/report.md` создается при исполнении, не заранее с фиктивным PASS. Большие artifacts хранятся в выбранном CI storage с digest и ограниченным retention; секреты туда не попадают.

Шаблон:

```markdown
# Evidence <NN> — <задача>
Commit:
Environment / OS / versions:
Dataset ID/hash:
Проблема и invariant:
Измененный Interface:
Commands and results:
Negative cases:
Real integration / native acceptance:
Migration / rollback implications:
Ограничения и что НЕ проверено:
Reviewer / findings / disposition:
Следующий ticket и передаваемые contracts:
```

Если задача заблокирована, завершить handoff конкретно: «Для 16 нужен выбранный custody provider и ответственный за ceremony; lab rotation test выполнен, production provisioning не выполнен». Не писать «нужно больше информации» без списка нужных решений.

## 10. Итоговая приемка

Работа агента завершается ticket evidence. Работа проекта завершается установкой программы, реальным role-aware workflow, независимой verification/monitoring и восстановлением на чистой target с продолжением работы. Production readiness дополнительно требует 60-day shadow pilot, независимого аудита/pentest, реального recovery drill, legal/privacy и governance approvals из старого плана. Эти gates не может заменить текстовый self-report агента.

## 11. Готовый стартовый prompt для Coordinator

```text
Реализуй следующий готовый вертикальный срез OneLayer по
.scratch/production-desktop/spec.md и очереди index.md.
Сначала прочитай AGENTS.md, CONTEXT.md, релевантные ADR и этот runbook.
Зафиксируй текущий commit, проверь чужие изменения и evidence dependencies.
Начни с первого незавершенного ready-for-agent ticket без незакрытых зависимостей.
Обновляй Owner/Execution, соблюдая canonical triage Status.
Реализуй acceptance, выполни необходимые отрицательные и интеграционные проверки,
сохрани evidence и проведи review; не ограничивайся повторным написанием плана.
Пользовательский продукт — устанавливаемая программа для внутренних участников;
внешние лица получают результат через сотрудника. Права всегда проверяет backend.
Не подменяй реальное восстановление summary, реальные backups строками БД,
а актуальность — только историческим proof. Frozen protocols меняй лишь versioned.
Если требуется решение владельца, подготовь конкретные варианты и продолжай
независимую работу. Production deployment/ключи/реальные данные — отдельный scope.
В handoff укажи реализованное, команды и результаты, ограничения и следующий ticket.
```
