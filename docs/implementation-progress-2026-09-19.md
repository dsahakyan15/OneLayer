# Реализация: первый этап защиты verifier и incident index

## Исторический отчёт

Проверки ниже относятся к срезу 2026-09-19. Они не подтверждают готовность desktop, нового workflow или полного восстановления. Актуальный статус на 2026-10-02: [что работает и что осталось](implementation-status-2026-10-02.md).

Дата: 2026-09-19. Изменения находятся в рабочем дереве поверх `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2`; commit и deployment не выполнялись. Это частичная реализация [пайплайна](application-pipeline-ru.md), не production acceptance.

## Что работает

1. Verifier требует внешнюю trust policy: genesis кластера, program, config PDA, registry, версии и разрешенные issuer keys. Чужой issuer, program, owner, ledger другого registry, отозванный ключ и истекшая policy отклоняются. Ключ внутри сертификата больше не является достаточным основанием доверия. Формат сертификата V1 сохранен.
2. Incident index читает все страницы до сохраненного cursor. Проверяет источник событий по invocation stack, отклоняет усеченные logs и отсутствующие транзакции. Перед продвижением watermark сверяет количество, идентичность, диапазоны и состояния всех инцидентов с finalized program-owned accounts. Это ловит и bootstrap по уже усеченной истории RPC.
3. Events, cursor и watermark фиксируются одной PostgreSQL-транзакцией с блокировкой на registry. Прерванный scan откатывается. CONFIRMED сохраняется отдельно и продолжает блокировать пригодность данных; FALSE_POSITIVE и RESOLVED снимают блокировку инцидента. Это не заменяет проверку актуальности записи.
4. API, verifier и Next production startup слушают `127.0.0.1`. Native launcher создает явную synthetic trust policy, отказывается молча менять существующее доверие и запрещает миграции при работающем управляемом demo-api.

## Проверено

Среда: Linux Mint 22.1, Node 24.10.0, PostgreSQL из локального pg_config. Использовались синтетические данные и одноразовая БД; рабочая база не мигрировалась.

| Команда | Результат |
|---|---|
| `npm --prefix apps/verifier test` | 29 tests PASS, включая реальные HTTP и provisioning subprocess |
| `npm --prefix apps/verifier run typecheck` | PASS |
| `npm --prefix apps/demo-api test` | 11 файлов PASS |
| `npm --prefix apps/demo-api run typecheck` | PASS |
| `npm --prefix apps/demo-api run test:integration` | PASS: одноразовый PostgreSQL, migrations 0001–0007, rollback, конкурентная сериализация |
| `node --test --experimental-strip-types tests/e2e/*.test.ts` | 9 tests PASS без skip; Rust→TS certificate, differential corpus, actual API/verifier/собранный web startup |
| `bash -n deploy/devnet-demo/native`, `git diff --check` | PASS |

Сетевой тест соединяется через localhost, затем требует ECONNREFUSED по LAN-адресу этой машины для каждого из трех процессов. Ошибка sandbox EPERM не считается успешным тестом. В чистом CI без `.next/BUILD_ID` web startup проверка явно пропускается; здесь сборка была доступна и проверка выполнена. Тесты аккаунтов Solana используют wire fixtures, не live validator. Новый код snapshot validation проверен на подмене owner, discriminator, version, bump, registry, sequence, диапазона, status и stale context.

## Границы результата

- F1 усилен, но trust policy пока локальный deployment-owned файл. Revision floor задает оператор; защищенного монотонного хранилища revision, подписанного распространения и автоматической безопасной ротации нет. Время issuedAt заявляет issuer; это не независимая отметка времени. При компрометации ключа нужен revoke, который запрещает и заявленные старые подписи.
- RPC остается доверенной зависимостью. Account checks не доказывают истинность ответа злонамеренного RPC. Одновременное изменение цепочки во время scan может вызвать безопасный отказ и повторную попытку. Полная сверка всех incidents при каждом refresh нуждается в нагрузочных испытаниях и отдельном фоновом worker.
- F4 остается: недоступный lifecycle не снимает anchored VERIFIED. Текущий результат нельзя трактовать как гарантированную актуальность документа. Это ticket 05.
- Recovery F5/S2–S7 не исправлены этим этапом: нет полного restore, независимых backup storage, устойчивой custody и доказанного full-state checkpoint.
- Loopback устраняет прямое LAN-прослушивание; он не заменяет IdP, MFA, device admission, разграничение полей/объектов и защиту от локального вредоносного процесса. Полная система ролей еще не реализована.
- Устанавливаемого клиента пока нет. Tauri и native UI без WebView сравниваются по [критериям](../.scratch/production-desktop/evidence/02/preflight.md); ни один не объявлен безопасным по названию framework.

## Следующий этап

Завершить контракт identity/session/permissions (07), затем workflow (08) и durable publication/signer (09). Параллельно выполнить native desktop spike (02) с подтверждением конкретных подписываемых данных вне потенциально скомпрометированного UI. До закрытия этих зависимостей не выдавать текущую demo за систему для реальных важных документов.

Инструкции обновления локального demo: [deployment README](../deploy/devnet-demo/README.md). Статусы и evidence: [очередь](../.scratch/production-desktop/index.md).
