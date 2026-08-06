# ADR-0003 — границы визуального MVP

**Статус:** принят, 2026-08-01
**Контекст:** §5.4 плана (`OL-C-21`…`OL-C-35`)

## Решение 1. Codama-клиент генерируется из закоммиченного IDL

`onchain/target/` в `.gitignore`, поэтому drift check не может зависеть от сборки
программы в CI. IDL копируется в `onchain/idl/onelayer_registry.json` и
коммитится; `packages/onchain-client` генерируется из него.
`npm run check-drift` проверяет обе границы: сгенерированный клиент против
закоммиченного IDL и, если рядом есть результат локальной сборки, закоммиченный
IDL против `onchain/target/idl/`.

Генератор дополнительно переписывает bundler-специфичные импорты в явные
`.ts`/`/index.ts` — Node ESM не резолвит ни расширения по умолчанию, ни
directory index. Преобразование детерминированное, поэтому drift check сравнивает
одинаково обработанные деревья. Из-за оставшихся в сгенерированном коде
angle-bracket type assertions потребители запускаются с
`--experimental-transform-types`, а не `--experimental-strip-types`.

## Решение 2. Wallet Standard используется напрямую, без `@solana/kit-plugin-wallet`

План называл `@solana/kit-plugin-wallet` + `@solana/react`. Реализовано на
`@wallet-standard/app` и feature-контракте `standard:connect` /
`solana:signTransaction` — том же, который оборачивает плагин.

Причина: в контуре разработки нет реального wallet-расширения, а плагин требует
цепочки `UiWalletAccount`/registry, которую нечем проверить. Прямой feature-API
проверяется mock-кошельком Wallet Standard в браузерном E2E и сохраняет все
нормативные свойства: подпись только точных подготовленных байтов, только
`solana:devnet`, отсутствие keypair/seed в UI. Переход на плагин возможен без
изменения серверного контракта.

## Решение 3. Детерминированный E2E работает против фикстурного backend, а не Surfpool

`OL-C-29` предполагал локальный Surfpool. Реализован фикстурный backend
(`tests/e2e-web/fixture-backend.ts`), воспроизводящий контракт Admin API —
сессии, роли, CSRF, idempotency, transaction state machine, QR hash binding — со
скриптованными ответами цепочки.

Что это проверяет: браузерный flow, все result views, ограничения роли на API,
двойной клик и reload, protokoll-независимое поведение при
`SIMULATION_FAILED`/`SIGNING_REJECTED`/`EXPIRED`.

Чего это **не** проверяет: on-chain инварианты программы (покрыты Rust-тестами
`onchain/`), криптографию сертификата (покрыта unit-тестами
`apps/demo-api`, `apps/verifier`, `packages/*`) и реальную finalization.
Последнее закрывает отдельно разрешённый native live-devnet smoke (`OL-C-34`).

## Решение 4. Live smoke проверяет внутренний путь, не подписывает в браузере

`OL-C-34` выполняется на сертификате, заякоренном guarded CLI publish: браузер
проверяет `QR → finalized anchor → VERIFIED` и отказ при подменённом QR hash
изнутри сети управляемых рабочих компьютеров реестра. Внешний public ingress не
является частью smoke и не должен существовать. Ключ операторского кошелька в
браузер не попадает даже в guarded-прогоне.

## Решение 5. Incident index имеет два источника с разным весом

Индекс строится из finalized `IncidentOpened` / `IncidentResolved` и задаёт
watermark. Локальные находки монитора (прямое вмешательство в БД, сценарий
`demo incident`) отдаются в том же ответе с `source: "LOCAL_MONITOR"` и **не**
влияют на watermark: доказуемость полноты остаётся свойством on-chain событий.
