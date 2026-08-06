# OneLayer synthetic devnet demo

Native demo для локальной проверки MVP: PostgreSQL 17, Node-сервисы, Solana
devnet и loopback-порты. Все данные синтетические, ключи создаются в tmpfs,
production credentials не используются.

## Запуск

Установите PostgreSQL 17 и зависимости приложений:

```bash
brew install postgresql@17
npm --prefix apps/demo-api ci
npm --prefix apps/verifier ci
npm --prefix apps/mvp-web ci
npm --prefix packages/onchain-client ci
```

Запустите MVP:

```bash
./deploy/devnet-demo/native start
```

Панели доступны по адресам:

- Admin: <http://127.0.0.1:8091/admin>
- OneLayer: <http://127.0.0.1:8091/verify>
- demo-api health: <http://127.0.0.1:8090/v1/health>
- verifier health: <http://127.0.0.1:8080/v1/health>

Демо-учётные данные находятся в
`/dev/shm/onelayer-devnet-demo/admin-credentials.json`.

## Управление native runtime

```bash
./deploy/devnet-demo/native status
./deploy/devnet-demo/native logs
./deploy/devnet-demo/native restart
./deploy/devnet-demo/native stop
```

Локальная база и логи находятся в игнорируемом каталоге
`deploy/devnet-demo/.runtime/native/`. База слушает только `127.0.0.1:55432`,
а веб и API — только loopback-порты `8091`, `8090` и `8080`.

## Граница публикации в devnet

Подготовка программы и её approval digest выполняются отдельно:

```bash
cd onchain && NO_DNA=1 anchor build && cd ..
./deploy/devnet-demo/scripts/initialize-runtime
./deploy/devnet-demo/scripts/program-deploy plan
```

Команда `plan` ничего не публикует. Применение требует явно переданного
`ONELAYER_DEVNET_DEPLOY_APPROVED`, а публикация реестра — отдельного
`ONELAYER_DEVNET_TX_APPROVED`. Для обычной проверки UI запуск в devnet не
нужен: native MVP использует синтетическую базу и заранее подготовленные
данные.

## Браузерные проверки

Детерминированный E2E запускается отдельно и не требует сети или SOL:

```bash
npm --prefix tests/e2e-web test
```

Для проверки уже подготовленного native devnet URL можно запустить guarded
live smoke вручную:

```bash
ONELAYER_LIVE_WEB_URL=http://127.0.0.1:8091 \
ONELAYER_LIVE_QR_URL='http://127.0.0.1:8091/verify?...' \
npx --prefix tests/e2e-web playwright test \
  --config=playwright.live.config.ts
```

## Backup-панель MVP

Оператор открывает `/admin/backups`, видит стартовые локальные
`BackupCenter`-ы и может создать snapshot, проверить статусы репликации и
запустить bounded recovery flow. Эти центры являются локальным MVP-хранилищем;
географическая независимость и production restore drill относятся к Gate E.

## Ограничения

Контур предназначен для synthetic devnet demo. Он не доказывает законность
исходных данных, production security, независимость recovery-центров или
готовность к работе с реальными персональными данными.
