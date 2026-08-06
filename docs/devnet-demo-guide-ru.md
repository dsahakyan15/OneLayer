# Native devnet demo OneLayer

Этот документ описывает локальный запуск MVP вне внешнего runtime. Контур
использует только synthetic-данные, Solana devnet и PostgreSQL 17 на loopback.

## 1. Требования

Нужны:

- Node.js 24 и npm;
- PostgreSQL 17;
- Rust toolchain для тестов и `cargo`-утилит;
- Solana CLI и Anchor CLI, если требуется подготовка или публикация программы
  в devnet.

На macOS PostgreSQL устанавливается так:

```bash
brew install postgresql@17
```

Проверьте зависимости приложений:

```bash
npm --prefix apps/demo-api ci
npm --prefix apps/verifier ci
npm --prefix apps/mvp-web ci
npm --prefix packages/onchain-client ci
```

## 2. Запуск MVP

```bash
./deploy/devnet-demo/native start
```

Лаунчер создаёт локальный PostgreSQL-кластер, применяет миграции и fixture,
собирает Next.js-приложение и запускает три Node-сервиса.

| Сервис | Адрес |
|---|---|
| Admin/OneLayer web | <http://127.0.0.1:8091> |
| demo-api | <http://127.0.0.1:8090> |
| verifier | <http://127.0.0.1:8080> |
| PostgreSQL | `127.0.0.1:55432` |

Проверка готовности:

```bash
./deploy/devnet-demo/native status
curl http://127.0.0.1:8090/v1/health
curl http://127.0.0.1:8080/v1/health
curl http://127.0.0.1:8091/verify
```

Демо-пароли создаются в tmpfs:
`/dev/shm/onelayer-devnet-demo/admin-credentials.json`.

## 3. Проверка в браузере

Откройте:

- <http://127.0.0.1:8091/admin> — Admin;
- <http://127.0.0.1:8091/verify> — публичная проверка.

Детерминированный браузерный E2E использует fixture backend и не требует
валидатора, devnet SOL или подготовленного аккаунта:

```bash
npm --prefix tests/e2e-web test
```

Native smoke уже запущенного контура можно выполнить вручную, если известен QR
URL сертификата:

```bash
cd tests/e2e-web
ONELAYER_LIVE_WEB_URL=http://127.0.0.1:8091 \
ONELAYER_LIVE_QR_URL='http://127.0.0.1:8091/verify?...' \
npx playwright test --config=playwright.live.config.ts
```

## 4. Approval boundary для devnet

Подготовьте runtime и соберите программу:

```bash
./deploy/devnet-demo/scripts/initialize-runtime
(cd onchain && NO_DNA=1 anchor build)
```

Сначала сформируйте digest без транзакций:

```bash
./deploy/devnet-demo/scripts/program-deploy plan
```

Применение deploy допускается только с тем же digest:

```bash
ONELAYER_DEVNET_DEPLOY_APPROVED=<approval_digest> \
./deploy/devnet-demo/scripts/program-deploy apply
```

Публикация реестра и операции Wallet Standard имеют отдельную approval-границу.
Никакой ключ, seed phrase или private key не вводится в браузер.

## 5. Backup MVP

В Admin откройте `/admin/backups`. Система создаёт локальные synthetic
`BackupCenter`-ы, сохраняет immutable snapshots, показывает статус каждой
копии и поддерживает bounded recovery flow с отдельным `chief_admin` approval.
Это демонстрация протокола и интерфейса; production storage, географическая
независимость и полноценный restore drill относятся к Gate E.

## 6. Управление и логи

```bash
./deploy/devnet-demo/native logs
./deploy/devnet-demo/native restart
./deploy/devnet-demo/native stop
```

Данные PostgreSQL, PID-файлы и логи лежат в
`deploy/devnet-demo/.runtime/native/` и исключены из Git. Ключи и demo-пароли
лежат в `/dev/shm/onelayer-devnet-demo`.

## 7. Типовые проблемы

| Симптом | Действие |
|---|---|
| `PostgreSQL 17 is required` | установить `postgresql@17` и повторить `native start` |
| порт `8080`, `8090` или `8091` занят | остановить процесс, который его держит, затем повторить запуск |
| отсутствует пакет Node | выполнить соответствующий `npm --prefix <app> ci` |
| не хватает `@solana/kit` | установить зависимости `apps/verifier` и `packages/onchain-client` |
| сервис не поднялся | посмотреть `./deploy/devnet-demo/native logs` |
