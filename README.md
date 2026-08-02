# OneLayer

Криптографический слой доказуемости и восстановления для государственного
земельного реестра. Anchoring в Solana, selective disclosure, независимый
мониторинг целостности.

**Статус:** Gate C (вертикальный pilot). Протокол заморожен (Gate B), собран
сквозной поток на synthetic-данных и devnet, включая визуальный MVP §5.4.
Gate D (независимый Monitor) и Gate E (production hardening) не начаты.

## Документы

| Файл | Содержание |
|---|---|
| `OneLayer_Solana_Technical_Spec_RU.md` | техническая спецификация v0.9 |
| `IMPLEMENTATION_PLAN.md` | план имплементации v2.6, gate-ы A–E |
| `spec/*.md` | draft-документы протокола; становятся нормативными после Gate B |
| `spec/vectors/*.json` | golden vectors — общий вход для обеих реализаций |
| `docs/adr/` | принятые архитектурные решения |
| `docs/use-cases-ru.md` | сценарии использования по акторам: оператор, ревизор, проверяющий, владелец реестра |
| `docs/presentation-ru.md` | разбор потока для презентации: ролевые модели, Merkle proof для QR, восстановление 3-из-5, FAQ |

## Что реализовано

| Крейт | Содержание |
|---|---|
| `crates/canonical` | deterministic CBOR (RFC 8949), NFC, `field_salt`, `field_commitment`, field- и batch-деревья, `anchor_preimage` |
| `crates/merkle` | RFC 6962: leaf/node hash, непарный узел без дублирования, proof |
| `onchain/programs/alloc-spike` | spike `OL-A-04`: измерение предела выделения PDA. В продукт не переносится |

| Пакет / приложение | Содержание |
|---|---|
| `packages/onchain-client` | Codama-клиент из закоммиченного Anchor IDL + drift check (`OL-C-32`) |
| `apps/demo-api` | Admin API: сессии и роли, transaction state machine, выдача сертификатов, event-backed incident index |
| `apps/mvp-web` | Next.js App Router: закрытая Admin-панель и публичная OneLayer-панель |
| `apps/verifier` | REST-верификатор, включая `VERIFIED_HISTORICAL` и `SUPERSEDED` |
| `tests/e2e-web` | детерминированный браузерный E2E с mock Wallet Standard и guarded live smoke |

TypeScript-реализация (`packages/canonical-ts`, `packages/merkle-ts`) пишется
в Gate B **по нормативным документам, а не по Rust-коду**: общая библиотека
дала бы Monitor-у и Builder-у одинаковую ошибку (§4.3 плана).

## Визуальный MVP

```bash
./deploy/devnet-demo/demo ui        # поднимает стек и печатает demo-логины
# Admin:    http://127.0.0.1:8091/admin
# OneLayer: http://127.0.0.1:8091/verify
```

Полный путь: сертификат пользователя (JSON/CSV по схеме `land-registry-v1`) →
валидация и canonical preview → batch и Merkle root → simulation → явный
transaction review → подпись Wallet Standard → finalized anchor → certificate
package и QR → публичная проверка. Сертификат не выдаётся до `finalized`;
`certificateHash` появляется только после выдачи package.

Поля записи задаёт импортированный сертификат, а не константа: поле вне схемы
отклоняется как `CANONICALIZATION_FAILED`. При выдаче оператор выбирает объём
раскрытия — `FULL_RECORD` или `SELECTIVE_FIELDS` с field proof только выбранных
путей. Публичная страница показывает ровно то, что доказал верификатор.

## Проверка

```bash
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check

# перегенерация векторов; в замороженном состоянии не меняет ни одного файла
cargo run -p onelayer-canonical --bin gen-vectors
git diff --exit-code -- spec/vectors

# generated on-chain client не разошёлся с IDL
npm --prefix packages/onchain-client run check-drift

# детерминированный браузерный E2E: без Docker, валидатора и SOL
ONELAYER_ADMIN_API_URL=http://127.0.0.1:8199 ONELAYER_VERIFIER_URL=http://127.0.0.1:8199 \
  npm --prefix apps/mvp-web run build
npm --prefix tests/e2e-web test
```

## Synthetic devnet demo

Presentation flow, guarded Compose project, approval digests, QR verification,
tampering incident, fixture-only reset, and optional clean-room recovery are in
[`deploy/devnet-demo/README.md`](deploy/devnet-demo/README.md). Start with:

```bash
./deploy/devnet-demo/demo plan
```

`plan` builds and prepares deterministic artifacts but sends no Solana transaction.

Пошаговая инструкция на русском (запуск, хеширование и anchoring в Solana, добавление
новых синтетических записей и сертификатов) — [`docs/devnet-demo-guide-ru.md`](docs/devnet-demo-guide-ru.md).

## Границы

Система доказывает, что состояние данных существовало не позднее
определённого Solana slot и входило в определённый пакет. Она **не**
доказывает законность первоначального ввода и не заменяет государственный
реестр. Полный перечень не-целей — §1.2 спецификации.
