# OneLayer

Криптографический слой доказуемости и восстановления для государственного
земельного реестра. Anchoring в Solana, selective disclosure, независимый
мониторинг целостности.

**Статус:** Gate A (feasibility). Кода продукта нет — есть криптографическое
ядро и нормативные документы, готовящие Gate B (protocol freeze).

## Документы

| Файл | Содержание |
|---|---|
| `OneLayer_Solana_Technical_Spec_RU.md` | техническая спецификация v0.9 |
| `IMPLEMENTATION_PLAN.md` | план имплементации v2.2, gate-ы A–E |
| `spec/*.md` | нормативные документы протокола |
| `spec/vectors/*.json` | golden vectors — общий вход для обеих реализаций |
| `docs/adr/` | принятые архитектурные решения |

## Что реализовано

| Крейт | Содержание |
|---|---|
| `crates/canonical` | deterministic CBOR (RFC 8949), NFC, `field_salt`, `field_commitment`, field- и batch-деревья, `anchor_preimage` |
| `crates/merkle` | RFC 6962: leaf/node hash, непарный узел без дублирования, proof |

TypeScript-реализация (`packages/canonical-ts`, `packages/merkle-ts`) пишется
в Gate B **по нормативным документам, а не по Rust-коду**: общая библиотека
дала бы Monitor-у и Builder-у одинаковую ошибку (§4.3 плана).

## Проверка

```bash
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check

# перегенерация векторов; в замороженном состоянии не меняет ни одного файла
cargo run -p onelayer-canonical --bin gen-vectors
git diff --exit-code -- spec/vectors
```

## Границы

Система доказывает, что состояние данных существовало не позднее
определённого Solana slot и входило в определённый пакет. Она **не**
доказывает законность первоначального ввода и не заменяет государственный
реестр. Полный перечень не-целей — §1.2 спецификации.
