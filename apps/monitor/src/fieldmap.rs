//! Независимая реализация отображения workflow-версии в протокольный лист.
//!
//! Monitor пересчитывает обязательства сам, по тексту контрактов, а не
//! вызывая Builder (`apps/demo-api`, TypeScript). Протокольные примитивы
//! (`spec/leaf-v1.md`, `spec/merkle-tree-v1.md`, `spec/canonical-record-v1.md`)
//! берутся из `crates/canonical` / `crates/merkle` — отдельной от Builder
//! реализации frozen spec.
//!
//! Нормативное описание, по которому написан этот модуль (для
//! `ONELAYER:WORKFLOW:FIELDMAP:V1` отдельного документа в `spec/` пока нет —
//! это открытый пункт handoff):
//!
//! * поле `operation` = text `upsert` | `tombstone`; tombstone не имеет других полей;
//! * каждый ключ верхнего уровня `K` объекта `payload` даёт поле `payload.K`,
//!   значение — весь JSON-подобъект в deterministic CBOR (объекты → map,
//!   массивы → array, строки → text NFC, целые — только safe integer
//!   `|n| <= 2^53-1`, дробные числа запрещены);
//! * ключи: непустые, без `.`, попарно различны после NFC (на любой глубине);
//! * `record_field_key = HMAC-SHA256(field_key_master, "ONELAYER:WORKFLOW:FIELDKEY:V1"
//!   || 0x00 || NFC(registry_id) || 0x00 || NFC(record_id) || 0x00 || decimal(version))`;
//! * `record_id_commitment = HMAC-SHA256(id_key, registry_id || 0x00 || record_id)` (leaf-v1).
//!
//! Хэш workflow payload (`docs/registry-workflow-contract.md`):
//! `SHA-256("ONELAYER:WORKFLOW:JSON:V1\n" || canonical_json({operation,payload}))`,
//! где canonical JSON — ключи объектов отсортированы рекурсивно (порядок
//! UTF-16 code units, как `Array.prototype.sort` в эталонном writer),
//! строки экранированы как в JSON.stringify, числа — десятичные целые.

use hmac::{Hmac, Mac};
use onelayer_canonical::cbor::Value;
use onelayer_canonical::commit::{
    batch_leaf_hash, record_commitment, record_id_commitment, registry_id_hash, BatchRecord,
    BatchTree, FieldEntry, FieldTree, RecordFieldKey,
};
use onelayer_canonical::nfc;
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

type HmacSha256 = Hmac<Sha256>;
pub type Hash = [u8; 32];

pub const FIELD_KEY_DOMAIN: &[u8] = b"ONELAYER:WORKFLOW:FIELDKEY:V1";
pub const WORKFLOW_JSON_DOMAIN: &[u8] = b"ONELAYER:WORKFLOW:JSON:V1\n";
const MAX_SAFE_INTEGER: i128 = 9_007_199_254_740_991;

/// Ключи обязательств. Monitor получает их только для пересчёта (read-only
/// verification material); подписывающих ключей chain у Monitor нет.
#[derive(Clone)]
pub struct CommitKeys {
    pub id_key: [u8; 32],
    pub field_key_master: [u8; 32],
}

impl std::fmt::Debug for CommitKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommitKeys(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapError(pub String);

impl std::fmt::Display for MapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UNMAPPABLE_VERSION: {}", self.0)
    }
}

/// Пересчитанные Monitor-ом обязательства одной версии.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafCommit {
    pub record_id: String,
    pub version: u64,
    pub record_id_commitment: Hash,
    pub field_root: Hash,
    pub record_commitment: Hash,
    pub leaf_hash: Hash,
}

fn json_to_cbor(value: &Json, at: &str) -> Result<Value, MapError> {
    Ok(match value {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::String(s) => Value::Text(s.clone()),
        Json::Number(n) => {
            Value::Int(safe_integer(n).ok_or_else(|| MapError(format!("{at}: number")))?)
        }
        Json::Array(items) => Value::Array(
            items
                .iter()
                .enumerate()
                .map(|(i, item)| json_to_cbor(item, &format!("{at}[{i}]")))
                .collect::<Result<_, _>>()?,
        ),
        Json::Object(map) => {
            let mut seen = BTreeSet::new();
            let mut out = BTreeMap::new();
            for (k, v) in map {
                if !seen.insert(nfc(k)) {
                    return Err(MapError(format!("{at}: NFC key collision")));
                }
                out.insert(k.clone(), json_to_cbor(v, &format!("{at}.{k}"))?);
            }
            Value::Map(out)
        }
    })
}

/// Число допустимо, только если его значение — safe integer (как в эталонном
/// JSON-парсере writer-а: `1.0` и `1` — одно значение, `1.5` — нет).
fn safe_integer(n: &serde_json::Number) -> Option<i128> {
    let v: i128 = if let Some(i) = n.as_i64() {
        i128::from(i)
    } else if let Some(u) = n.as_u64() {
        i128::from(u)
    } else {
        let f = n.as_f64()?;
        if !f.is_finite() || f.fract() != 0.0 || f.abs() > MAX_SAFE_INTEGER as f64 {
            return None;
        }
        f as i128
    };
    (v.abs() <= MAX_SAFE_INTEGER).then_some(v)
}

/// Поля FIELDMAP:V1.
pub fn workflow_fields(operation: &str, payload: &Json) -> Result<Vec<FieldEntry>, MapError> {
    if operation != "upsert" && operation != "tombstone" {
        return Err(MapError("operation".into()));
    }
    let Json::Object(map) = payload else {
        return Err(MapError("payload is not an object".into()));
    };
    if operation == "tombstone" && !map.is_empty() {
        return Err(MapError("tombstone payload".into()));
    }
    let mut fields = vec![FieldEntry {
        path: "operation".into(),
        value: Value::Text(operation.into()),
    }];
    let mut seen = BTreeSet::new();
    for (k, v) in map {
        if k.is_empty() || k.contains('.') {
            return Err(MapError("payload key".into()));
        }
        if !seen.insert(nfc(k)) {
            return Err(MapError("payload: NFC key collision".into()));
        }
        fields.push(FieldEntry {
            path: format!("payload.{k}"),
            value: json_to_cbor(v, &format!("payload.{k}"))?,
        });
    }
    Ok(fields)
}

pub fn record_field_key(
    master: &[u8; 32],
    registry_id: &str,
    record_id: &str,
    version: u64,
) -> RecordFieldKey {
    let mut mac = HmacSha256::new_from_slice(master).expect("HMAC принимает ключ любой длины");
    mac.update(FIELD_KEY_DOMAIN);
    mac.update(&[0]);
    mac.update(nfc(registry_id).as_bytes());
    mac.update(&[0]);
    mac.update(nfc(record_id).as_bytes());
    mac.update(&[0]);
    mac.update(version.to_string().as_bytes());
    RecordFieldKey::from_bytes(mac.finalize().into_bytes().into())
}

/// Лист batch-дерева для одной workflow-версии.
pub fn leaf(
    keys: &CommitKeys,
    registry_id: &str,
    record_id: &str,
    version: u64,
    operation: &str,
    payload: &Json,
) -> Result<LeafCommit, MapError> {
    let fields = workflow_fields(operation, payload)?;
    let key = record_field_key(&keys.field_key_master, registry_id, record_id, version);
    let tree = FieldTree::build(&key, &fields).map_err(|e| MapError(e.to_string()))?;
    let rid = record_id_commitment(&keys.id_key, registry_id, record_id);
    let commitment = record_commitment(&registry_id_hash(registry_id), &rid, version, &tree.root());
    Ok(LeafCommit {
        record_id: record_id.into(),
        version,
        record_id_commitment: rid,
        field_root: tree.root(),
        record_commitment: commitment,
        leaf_hash: batch_leaf_hash(&commitment),
    })
}

/// Корень batch по leaf-v1: сортировка `(record_id_commitment, version)`.
pub fn batch_root(leaves: &[LeafCommit]) -> Result<Hash, MapError> {
    let mut sorted: Vec<&LeafCommit> = leaves.iter().collect();
    sorted.sort_by(|a, b| {
        a.record_id_commitment
            .cmp(&b.record_id_commitment)
            .then(a.version.cmp(&b.version))
    });
    if sorted.windows(2).any(|w| {
        w[0].record_id_commitment == w[1].record_id_commitment && w[0].version == w[1].version
    }) {
        return Err(MapError("duplicate record version in batch".into()));
    }
    let records = leaves
        .iter()
        .map(|l| BatchRecord {
            record_id_commitment: l.record_id_commitment,
            record_version: l.version,
            record_commitment: l.record_commitment,
        })
        .collect();
    BatchTree::build(records)
        .map(|t| t.root())
        .map_err(|e| MapError(e.to_string()))
}

fn push_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn canonical_json(value: &Json, out: &mut String) -> Result<(), MapError> {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::String(s) => push_json_string(s, out),
        Json::Number(n) => {
            let v = safe_integer(n)
                .ok_or_else(|| MapError("payload hash: non-integer number".into()))?;
            out.push_str(&v.to_string());
        }
        Json::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(item, out)?;
            }
            out.push(']');
        }
        Json::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                push_json_string(k, out);
                out.push(':');
                canonical_json(&map[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// `payload_hash` по контракту workflow V1 над `{operation, payload}`.
pub fn workflow_payload_hash(operation: &str, payload: &Json) -> Result<String, MapError> {
    let mut body = serde_json::Map::new();
    body.insert("operation".into(), Json::String(operation.into()));
    body.insert("payload".into(), payload.clone());
    let mut text = String::new();
    canonical_json(&Json::Object(body), &mut text)?;
    let mut h = Sha256::new();
    h.update(WORKFLOW_JSON_DOMAIN);
    h.update(text.as_bytes());
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn keys() -> CommitKeys {
        CommitKeys {
            id_key: [7; 32],
            field_key_master: [9; 32],
        }
    }

    #[test]
    fn tombstone_rejects_fields_and_float_is_unmappable() {
        assert!(workflow_fields("tombstone", &json!({"a": 1})).is_err());
        assert!(workflow_fields("tombstone", &json!({})).is_ok());
        assert!(workflow_fields("upsert", &json!({"a": 1.5})).is_err());
        assert!(workflow_fields("upsert", &json!({"a": 9007199254740992u64})).is_err());
        assert!(workflow_fields("upsert", &json!({"a.b": 1})).is_err());
        assert!(workflow_fields("upsert", &json!({"": 1})).is_err());
        assert!(workflow_fields("delete", &json!({})).is_err());
        // 1.0 — то же значение, что 1 (как в JSON.parse эталонного writer).
        let a = leaf(&keys(), "r", "x", 1, "upsert", &json!({"n": 1})).unwrap();
        let b = leaf(
            &keys(),
            "r",
            "x",
            1,
            "upsert",
            &serde_json::from_str::<Json>("{\"n\":1.0}").unwrap(),
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn every_input_changes_the_leaf() {
        let base = leaf(&keys(), "r", "x", 1, "upsert", &json!({"n": 1})).unwrap();
        let other = [
            leaf(&keys(), "r", "x", 2, "upsert", &json!({"n": 1})).unwrap(),
            leaf(&keys(), "r", "y", 1, "upsert", &json!({"n": 1})).unwrap(),
            leaf(&keys(), "q", "x", 1, "upsert", &json!({"n": 1})).unwrap(),
            leaf(&keys(), "r", "x", 1, "upsert", &json!({"n": 2})).unwrap(),
            leaf(&keys(), "r", "x", 1, "upsert", &json!({"m": 1})).unwrap(),
        ];
        for o in other {
            assert_ne!(o.leaf_hash, base.leaf_hash);
        }
    }

    #[test]
    fn payload_hash_matches_contract_text() {
        // Эталон вручную: canonical JSON строки ниже, SHA-256 с доменом.
        let text = "{\"operation\":\"upsert\",\"payload\":{\"a\":[1,\"x\\n\"],\"b\":null}}";
        let mut h = Sha256::new();
        h.update(WORKFLOW_JSON_DOMAIN);
        h.update(text.as_bytes());
        let expected = hex::encode(h.finalize());
        assert_eq!(
            workflow_payload_hash("upsert", &json!({"b": null, "a": [1, "x\n"]})).unwrap(),
            expected
        );
    }

    #[test]
    fn utf16_key_order_differs_from_byte_order() {
        // U+FF61 (BMP) и U+1F600 (surrogate pair): в UTF-16 суррогат 0xD83D < 0xFF61.
        let mut s = String::new();
        canonical_json(&json!({"\u{ff61}": 1, "\u{1f600}": 2}), &mut s).unwrap();
        assert!(s.find('\u{1f600}').unwrap() < s.find('\u{ff61}').unwrap());
    }

    #[test]
    fn batch_root_rejects_duplicate_versions() {
        let a = leaf(&keys(), "r", "x", 1, "upsert", &json!({"n": 1})).unwrap();
        assert!(batch_root(&[a.clone(), a]).is_err());
    }
}
