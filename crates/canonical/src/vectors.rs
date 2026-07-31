//! Golden vectors (§4.2 плана).
//!
//! Векторы порождаются из одного описания кейсов и записываются в
//! `spec/vectors/*.json`. Оба контура — Rust-pipeline и TypeScript
//! Monitor/Verifier — прогоняют один и тот же файл.
//!
//! Векторы выбраны по классам эквивалентности, а не по количеству.
//! Каждый вектор несёт вход, промежуточные значения и итог: для field-дерева
//! это `field_salt`, `field_commitment`, `field_tree_leaf_hash`, `field_root`,
//! `record_commitment` и `batch_leaf_hash` **раздельно** — двойное
//! хэширование фиксируется явно, чтобы вторая реализация не могла
//! «угадать» его одним совпавшим корнем.

use crate::anchor::AnchorFields;
use crate::cbor::{self, Value};
use crate::certificate::{
    AnchorReference, CertificateBody, DisclosureMode, FieldProof, MerkleProof,
};
use crate::commit::{
    self, batch_leaf_hash, field_commitment, field_salt, field_tree_leaf_hash, record_commitment,
    registry_id_hash, BatchRecord, BatchTree, FieldEntry, FieldTree, RecordFieldKey,
};
use crate::manifest::ManifestFields;
use onelayer_merkle as merkle;
use serde_json::{json, Map, Value as J};

/// Ключ солей во всех векторах. Тестовое значение, не CSPRNG: вектор должен
/// быть воспроизводим побайтово.
const VECTOR_FIELD_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

const VECTOR_REGISTRY_ID: &str = "gov.registry.land";
const VECTOR_ID_KEY: [u8; 32] = [0x5a; 32];
const VECTOR_INTERNAL_RECORD_ID: &str = "record-001";

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

/// Описание значения в файле вектора. Тип указан явно, чтобы TS-реализация
/// не выводила его из JSON: `1` и `1.0` в JSON неразличимы, а в CBOR — да.
fn value_json(v: &Value) -> J {
    match v {
        Value::Null => json!({ "type": "null" }),
        Value::Bool(b) => json!({ "type": "bool", "value": b }),
        Value::Int(i) => json!({ "type": "int", "value": i.to_string() }),
        Value::Text(s) => json!({ "type": "text", "value": s }),
        Value::Bytes(b) => json!({ "type": "bytes", "hex": hx(b) }),
        Value::Array(items) => json!({
            "type": "array",
            "items": items.iter().map(value_json).collect::<Vec<_>>()
        }),
        Value::Map(m) => {
            let mut entries = Map::new();
            for (k, val) in m {
                entries.insert(k.clone(), value_json(val));
            }
            json!({ "type": "map", "entries": entries })
        }
    }
}

// ---------------------------------------------------------------- canonical

fn canonical_cases() -> Vec<(&'static str, &'static str, Value)> {
    use Value::*;
    vec![
        ("int-zero", "нижняя граница короткой формы", Int(0)),
        ("int-23", "последнее значение в заголовке", Int(23)),
        ("int-24", "переход на 1-байтовый argument", Int(24)),
        ("int-255", "граница 1 байта", Int(255)),
        ("int-256", "переход на 2 байта", Int(256)),
        ("int-65536", "переход на 4 байта", Int(65_536)),
        ("int-4294967296", "переход на 8 байт", Int(4_294_967_296)),
        ("int-neg-1", "major type 1, кратчайшая форма", Int(-1)),
        ("int-neg-24", "последнее значение в заголовке", Int(-24)),
        ("int-neg-25", "переход на 1-байтовый argument", Int(-25)),
        ("null", "null отличается от отсутствующего ключа", Null),
        ("bool-true", "простое значение", Bool(true)),
        ("bool-false", "простое значение", Bool(false)),
        ("text-empty", "пустая строка", Text(String::new())),
        (
            "text-cyrillic-precomposed",
            "U+0439 — NFC-форма",
            Text("\u{0439}".into()),
        ),
        (
            "text-cyrillic-decomposed",
            "U+0438 U+0306 — обязан дать те же байты, что precomposed",
            Text("\u{0438}\u{0306}".into()),
        ),
        (
            "text-armenian-ligature",
            "U+0587 не разлагается под NFC (в отличие от NFKC)",
            Text("\u{0587}".into()),
        ),
        (
            "text-non-bmp",
            "U+1F600: суррогатная пара в UTF-16, 4 байта в UTF-8",
            Text("\u{1F600}".into()),
        ),
        (
            "text-rtl-marker",
            "U+200F значим и не удаляется",
            Text("a\u{200F}b".into()),
        ),
        (
            "decimal-scale-preserved",
            "0.10 и 0.1 различны: decimal — строка с фиксированным scale",
            Text("0.10".into()),
        ),
        (
            "decimal-scale-alt",
            "парный вектор к decimal-scale-preserved",
            Text("0.1".into()),
        ),
        (
            "decimal-negative",
            "отрицательный decimal остаётся строкой",
            Text("-1234.50".into()),
        ),
        (
            "decimal-negative-zero",
            "-0 отличается от 0 как строка",
            Text("-0".into()),
        ),
        (
            "timestamp-rfc3339",
            "UTC без дробной части",
            Text("2026-07-31T00:00:00Z".into()),
        ),
        (
            "timestamp-leap-second",
            "60-я секунда допустима в RFC 3339 и должна кодироваться как есть",
            Text("2016-12-31T23:59:60Z".into()),
        ),
        ("array-empty", "пустой массив", Array(vec![])),
        (
            "array-order-ab",
            "порядок массива значим",
            Array(vec![Text("a".into()), Text("b".into())]),
        ),
        (
            "array-order-ba",
            "парный вектор к array-order-ab",
            Array(vec![Text("b".into()), Text("a".into())]),
        ),
        ("map-empty", "пустая map", Map(Default::default())),
        (
            "map-key-order",
            "ключи сортируются по закодированным байтам: \"z\" перед \"aa\"",
            {
                let mut m = std::collections::BTreeMap::new();
                m.insert("aa".to_string(), Int(1));
                m.insert("z".to_string(), Int(2));
                Map(m)
            },
        ),
        ("map-with-null", "явный null в map", {
            let mut m = std::collections::BTreeMap::new();
            m.insert("a".to_string(), Null);
            Map(m)
        }),
        ("map-nested", "вложенная структура", {
            let mut inner = std::collections::BTreeMap::new();
            inner.insert("type".to_string(), Text("OWNERSHIP".into()));
            inner.insert("share".to_string(), Text("1/2".into()));
            let mut m = std::collections::BTreeMap::new();
            m.insert("rights".to_string(), Array(vec![Map(inner)]));
            Map(m)
        }),
    ]
}

pub fn canonical_vectors() -> J {
    let items: Vec<J> = canonical_cases()
        .into_iter()
        .map(|(id, desc, v)| {
            let bytes = cbor::encode(&v).expect("вектор должен кодироваться");
            json!({
                "id": id,
                "description": desc,
                "input": value_json(&v),
                "expected": {
                    "cbor_hex": hx(&bytes),
                    "byte_len": bytes.len(),
                }
            })
        })
        .collect();
    json!({
        "spec": "spec/canonical-record-v1.md",
        "profile": "RFC 8949 core deterministic; floats запрещены; NFC до кодирования",
        "vectors": items
    })
}

// --------------------------------------------------------------------- leaf

struct LeafCase {
    id: &'static str,
    description: &'static str,
    record_version: u64,
    fields: Vec<(&'static str, Value)>,
}

fn leaf_cases() -> Vec<LeafCase> {
    vec![
        LeafCase {
            id: "single-field",
            description: "одно поле: field_root равен field_tree_leaf_hash",
            record_version: 1,
            fields: vec![("status", Value::Text("ACTIVE".into()))],
        },
        LeafCase {
            id: "two-fields",
            description: "два поля, полная пара",
            record_version: 1,
            fields: vec![
                ("status", Value::Text("ACTIVE".into())),
                ("area", Value::Text("1234.50".into())),
            ],
        },
        LeafCase {
            id: "three-fields-unpaired",
            description: "три поля: непарный лист поднимается без хэширования",
            record_version: 1,
            fields: vec![
                ("status", Value::Text("ACTIVE".into())),
                ("area", Value::Text("1234.50".into())),
                ("registeredAt", Value::Text("2026-07-31T00:00:00Z".into())),
            ],
        },
        LeafCase {
            id: "nested-paths",
            description: "вложенные пути с индексами массива",
            record_version: 7,
            fields: vec![
                ("rights/0/type", Value::Text("OWNERSHIP".into())),
                ("rights/0/share", Value::Text("1/2".into())),
                ("rights/1/type", Value::Text("MORTGAGE".into())),
                ("status", Value::Text("ACTIVE".into())),
            ],
        },
        LeafCase {
            id: "path-sorting-by-bytes",
            description: "порядок листьев — по path_bytes, не по code points: \"z\" < \"aa\" ложно",
            record_version: 1,
            fields: vec![
                ("z", Value::Int(1)),
                ("aa", Value::Int(2)),
                ("\u{0430}", Value::Int(3)), // кириллическая "а": 2 байта UTF-8
            ],
        },
        LeafCase {
            id: "unicode-path-nfc",
            description: "путь нормализуется NFC до вычисления соли и длины",
            record_version: 1,
            fields: vec![("\u{0438}\u{0306}", Value::Text("значение".into()))],
        },
        LeafCase {
            id: "null-value-field",
            description: "поле со значением null присутствует в дереве",
            record_version: 2,
            fields: vec![
                ("encumbrances", Value::Null),
                ("status", Value::Text("ACTIVE".into())),
            ],
        },
        LeafCase {
            id: "empty-array-value",
            description: "пустой массив отличается от null и от отсутствия поля",
            record_version: 2,
            fields: vec![
                ("encumbrances", Value::Array(vec![])),
                ("status", Value::Text("ACTIVE".into())),
            ],
        },
        LeafCase {
            id: "high-record-version",
            description: "record_version в record_commitment кодируется u64_be",
            record_version: u64::MAX,
            fields: vec![("status", Value::Text("ACTIVE".into()))],
        },
    ]
}

pub fn leaf_vectors() -> J {
    let key = RecordFieldKey::from_bytes(VECTOR_FIELD_KEY);
    let rid_hash = registry_id_hash(VECTOR_REGISTRY_ID);
    let idc = commit::record_id_commitment(
        &VECTOR_ID_KEY,
        VECTOR_REGISTRY_ID,
        VECTOR_INTERNAL_RECORD_ID,
    );

    let items: Vec<J> = leaf_cases()
        .into_iter()
        .map(|case| {
            let entries: Vec<FieldEntry> = case
                .fields
                .iter()
                .map(|(p, v)| FieldEntry {
                    path: (*p).to_string(),
                    value: v.clone(),
                })
                .collect();
            let tree = FieldTree::build(&key, &entries).expect("вектор должен строиться");

            let fields: Vec<J> = case
                .fields
                .iter()
                .map(|(path, value)| {
                    let salt = field_salt(&key, path).unwrap();
                    let commitment = field_commitment(path, value, &salt).unwrap();
                    let pb = commit::path_bytes(path).unwrap();
                    json!({
                        "path": path,
                        "path_bytes_hex": hx(&pb),
                        "path_byte_len": pb.len(),
                        "value": value_json(value),
                        "value_cbor_hex": hx(&cbor::encode(value).unwrap()),
                        "field_salt": hx(&salt),
                        "field_commitment": hx(&commitment),
                        "field_tree_leaf_hash": hx(&field_tree_leaf_hash(&commitment)),
                        "leaf_index": tree.index_of(path).unwrap(),
                    })
                })
                .collect();

            let field_root = tree.root();
            let rc = record_commitment(&rid_hash, &idc, case.record_version, &field_root);

            json!({
                "id": case.id,
                "description": case.description,
                "input": {
                    "registry_id": VECTOR_REGISTRY_ID,
                    "record_id_commitment": hx(&idc),
                    "record_field_key": hx(&VECTOR_FIELD_KEY),
                    "record_version": case.record_version.to_string(),
                },
                "fields": fields,
                "expected": {
                    "registry_id_hash": hx(&rid_hash),
                    "field_root": hx(&field_root),
                    "record_commitment": hx(&rc),
                    "batch_leaf_hash": hx(&batch_leaf_hash(&rc)),
                }
            })
        })
        .collect();

    json!({
        "spec": "spec/leaf-v1.md",
        "note": "record_field_key присутствует только в векторе; в сертификате и API он не появляется никогда",
        "vectors": items
    })
}

// ------------------------------------------------------------------- merkle

pub fn merkle_vectors() -> J {
    // Листья строятся из детерминированных commitment: вектор проверяет форму
    // дерева, а не содержимое записей.
    let build = |n: usize| -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| {
                let mut c = [0u8; 32];
                c[31] = i as u8;
                merkle::leaf_hash(&c)
            })
            .collect()
    };

    let items: Vec<J> = [1usize, 2, 3, 4, 5, 7, 8, 9, 16]
        .into_iter()
        .map(|n| {
            let leaves = build(n);
            let root = merkle::root(&leaves).unwrap();
            let proofs: Vec<J> = [0usize, n / 2, n - 1]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .map(|i| {
                    let steps = merkle::proof(&leaves, i).unwrap();
                    json!({
                        "leaf_index": i,
                        "path": steps.iter().map(|s| json!({
                            "sibling": hx(&s.sibling),
                            "side": match s.side { merkle::Side::Left => "LEFT", merkle::Side::Right => "RIGHT" },
                        })).collect::<Vec<_>>()
                    })
                })
                .collect();

            json!({
                "id": format!("leaves-{n}"),
                "description": format!("{n} листьев; непарные узлы поднимаются без дублирования"),
                "leaf_hashes": leaves.iter().map(|l| hx(l)).collect::<Vec<_>>(),
                "expected": { "root": hx(&root) },
                "proofs": proofs,
            })
        })
        .collect();

    json!({
        "spec": "spec/merkle-tree-v1.md",
        "rules": {
            "leaf": "SHA256(0x00 || commitment)",
            "node": "SHA256(0x01 || left || right)",
            "unpaired": "поднимается на следующий уровень без хэширования; дублирование запрещено"
        },
        "vectors": items
    })
}

// ------------------------------------------------------------------- anchor

pub fn anchor_vectors() -> J {
    let rid_hash = registry_id_hash(VECTOR_REGISTRY_ID);
    let genesis = commit::genesis_anchor_hash(&rid_hash);

    let base = AnchorFields {
        registry_id_hash: rid_hash,
        batch_sequence: 1,
        registry_version: 1,
        source_cursor_start: 1,
        source_cursor_end: 100,
        merkle_root: [0x11; 32],
        manifest_hash: [0x22; 32],
        snapshot_hash: [0u8; 32],
        previous_anchor_hash: genesis,
        leaf_count: 3,
        schema_version: 1,
        flags: 0,
        hash_algorithm: 1,
        tree_algorithm: 1,
        operator_pubkey: [0x33; 32],
        published_at: 1_785_000_000,
    };

    let mut with_snapshot = base.clone();
    with_snapshot.batch_sequence = 2;
    with_snapshot.source_cursor_start = 101;
    with_snapshot.source_cursor_end = 250;
    with_snapshot.snapshot_hash = [0x44; 32];
    with_snapshot.previous_anchor_hash = base.anchor_hash();

    let mut negative_time = base.clone();
    negative_time.batch_sequence = 3;
    negative_time.published_at = -1;
    negative_time.previous_anchor_hash = with_snapshot.anchor_hash();

    let mut max_fields = base.clone();
    max_fields.batch_sequence = u64::MAX;
    max_fields.registry_version = u64::MAX;
    max_fields.source_cursor_start = u64::MAX - 1;
    max_fields.source_cursor_end = u64::MAX;
    max_fields.leaf_count = u32::MAX;
    max_fields.schema_version = u16::MAX;
    max_fields.flags = u16::MAX;
    max_fields.hash_algorithm = u8::MAX;
    max_fields.tree_algorithm = u8::MAX;
    max_fields.published_at = i64::MAX;

    let cases = [
        (
            "genesis-successor",
            "первый якорь: previous_anchor_hash = genesis",
            &base,
        ),
        (
            "with-snapshot",
            "snapshot_hash не нулевой, цепочка от предыдущего",
            &with_snapshot,
        ),
        (
            "negative-published-at",
            "published_at < 0 кодируется i64_be в дополнительном коде",
            &negative_time,
        ),
        (
            "boundary-max",
            "все целые поля на верхней границе",
            &max_fields,
        ),
    ];

    let items: Vec<J> = cases
        .into_iter()
        .map(|(id, desc, a)| {
            let preimage = a.preimage();
            json!({
                "id": id,
                "description": desc,
                "input": {
                    "registry_id": VECTOR_REGISTRY_ID,
                    "registry_id_hash": hx(&a.registry_id_hash),
                    "batch_sequence": a.batch_sequence.to_string(),
                    "registry_version": a.registry_version.to_string(),
                    "source_cursor_start": a.source_cursor_start.to_string(),
                    "source_cursor_end": a.source_cursor_end.to_string(),
                    "merkle_root": hx(&a.merkle_root),
                    "manifest_hash": hx(&a.manifest_hash),
                    "snapshot_hash": hx(&a.snapshot_hash),
                    "previous_anchor_hash": hx(&a.previous_anchor_hash),
                    "leaf_count": a.leaf_count,
                    "schema_version": a.schema_version,
                    "flags": a.flags,
                    "hash_algorithm": a.hash_algorithm,
                    "tree_algorithm": a.tree_algorithm,
                    "operator_pubkey": hx(&a.operator_pubkey),
                    "published_at": a.published_at.to_string(),
                },
                "expected": {
                    "anchor_preimage": hx(&preimage),
                    "anchor_preimage_len": preimage.len(),
                    "anchor_hash": hx(&a.anchor_hash()),
                }
            })
        })
        .collect();

    json!({
        "spec": "spec/anchor-chain-v1.md",
        "genesis": {
            "registry_id": VECTOR_REGISTRY_ID,
            "registry_id_hash": hx(&rid_hash),
            "genesis_anchor_hash": hx(&genesis),
        },
        "vectors": items
    })
}

// -------------------------------------------------------------------- batch

pub fn batch_vectors() -> J {
    let key = RecordFieldKey::from_bytes(VECTOR_FIELD_KEY);
    let rid_hash = registry_id_hash(VECTOR_REGISTRY_ID);
    let id_key = VECTOR_ID_KEY;

    // Записи умышленно подаются не в порядке сортировки: вектор фиксирует,
    // что порядок листьев определяется (record_id_commitment, record_version),
    // а не порядком подачи.
    let raw = [
        ("record-c", 1u64, "ACTIVE"),
        ("record-a", 2u64, "CLOSED"),
        ("record-a", 1u64, "ACTIVE"),
        ("record-b", 1u64, "ACTIVE"),
        ("record-b", 3u64, "ACTIVE"),
    ];

    let mut described = Vec::new();
    let mut records = Vec::new();
    for (rid, version, status) in raw {
        let idc = commit::record_id_commitment(&id_key, VECTOR_REGISTRY_ID, rid);
        let tree = FieldTree::build(
            &key,
            &[FieldEntry {
                path: "status".into(),
                value: Value::Text(status.into()),
            }],
        )
        .unwrap();
        let rc = record_commitment(&rid_hash, &idc, version, &tree.root());
        described.push(json!({
            "internal_record_id": rid,
            "record_version": version.to_string(),
            "record_id_commitment": hx(&idc),
            "field_root": hx(&tree.root()),
            "record_commitment": hx(&rc),
            "batch_leaf_hash": hx(&batch_leaf_hash(&rc)),
        }));
        records.push(BatchRecord {
            record_id_commitment: idc,
            record_version: version,
            record_commitment: rc,
        });
    }

    let tree = BatchTree::build(records).unwrap();
    let proofs: Vec<J> = (0..tree.leaves().len())
        .map(|i| {
            let steps = tree.proof(i).unwrap();
            json!({
                "leaf_index": i,
                "leaf_hash": hx(&tree.leaves()[i]),
                "path": steps.iter().map(|s| json!({
                    "sibling": hx(&s.sibling),
                    "side": match s.side { merkle::Side::Left => "LEFT", merkle::Side::Right => "RIGHT" },
                })).collect::<Vec<_>>()
            })
        })
        .collect();

    json!({
        "spec": "spec/leaf-v1.md",
        "vectors": [{
            "id": "batch-five-records-unsorted-input",
            "description": "листья сортируются по (record_id_commitment, record_version) независимо от порядка подачи",
            "input": {
                "registry_id": VECTOR_REGISTRY_ID,
                "id_key": hx(&id_key),
                "record_field_key": hx(&VECTOR_FIELD_KEY),
                "records": described,
            },
            "expected": {
                "leaf_order": tree.leaves().iter().map(|l| hx(l)).collect::<Vec<_>>(),
                "merkle_root": hx(&tree.root()),
            },
            "proofs": proofs,
        }]
    })
}

// ----------------------------------------------------------------- manifest

pub fn manifest_vectors() -> J {
    let signing_key = [0x07u8; 32];
    let cases = [
        ("without-snapshot", None),
        ("with-snapshot", Some([0x44u8; 32])),
    ];
    let vectors = cases
        .into_iter()
        .enumerate()
        .map(|(index, (id, snapshot_hash))| {
            let fields = ManifestFields {
                registry_id_hash: registry_id_hash(VECTOR_REGISTRY_ID),
                batch_sequence: index as u64 + 1,
                registry_version: 7,
                source_cursor_start: index as u64 * 100 + 1,
                source_cursor_end: index as u64 * 100 + 100,
                created_at: "2026-07-31T00:00:00Z".into(),
                schema_version: 1,
                leaf_count: 3,
                merkle_root: [0x11; 32],
                previous_anchor_hash: [0x22; 32],
                snapshot_hash,
                leaves_object_uri: format!("s3://onelayer-pilot/batches/{}/leaves.cbor", index + 1),
                leaves_object_hash: [0x33; 32],
                builder_version: "onelayer-pipeline/0.1.0".into(),
                operator_key_id: "pilot-operator-1".into(),
            };
            let unsigned = fields.unsigned_cbor().unwrap();
            let signed = fields.sign(&signing_key).unwrap();
            json!({
                "id": id,
                "description": if snapshot_hash.is_some() { "snapshotHash = bytes(32)" } else { "snapshotHash = CBOR null" },
                "input": {
                    "manifest_version": 1,
                    "registry_id_hash": hx(&fields.registry_id_hash),
                    "batch_sequence": fields.batch_sequence.to_string(),
                    "registry_version": fields.registry_version.to_string(),
                    "source_cursor_start": fields.source_cursor_start.to_string(),
                    "source_cursor_end": fields.source_cursor_end.to_string(),
                    "created_at": fields.created_at,
                    "schema_version": fields.schema_version,
                    "hash_algorithm": "SHA256",
                    "tree_algorithm": "RFC6962_SHA256_V1",
                    "leaf_count": fields.leaf_count,
                    "merkle_root": hx(&fields.merkle_root),
                    "previous_anchor_hash": hx(&fields.previous_anchor_hash),
                    "snapshot_hash": fields.snapshot_hash.map(|hash| hx(&hash)),
                    "leaves_object_uri": fields.leaves_object_uri,
                    "leaves_object_hash": hx(&fields.leaves_object_hash),
                    "builder_version": fields.builder_version,
                    "operator_key_id": fields.operator_key_id,
                    "test_signing_key": hx(&signing_key),
                },
                "expected": {
                    "unsigned_manifest_cbor": hx(&unsigned),
                    "manifest_hash": hx(&signed.manifest_hash),
                    "operator_public_key": hx(&signed.operator_public_key),
                    "manifest_signature": hx(&signed.manifest_signature),
                }
            })
        })
        .collect::<Vec<_>>();
    json!({
        "spec": "spec/batch-manifest-v1.md",
        "note": "test_signing_key используется только для воспроизводимого golden vector",
        "vectors": vectors,
    })
}

// -------------------------------------------------------------- certificate

pub fn certificate_vectors() -> J {
    let key = RecordFieldKey::from_bytes(VECTOR_FIELD_KEY);
    let registry_hash = registry_id_hash(VECTOR_REGISTRY_ID);
    let record_id = commit::record_id_commitment(
        &VECTOR_ID_KEY,
        VECTOR_REGISTRY_ID,
        VECTOR_INTERNAL_RECORD_ID,
    );
    let issuer_key = [0x09u8; 32];
    let all_fields = vec![
        FieldEntry {
            path: "area".into(),
            value: Value::Text("1234.50".into()),
        },
        FieldEntry {
            path: "registeredAt".into(),
            value: Value::Text("2026-07-31T00:00:00Z".into()),
        },
        FieldEntry {
            path: "status".into(),
            value: Value::Text("ACTIVE".into()),
        },
    ];
    let field_tree = FieldTree::build(&key, &all_fields).unwrap();

    let cases = [
        (
            "full-record",
            DisclosureMode::FullRecord,
            vec!["area", "registeredAt", "status"],
            1,
            false,
        ),
        (
            "selective-one",
            DisclosureMode::SelectiveFields,
            vec!["status"],
            1,
            false,
        ),
        (
            "selective-two",
            DisclosureMode::SelectiveFields,
            vec!["area", "status"],
            1,
            false,
        ),
        (
            "tampered-signature",
            DisclosureMode::SelectiveFields,
            vec!["status"],
            1,
            true,
        ),
        (
            "unsupported-schema",
            DisclosureMode::FullRecord,
            vec!["area", "registeredAt", "status"],
            99,
            false,
        ),
    ];

    let vectors = cases
        .into_iter()
        .enumerate()
        .map(|(case_index, (id, mode, disclosed_paths, schema_version, tamper_signature))| {
            let record_commitment = record_commitment(
                &registry_hash,
                &record_id,
                1,
                &field_tree.root(),
            );
            let batch_leaf = batch_leaf_hash(&record_commitment);
            let disclosed_fields = all_fields
                .iter()
                .filter(|field| disclosed_paths.contains(&field.path.as_str()))
                .map(|field| (field.path.clone(), field.value.clone()))
                .collect();
            let field_salts = all_fields
                .iter()
                .filter(|field| disclosed_paths.contains(&field.path.as_str()))
                .map(|field| (field.path.clone(), field_salt(&key, &field.path).unwrap()))
                .collect();
            let field_proofs = match mode {
                DisclosureMode::FullRecord => Vec::new(),
                DisclosureMode::SelectiveFields => disclosed_paths
                    .iter()
                    .map(|path| FieldProof {
                        path: (*path).into(),
                        leaf_index: field_tree.index_of(path).unwrap() as u32,
                        siblings: field_tree.proof(path).unwrap(),
                    })
                    .collect(),
            };
            let mut body = CertificateBody {
                certificate_id: [case_index as u8 + 1; 16],
                registry_id: VECTOR_REGISTRY_ID.into(),
                issued_at: "2026-07-31T00:00:00Z".into(),
                record_id_commitment: record_id,
                record_version: 1,
                schema_version,
                disclosure_mode: mode,
                disclosed_fields,
                field_salts,
                field_root: field_tree.root(),
                field_proofs,
                batch_proof: MerkleProof {
                    leaf_index: 0,
                    leaf_hash: batch_leaf,
                    siblings: vec![],
                    expected_root: batch_leaf,
                },
                anchor: AnchorReference {
                    batch_sequence: 1,
                    registry_version: 1,
                    merkle_root: batch_leaf,
                    manifest_hash: [0x44; 32],
                    solana_program_id: [0x55; 32],
                    segment_index: 0,
                    segment_pda: [0x66; 32],
                    transaction_signature: [0x77; 64],
                    anchor_slot: 412_345_678,
                },
                issuer_key_id: "pilot-issuer-1".into(),
                issuer_public_key: [0; 32],
            };
            let signed = body.sign(&issuer_key).unwrap();
            let mut signature = signed.issuer_signature;
            if tamper_signature {
                signature[0] ^= 0x80;
            }
            let package = body.package_cbor(&signature).unwrap();

            json!({
                "id": id,
                "input": {
                    "registry_id": VECTOR_REGISTRY_ID,
                    "record_field_key": hx(&VECTOR_FIELD_KEY),
                    "record_id_commitment": hx(&record_id),
                    "record_version": "1",
                    "schema_version": schema_version,
                    "disclosure_mode": mode.as_str(),
                    "disclosed_paths": disclosed_paths,
                    "fields": all_fields.iter().map(|field| json!({
                        "path": field.path,
                        "value": value_json(&field.value),
                    })).collect::<Vec<_>>(),
                    "certificate_id": hx(&body.certificate_id),
                    "issued_at": body.issued_at,
                    "test_signing_key": hx(&issuer_key),
                },
                "expected": {
                    "field_root": hx(&field_tree.root()),
                    "record_commitment": hx(&record_commitment),
                    "batch_leaf_hash": hx(&batch_leaf),
                    "certificate_body_cbor": hx(&body.body_cbor().unwrap()),
                    "certificate_hash": hx(&signed.certificate_hash),
                    "issuer_public_key": hx(&body.issuer_public_key),
                    "issuer_signature": hx(&signature),
                    "certificate_package_cbor": hx(&package),
                    "result": if tamper_signature { "CERT_SIGNATURE_INVALID" } else if schema_version != 1 { "SCHEMA_UNSUPPORTED" } else { "VALID" },
                }
            })
        })
        .collect::<Vec<_>>();

    json!({
        "spec": "spec/certificate-package-v1.md",
        "vectors": vectors,
    })
}

/// Имя файла → содержимое. Единственный источник для генератора и теста.
pub fn all() -> Vec<(&'static str, J)> {
    vec![
        ("canonical.json", canonical_vectors()),
        ("leaf.json", leaf_vectors()),
        ("merkle.json", merkle_vectors()),
        ("anchor.json", anchor_vectors()),
        ("batch.json", batch_vectors()),
        ("manifest.json", manifest_vectors()),
        ("certificate.json", certificate_vectors()),
    ]
}

/// Сериализация в том виде, в каком файл лежит в репозитории.
pub fn render(value: &J) -> String {
    let mut s = serde_json::to_string_pretty(value).expect("сериализация векторов");
    s.push('\n');
    s
}
