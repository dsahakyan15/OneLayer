//! Замороженность golden vectors и самопроверка их содержимого.
//!
//! Тест решает две разные задачи:
//!   1) файлы в `spec/vectors/` совпадают с тем, что порождает реализация —
//!      молчаливое изменение протокола невозможно;
//!   2) содержимое векторов пересчитывается независимым путём (proof →
//!      корень, а не «поле expected равно полю expected»).

use onelayer_canonical::vectors;
use serde_json::Value as J;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR = crates/canonical
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors")
        .canonicalize()
        .expect("каталог spec/vectors должен существовать; см. cargo run --bin gen-vectors")
}

#[test]
fn vectors_on_disk_match_implementation() {
    let dir = vectors_dir();
    for (name, value) in vectors::all() {
        let path = dir.join(name);
        let on_disk =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(
            on_disk,
            vectors::render(&value),
            "{name} разошёлся с реализацией: либо регрессия, либо изменение протокола без ADR"
        );
    }
}

fn hex32(s: &str) -> [u8; 32] {
    let b = hex::decode(s).expect("hex");
    b.try_into().expect("32 байта")
}

fn load(name: &str) -> J {
    let raw = std::fs::read_to_string(vectors_dir().join(name)).expect("вектор читается");
    serde_json::from_str(&raw).expect("вектор — валидный JSON")
}

#[test]
fn merkle_proofs_in_vectors_reconstruct_root() {
    let doc = load("merkle.json");
    for v in doc["vectors"].as_array().unwrap() {
        let root = hex32(v["expected"]["root"].as_str().unwrap());
        let leaves: Vec<[u8; 32]> = v["leaf_hashes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| hex32(h.as_str().unwrap()))
            .collect();

        for p in v["proofs"].as_array().unwrap() {
            let idx = p["leaf_index"].as_u64().unwrap() as usize;
            let steps: Vec<onelayer_merkle::ProofStep> = p["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| onelayer_merkle::ProofStep {
                    sibling: hex32(s["sibling"].as_str().unwrap()),
                    side: match s["side"].as_str().unwrap() {
                        "LEFT" => onelayer_merkle::Side::Left,
                        "RIGHT" => onelayer_merkle::Side::Right,
                        other => panic!("неизвестная сторона {other}"),
                    },
                })
                .collect();
            assert!(
                onelayer_merkle::verify(&leaves[idx], &steps, &root),
                "{}: proof листа {idx} не даёт корень",
                v["id"]
            );
        }
    }
}

#[test]
fn leaf_vectors_field_roots_follow_from_leaf_hashes() {
    let doc = load("leaf.json");
    for v in doc["vectors"].as_array().unwrap() {
        let mut indexed: Vec<(usize, [u8; 32])> = v["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["leaf_index"].as_u64().unwrap() as usize,
                    hex32(f["field_tree_leaf_hash"].as_str().unwrap()),
                )
            })
            .collect();
        indexed.sort_by_key(|(i, _)| *i);
        let leaves: Vec<[u8; 32]> = indexed.into_iter().map(|(_, h)| h).collect();

        assert_eq!(
            onelayer_merkle::root(&leaves).unwrap(),
            hex32(v["expected"]["field_root"].as_str().unwrap()),
            "{}: field_root не следует из листьев",
            v["id"]
        );
    }
}

#[test]
fn leaf_vectors_keep_commitment_and_leaf_hash_distinct() {
    // Двойное хэширование фиксируется явно: вектор бесполезен, если вторая
    // реализация может спутать commitment с leaf hash.
    let doc = load("leaf.json");
    for v in doc["vectors"].as_array().unwrap() {
        for f in v["fields"].as_array().unwrap() {
            let c = hex32(f["field_commitment"].as_str().unwrap());
            let l = hex32(f["field_tree_leaf_hash"].as_str().unwrap());
            assert_ne!(c, l);
            assert_eq!(l, onelayer_merkle::leaf_hash(&c));
        }
        let rc = hex32(v["expected"]["record_commitment"].as_str().unwrap());
        let bl = hex32(v["expected"]["batch_leaf_hash"].as_str().unwrap());
        assert_ne!(rc, bl);
        assert_eq!(bl, onelayer_merkle::leaf_hash(&rc));
    }
}

#[test]
fn nfc_pair_vectors_agree() {
    // Кириллическая "й" в двух формах обязана дать одинаковый CBOR.
    let doc = load("canonical.json");
    let get = |id: &str| -> String {
        doc["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == id)
            .unwrap_or_else(|| panic!("вектор {id} отсутствует"))["expected"]["cbor_hex"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(
        get("text-cyrillic-precomposed"),
        get("text-cyrillic-decomposed")
    );
    assert_ne!(get("decimal-scale-preserved"), get("decimal-scale-alt"));
    assert_ne!(get("array-order-ab"), get("array-order-ba"));
}

#[test]
fn anchor_preimages_are_260_bytes_and_chain() {
    let doc = load("anchor.json");
    let vectors = doc["vectors"].as_array().unwrap();
    for v in vectors {
        let preimage = hex::decode(v["expected"]["anchor_preimage"].as_str().unwrap()).unwrap();
        assert_eq!(
            preimage.len(),
            onelayer_canonical::ANCHOR_PREIMAGE_LEN,
            "{}: длина preimage",
            v["id"]
        );
        assert_eq!(
            hex::encode(<[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(
                &preimage
            ))),
            v["expected"]["anchor_hash"].as_str().unwrap(),
            "{}: anchor_hash не равен SHA-256(preimage)",
            v["id"]
        );
    }

    // Первый вектор ссылается на genesis, второй — на первый.
    assert_eq!(
        vectors[0]["input"]["previous_anchor_hash"],
        doc["genesis"]["genesis_anchor_hash"]
    );
    assert_eq!(
        vectors[1]["input"]["previous_anchor_hash"]
            .as_str()
            .unwrap(),
        vectors[0]["expected"]["anchor_hash"].as_str().unwrap()
    );
}

#[test]
fn batch_vector_leaf_order_is_sorted_not_input_order() {
    let doc = load("batch.json");
    let v = &doc["vectors"][0];
    let input_order: Vec<String> = v["input"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["batch_leaf_hash"].as_str().unwrap().to_string())
        .collect();
    let leaf_order: Vec<String> = v["expected"]["leaf_order"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str().unwrap().to_string())
        .collect();

    assert_ne!(
        input_order, leaf_order,
        "вектор потерял смысл: порядок подачи совпал с порядком листьев"
    );
    let mut a = input_order.clone();
    let mut b = leaf_order.clone();
    a.sort();
    b.sort();
    assert_eq!(a, b, "набор листьев изменился при сортировке");

    let root = hex32(v["expected"]["merkle_root"].as_str().unwrap());
    let leaves: Vec<[u8; 32]> = leaf_order.iter().map(|h| hex32(h)).collect();
    assert_eq!(onelayer_merkle::root(&leaves).unwrap(), root);
}

#[test]
fn batch_vector_binds_identical_content_to_record_id() {
    let doc = load("batch.json");
    let records = doc["vectors"][0]["input"]["records"].as_array().unwrap();
    let first = records
        .iter()
        .find(|r| r["internal_record_id"] == "record-c")
        .unwrap();
    let second = records
        .iter()
        .find(|r| r["internal_record_id"] == "record-b" && r["record_version"] == "1")
        .unwrap();

    assert_eq!(first["field_root"], second["field_root"]);
    assert_eq!(first["record_version"], second["record_version"]);
    assert_ne!(
        first["record_id_commitment"],
        second["record_id_commitment"]
    );
    assert_ne!(first["record_commitment"], second["record_commitment"]);
}
