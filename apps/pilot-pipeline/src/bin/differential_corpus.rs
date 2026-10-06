use onelayer_canonical::{
    batch_leaf_hash, cbor::Value, record_commitment, record_id_commitment, registry_id_hash,
    FieldEntry, FieldTree, RecordFieldKey,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CorpusCase {
    internal_record_id: String,
    record_version: u64,
    record_field_key_hex: String,
    status: String,
    area: String,
    record_id_commitment_hex: String,
    field_root_hex: String,
    record_commitment_hex: String,
    batch_leaf_hash_hex: String,
}

fn main() -> Result<(), String> {
    let registry_id = "gov.registry.land";
    let registry_hash = registry_id_hash(registry_id);
    let id_key = [9; 32];
    let mut corpus = Vec::with_capacity(1_000);
    for index in 0u64..1_000 {
        let internal_record_id = format!("DIFF-{index:04}");
        let record_version = index % 7 + 1;
        let key_bytes: [u8; 32] =
            Sha256::digest([b"ONELAYER:DIFF:V1".as_slice(), &index.to_be_bytes()].concat()).into();
        let status = if index.is_multiple_of(3) {
            "ACTIVE"
        } else {
            "PENDING"
        }
        .to_string();
        let area = format!("{}.{:02}", index / 100, index % 100);
        let tree = FieldTree::build(
            &RecordFieldKey::from_bytes(key_bytes),
            &[
                FieldEntry {
                    path: "status".into(),
                    value: Value::Text(status.clone()),
                },
                FieldEntry {
                    path: "area".into(),
                    value: Value::Text(area.clone()),
                },
            ],
        )
        .map_err(|error| error.to_string())?;
        let record_id = record_id_commitment(&id_key, registry_id, &internal_record_id);
        let commitment =
            record_commitment(&registry_hash, &record_id, record_version, &tree.root());
        corpus.push(CorpusCase {
            internal_record_id,
            record_version,
            record_field_key_hex: hex::encode(key_bytes),
            status,
            area,
            record_id_commitment_hex: hex::encode(record_id),
            field_root_hex: hex::encode(tree.root()),
            record_commitment_hex: hex::encode(commitment),
            batch_leaf_hash_hex: hex::encode(batch_leaf_hash(&commitment)),
        });
    }
    serde_json::to_writer(std::io::stdout(), &corpus).map_err(|error| error.to_string())?;
    Ok(())
}
