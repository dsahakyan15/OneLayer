use crate::{
    BatchArtifact, BatchBuildRequest, ChangeOperation, PilotPipeline, SyntheticChange,
    WorkflowEvent,
};
use onelayer_canonical::{
    cbor::Value, genesis_anchor_hash, registry_id_hash, FieldEntry, RecordFieldKey,
};

pub const DEMO_REGISTRY_ID: &str = "gov.registry.land";
pub const DEMO_CREATED_AT: &str = "2026-07-31T00:00:00Z";
pub const DEMO_OPERATOR_SECRET: [u8; 32] = [4; 32];
pub const DEMO_ISSUER_SECRET: [u8; 32] = [9; 32];

pub fn build_demo_batch() -> Result<BatchArtifact, String> {
    let mut pipeline = PilotPipeline::new(DEMO_REGISTRY_ID, 1, [9; 32], 0, 0);
    for (cursor, record_id, field_key) in [(1, "SYNTHETIC-1", [1; 32]), (2, "SYNTHETIC-2", [2; 32])]
    {
        pipeline
            .ingest(
                SyntheticChange {
                    registry_id: DEMO_REGISTRY_ID.into(),
                    source_cursor: cursor,
                    internal_record_id: record_id.into(),
                    operation: ChangeOperation::Insert,
                    fields: vec![FieldEntry {
                        path: "status".into(),
                        value: Value::Text("ACTIVE".into()),
                    }],
                },
                &WorkflowEvent {
                    registry_id: DEMO_REGISTRY_ID.into(),
                    internal_record_id: record_id.into(),
                    operation: ChangeOperation::Insert,
                    authorized: true,
                },
                RecordFieldKey::from_bytes(field_key),
            )
            .map_err(|error| error.to_string())?;
    }
    let registry_hash = registry_id_hash(DEMO_REGISTRY_ID);
    pipeline
        .build_batch(BatchBuildRequest {
            batch_sequence: 1,
            registry_version: 1,
            previous_anchor_hash: genesis_anchor_hash(&registry_hash),
            created_at: DEMO_CREATED_AT,
            leaves_object_uri: "synthetic://onelayer-devnet-demo/batch-1/leaves.cbor",
            operator_key_id: "synthetic-demo-operator-1",
            operator_secret_key: &DEMO_OPERATOR_SECRET,
        })
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_batch_is_stable_and_contains_only_synthetic_records() {
        let first = build_demo_batch().unwrap();
        let second = build_demo_batch().unwrap();
        assert_eq!(first.merkle_root, second.merkle_root);
        assert_eq!(
            first.signed_manifest.manifest_hash,
            second.signed_manifest.manifest_hash
        );
        assert_eq!(first.records.len(), 2);
        assert!(first
            .records
            .iter()
            .all(|record| record.internal_record_id.starts_with("SYNTHETIC-")));
    }
}
