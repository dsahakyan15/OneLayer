use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use onelayer_canonical::{
    cbor::Value, genesis_anchor_hash, registry_id_hash, AnchorReference, DisclosureMode,
    FieldEntry, RecordFieldKey,
};
use onelayer_pilot_pipeline::{
    BatchBuildRequest, CertificateRequest, ChangeOperation, PilotPipeline, SyntheticChange,
    WorkflowEvent,
};

fn main() -> Result<(), String> {
    let registry_id = "gov.registry.land";
    let mut pipeline = PilotPipeline::new(registry_id, 1, [9; 32], 0, 0);
    pipeline
        .ingest(
            SyntheticChange {
                registry_id: registry_id.into(),
                source_cursor: 1,
                internal_record_id: "SYNTHETIC-1".into(),
                operation: ChangeOperation::Insert,
                fields: vec![FieldEntry {
                    path: "status".into(),
                    value: Value::Text("ACTIVE".into()),
                }],
            },
            &WorkflowEvent {
                registry_id: registry_id.into(),
                internal_record_id: "SYNTHETIC-1".into(),
                operation: ChangeOperation::Insert,
                authorized: true,
            },
            RecordFieldKey::from_bytes([1; 32]),
        )
        .map_err(|error| error.to_string())?;
    let registry_hash = registry_id_hash(registry_id);
    let batch = pipeline
        .build_batch(BatchBuildRequest {
            batch_sequence: 1,
            registry_version: 1,
            previous_anchor_hash: genesis_anchor_hash(&registry_hash),
            created_at: "2026-07-31T00:00:00Z",
            leaves_object_uri: "file:///pilot/1/leaves.cbor",
            operator_key_id: "pilot-operator-1",
            operator_secret_key: &[4; 32],
        })
        .map_err(|error| error.to_string())?;
    let certificate = batch
        .issue_certificate(CertificateRequest {
            internal_record_id: "SYNTHETIC-1",
            disclosed_paths: &["status"],
            disclosure_mode: DisclosureMode::FullRecord,
            certificate_id: [8; 16],
            issued_at: "2026-07-31T00:00:00Z",
            anchor: AnchorReference {
                batch_sequence: 1,
                registry_version: 1,
                merkle_root: batch.merkle_root,
                manifest_hash: batch.signed_manifest.manifest_hash,
                solana_program_id: [5; 32],
                segment_index: 0,
                segment_pda: [6; 32],
                transaction_signature: [7; 64],
                anchor_slot: 1_000,
            },
            issuer_key_id: "pilot-issuer-1",
            issuer_secret_key: &[9; 32],
            verifier_base_url: "https://verify.example",
        })
        .map_err(|error| error.to_string())?;
    println!("{}", URL_SAFE_NO_PAD.encode(certificate.package_cbor));
    Ok(())
}
