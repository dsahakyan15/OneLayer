use anchor_client::anchor_lang::prelude::Pubkey;
use onelayer_canonical::{
    cbor::Value, genesis_anchor_hash, registry_id_hash, FieldEntry, RecordFieldKey,
};
use onelayer_pilot_pipeline::{
    artifacts::write_artifact_copies,
    publisher::{PilotPublisher, PublishAccounts, PublishStatus},
    store::{
        AttemptResolution, InitialOutcome, PilotStore, PreparedBatchRow, SignedAttempt,
        TerminalOutcome,
    },
    BatchBuildRequest, ChangeOperation, PilotPipeline, SyntheticChange, WorkflowEvent,
};
use onelayer_registry::AnchorEntryInputV1;
use std::{env, fs::File, io::Read, path::Path, str::FromStr, thread, time::Duration};

fn key_from_env(name: &str) -> Result<[u8; 32], String> {
    let value = env::var(name).map_err(|_| format!("{name} is required"))?;
    let bytes =
        hex::decode(value).map_err(|_| format!("{name} must be 64 hexadecimal characters"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{name} must be 32 bytes"))
}

fn random_field_key() -> Result<RecordFieldKey, String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("CSPRNG unavailable: {error}"))?;
    Ok(RecordFieldKey::from_bytes(bytes))
}

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} is required"))
}

fn pubkey(name: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(&required(name)?).map_err(|_| format!("{name} is invalid"))
}

fn main() -> Result<(), String> {
    let registry_id = "gov.registry.land";
    let id_key = key_from_env("ONELAYER_ID_KEY_HEX")?;
    let operator_key = key_from_env("ONELAYER_OPERATOR_KEY_HEX")?;
    let mut pipeline = PilotPipeline::new(registry_id, 1, id_key, 0, 0);
    let change = SyntheticChange {
        registry_id: registry_id.into(),
        source_cursor: 1,
        internal_record_id: "SYNTHETIC-1".into(),
        operation: ChangeOperation::Insert,
        fields: vec![FieldEntry {
            path: "status".into(),
            value: Value::Text("ACTIVE".into()),
        }],
    };
    let workflow = WorkflowEvent {
        registry_id: registry_id.into(),
        internal_record_id: "SYNTHETIC-1".into(),
        operation: ChangeOperation::Insert,
        authorized: true,
    };
    pipeline
        .ingest(change, &workflow, random_field_key()?)
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
            operator_secret_key: &operator_key,
        })
        .map_err(|error| error.to_string())?;
    let manifest_hash_hex = hex::encode(batch.signed_manifest.manifest_hash);
    println!(
        "batch_sequence={} leaf_count={} cursor={}..{} merkle_root={} manifest_hash={}",
        batch.batch_sequence,
        batch.records.len(),
        batch.cursor_start,
        batch.cursor_end,
        hex::encode(batch.merkle_root),
        manifest_hash_hex,
    );

    if env::var("ONELAYER_MODE").unwrap_or_else(|_| "prepare".into()) != "publish" {
        return Ok(());
    }
    if env::var("ONELAYER_APPROVED_MANIFEST_HASH").ok().as_deref()
        != Some(manifest_hash_hex.as_str())
    {
        return Err(
            "ONELAYER_APPROVED_MANIFEST_HASH must match the prepared transaction summary".into(),
        );
    }
    write_artifact_copies(
        &batch,
        Path::new(&required("ONELAYER_MANIFEST_STORE_DIR")?),
        Path::new(&required("ONELAYER_LOCAL_ARTIFACT_DIR")?),
    )
    .map_err(|_| "manifest artifact persistence failed".to_string())?;

    let rpc_url = required("ONELAYER_RPC_URL")?;
    let websocket_url = required("ONELAYER_WEBSOCKET_URL")?;
    let accounts = PublishAccounts {
        config: pubkey("ONELAYER_CONFIG_PUBKEY")?,
        role: pubkey("ONELAYER_ROLE_PUBKEY")?,
        segment: pubkey("ONELAYER_SEGMENT_PUBKEY")?,
    };
    let publisher = PilotPublisher::from_keypair_file(
        rpc_url.clone(),
        websocket_url,
        Path::new(&required("ONELAYER_OPERATOR_KEYPAIR_PATH")?),
    )
    .map_err(|_| "publisher initialization failed".to_string())?;
    let mut store = PilotStore::connect(&required("ONELAYER_DATABASE_URL")?)
        .map_err(|_| "pilot database connection failed".to_string())?;
    store
        .migrate()
        .map_err(|_| "pilot database migration failed".to_string())?;
    store
        .enqueue_batch(PreparedBatchRow {
            registry_id,
            batch_sequence: i64::try_from(batch.batch_sequence)
                .map_err(|_| "batch sequence exceeds database range")?,
            registry_version: 1,
            cursor_start: i64::try_from(batch.cursor_start)
                .map_err(|_| "cursor exceeds database range")?,
            cursor_end: i64::try_from(batch.cursor_end)
                .map_err(|_| "cursor exceeds database range")?,
            leaf_count: i32::try_from(batch.records.len())
                .map_err(|_| "leaf count exceeds database range")?,
            merkle_root: &batch.merkle_root,
            manifest_hash: &batch.signed_manifest.manifest_hash,
            previous_anchor_hash: &batch.manifest.previous_anchor_hash,
            anchor_hash: None,
        })
        .map_err(|_| "batch enqueue failed".to_string())?;
    let queue = store
        .claim_next("pilot-publisher-1", Duration::from_secs(30))
        .map_err(|_| "publish queue claim failed".to_string())?
        .ok_or_else(|| "publish queue is empty".to_string())?;
    let input = AnchorEntryInputV1 {
        batch_sequence: batch.batch_sequence,
        registry_version: batch.manifest.registry_version,
        source_cursor_start: batch.cursor_start,
        source_cursor_end: batch.cursor_end,
        merkle_root: batch.merkle_root,
        manifest_hash: batch.signed_manifest.manifest_hash,
        snapshot_hash: [0; 32],
        previous_anchor_hash: batch.manifest.previous_anchor_hash,
        leaf_count: u32::try_from(batch.records.len())
            .map_err(|_| "leaf count exceeds protocol range")?,
        schema_version: 1,
        flags: 0,
        hash_algorithm: 1,
        tree_algorithm: 1,
    };
    let segment = accounts.segment;
    let signed = publisher
        .build_publish_transaction(accounts, input)
        .map_err(|_| "publish transaction build failed".to_string())?;
    let submission = publisher.submit(&signed);
    let initial_outcome = if submission.is_ok() {
        InitialOutcome::Submitted
    } else {
        InitialOutcome::Unknown
    };
    let signature = signed.signature.to_string();
    store
        .record_signed_attempt(SignedAttempt {
            registry_id,
            batch_sequence: queue.batch_sequence,
            attempt_no: queue.attempt_count,
            transaction_b64: &signed.transaction_b64,
            signature: &signature,
            recent_blockhash: &signed.recent_blockhash,
            submitted_to: &[rpc_url.as_str()],
            outcome: initial_outcome,
        })
        .map_err(|_| "signed publish attempt persistence failed".to_string())?;

    loop {
        match publisher
            .finalized_status(&signed)
            .map_err(|_| "publish status check failed".to_string())?
        {
            PublishStatus::Pending => thread::sleep(Duration::from_secs(2)),
            PublishStatus::Finalized => {
                let observed = publisher
                    .finalized_observation(
                        &segment,
                        batch.batch_sequence,
                        &registry_hash,
                        &signed.signature,
                    )
                    .map_err(|_| "finalized anchor observation failed".to_string())?;
                store
                    .resolve_attempt(AttemptResolution {
                        registry_id,
                        batch_sequence: queue.batch_sequence,
                        attempt_no: queue.attempt_count,
                        outcome: TerminalOutcome::Finalized,
                        error_code: None,
                        provider_error: None,
                        solana_slot: Some(
                            i64::try_from(observed.slot)
                                .map_err(|_| "slot exceeds database range")?,
                        ),
                        anchor_hash: Some(&observed.anchor_hash),
                    })
                    .map_err(|_| "finalized attempt persistence failed".to_string())?;
                pipeline
                    .mark_finalized(batch.cursor_end)
                    .map_err(|error| error.to_string())?;
                break;
            }
            PublishStatus::Expired => {
                store
                    .resolve_attempt(AttemptResolution {
                        registry_id,
                        batch_sequence: queue.batch_sequence,
                        attempt_no: queue.attempt_count,
                        outcome: TerminalOutcome::Expired,
                        error_code: Some("BLOCKHASH_EXPIRED"),
                        provider_error: None,
                        solana_slot: None,
                        anchor_hash: None,
                    })
                    .map_err(|_| "expired attempt persistence failed".to_string())?;
                return Err("publish transaction expired".into());
            }
            PublishStatus::Failed(provider_error) => {
                store
                    .resolve_attempt(AttemptResolution {
                        registry_id,
                        batch_sequence: queue.batch_sequence,
                        attempt_no: queue.attempt_count,
                        outcome: TerminalOutcome::Failed,
                        error_code: Some("TRANSACTION_FAILED"),
                        provider_error: Some(provider_error.as_bytes()),
                        solana_slot: None,
                        anchor_hash: None,
                    })
                    .map_err(|_| "failed attempt persistence failed".to_string())?;
                return Err("publish transaction failed".into());
            }
        }
    }
    Ok(())
}
