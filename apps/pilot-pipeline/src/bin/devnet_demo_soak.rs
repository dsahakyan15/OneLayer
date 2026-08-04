//! One publish cycle of the Gate C synthetic soak run.
//!
//! Each invocation reads the current registry state, builds the next batch from
//! the synthetic source, publishes it with the tmpfs software test key
//! (`OL-C-12`), waits for `finalized`, rebuilds the same range independently and
//! prints the chain half of one evidence record as a single JSON line.
//!
//! The runner (`deploy/devnet-demo/scripts/soak`) owns the loop, the interval
//! and the incident-index half of the record; `soak_report` turns the resulting
//! JSONL into the Gate C verdict. Splitting it this way keeps a restart of the
//! loop from rebuilding or re-signing anything already published.
use anchor_client::{
    anchor_lang::prelude::Pubkey, anchor_lang::system_program, anchor_lang::AccountDeserialize,
    Client, Cluster, CommitmentConfig, Program, Signer,
};
use onelayer_canonical::registry_id_hash;
use onelayer_pilot_pipeline::{
    demo::{build_soak_batch, DEMO_REGISTRY_ID},
    publisher::{PilotPublisher, PublishAccounts, PublishStatus},
};
use onelayer_registry::{AnchorEntryInputV1, CreateLedgerSegmentArgs, LEDGER_CAPACITY};
use solana_keypair::{read_keypair_file, Keypair};
use std::{
    env,
    path::Path,
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const RPC_URL: &str = "https://api.devnet.solana.com";
const WS_URL: &str = "wss://api.devnet.solana.com";
const SEGMENTS_PER_DAY: u16 = 3;

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} is required"))
}

fn now_seconds() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs())
}

/// YYYYMMDD in UTC, matching the encoding the program expects for `day_utc`.
fn utc_day(timestamp: u64) -> Result<u32, String> {
    let days = i64::try_from(timestamp / 86_400).map_err(|_| "timestamp overflow".to_string())?;
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    u32::try_from(year * 10_000 + month * 100 + day)
        .map_err(|_| "UTC day cannot be encoded as YYYYMMDD".to_string())
}

fn segment_address(config: &Pubkey, day_utc: u32, segment_index: u16) -> Pubkey {
    Pubkey::find_program_address(
        &[
            b"ledger",
            config.as_ref(),
            &day_utc.to_be_bytes(),
            &segment_index.to_le_bytes(),
        ],
        &onelayer_registry::ID,
    )
    .0
}

/// Returns the first segment of the day that still has room, creating segment 0
/// when the day has just rolled over.
fn open_segment(
    program: &Program<Rc<Keypair>>,
    config: &Pubkey,
    role: &Pubkey,
    operator: &Pubkey,
    day_utc: u32,
) -> Result<Pubkey, String> {
    let mut previous: Option<Pubkey> = None;
    for index in 0..SEGMENTS_PER_DAY {
        let address = segment_address(config, day_utc, index);
        match program.rpc().get_account(&address) {
            Ok(account) => {
                if account.owner != onelayer_registry::ID {
                    return Err("ledger segment owner mismatch".into());
                }
                let mut bytes = account.data.as_slice();
                let segment =
                    onelayer_registry::DailyAnchorLedgerSegment::try_deserialize(&mut bytes)
                        .map_err(|error| error.to_string())?;
                if segment.sealed == 0 && segment.entry_count < segment.capacity {
                    return Ok(address);
                }
                previous = Some(address);
            }
            Err(_) => {
                let transaction = program
                    .request()
                    .accounts(onelayer_registry::accounts::CreateLedgerSegment {
                        config: *config,
                        role: *role,
                        operator: *operator,
                        segment: address,
                        previous_segment: previous,
                        system_program: system_program::ID,
                    })
                    .args(onelayer_registry::instruction::CreateLedgerSegment {
                        args: CreateLedgerSegmentArgs {
                            day_utc,
                            segment_index: index,
                            capacity: LEDGER_CAPACITY as u16,
                        },
                    })
                    .signed_transaction()
                    .map_err(|error| error.to_string())?;
                let simulation = program
                    .rpc()
                    .simulate_transaction(&transaction)
                    .map_err(|error| error.to_string())?;
                if let Some(error) = simulation.value.err {
                    return Err(format!(
                        "create_ledger_segment simulation failed: {error:?}"
                    ));
                }
                program
                    .rpc()
                    .send_and_confirm_transaction_with_spinner_and_commitment(
                        &transaction,
                        CommitmentConfig::finalized(),
                    )
                    .map_err(|error| format!("create_ledger_segment failed: {error}"))?;
                return Ok(address);
            }
        }
    }
    Err("every ledger segment of the day is full".into())
}

fn main() -> Result<(), String> {
    if env::args().nth(1).as_deref() != Some("cycle") {
        return Err("usage: devnet_demo_soak cycle".into());
    }
    if env::var("APPROVE_ONELAYER_SOAK").ok().as_deref() != Some("yes") {
        return Err("APPROVE_ONELAYER_SOAK=yes is required".into());
    }
    if required("ONELAYER_RPC_URL")? != RPC_URL || required("ONELAYER_WEBSOCKET_URL")? != WS_URL {
        return Err("the soak run only accepts the canonical Solana devnet endpoints".into());
    }
    let cycle: u64 = required("ONELAYER_SOAK_CYCLE")?
        .parse()
        .map_err(|_| "ONELAYER_SOAK_CYCLE must be a number".to_string())?;
    let keypair_path = required("ONELAYER_TEST_KEYPAIR_PATH")?;
    if !keypair_path.starts_with("/dev/shm/onelayer-devnet-demo/") {
        return Err("test keypair must live under /dev/shm/onelayer-devnet-demo".into());
    }

    let payer = Rc::new(read_keypair_file(&keypair_path).map_err(|error| error.to_string())?);
    let client = Client::new_with_options(
        Cluster::Custom(RPC_URL.into(), WS_URL.into()),
        payer.clone(),
        CommitmentConfig::finalized(),
    );
    let program = client
        .program(onelayer_registry::ID)
        .map_err(|error| error.to_string())?;

    let registry_hash = registry_id_hash(DEMO_REGISTRY_ID);
    let (config, _) = Pubkey::find_program_address(
        &[b"registry", registry_hash.as_ref()],
        &onelayer_registry::ID,
    );
    let (role, _) = Pubkey::find_program_address(
        &[b"operator", config.as_ref(), payer.pubkey().as_ref()],
        &onelayer_registry::ID,
    );
    // The registry and the operator role are created by the guarded bootstrap;
    // the soak run never grants itself authority.
    let state: onelayer_registry::RegistryConfig = program
        .account(config)
        .map_err(|_| "registry config is missing; run the guarded bootstrap first".to_string())?;
    if state.paused {
        return Err("registry is paused".into());
    }
    let batch_sequence = state.current_batch_sequence + 1;
    let previous_anchor_hash = state.last_anchor_hash;

    let batch = build_soak_batch(
        cycle,
        batch_sequence,
        state.current_registry_version,
        previous_anchor_hash,
    )?;
    // Independent rebuild of the same range: the manifest hash must not move.
    let rebuilt = build_soak_batch(
        cycle,
        batch_sequence,
        state.current_registry_version,
        previous_anchor_hash,
    )?;

    let day_utc = utc_day(now_seconds()?)?;
    let segment = open_segment(&program, &config, &role, &payer.pubkey(), day_utc)?;

    let publisher =
        PilotPublisher::from_keypair_file(RPC_URL.into(), WS_URL.into(), Path::new(&keypair_path))?;
    let input = AnchorEntryInputV1 {
        batch_sequence,
        registry_version: state.current_registry_version,
        source_cursor_start: batch.cursor_start,
        source_cursor_end: batch.cursor_end,
        merkle_root: batch.merkle_root,
        manifest_hash: batch.signed_manifest.manifest_hash,
        snapshot_hash: [0; 32],
        previous_anchor_hash,
        leaf_count: u32::try_from(batch.records.len()).map_err(|_| "leaf count overflow")?,
        schema_version: state.schema_version,
        flags: 0,
        hash_algorithm: state.hash_algorithm,
        tree_algorithm: state.tree_algorithm,
    };
    let signed = publisher.build_publish_transaction(
        PublishAccounts {
            config,
            role,
            segment,
        },
        input,
    )?;
    let simulation = publisher.simulate(&signed)?;
    eprintln!(
        "cycle={cycle} batch_sequence={batch_sequence} units={} fee_lamports={}",
        simulation.units_consumed.unwrap_or(0),
        simulation.fee.unwrap_or(0)
    );
    publisher.submit(&signed)?;
    loop {
        match publisher.finalized_status(&signed)? {
            PublishStatus::Pending => std::thread::sleep(Duration::from_secs(2)),
            PublishStatus::Finalized => break,
            PublishStatus::Expired => return Err("publish transaction expired".into()),
            PublishStatus::Failed(error) => {
                return Err(format!("publish transaction failed: {error}"))
            }
        }
    }
    let observed = publisher.finalized_observation(
        &segment,
        batch_sequence,
        &registry_hash,
        &signed.signature,
    )?;

    let record = serde_json::json!({
        "cycle": cycle,
        "finalized_at": now_seconds()?,
        "batch_sequence": batch_sequence,
        "previous_anchor_hash": hex::encode(previous_anchor_hash),
        "anchor_hash": hex::encode(observed.anchor_hash),
        "manifest_hash": hex::encode(batch.signed_manifest.manifest_hash),
        "rebuilt_manifest_hash": hex::encode(rebuilt.signed_manifest.manifest_hash),
        "source_cursor_start": batch.cursor_start,
        "source_cursor_end": batch.cursor_end,
        "rebuilt_source_cursor_start": rebuilt.cursor_start,
        "rebuilt_source_cursor_end": rebuilt.cursor_end,
        "merkle_root": hex::encode(batch.merkle_root),
        "anchor_slot": observed.slot,
        "transaction_signature": signed.signature.to_string(),
        "ledger_segment": segment.to_string(),
    });
    println!(
        "{}",
        serde_json::to_string(&record).map_err(|error| error.to_string())?
    );
    Ok(())
}
