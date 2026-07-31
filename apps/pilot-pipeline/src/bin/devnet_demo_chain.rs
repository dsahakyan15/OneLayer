use anchor_client::{
    anchor_lang::{prelude::Pubkey, system_program, Space},
    Client, Cluster, CommitmentConfig, Program, Signer, Transaction,
};
use onelayer_canonical::registry_id_hash;
use onelayer_pilot_pipeline::{
    demo::{build_demo_batch, DEMO_REGISTRY_ID},
    publisher::{PilotPublisher, PublishAccounts},
};
use onelayer_registry::{
    AnchorEntryInputV1, CreateLedgerSegmentArgs, GrantOperatorArgs, InitializeRegistryArgs,
    LEDGER_CAPACITY, PERM_CREATE_LEDGER, PERM_PUBLISH_ANCHOR, PERM_REPORT_INCIDENT,
};
use sha2::{Digest, Sha256};
use solana_keypair::{read_keypair_file, Keypair};
use std::{
    env,
    path::Path,
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

const RPC_URL: &str = "https://api.devnet.solana.com";
const WS_URL: &str = "wss://api.devnet.solana.com";

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} is required"))
}

fn keypair_path() -> Result<String, String> {
    let path = required("ONELAYER_TEST_KEYPAIR_PATH")?;
    if !path.starts_with("/dev/shm/onelayer-devnet-demo/") {
        return Err("test keypair must live under /dev/shm/onelayer-devnet-demo".into());
    }
    Ok(path)
}

fn approval_digest(
    payer: &Pubkey,
    config: &Pubkey,
    role: &Pubkey,
    segment: &Pubkey,
    merkle_root: &[u8; 32],
    manifest_hash: &[u8; 32],
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ONELAYER:SYNTHETIC:DEVNET:DEMO:APPROVAL:V1");
    digest.update(RPC_URL.as_bytes());
    digest.update(onelayer_registry::ID.as_ref());
    digest.update(payer.as_ref());
    digest.update(config.as_ref());
    digest.update(role.as_ref());
    digest.update(segment.as_ref());
    digest.update(merkle_root);
    digest.update(manifest_hash);
    hex::encode(digest.finalize())
}

fn simulate(
    program: &Program<Rc<Keypair>>,
    transaction: &Transaction,
    step: &str,
) -> Result<(), String> {
    let response = program
        .rpc()
        .simulate_transaction(transaction)
        .map_err(|error| format!("{step} simulation RPC failed: {error}"))?;
    if let Some(error) = response.value.err {
        return Err(format!("{step} simulation failed: {error:?}"));
    }
    eprintln!(
        "simulation step={step} units={} fee_lamports={}",
        response.value.units_consumed.unwrap_or(0),
        response.value.fee.unwrap_or(0)
    );
    Ok(())
}

fn send(
    program: &Program<Rc<Keypair>>,
    transaction: &Transaction,
    step: &str,
) -> Result<(), String> {
    let signature = program
        .rpc()
        .send_and_confirm_transaction_with_spinner_and_commitment(
            transaction,
            CommitmentConfig::finalized(),
        )
        .map_err(|error| format!("{step} failed: {error}"))?;
    eprintln!("finalized step={step} signature={signature}");
    Ok(())
}

fn account_exists(program: &Program<Rc<Keypair>>, address: &Pubkey) -> Result<bool, String> {
    match program.rpc().get_account(address) {
        Ok(_) => Ok(true),
        Err(error)
            if error.to_string().contains("AccountNotFound")
                || error.to_string().contains("not found") =>
        {
            Ok(false)
        }
        Err(error) => Err(error.to_string()),
    }
}

fn main() -> Result<(), String> {
    let mode = env::args().nth(1).unwrap_or_else(|| "plan".into());
    if mode != "plan" && mode != "apply" {
        return Err("usage: devnet_demo_chain [plan|apply]".into());
    }
    if required("ONELAYER_RPC_URL")? != RPC_URL || required("ONELAYER_WEBSOCKET_URL")? != WS_URL {
        return Err("devnet demo only accepts the canonical Solana devnet endpoints".into());
    }
    let keypair_path = keypair_path()?;
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
    let day_utc = u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs()
            / 86_400,
    )
    .map_err(|_| "current UTC day exceeds u32".to_string())?;
    let (segment, _) = Pubkey::find_program_address(
        &[
            b"ledger",
            config.as_ref(),
            &day_utc.to_be_bytes(),
            &0u16.to_le_bytes(),
        ],
        &onelayer_registry::ID,
    );
    let batch = build_demo_batch()?;
    let digest = approval_digest(
        &payer.pubkey(),
        &config,
        &role,
        &segment,
        &batch.merkle_root,
        &batch.signed_manifest.manifest_hash,
    );
    println!("cluster=devnet");
    println!("rpc={RPC_URL}");
    println!("fee_payer={}", payer.pubkey());
    println!("token=SOL");
    println!("program_id={}", onelayer_registry::ID);
    println!("registry_config={config}");
    println!("operator_role={role}");
    println!("ledger_segment={segment}");
    println!("batch_sequence=1");
    println!("leaf_count={}", batch.records.len());
    println!("merkle_root={}", hex::encode(batch.merkle_root));
    println!(
        "manifest_hash={}",
        hex::encode(batch.signed_manifest.manifest_hash)
    );
    let registry_rent = program
        .rpc()
        .get_minimum_balance_for_rent_exemption(8 + onelayer_registry::RegistryConfig::INIT_SPACE)
        .map_err(|error| error.to_string())?;
    let role_rent = program
        .rpc()
        .get_minimum_balance_for_rent_exemption(8 + onelayer_registry::OperatorRole::INIT_SPACE)
        .map_err(|error| error.to_string())?;
    let segment_rent = program
        .rpc()
        .get_minimum_balance_for_rent_exemption(onelayer_registry::SEGMENT_ACCOUNT_SIZE)
        .map_err(|error| error.to_string())?;
    println!("recipient=registry_config,operator_role,ledger_segment");
    println!(
        "max_rent_lamports={}",
        registry_rent + role_rent + segment_rent
    );
    println!("fee_lamports=reported_by_each_pre-send_simulation");
    println!("approval_digest={digest}");
    if mode == "plan" {
        println!("send=blocked");
        return Ok(());
    }
    if env::var("ONELAYER_DEVNET_TX_APPROVED").ok().as_deref() != Some(digest.as_str()) {
        return Err("ONELAYER_DEVNET_TX_APPROVED must equal approval_digest".into());
    }
    let program_account = program
        .rpc()
        .get_account(&onelayer_registry::ID)
        .map_err(|_| {
            "Anchor program is not deployed on devnet; deployment approval is required first"
                .to_string()
        })?;
    if !program_account.executable {
        return Err("devnet program account is not executable".into());
    }

    if !account_exists(&program, &config)? {
        let transaction = program
            .request()
            .accounts(onelayer_registry::accounts::InitializeRegistry {
                config,
                governance: payer.pubkey(),
                system_program: system_program::ID,
            })
            .args(onelayer_registry::instruction::InitializeRegistry {
                args: InitializeRegistryArgs {
                    registry_id_hash: registry_hash,
                    emergency_authority: payer.pubkey(),
                    schema_version: 1,
                    hash_algorithm: 1,
                    tree_algorithm: 1,
                    anchor_interval_seconds: 60,
                    max_entries_per_day: LEDGER_CAPACITY as u16,
                },
            })
            .signed_transaction()
            .map_err(|error| error.to_string())?;
        simulate(&program, &transaction, "initialize_registry")?;
        send(&program, &transaction, "initialize_registry")?;
    }
    if !account_exists(&program, &role)? {
        let transaction = program
            .request()
            .accounts(onelayer_registry::accounts::GrantOperator {
                config,
                role,
                operator: payer.pubkey(),
                governance_authority: payer.pubkey(),
                system_program: system_program::ID,
            })
            .args(onelayer_registry::instruction::GrantOperator {
                args: GrantOperatorArgs {
                    permissions: PERM_PUBLISH_ANCHOR | PERM_CREATE_LEDGER | PERM_REPORT_INCIDENT,
                    valid_from: 0,
                    valid_until: 0,
                    key_id_hash: Sha256::digest(b"synthetic-demo-operator-1").into(),
                },
            })
            .signed_transaction()
            .map_err(|error| error.to_string())?;
        simulate(&program, &transaction, "grant_operator")?;
        send(&program, &transaction, "grant_operator")?;
    }
    if !account_exists(&program, &segment)? {
        let transaction = program
            .request()
            .accounts(onelayer_registry::accounts::CreateLedgerSegment {
                config,
                role,
                operator: payer.pubkey(),
                segment,
                previous_segment: None,
                system_program: system_program::ID,
            })
            .args(onelayer_registry::instruction::CreateLedgerSegment {
                args: CreateLedgerSegmentArgs {
                    day_utc,
                    segment_index: 0,
                    capacity: LEDGER_CAPACITY as u16,
                },
            })
            .signed_transaction()
            .map_err(|error| error.to_string())?;
        simulate(&program, &transaction, "create_ledger_segment")?;
        send(&program, &transaction, "create_ledger_segment")?;
    }

    let publisher =
        PilotPublisher::from_keypair_file(RPC_URL.into(), WS_URL.into(), Path::new(&keypair_path))?;
    let input = AnchorEntryInputV1 {
        batch_sequence: 1,
        registry_version: 1,
        source_cursor_start: batch.cursor_start,
        source_cursor_end: batch.cursor_end,
        merkle_root: batch.merkle_root,
        manifest_hash: batch.signed_manifest.manifest_hash,
        snapshot_hash: [0; 32],
        previous_anchor_hash: batch.manifest.previous_anchor_hash,
        leaf_count: u32::try_from(batch.records.len()).map_err(|_| "leaf count overflow")?,
        schema_version: 1,
        flags: 0,
        hash_algorithm: 1,
        tree_algorithm: 1,
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
        "simulation step=publish_anchor units={} fee_lamports={} log_lines={}",
        simulation.units_consumed.unwrap_or(0),
        simulation.fee.unwrap_or(0),
        simulation.logs.len(),
    );
    publisher.submit(&signed)?;
    loop {
        match publisher.finalized_status(&signed)? {
            onelayer_pilot_pipeline::publisher::PublishStatus::Pending => {
                std::thread::sleep(std::time::Duration::from_secs(2))
            }
            onelayer_pilot_pipeline::publisher::PublishStatus::Finalized => break,
            onelayer_pilot_pipeline::publisher::PublishStatus::Expired => {
                return Err("publish transaction expired".into())
            }
            onelayer_pilot_pipeline::publisher::PublishStatus::Failed(error) => {
                return Err(format!("publish transaction failed: {error}"))
            }
        }
    }
    let observed =
        publisher.finalized_observation(&segment, 1, &registry_hash, &signed.signature)?;
    println!("transaction_signature={}", signed.signature);
    println!("anchor_slot={}", observed.slot);
    println!("anchor_hash={}", hex::encode(observed.anchor_hash));
    println!("commitment=finalized");
    println!("send=complete");
    Ok(())
}
