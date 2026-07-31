use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use onelayer_canonical::{AnchorReference, DisclosureMode};
use onelayer_pilot_pipeline::{
    demo::{build_demo_batch, DEMO_CREATED_AT, DEMO_ISSUER_SECRET, DEMO_REGISTRY_ID},
    CertificateRequest,
};
use serde::Serialize;
use solana_signature::Signature;
use std::{env, str::FromStr};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparedOutput {
    cluster: &'static str,
    registry_id: &'static str,
    batch_sequence: u64,
    registry_version: u64,
    leaf_count: usize,
    merkle_root: String,
    manifest_hash: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertificateOutput {
    cluster: &'static str,
    registry_id: &'static str,
    batch_sequence: u64,
    registry_version: u64,
    merkle_root: String,
    manifest_hash: String,
    anchor_hash: String,
    program_id: String,
    segment_pda: String,
    transaction_signature: String,
    anchor_slot: u64,
    certificate_id: String,
    certificate_hash: String,
    certificate_package: String,
    qr_url: String,
    issued_at: &'static str,
}

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} is required"))
}

fn main() -> Result<(), String> {
    let command = env::args().nth(1).unwrap_or_else(|| "prepare".into());
    let batch = build_demo_batch()?;
    if command == "prepare" {
        let output = PreparedOutput {
            cluster: "devnet",
            registry_id: DEMO_REGISTRY_ID,
            batch_sequence: batch.batch_sequence,
            registry_version: batch.manifest.registry_version,
            leaf_count: batch.records.len(),
            merkle_root: hex::encode(batch.merkle_root),
            manifest_hash: hex::encode(batch.signed_manifest.manifest_hash),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|error| error.to_string())?
        );
        return Ok(());
    }
    if command != "certificate" {
        return Err("usage: devnet_demo_fixture [prepare|certificate]".into());
    }

    let program_id = onelayer_registry::ID;
    let configured_program = required("ONELAYER_PROGRAM_ID")?
        .parse::<anchor_client::anchor_lang::prelude::Pubkey>()
        .map_err(|_| "ONELAYER_PROGRAM_ID is invalid".to_string())?;
    if configured_program != program_id {
        return Err("ONELAYER_PROGRAM_ID does not match the compiled Anchor program".into());
    }
    let segment = required("ONELAYER_SEGMENT_PDA")?
        .parse::<anchor_client::anchor_lang::prelude::Pubkey>()
        .map_err(|_| "ONELAYER_SEGMENT_PDA is invalid".to_string())?;
    let transaction_signature =
        Signature::from_str(&required("ONELAYER_TRANSACTION_SIGNATURE")?)
            .map_err(|_| "ONELAYER_TRANSACTION_SIGNATURE is invalid".to_string())?;
    let anchor_slot = required("ONELAYER_ANCHOR_SLOT")?
        .parse::<u64>()
        .map_err(|_| "ONELAYER_ANCHOR_SLOT is invalid".to_string())?;
    let anchor_hash = required("ONELAYER_ANCHOR_HASH")?;
    if !anchor_hash
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || anchor_hash.len() != 64
    {
        return Err("ONELAYER_ANCHOR_HASH must be 64 lowercase hexadecimal characters".into());
    }
    let verifier_base_url = required("ONELAYER_VERIFIER_BASE_URL")?;
    if verifier_base_url != "http://127.0.0.1:8090" {
        return Err("ONELAYER_VERIFIER_BASE_URL must be the loopback demo endpoint".into());
    }
    let mut signature_bytes = [0u8; 64];
    signature_bytes.copy_from_slice(transaction_signature.as_ref());
    let certificate_id = [8; 16];
    let certificate = batch
        .issue_certificate(CertificateRequest {
            internal_record_id: "SYNTHETIC-1",
            disclosed_paths: &["status"],
            disclosure_mode: DisclosureMode::FullRecord,
            certificate_id,
            issued_at: DEMO_CREATED_AT,
            anchor: AnchorReference {
                batch_sequence: batch.batch_sequence,
                registry_version: batch.manifest.registry_version,
                merkle_root: batch.merkle_root,
                manifest_hash: batch.signed_manifest.manifest_hash,
                solana_program_id: program_id.to_bytes(),
                segment_index: 0,
                segment_pda: segment.to_bytes(),
                transaction_signature: signature_bytes,
                anchor_slot,
            },
            issuer_key_id: "synthetic-demo-issuer-1",
            issuer_secret_key: &DEMO_ISSUER_SECRET,
            verifier_base_url: &verifier_base_url,
        })
        .map_err(|error| error.to_string())?;
    let certificate_id_hex = hex::encode(certificate_id);
    let qr_url = certificate
        .qr_url
        .replace("08080808-0808-0808-0808-080808080808", &certificate_id_hex);
    let output = CertificateOutput {
        cluster: "devnet",
        registry_id: DEMO_REGISTRY_ID,
        batch_sequence: batch.batch_sequence,
        registry_version: batch.manifest.registry_version,
        merkle_root: hex::encode(batch.merkle_root),
        manifest_hash: hex::encode(batch.signed_manifest.manifest_hash),
        anchor_hash,
        program_id: program_id.to_string(),
        segment_pda: segment.to_string(),
        transaction_signature: transaction_signature.to_string(),
        anchor_slot,
        certificate_id: certificate_id_hex,
        certificate_hash: hex::encode(certificate.signed.certificate_hash),
        certificate_package: URL_SAFE_NO_PAD.encode(certificate.package_cbor),
        qr_url,
        issued_at: DEMO_CREATED_AT,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|error| error.to_string())?
    );
    Ok(())
}
