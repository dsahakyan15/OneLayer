use anchor_client::{
    anchor_lang::{prelude::Pubkey, AccountDeserialize},
    Client, Cluster, CommitmentConfig, Hash, Signer, Transaction,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use onelayer_registry::AnchorEntryInputV1;
use solana_keypair::{read_keypair_file, Keypair};
use solana_signature::Signature;
use std::{path::Path, rc::Rc, str::FromStr};

pub struct PublishAccounts {
    pub config: Pubkey,
    pub role: Pubkey,
    pub segment: Pubkey,
}

pub struct SignedPublishTransaction {
    pub transaction: Transaction,
    pub transaction_b64: String,
    pub signature: Signature,
    pub recent_blockhash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishStatus {
    Pending,
    Finalized,
    Expired,
    Failed(String),
}

pub struct FinalizedObservation {
    pub slot: u64,
    pub anchor_hash: [u8; 32],
}

pub struct PilotPublisher {
    client: Client<Rc<Keypair>>,
    operator: Rc<Keypair>,
}

impl PilotPublisher {
    pub fn from_keypair_file(
        rpc_url: String,
        websocket_url: String,
        keypair_path: &Path,
    ) -> Result<Self, String> {
        let operator = Rc::new(
            read_keypair_file(keypair_path)
                .map_err(|error| format!("operator keypair could not be read: {error}"))?,
        );
        let client = Client::new_with_options(
            Cluster::Custom(rpc_url, websocket_url),
            operator.clone(),
            CommitmentConfig::finalized(),
        );
        Ok(Self { client, operator })
    }

    pub fn build_publish_transaction(
        &self,
        accounts: PublishAccounts,
        input: AnchorEntryInputV1,
    ) -> Result<SignedPublishTransaction, String> {
        let program = self
            .client
            .program(onelayer_registry::ID)
            .map_err(|error| error.to_string())?;
        let transaction = program
            .request()
            .accounts(onelayer_registry::accounts::PublishAnchor {
                config: accounts.config,
                role: accounts.role,
                operator: self.operator.pubkey(),
                segment: accounts.segment,
            })
            .args(onelayer_registry::instruction::PublishAnchor { input })
            .signed_transaction()
            .map_err(|error| error.to_string())?;
        let signature = transaction.signatures[0];
        let recent_blockhash = transaction.message.recent_blockhash.to_string();
        let transaction_b64 =
            STANDARD.encode(bincode::serialize(&transaction).map_err(|error| error.to_string())?);
        Ok(SignedPublishTransaction {
            transaction,
            transaction_b64,
            signature,
            recent_blockhash,
        })
    }

    pub fn submit(&self, signed: &SignedPublishTransaction) -> Result<Signature, String> {
        let program = self
            .client
            .program(onelayer_registry::ID)
            .map_err(|error| error.to_string())?;
        program
            .rpc()
            .send_transaction(&signed.transaction)
            .map_err(|error| error.to_string())
    }

    pub fn finalized_status(
        &self,
        signed: &SignedPublishTransaction,
    ) -> Result<PublishStatus, String> {
        let program = self
            .client
            .program(onelayer_registry::ID)
            .map_err(|error| error.to_string())?;
        match program
            .rpc()
            .get_signature_status_with_commitment(&signed.signature, CommitmentConfig::finalized())
            .map_err(|error| error.to_string())?
        {
            Some(Ok(())) => Ok(PublishStatus::Finalized),
            Some(Err(error)) => Ok(PublishStatus::Failed(error.to_string())),
            None => {
                let blockhash = Hash::from_str(&signed.recent_blockhash)
                    .map_err(|error| format!("invalid stored recent blockhash: {error}"))?;
                let valid = program
                    .rpc()
                    .is_blockhash_valid(&blockhash, CommitmentConfig::finalized())
                    .map_err(|error| error.to_string())?;
                Ok(if valid {
                    PublishStatus::Pending
                } else {
                    PublishStatus::Expired
                })
            }
        }
    }

    pub fn finalized_observation(
        &self,
        segment: &Pubkey,
        batch_sequence: u64,
        registry_id_hash: &[u8; 32],
        signature: &Signature,
    ) -> Result<FinalizedObservation, String> {
        let program = self
            .client
            .program(onelayer_registry::ID)
            .map_err(|error| error.to_string())?;
        let statuses = program
            .rpc()
            .get_signature_statuses(&[*signature])
            .map_err(|error| error.to_string())?;
        let status = statuses
            .value
            .into_iter()
            .next()
            .flatten()
            .ok_or_else(|| "finalized signature status unavailable".to_string())?;
        if status.err.is_some() {
            return Err("finalized transaction failed".into());
        }
        let response = program
            .rpc()
            .get_account_with_commitment(segment, CommitmentConfig::finalized())
            .map_err(|error| error.to_string())?;
        let account = response
            .value
            .ok_or_else(|| "ledger segment account unavailable".to_string())?;
        if account.owner != onelayer_registry::ID {
            return Err("ledger segment owner mismatch".into());
        }
        let mut bytes = account.data.as_slice();
        let ledger = onelayer_registry::DailyAnchorLedgerSegment::try_deserialize(&mut bytes)
            .map_err(|error| error.to_string())?;
        let entry = ledger.entries[..usize::from(ledger.entry_count)]
            .iter()
            .find(|entry| entry.batch_sequence == batch_sequence)
            .ok_or_else(|| "published anchor entry unavailable".to_string())?;
        Ok(FinalizedObservation {
            slot: status.slot,
            anchor_hash: onelayer_registry::anchor_hash(registry_id_hash, entry),
        })
    }
}
