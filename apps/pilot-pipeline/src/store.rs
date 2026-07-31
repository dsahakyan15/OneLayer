use postgres::{Client, NoTls};
use sha2::{Digest, Sha256};
use std::time::Duration;

pub const PILOT_MIGRATION: &str = include_str!("../../../db/migrations/0001_pilot.sql");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueItem {
    pub registry_id: String,
    pub batch_sequence: i64,
    pub attempt_count: i32,
}

pub struct PreparedBatchRow<'a> {
    pub registry_id: &'a str,
    pub batch_sequence: i64,
    pub registry_version: i64,
    pub cursor_start: i64,
    pub cursor_end: i64,
    pub leaf_count: i32,
    pub merkle_root: &'a [u8; 32],
    pub manifest_hash: &'a [u8; 32],
    pub previous_anchor_hash: &'a [u8; 32],
    pub anchor_hash: Option<&'a [u8; 32]>,
}

pub struct SignedAttempt<'a> {
    pub registry_id: &'a str,
    pub batch_sequence: i64,
    pub attempt_no: i32,
    pub transaction_b64: &'a str,
    pub signature: &'a str,
    pub recent_blockhash: &'a str,
    pub submitted_to: &'a [&'a str],
    pub outcome: InitialOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialOutcome {
    Submitted,
    Unknown,
}

impl InitialOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "SUBMITTED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalOutcome {
    Finalized,
    Expired,
    Failed,
}

impl TerminalOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Finalized => "FINALIZED",
            Self::Expired => "EXPIRED",
            Self::Failed => "FAILED",
        }
    }
}

pub struct AttemptResolution<'a> {
    pub registry_id: &'a str,
    pub batch_sequence: i64,
    pub attempt_no: i32,
    pub outcome: TerminalOutcome,
    pub error_code: Option<&'a str>,
    pub provider_error: Option<&'a [u8]>,
    pub solana_slot: Option<i64>,
    pub anchor_hash: Option<&'a [u8; 32]>,
}

pub struct PilotStore {
    client: Client,
}

impl PilotStore {
    pub fn connect(connection_string: &str) -> Result<Self, postgres::Error> {
        Ok(Self {
            client: Client::connect(connection_string, NoTls)?,
        })
    }

    pub fn migrate(&mut self) -> Result<(), postgres::Error> {
        self.client.batch_execute(PILOT_MIGRATION)
    }

    pub fn enqueue_batch(&mut self, batch: PreparedBatchRow<'_>) -> Result<(), postgres::Error> {
        let mut transaction = self.client.transaction()?;
        transaction.execute(
            "INSERT INTO anchor_batch (
                registry_id, batch_sequence, registry_version, cursor_start, cursor_end,
                leaf_count, merkle_root, manifest_hash, previous_anchor_hash, anchor_hash,
                status, prepared_at
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'PREPARED',now())",
            &[
                &batch.registry_id,
                &batch.batch_sequence,
                &batch.registry_version,
                &batch.cursor_start,
                &batch.cursor_end,
                &batch.leaf_count,
                &&batch.merkle_root[..],
                &&batch.manifest_hash[..],
                &&batch.previous_anchor_hash[..],
                &batch.anchor_hash.map(|hash| &hash[..]),
            ],
        )?;
        transaction.execute(
            "INSERT INTO publish_queue (registry_id, batch_sequence, status) VALUES ($1,$2,'QUEUED')",
            &[&batch.registry_id, &batch.batch_sequence],
        )?;
        transaction.execute(
            "INSERT INTO source_cursor_state (registry_id, last_processed, last_anchored, updated_at)
             VALUES ($1,$2,0,now())
             ON CONFLICT (registry_id) DO UPDATE
             SET last_processed=GREATEST(source_cursor_state.last_processed, EXCLUDED.last_processed),
                 updated_at=now()",
            &[&batch.registry_id, &batch.cursor_end],
        )?;
        transaction.commit()
    }

    pub fn claim_next(
        &mut self,
        worker_id: &str,
        lease: Duration,
    ) -> Result<Option<QueueItem>, postgres::Error> {
        let lease_seconds = i64::try_from(lease.as_secs()).unwrap_or(i64::MAX);
        let row = self.client.query_opt(
            "WITH candidate AS (
                SELECT registry_id, batch_sequence
                FROM publish_queue
                WHERE status IN ('QUEUED','EXPIRED')
                   OR (status = 'CLAIMED' AND claimed_until < now())
                ORDER BY registry_id, batch_sequence
                FOR UPDATE SKIP LOCKED
                LIMIT 1
             )
             UPDATE publish_queue q
             SET status='CLAIMED', claimed_by=$1,
                 claimed_until=now() + make_interval(secs => $2::double precision),
                 attempt_count=q.attempt_count + 1, updated_at=now()
             FROM candidate c
             WHERE q.registry_id=c.registry_id AND q.batch_sequence=c.batch_sequence
             RETURNING q.registry_id, q.batch_sequence, q.attempt_count",
            &[&worker_id, &lease_seconds],
        )?;
        Ok(row.map(|row| QueueItem {
            registry_id: row.get(0),
            batch_sequence: row.get(1),
            attempt_count: row.get(2),
        }))
    }

    pub fn record_signed_attempt(
        &mut self,
        attempt: SignedAttempt<'_>,
    ) -> Result<(), postgres::Error> {
        let submitted_to: Vec<String> = attempt
            .submitted_to
            .iter()
            .map(|value| (*value).into())
            .collect();
        let mut transaction = self.client.transaction()?;
        transaction.execute(
            "INSERT INTO publish_attempt (
                registry_id, batch_sequence, attempt_no, transaction_b64, signature,
                recent_blockhash, submitted_to, outcome
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            &[
                &attempt.registry_id,
                &attempt.batch_sequence,
                &attempt.attempt_no,
                &attempt.transaction_b64,
                &attempt.signature,
                &attempt.recent_blockhash,
                &submitted_to,
                &attempt.outcome.as_str(),
            ],
        )?;
        transaction.execute(
            "UPDATE publish_queue SET status='SUBMITTED', claimed_by=NULL, claimed_until=NULL, updated_at=now()
             WHERE registry_id=$1 AND batch_sequence=$2 AND status='CLAIMED'",
            &[&attempt.registry_id, &attempt.batch_sequence],
        )?;
        transaction.execute(
            "UPDATE anchor_batch SET status='SUBMITTED', solana_signature=$3
             WHERE registry_id=$1 AND batch_sequence=$2 AND status IN ('PREPARED','SIGNED','SUBMITTED')",
            &[&attempt.registry_id, &attempt.batch_sequence, &attempt.signature],
        )?;
        transaction.commit()
    }

    pub fn resolve_attempt(
        &mut self,
        resolution: AttemptResolution<'_>,
    ) -> Result<bool, postgres::Error> {
        let (message, payload_hash) = resolution
            .provider_error
            .map(|payload| {
                (
                    Some(sanitize_provider_error(payload)),
                    Some(Sha256::digest(payload).to_vec()),
                )
            })
            .unwrap_or((None, None));
        if resolution.outcome == TerminalOutcome::Finalized
            && (resolution.solana_slot.is_none() || resolution.anchor_hash.is_none())
        {
            return Ok(false);
        }
        let mut transaction = self.client.transaction()?;
        let changed = transaction.execute(
            "UPDATE publish_attempt
             SET outcome=$4, error_code=$5, error_message=$6, error_payload_hash=$7, resolved_at=now()
             WHERE registry_id=$1 AND batch_sequence=$2 AND attempt_no=$3
               AND outcome IN ('SUBMITTED','UNKNOWN')",
            &[
                &resolution.registry_id,
                &resolution.batch_sequence,
                &resolution.attempt_no,
                &resolution.outcome.as_str(),
                &resolution.error_code,
                &message,
                &payload_hash,
            ],
        )?;
        if changed != 1 {
            transaction.rollback()?;
            return Ok(false);
        }
        transaction.execute(
            "UPDATE publish_queue SET status=$3, updated_at=now()
             WHERE registry_id=$1 AND batch_sequence=$2",
            &[
                &resolution.registry_id,
                &resolution.batch_sequence,
                &resolution.outcome.as_str(),
            ],
        )?;
        match resolution.outcome {
            TerminalOutcome::Finalized => {
                transaction.execute(
                    "UPDATE anchor_batch b
                     SET status='FINALIZED', solana_slot=$4, anchor_hash=$5, finalized_at=now(),
                         solana_signature=a.signature
                     FROM publish_attempt a
                     WHERE b.registry_id=$1 AND b.batch_sequence=$2
                       AND a.registry_id=$1 AND a.batch_sequence=$2 AND a.attempt_no=$3",
                    &[
                        &resolution.registry_id,
                        &resolution.batch_sequence,
                        &resolution.attempt_no,
                        &resolution.solana_slot,
                        &resolution.anchor_hash.map(|hash| &hash[..]),
                    ],
                )?;
                transaction.execute(
                    "UPDATE source_cursor_state s
                     SET last_anchored=GREATEST(s.last_anchored, b.cursor_end), updated_at=now()
                     FROM anchor_batch b
                     WHERE s.registry_id=$1 AND b.registry_id=$1 AND b.batch_sequence=$2",
                    &[&resolution.registry_id, &resolution.batch_sequence],
                )?;
            }
            TerminalOutcome::Failed => {
                transaction.execute(
                    "UPDATE anchor_batch SET status='FAILED' WHERE registry_id=$1 AND batch_sequence=$2",
                    &[&resolution.registry_id, &resolution.batch_sequence],
                )?;
            }
            TerminalOutcome::Expired => {}
        }
        transaction.commit()?;
        Ok(changed == 1)
    }
}

pub fn sanitize_provider_error(payload: &[u8]) -> String {
    format!("provider error payload redacted ({} bytes)", payload.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_error_is_bounded_and_control_free() {
        let payload = [b"rpc\nsecret\0".as_slice(), &[b'x'; 600]].concat();
        let message = sanitize_provider_error(&payload);
        assert_eq!(message, "provider error payload redacted (611 bytes)");
        assert!(!message.contains("secret"));
    }

    #[test]
    fn terminal_outcomes_match_database_contract() {
        assert_eq!(InitialOutcome::Submitted.as_str(), "SUBMITTED");
        assert_eq!(InitialOutcome::Unknown.as_str(), "UNKNOWN");
        assert_eq!(TerminalOutcome::Finalized.as_str(), "FINALIZED");
        assert_eq!(TerminalOutcome::Expired.as_str(), "EXPIRED");
        assert_eq!(TerminalOutcome::Failed.as_str(), "FAILED");
    }
}
