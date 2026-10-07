//! Rebuildable PG projection. Единственный вход — проверенный protected
//! destination (`ProtectedSink::stream_for_source`, которая отказывает при
//! tail rollback). Durable cursor/status в `audit_evidence_rebuild_state`:
//! crash/restart продолжает с cursor, `ON CONFLICT DO NOTHING` по
//! `(source_identity, source_sequence)` даёт exactly-once. Пока статус
//! `REBUILDING`, projection никогда не объявляется current.

use crate::sink::SinkEntry;
use postgres::{Client, NoTls};
use serde::{Deserialize, Serialize};

pub const REBUILD_STATE_ID: i16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RebuildStatus {
    Idle,
    Rebuilding,
    Complete,
    Failed,
}

impl RebuildStatus {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "IDLE" => Ok(Self::Idle),
            "REBUILDING" => Ok(Self::Rebuilding),
            "COMPLETE" => Ok(Self::Complete),
            "FAILED" => Ok(Self::Failed),
            other => Err(format!("AUDIT_REBUILD_INVALID: unknown status {other}")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "IDLE",
            Self::Rebuilding => "REBUILDING",
            Self::Complete => "COMPLETE",
            Self::Failed => "FAILED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RebuildState {
    pub status: RebuildStatus,
    pub source_identity: Option<String>,
    pub cursor_sequence: u64,
    pub head_sequence: u64,
    pub head_hash: Option<String>,
    pub floor_sequence: u64,
    pub error: Option<String>,
}

impl RebuildState {
    pub fn unknown() -> Self {
        Self {
            status: RebuildStatus::Idle,
            source_identity: None,
            cursor_sequence: 0,
            head_sequence: 0,
            head_hash: None,
            floor_sequence: 0,
            error: None,
        }
    }

    /// Проекция current, только если rebuild завершён и cursor догнал
    /// destination head. Во всех остальных случаях — UNKNOWN/INCOMPLETE.
    pub fn projection_status(&self, destination_head_seq: u64) -> &'static str {
        match self.status {
            RebuildStatus::Rebuilding | RebuildStatus::Idle => "UNKNOWN",
            RebuildStatus::Failed => "FAILED",
            RebuildStatus::Complete => {
                if self.cursor_sequence == destination_head_seq {
                    "CURRENT"
                } else {
                    "INCOMPLETE"
                }
            }
        }
    }
}

pub struct Projector {
    client: Client,
}

impl Projector {
    pub fn connect(dsn: &str) -> Result<Self, String> {
        let client = Client::connect(dsn, NoTls).map_err(|e| format!("projection connect: {e}"))?;
        Ok(Self { client })
    }

    pub fn state(&mut self) -> Result<RebuildState, String> {
        let row = self
            .client
            .query_opt(
                "SELECT status, source_identity, cursor_sequence::bigint, head_sequence::bigint, \
                        head_hash, floor_sequence::bigint, error \
                 FROM audit_evidence_rebuild_state WHERE id = $1",
                &[&REBUILD_STATE_ID],
            )
            .map_err(|e| format!("projection state: {e}"))?;
        let Some(row) = row else {
            return Err(
                "AUDIT_REBUILD_INVALID: rebuild state row missing (apply migration 0026)".into(),
            );
        };
        Ok(RebuildState {
            status: RebuildStatus::parse(row.get::<_, String>(0).as_str())?,
            source_identity: row.get(1),
            cursor_sequence: row.get::<_, i64>(2).max(0) as u64,
            head_sequence: row.get::<_, i64>(3).max(0) as u64,
            head_hash: row.get(4),
            floor_sequence: row.get::<_, i64>(5).max(0) as u64,
            error: row.get(6),
        })
    }

    /// Переводит projection в REBUILDING с новым head; cursor сохраняется при
    /// resume (restart после crash продолжает, а не начинает заново).
    pub fn begin(
        &mut self,
        source: &str,
        head_sequence: u64,
        head_hash: &str,
        floor_sequence: u64,
        resume: bool,
    ) -> Result<RebuildState, String> {
        let cursor = if resume {
            self.state()?.cursor_sequence
        } else {
            0
        };
        self.client
            .execute(
                "UPDATE audit_evidence_rebuild_state SET status='REBUILDING', source_identity=$1, \
                 head_sequence=$2, head_hash=$3, floor_sequence=$4, cursor_sequence=$5, \
                 started_at=coalesce(started_at, clock_timestamp()), updated_at=clock_timestamp(), error=NULL \
                 WHERE id=$6",
                &[
                    &source,
                    &(head_sequence as i64),
                    &head_hash,
                    &(floor_sequence as i64),
                    &(cursor as i64),
                    &REBUILD_STATE_ID,
                ],
            )
            .map_err(|e| format!("projection begin: {e}"))?;
        self.state()
    }

    /// Проекция одного события и продвижение cursor в одной транзакции.
    /// Существующая строка сверяется с проверенным destination: расхождение
    /// digest — ошибка (rebuild не «замораживает» устаревшую projection).
    pub fn project_entry(&mut self, entry: &SinkEntry) -> Result<bool, String> {
        let digest = entry.event.digest();
        let mut tx = self
            .client
            .transaction()
            .map_err(|e| format!("projection tx: {e}"))?;
        let existing: Option<String> = tx
            .query_opt(
                "SELECT event_digest FROM audit_evidence_projection WHERE source_identity=$1 AND source_sequence=$2",
                &[&entry.event.source, &(entry.event.sequence as i64)],
            )
            .map_err(|e| format!("projection lookup: {e}"))?
            .map(|row| row.get(0));
        let inserted = match existing {
            Some(found) if found == digest => false,
            Some(found) => {
                return Err(format!(
                    "AUDIT_REBUILD_INVALID: projection {}#{} digest {} conflicts with verified destination {}",
                    entry.event.source, entry.event.sequence, found, digest
                ));
            }
            None => tx
                .execute(
                    "INSERT INTO audit_evidence_projection \
                     (source_identity, source_sequence, event_id, event_digest, registry_id, event, \
                      destination_seq, destination_hash) \
                     VALUES ($1,$2,$3::text::uuid,$4,$5,$6::jsonb,$7,$8) \
                     ON CONFLICT (source_identity, source_sequence) DO NOTHING",
                    &[
                        &entry.event.source,
                        &(entry.event.sequence as i64),
                        &entry.event.event_id,
                        &digest,
                        &entry.event.registry_id,
                        &serde_json::to_value(&entry.event).expect("serializable"),
                        &(entry.delivery_seq as i64),
                        &entry.hash.clone().unwrap_or_default(),
                    ],
                )
                .map_err(|e| format!("projection insert: {e}"))?
                > 0,
        };
        tx.execute(
            "UPDATE audit_evidence_rebuild_state SET cursor_sequence=$1, updated_at=clock_timestamp() WHERE id=$2",
            &[&(entry.event.sequence as i64), &REBUILD_STATE_ID],
        )
        .map_err(|e| format!("projection cursor: {e}"))?;
        tx.commit().map_err(|e| format!("projection commit: {e}"))?;
        Ok(inserted)
    }

    pub fn complete(
        &mut self,
        source: &str,
        head_sequence: u64,
        head_hash: &str,
    ) -> Result<(), String> {
        self.client
            .execute(
                "UPDATE audit_evidence_rebuild_state SET status='COMPLETE', cursor_sequence=$1, \
                 head_sequence=$1, head_hash=$2, updated_at=clock_timestamp(), error=NULL \
                 WHERE id=$3 AND source_identity=$4",
                &[
                    &(head_sequence as i64),
                    &head_hash,
                    &REBUILD_STATE_ID,
                    &source,
                ],
            )
            .map_err(|e| format!("projection complete: {e}"))?;
        Ok(())
    }

    pub fn fail(&mut self, error: &str) -> Result<(), String> {
        self.client
            .execute(
                "UPDATE audit_evidence_rebuild_state SET status='FAILED', error=$1, updated_at=clock_timestamp() WHERE id=$2",
                &[&error, &REBUILD_STATE_ID],
            )
            .map_err(|e| format!("projection fail: {e}"))?;
        Ok(())
    }

    pub fn projection_count(&mut self, source: &str) -> Result<u64, String> {
        let row = self
            .client
            .query_one(
                "SELECT count(*)::bigint FROM audit_evidence_projection WHERE source_identity=$1",
                &[&source],
            )
            .map_err(|e| format!("projection count: {e}"))?;
        Ok(row.get::<_, i64>(0).max(0) as u64)
    }

    /// Проверка completeness: каждая строка destination присутствует ровно
    /// один раз с тем же digest.
    pub fn verify_complete(&mut self, entries: &[&SinkEntry]) -> Result<Vec<String>, String> {
        let mut errors = Vec::new();
        for entry in entries {
            let row = self
                .client
                .query_opt(
                    "SELECT event_digest FROM audit_evidence_projection WHERE source_identity=$1 AND source_sequence=$2",
                    &[&entry.event.source, &(entry.event.sequence as i64)],
                )
                .map_err(|e| format!("projection verify: {e}"))?;
            match row {
                None => errors.push(format!(
                    "projection missing {}#{}",
                    entry.event.source, entry.event.sequence
                )),
                Some(row) => {
                    let digest: String = row.get(0);
                    if digest != entry.event.digest() {
                        errors.push(format!(
                            "projection digest mismatch {}#{}",
                            entry.event.source, entry.event.sequence
                        ));
                    }
                }
            }
        }
        Ok(errors)
    }
}
