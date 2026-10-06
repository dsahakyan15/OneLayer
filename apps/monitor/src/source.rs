//! Read-only чтение защищаемого source (PostgreSQL registry workflow + publication).
//!
//! Все значения отсюда считаются НЕдоверенными: они проверяются против chain
//! и против собственных наблюдений Monitor. Чтение выполняется одной
//! `REPEATABLE READ, READ ONLY` транзакцией под отдельной ролью
//! (`apps/monitor/sql/monitor_readonly_role.sql`). Перед работой Monitor
//! проверяет, что у роли нет права записи ни в одну наблюдаемую таблицу.

use postgres::{Client, IsolationLevel, NoTls};
use serde_json::Value as Json;

/// Таблицы, которые Monitor читает. Роль должна иметь на них только SELECT.
pub const WATCHED_TABLES: &[&str] = &[
    "wf_record",
    "wf_version",
    "wf_outbox",
    "wf_source_cursor",
    "wf_source_event",
    "wf_publication",
    "wf_publication_item",
    "wf_publication_intent",
    "wf_publication_anchor",
];

#[derive(Debug, Clone)]
pub struct VersionRow {
    pub record_id: String,
    pub version: i64,
    pub operation: String,
    /// `None`, если payload в БД не является JSON (не должно случаться).
    pub payload: Option<Json>,
    pub payload_hash: String,
}

#[derive(Debug, Clone)]
pub struct OutboxRow {
    pub event_id: String,
    pub record_id: String,
    pub version: i64,
    pub payload_hash: String,
    pub created_at_unix: i64,
}

#[derive(Debug, Clone)]
pub struct MemberRow {
    pub operation_id: String,
    pub ordinal: i32,
    pub event_id: String,
}

#[derive(Debug, Clone)]
pub struct OperationRow {
    pub operation_id: String,
    pub state: String,
}

#[derive(Debug, Clone)]
pub struct LocalAnchor {
    pub operation_id: String,
    pub batch_sequence: String,
    pub merkle_root: String,
    pub manifest_hash: String,
    pub anchor_hash: String,
    pub intent_hash: String,
    /// `(stored intent_hash, intent_bytes)` из `wf_publication_intent`, если есть.
    pub intent: Option<(String, Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub struct SourceEventRow {
    pub source_id: String,
    pub cursor: i64,
}

#[derive(Debug, Clone, Default)]
pub struct SourceSnapshot {
    pub db_now_unix: i64,
    pub versions: Vec<VersionRow>,
    pub heads: Vec<(String, i64)>,
    pub outbox: Vec<OutboxRow>,
    pub operations: Vec<OperationRow>,
    pub members: Vec<MemberRow>,
    pub anchors: Vec<LocalAnchor>,
    /// `(operation_id, batch_sequence)` всех intent реестра.
    pub intents: Vec<(String, String)>,
    pub source_events: Vec<SourceEventRow>,
    pub source_heads: Vec<(String, i64)>,
}

pub trait SourceReader {
    fn snapshot(&mut self, registry_id: &str) -> Result<SourceSnapshot, String>;
}

pub struct PgSource {
    client: Client,
}

impl PgSource {
    /// Подключается и отказывается работать с учётными данными, способными писать.
    pub fn connect(dsn: &str) -> Result<Self, String> {
        let mut client = Client::connect(dsn, NoTls).map_err(|e| format!("source connect: {e}"))?;
        let row = client
            .query_one(
                "SELECT r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb, current_user::text \
                 FROM pg_roles r WHERE r.rolname = current_user",
                &[],
            )
            .map_err(|e| format!("source role check: {e}"))?;
        let user: String = row.get(4);
        for (i, attr) in ["SUPERUSER", "BYPASSRLS", "CREATEROLE", "CREATEDB"]
            .iter()
            .enumerate()
        {
            if row.get::<_, bool>(i) {
                return Err(format!(
                    "MONITOR_CREDENTIAL_NOT_READ_ONLY: role {user} has {attr}"
                ));
            }
        }
        for table in WATCHED_TABLES {
            let r = client
                .query_one(
                    "SELECT has_table_privilege(current_user, $1, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'), \
                            has_table_privilege(current_user, $1, 'SELECT')",
                    &[&format!("public.{table}")],
                )
                .map_err(|e| format!("source privilege check {table}: {e}"))?;
            if r.get::<_, bool>(0) {
                return Err(format!(
                    "MONITOR_CREDENTIAL_NOT_READ_ONLY: role {user} can modify {table}"
                ));
            }
            if !r.get::<_, bool>(1) {
                return Err(format!(
                    "MONITOR_CREDENTIAL_MISSING_SELECT: role {user} cannot read {table}"
                ));
            }
        }
        Ok(Self { client })
    }
}

impl SourceReader for PgSource {
    fn snapshot(&mut self, registry_id: &str) -> Result<SourceSnapshot, String> {
        let mut tx = self
            .client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .map_err(|e| format!("source tx: {e}"))?;
        let e = |what: &str| {
            let what = what.to_string();
            move |err: postgres::Error| format!("source read {what}: {err}")
        };
        let mut s = SourceSnapshot {
            db_now_unix: tx
                .query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                    &[],
                )
                .map_err(e("clock"))?
                .get(0),
            ..Default::default()
        };
        for r in tx
            .query(
                "SELECT record_id, version::bigint, operation, payload::text, payload_hash FROM wf_version WHERE registry_id=$1",
                &[&registry_id],
            )
            .map_err(e("wf_version"))?
        {
            let text: String = r.get(3);
            s.versions.push(VersionRow {
                record_id: r.get(0),
                version: r.get(1),
                operation: r.get(2),
                payload: serde_json::from_str(&text).ok(),
                payload_hash: r.get(4),
            });
        }
        for r in tx
            .query(
                "SELECT record_id, version::bigint FROM wf_record WHERE registry_id=$1",
                &[&registry_id],
            )
            .map_err(e("wf_record"))?
        {
            s.heads.push((r.get(0), r.get(1)));
        }
        for r in tx
            .query(
                "SELECT event_id::text, record_id, version::bigint, payload_hash, floor(extract(epoch FROM created_at))::bigint \
                 FROM wf_outbox WHERE registry_id=$1",
                &[&registry_id],
            )
            .map_err(e("wf_outbox"))?
        {
            s.outbox.push(OutboxRow {
                event_id: r.get(0),
                record_id: r.get(1),
                version: r.get(2),
                payload_hash: r.get(3),
                created_at_unix: r.get(4),
            });
        }
        for r in tx
            .query(
                "SELECT operation_id::text, state FROM wf_publication WHERE registry_id=$1",
                &[&registry_id],
            )
            .map_err(e("wf_publication"))?
        {
            s.operations.push(OperationRow {
                operation_id: r.get(0),
                state: r.get(1),
            });
        }
        for r in tx
            .query(
                "SELECT i.operation_id::text, i.ordinal, i.event_id::text FROM wf_publication_item i \
                 JOIN wf_publication p USING (operation_id) WHERE p.registry_id=$1",
                &[&registry_id],
            )
            .map_err(e("wf_publication_item"))?
        {
            s.members.push(MemberRow {
                operation_id: r.get(0),
                ordinal: r.get(1),
                event_id: r.get(2),
            });
        }
        for r in tx
            .query(
                "SELECT a.operation_id::text, a.batch_sequence::text, a.merkle_root, a.manifest_hash, a.anchor_hash, \
                        a.intent_hash, i.intent_hash, i.intent_bytes \
                 FROM wf_publication_anchor a LEFT JOIN wf_publication_intent i USING (operation_id) \
                 WHERE a.registry_id=$1",
                &[&registry_id],
            )
            .map_err(e("wf_publication_anchor"))?
        {
            let stored: Option<String> = r.get(6);
            let bytes: Option<Vec<u8>> = r.get(7);
            s.anchors.push(LocalAnchor {
                operation_id: r.get(0),
                batch_sequence: r.get(1),
                merkle_root: r.get(2),
                manifest_hash: r.get(3),
                anchor_hash: r.get(4),
                intent_hash: r.get(5),
                intent: stored.zip(bytes),
            });
        }
        for r in tx
            .query(
                "SELECT operation_id::text, batch_sequence::text FROM wf_publication_intent WHERE registry_id=$1",
                &[&registry_id],
            )
            .map_err(e("wf_publication_intent"))?
        {
            s.intents.push((r.get(0), r.get(1)));
        }
        for r in tx
            .query(
                "SELECT source_id, cursor FROM wf_source_event WHERE registry_id=$1",
                &[&registry_id],
            )
            .map_err(e("wf_source_event"))?
        {
            s.source_events.push(SourceEventRow {
                source_id: r.get(0),
                cursor: r.get(1),
            });
        }
        for r in tx
            .query(
                "SELECT source_id, cursor FROM wf_source_cursor WHERE registry_id=$1",
                &[&registry_id],
            )
            .map_err(e("wf_source_cursor"))?
        {
            s.source_heads.push((r.get(0), r.get(1)));
        }
        tx.commit().map_err(e("commit"))?;
        Ok(s)
    }
}
