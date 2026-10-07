//! Protected append-only destination независимый от mutable primary audit:
//! собственный каталог 0700, hash-цепочка `events.jsonl`, внешний `floor.json`
//! с per-source identity/sequence/hash/floor, append-only `checkpoints.jsonl`.
//!
//! Гарантии:
//! * повторная доставка `(eventId, source, sequence, digest)` идемпотентна;
//! * тот же sequence с другим digest — fork/rollback, отказ;
//! * gap в source sequence — отказ (доставка упорядочена; rebuild идёт по
//!   destination, а не по догадкам);
//! * tail-delete/rollback обнаруживается по floor даже при внутренне целой
//!   оставшейся цепочке;
//! * append: строка + fsync, затем floor (tmp+rename+fsync каталога); crash
//!   между ними восстанавливается при replay, floor никогда не «откатывает»
//!   принятое.

use crate::canonical::{canonical_json, sha256_hex};
use crate::event::AuditEvent;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const SINK_DOMAIN: &[u8] = b"ONELAYER:AUDIT:SINK:V1\n";
pub const BUNDLE_DOMAIN: &[u8] = b"ONELAYER:AUDIT:BUNDLE:V1\n";
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const BUNDLE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SinkEntry {
    pub delivery_seq: u64,
    pub prev: String,
    pub event: AuditEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

pub fn entry_hash(entry: &SinkEntry) -> String {
    let mut unsigned = entry.clone();
    unsigned.hash = None;
    let value = serde_json::to_value(&unsigned).expect("serializable");
    sha256_hex(&[
        SINK_DOMAIN,
        entry.prev.as_bytes(),
        canonical_json(&value).as_bytes(),
    ])
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SourcePin {
    pub identity: String,
    /// Следующий ожидаемый source sequence (1-based).
    pub next_sequence: u64,
    /// Digest последнего принятого события источника ("" пока пусто).
    pub last_hash: String,
    /// Проверенная нижняя граница: rebuild начинается отсюда.
    pub floor_sequence: u64,
    pub head_seq: u64,
    pub head_hash: String,
    /// deliverySeq последнего принятого события источника (0 пока пусто).
    pub last_delivery_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FloorFile {
    pub head_seq: u64,
    pub head_hash: String,
    pub sources: BTreeMap<String, SourcePin>,
    pub at_unix_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Checkpoint {
    pub at_unix_ms: i64,
    pub status: String,
    pub source: String,
    pub cursor_sequence: u64,
    pub head_seq: u64,
    pub head_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SinkStatus {
    pub head_seq: u64,
    pub head_hash: String,
    pub sources: Vec<SourcePin>,
    pub tail_rollback: Option<String>,
    pub entries: u64,
}

#[derive(Debug, Clone)]
pub struct AppendOutcome {
    pub status: &'static str,
    pub delivery_seq: u64,
    pub destination_hash: String,
    pub source_sequence: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    pub source: Option<String>,
    pub registry_id: Option<String>,
    pub action: Option<String>,
    pub actor: Option<String>,
    pub from_sequence: Option<u64>,
    pub to_sequence: Option<u64>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleEvent {
    pub delivery_seq: u64,
    pub prev: String,
    pub hash: String,
    pub event_digest: String,
    pub event: AuditEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceBundle {
    pub bundle_version: u32,
    pub generated_at_ms: i64,
    pub registry_id: String,
    pub destination_head: SinkStatus,
    pub floor: FloorFile,
    pub events: Vec<BundleEvent>,
    pub checkpoints: Vec<Checkpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleVerification {
    pub verified: bool,
    pub errors: Vec<String>,
}

pub fn bundle_hash(bundle: &EvidenceBundle) -> String {
    let mut unsigned = bundle.clone();
    unsigned.bundle_hash = None;
    let value = serde_json::to_value(&unsigned).expect("serializable");
    sha256_hex(&[BUNDLE_DOMAIN, canonical_json(&value).as_bytes()])
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn read_floor(path: &Path) -> Result<Option<FloorFile>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| format!("AUDIT_SINK_CORRUPT: floor {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("floor {}: {e}", path.display())),
    }
}

fn write_floor(path: &Path, floor: &FloorFile) -> Result<(), String> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let bytes = serde_json::to_vec(floor).expect("serializable");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("floor tmp: {e}"))?;
        f.write_all(&bytes)
            .map_err(|e| format!("floor write: {e}"))?;
        f.sync_all().map_err(|e| format!("floor sync: {e}"))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("floor rename: {e}"))?;
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("floor dir sync: {e}"))?;
    Ok(())
}

#[derive(Debug)]
pub struct ProtectedSink {
    dir: PathBuf,
    events_path: PathBuf,
    floor_path: PathBuf,
    checkpoints_path: PathBuf,
    file: File,
    entries: Vec<SinkEntry>,
    event_ids: BTreeMap<String, u64>,
    sources: BTreeMap<String, SourcePin>,
    tail_rollback: Option<String>,
}

impl ProtectedSink {
    pub fn open(dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("sink dir: {e}"))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("sink dir mode: {e}"))?;
        let events_path = dir.join("events.jsonl");
        let floor_path = dir.join("floor.json");
        let checkpoints_path = dir.join("checkpoints.jsonl");

        let mut entries: Vec<SinkEntry> = Vec::new();
        let mut event_ids: BTreeMap<String, u64> = BTreeMap::new();
        let mut sources: BTreeMap<String, SourcePin> = BTreeMap::new();
        let mut head_hash = GENESIS.to_string();
        if let Ok(file) = File::open(&events_path) {
            for (index, line) in BufReader::new(file).lines().enumerate() {
                let line = line.map_err(|e| format!("sink read: {e}"))?;
                if line.trim().is_empty() {
                    continue;
                }
                let entry: SinkEntry = serde_json::from_str(&line)
                    .map_err(|e| format!("AUDIT_SINK_CORRUPT line {}: {e}", index + 1))?;
                let expected_seq = entries.len() as u64 + 1;
                if entry.delivery_seq != expected_seq || entry.prev != head_hash {
                    return Err(format!(
                        "AUDIT_SINK_CORRUPT line {}: delivery chain broken",
                        index + 1
                    ));
                }
                let expected_hash = entry_hash(&entry);
                if entry.hash.as_deref() != Some(expected_hash.as_str()) {
                    return Err(format!(
                        "AUDIT_SINK_CORRUPT line {}: entry hash mismatch",
                        index + 1
                    ));
                }
                entry
                    .event
                    .validate()
                    .map_err(|e| format!("AUDIT_SINK_CORRUPT line {}: {e}", index + 1))?;
                let digest = entry.event.digest();
                let pin = sources
                    .entry(entry.event.source.clone())
                    .or_insert_with(|| SourcePin {
                        identity: entry.event.source.clone(),
                        next_sequence: 1,
                        last_hash: String::new(),
                        floor_sequence: 0,
                        head_seq: 0,
                        head_hash: String::new(),
                        last_delivery_seq: 0,
                    });
                if entry.event.sequence != pin.next_sequence {
                    return Err(format!(
                        "AUDIT_SINK_CORRUPT line {}: source {} sequence {} does not continue {}",
                        index + 1,
                        entry.event.source,
                        entry.event.sequence,
                        pin.next_sequence
                    ));
                }
                if pin.next_sequence > 1 && digest == pin.last_hash {
                    return Err(format!(
                        "AUDIT_SINK_CORRUPT line {}: duplicate source digest",
                        index + 1
                    ));
                }
                if event_ids
                    .insert(entry.event.event_id.clone(), entry.delivery_seq)
                    .is_some()
                {
                    return Err(format!(
                        "AUDIT_SINK_CORRUPT line {}: duplicate eventId",
                        index + 1
                    ));
                }
                pin.next_sequence += 1;
                pin.last_hash = digest.clone();
                pin.head_seq = entry.event.sequence;
                pin.head_hash = digest;
                pin.last_delivery_seq = entry.delivery_seq;
                head_hash = expected_hash;
                entries.push(entry);
            }
        }

        let head_seq = entries.len() as u64;
        let replay_floor = FloorFile {
            head_seq,
            head_hash: head_hash.clone(),
            sources: sources.clone(),
            at_unix_ms: now_unix_ms(),
        };
        let mut tail_rollback = None;
        match read_floor(&floor_path)? {
            Some(floor) => {
                if floor.head_seq > head_seq
                    || (floor.head_seq == head_seq && floor.head_hash != head_hash)
                {
                    tail_rollback = Some(format!(
                        "AUDIT_SINK_TAIL_ROLLBACK: floor has {} entries head {} but journal has {} entries head {}",
                        floor.head_seq, floor.head_hash, head_seq, head_hash
                    ));
                } else if floor.head_seq < head_seq || floor.head_hash != head_hash {
                    write_floor(&floor_path, &replay_floor)?;
                }
            }
            None if !entries.is_empty() => {
                // Удаление floor не должно «обнулять» защиту от rollback.
                tail_rollback = Some(format!(
                    "AUDIT_SINK_FLOOR_MISSING: journal has {} entries but floor {} is absent (rollback evidence)",
                    entries.len(),
                    floor_path.display()
                ));
            }
            None => write_floor(&floor_path, &replay_floor)?,
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&events_path)
            .map_err(|e| format!("sink open: {e}"))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            events_path,
            floor_path,
            checkpoints_path,
            file,
            entries,
            event_ids,
            sources,
            tail_rollback,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn events_path(&self) -> &Path {
        &self.events_path
    }

    pub fn tail_rollback(&self) -> Option<&str> {
        self.tail_rollback.as_deref()
    }

    pub fn head(&self) -> (u64, String) {
        (
            self.entries.len() as u64,
            self.entries
                .last()
                .and_then(|e| e.hash.clone())
                .unwrap_or_else(|| GENESIS.to_string()),
        )
    }

    pub fn status(&self) -> SinkStatus {
        SinkStatus {
            head_seq: self.entries.len() as u64,
            head_hash: self
                .entries
                .last()
                .and_then(|e| e.hash.clone())
                .unwrap_or_else(|| GENESIS.to_string()),
            sources: self.sources.values().cloned().collect(),
            tail_rollback: self.tail_rollback.clone(),
            entries: self.entries.len() as u64,
        }
    }

    fn require_healthy(&self) -> Result<(), String> {
        match &self.tail_rollback {
            Some(reason) => Err(reason.clone()),
            None => Ok(()),
        }
    }

    fn write_floor_now(&self) -> Result<(), String> {
        let (head_seq, head_hash) = self.head();
        write_floor(
            &self.floor_path,
            &FloorFile {
                head_seq,
                head_hash,
                sources: self.sources.clone(),
                at_unix_ms: now_unix_ms(),
            },
        )
    }

    pub fn append(&mut self, event: AuditEvent) -> Result<AppendOutcome, String> {
        self.require_healthy()?;
        event.validate()?;
        let digest = event.digest();

        if let Some(&delivery_seq) = self.event_ids.get(&event.event_id) {
            let existing = &self.entries[(delivery_seq - 1) as usize];
            if existing.event.digest() == digest {
                return Ok(AppendOutcome {
                    status: "DUPLICATE",
                    delivery_seq,
                    destination_hash: existing.hash.clone().unwrap_or_default(),
                    source_sequence: existing.event.sequence,
                });
            }
            return Err(format!(
                "AUDIT_SINK_EVENT_CONFLICT: eventId {} already stored with a different digest",
                event.event_id
            ));
        }

        let (expected, last_hash, last_delivery_seq) = match self.sources.get(&event.source) {
            Some(pin) => (
                pin.next_sequence,
                pin.last_hash.clone(),
                pin.last_delivery_seq,
            ),
            None => (1, String::new(), 0),
        };
        if event.sequence + 1 == expected && event.sequence > 0 {
            if digest != last_hash {
                return Err(format!(
                    "AUDIT_SINK_SEQUENCE_CONFLICT: source {} sequence {} already delivered with a different digest",
                    event.source, event.sequence
                ));
            }
            let existing = &self.entries[(last_delivery_seq - 1) as usize];
            return Ok(AppendOutcome {
                status: "DUPLICATE",
                delivery_seq: last_delivery_seq,
                destination_hash: existing.hash.clone().unwrap_or_default(),
                source_sequence: event.sequence,
            });
        }
        if event.sequence != expected {
            return Err(format!(
                "AUDIT_SINK_SEQUENCE_GAP: source {} expected sequence {}, got {}",
                event.source, expected, event.sequence
            ));
        }

        let prev = self
            .entries
            .last()
            .and_then(|e| e.hash.clone())
            .unwrap_or_else(|| GENESIS.to_string());
        let delivery_seq = self.entries.len() as u64 + 1;
        let mut entry = SinkEntry {
            delivery_seq,
            prev,
            event,
            hash: None,
        };
        let hash = entry_hash(&entry);
        entry.hash = Some(hash.clone());
        let mut line = serde_json::to_vec(&entry).expect("serializable");
        line.push(b'\n');
        self.file
            .write_all(&line)
            .map_err(|e| format!("sink write: {e}"))?;
        self.file
            .sync_data()
            .map_err(|e| format!("sink sync: {e}"))?;

        let pin = self
            .sources
            .entry(entry.event.source.clone())
            .or_insert_with(|| SourcePin {
                identity: entry.event.source.clone(),
                next_sequence: 1,
                last_hash: String::new(),
                floor_sequence: 0,
                head_seq: 0,
                head_hash: String::new(),
                last_delivery_seq: 0,
            });
        pin.next_sequence = entry.event.sequence + 1;
        pin.last_hash = entry.event.digest();
        pin.head_seq = entry.event.sequence;
        pin.head_hash = entry.event.digest();
        pin.last_delivery_seq = delivery_seq;
        self.event_ids
            .insert(entry.event.event_id.clone(), delivery_seq);
        let source_sequence = entry.event.sequence;
        self.entries.push(entry);
        self.write_floor_now()?;
        Ok(AppendOutcome {
            status: "APPENDED",
            delivery_seq,
            destination_hash: hash,
            source_sequence,
        })
    }

    pub fn search(&self, query: &SearchQuery) -> Vec<&SinkEntry> {
        let limit = query.limit.unwrap_or(100).min(1_000);
        self.entries
            .iter()
            .filter(|entry| {
                let e = &entry.event;
                query
                    .source
                    .as_deref()
                    .is_none_or(|source| e.source == source)
                    && query
                        .registry_id
                        .as_deref()
                        .is_none_or(|registry| e.registry_id == registry)
                    && query
                        .action
                        .as_deref()
                        .is_none_or(|action| e.action == action)
                    && query.actor.as_deref().is_none_or(|actor| e.actor == actor)
                    && query.from_sequence.is_none_or(|from| e.sequence >= from)
                    && query.to_sequence.is_none_or(|to| e.sequence <= to)
            })
            .take(limit)
            .collect()
    }

    pub fn checkpoints(&self) -> Vec<Checkpoint> {
        let Ok(file) = File::open(&self.checkpoints_path) else {
            return Vec::new();
        };
        BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str(&line).ok())
            .collect()
    }

    pub fn append_checkpoint(&mut self, checkpoint: &Checkpoint) -> Result<(), String> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.checkpoints_path)
            .map_err(|e| format!("checkpoint open: {e}"))?;
        let mut line = serde_json::to_vec(checkpoint).expect("serializable");
        line.push(b'\n');
        f.write_all(&line)
            .map_err(|e| format!("checkpoint write: {e}"))?;
        f.sync_data().map_err(|e| format!("checkpoint sync: {e}"))?;
        Ok(())
    }

    /// Экспорт scoped registry. Payload уже allowlist-redacted при append;
    /// bundle содержит только выбранный registry и (если заданы) источники
    /// capability. Пустой `sources` = все источники.
    pub fn export(
        &self,
        registry_id: &str,
        from: u64,
        to: u64,
        sources: &[String],
    ) -> EvidenceBundle {
        let events: Vec<BundleEvent> = self
            .entries
            .iter()
            .filter(|e| {
                e.event.registry_id == registry_id
                    && (sources.is_empty() || sources.iter().any(|s| s == &e.event.source))
                    && e.event.sequence >= from
                    && e.event.sequence <= to
            })
            .map(|e| BundleEvent {
                delivery_seq: e.delivery_seq,
                prev: e.prev.clone(),
                hash: e.hash.clone().unwrap_or_default(),
                event_digest: e.event.digest(),
                event: e.event.clone(),
            })
            .collect();
        let (head_seq, head_hash) = self.head();
        let floor = FloorFile {
            head_seq,
            head_hash,
            sources: self.sources.clone(),
            at_unix_ms: now_unix_ms(),
        };
        let mut bundle = EvidenceBundle {
            bundle_version: BUNDLE_VERSION,
            generated_at_ms: now_unix_ms(),
            registry_id: registry_id.to_string(),
            destination_head: self.status(),
            floor,
            events,
            checkpoints: self.checkpoints(),
            bundle_hash: None,
        };
        bundle.bundle_hash = Some(bundle_hash(&bundle));
        bundle
    }

    pub fn verify_bundle(bundle: &EvidenceBundle) -> BundleVerification {
        let mut errors = Vec::new();
        if bundle.bundle_version != BUNDLE_VERSION {
            errors.push(format!(
                "unsupported bundleVersion {}",
                bundle.bundle_version
            ));
        }
        match &bundle.bundle_hash {
            Some(hash) if *hash == bundle_hash(bundle) => {}
            Some(_) => errors.push("bundleHash mismatch".into()),
            None => errors.push("bundleHash missing".into()),
        }
        let mut prev = if bundle.events.is_empty() {
            bundle.floor.head_hash.clone()
        } else {
            let first = &bundle.events[0];
            if first.delivery_seq == 1 {
                GENESIS.to_string()
            } else if first.delivery_seq == bundle.floor.head_seq + 1 {
                bundle.floor.head_hash.clone()
            } else {
                errors.push("bundle does not continue the declared floor".into());
                GENESIS.to_string()
            }
        };
        for event in &bundle.events {
            if event.prev != prev {
                errors.push(format!("delivery {} prev link broken", event.delivery_seq));
            }
            let recomputed = entry_hash(&SinkEntry {
                delivery_seq: event.delivery_seq,
                prev: event.prev.clone(),
                event: event.event.clone(),
                hash: Some(event.hash.clone()),
            });
            if recomputed != event.hash {
                errors.push(format!("delivery {} hash mismatch", event.delivery_seq));
            }
            if event.event.digest() != event.event_digest {
                errors.push(format!(
                    "delivery {} event digest mismatch",
                    event.delivery_seq
                ));
            }
            if event.event.registry_id != bundle.registry_id {
                errors.push(format!(
                    "delivery {} is outside exported registry scope",
                    event.delivery_seq
                ));
            }
            if let Err(e) = event.event.validate() {
                errors.push(format!("delivery {} invalid: {e}", event.delivery_seq));
            }
            prev = event.hash.clone();
        }
        BundleVerification {
            verified: errors.is_empty(),
            errors,
        }
    }

    /// Полный упорядоченный поток источника из проверенного destination —
    /// единственный вход rebuild. Tail rollback блокирует rebuild.
    pub fn stream_for_source(&self, source: &str) -> Result<Vec<&SinkEntry>, String> {
        self.require_healthy()?;
        Ok(self
            .entries
            .iter()
            .filter(|e| e.event.source == source)
            .collect())
    }

    pub fn all_entries(&self) -> &[SinkEntry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::sample;
    use serde_json::{json, Value as Json};

    fn tmp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("onelayer-audit-sink-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn event(sequence: u64, id: &str, payload: Json) -> AuditEvent {
        let mut e = sample();
        e.sequence = sequence;
        e.event_id = id.into();
        e.payload = payload;
        e
    }

    #[test]
    fn append_is_idempotent_and_detects_gap_conflict_and_fork() {
        let dir = tmp("append");
        let mut sink = ProtectedSink::open(&dir).unwrap();
        let a = event(
            1,
            "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
            json!({"reason": "a"}),
        );
        let out = sink.append(a.clone()).unwrap();
        assert_eq!(out.status, "APPENDED");
        let again = sink.append(a).unwrap();
        assert_eq!(again.status, "DUPLICATE");
        assert_eq!(again.delivery_seq, out.delivery_seq);

        let mut forked = event(
            1,
            "3f2504e0-4f89-41d3-9a0c-0305e82c3302",
            json!({"reason": "b"}),
        );
        forked.event_id = "3f2504e0-4f89-41d3-9a0c-0305e82c3302".into();
        assert!(sink
            .append(forked)
            .unwrap_err()
            .contains("AUDIT_SINK_SEQUENCE_CONFLICT"));

        let skipped = event(
            3,
            "3f2504e0-4f89-41d3-9a0c-0305e82c3303",
            json!({"reason": "c"}),
        );
        assert!(sink
            .append(skipped)
            .unwrap_err()
            .contains("AUDIT_SINK_SEQUENCE_GAP"));
        let b = event(
            2,
            "3f2504e0-4f89-41d3-9a0c-0305e82c3304",
            json!({"reason": "d"}),
        );
        assert_eq!(sink.append(b).unwrap().status, "APPENDED");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tail_truncation_and_middle_edit_are_detected() {
        let dir = tmp("tail");
        {
            let mut sink = ProtectedSink::open(&dir).unwrap();
            for (i, id) in [
                "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
                "3f2504e0-4f89-41d3-9a0c-0305e82c3302",
                "3f2504e0-4f89-41d3-9a0c-0305e82c3303",
            ]
            .iter()
            .enumerate()
            {
                sink.append(event(i as u64 + 1, id, json!({"reason": format!("r{i}")})))
                    .unwrap();
            }
        }
        let text = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(
            dir.join("events.jsonl"),
            format!("{}\n{}\n", lines[0], lines[1]),
        )
        .unwrap();
        let reopened = ProtectedSink::open(&dir).unwrap();
        assert!(reopened.tail_rollback().is_some());
        assert!(reopened
            .status()
            .tail_rollback
            .unwrap()
            .contains("AUDIT_SINK_TAIL_ROLLBACK"));
        assert!(ProtectedSink::open(&dir)
            .unwrap()
            .append(event(2, "3f2504e0-4f89-41d3-9a0c-0305e82c3304", json!({})))
            .unwrap_err()
            .contains("TAIL_ROLLBACK"));

        std::fs::write(dir.join("events.jsonl"), &text).unwrap();
        std::fs::write(dir.join("events.jsonl"), text.replacen("r1", "rX", 1)).unwrap();
        let err = ProtectedSink::open(&dir).unwrap_err();
        assert!(err.contains("AUDIT_SINK_CORRUPT"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn floor_deletion_is_refused_with_nonempty_journal() {
        let dir = tmp("floor-missing");
        {
            let mut sink = ProtectedSink::open(&dir).unwrap();
            sink.append(event(
                1,
                "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
                json!({"reason": "a"}),
            ))
            .unwrap();
        }
        std::fs::remove_file(dir.join("floor.json")).unwrap();
        let mut reopened = ProtectedSink::open(&dir).unwrap();
        let reason = reopened.tail_rollback().unwrap().to_string();
        assert!(reason.contains("AUDIT_SINK_FLOOR_MISSING"), "{reason}");
        assert!(reopened
            .append(event(
                2,
                "3f2504e0-4f89-41d3-9a0c-0305e82c3302",
                json!({"reason": "b"})
            ))
            .unwrap_err()
            .contains("FLOOR_MISSING"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn crash_window_advances_floor_and_export_verifies() {
        let dir = tmp("crash");
        let mut sink = ProtectedSink::open(&dir).unwrap();
        sink.append(event(
            1,
            "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
            json!({"reason": "a"}),
        ))
        .unwrap();
        sink.append(event(
            2,
            "3f2504e0-4f89-41d3-9a0c-0305e82c3302",
            json!({"reason": "b"}),
        ))
        .unwrap();
        // floor отстал (crash между строкой и floor).
        let mut floor: FloorFile =
            serde_json::from_str(&std::fs::read_to_string(dir.join("floor.json")).unwrap())
                .unwrap();
        floor.head_seq = 1;
        write_floor(&dir.join("floor.json"), &floor).unwrap();
        drop(sink);
        let reopened = ProtectedSink::open(&dir).unwrap();
        assert!(reopened.tail_rollback().is_none());
        assert_eq!(reopened.status().head_seq, 2);

        let bundle = reopened.export("registry:r", 1, 10, &[]);
        assert!(ProtectedSink::verify_bundle(&bundle).verified);
        // Источники capability фильтруют export: чужой source не попадает.
        let foreign = reopened.export("registry:r", 1, 10, &["other-source".to_string()]);
        assert!(foreign.events.is_empty());
        let own = reopened.export("registry:r", 1, 10, &["demo-api".to_string()]);
        assert_eq!(own.events.len(), 2);
        let mut tampered = bundle.clone();
        tampered.events[1].event.payload = json!({"reason": "evil"});
        assert!(!ProtectedSink::verify_bundle(&tampered).verified);
        let mut scoped = bundle;
        scoped.registry_id = "other".into();
        assert!(!ProtectedSink::verify_bundle(&scoped).verified);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
