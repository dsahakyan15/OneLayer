//! Append-only evidence log Monitor-а (`evidence.jsonl`).
//!
//! Хранится вне защищаемой БД, в каталоге с отдельными правами Monitor-а.
//! Каждая строка связана hash-цепочкой:
//! `hash = SHA-256("ONELAYER:MONITOR:EVIDENCE:V1\n" || prev_hash || JSON(entry без hash))`.
//! Изменение или удаление строки в середине обнаруживается при открытии;
//! усечение хвоста локально не обнаружимо без внешней фиксации головы
//! цепочки (открытый пункт, см. evidence 12). Monitor никогда не переписывает
//! и не удаляет записи: только добавляет.

use crate::detect::{Baseline, Observed, RecordRef};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const EVIDENCE_DOMAIN: &[u8] = b"ONELAYER:MONITOR:EVIDENCE:V1\n";
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub seq: u64,
    pub prev: String,
    pub at_unix_ms: i64,
    #[serde(rename = "type")]
    pub kind: String,
    pub body: Json,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

fn entry_hash(e: &Entry) -> String {
    let mut unsigned = e.clone();
    unsigned.hash = None;
    let mut h = Sha256::new();
    h.update(EVIDENCE_DOMAIN);
    h.update(e.prev.as_bytes());
    h.update(serde_json::to_vec(&unsigned).expect("serializable"));
    hex::encode(h.finalize())
}

/// Состояние, восстановленное из log (baseline + активные findings).
#[derive(Debug, Default, Clone)]
pub struct Replayed {
    pub baseline: Baseline,
    pub active: BTreeSet<String>,
    pub entries: u64,
    pub head: String,
}

pub struct EvidenceLog {
    path: PathBuf,
    file: File,
    next_seq: u64,
    head: String,
}

pub fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Проверяет цепочку и восстанавливает состояние. Ошибка = log повреждён.
pub fn replay(path: &Path) -> Result<Replayed, String> {
    let mut r = Replayed {
        head: GENESIS.into(),
        ..Default::default()
    };
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(r),
        Err(e) => return Err(format!("evidence open: {e}")),
    };
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| format!("evidence read: {e}"))?;
        let e: Entry = serde_json::from_str(&line)
            .map_err(|err| format!("EVIDENCE_CORRUPT line {}: {err}", i + 1))?;
        if e.seq != r.entries + 1 || e.prev != r.head {
            return Err(format!(
                "EVIDENCE_CORRUPT line {}: sequence/prev link broken",
                i + 1
            ));
        }
        let expected = entry_hash(&e);
        if e.hash.as_deref() != Some(expected.as_str()) {
            return Err(format!("EVIDENCE_CORRUPT line {}: hash mismatch", i + 1));
        }
        apply(&mut r, &e)?;
        r.entries = e.seq;
        r.head = expected;
    }
    Ok(r)
}

fn apply(r: &mut Replayed, e: &Entry) -> Result<(), String> {
    let bad = |what: &str| format!("EVIDENCE_CORRUPT seq {}: {what}", e.seq);
    match e.kind.as_str() {
        "baseline_batch" => {
            let seq = e.body["batchSequence"]
                .as_u64()
                .ok_or_else(|| bad("batchSequence"))?;
            let leaves: Vec<(RecordRef, String)> =
                serde_json::from_value(e.body["leaves"].clone()).map_err(|_| bad("leaves"))?;
            r.baseline.batches.insert(seq, leaves.into_iter().collect());
        }
        "observations" => {
            let items: Vec<(RecordRef, Observed)> =
                serde_json::from_value(e.body["versions"].clone()).map_err(|_| bad("versions"))?;
            r.baseline.observed.extend(items);
            let events: Vec<(String, i64)> =
                serde_json::from_value(e.body["events"].clone()).map_err(|_| bad("events"))?;
            r.baseline.events_first_seen.extend(events);
        }
        "finding" => {
            r.active.insert(
                e.body["key"]
                    .as_str()
                    .ok_or_else(|| bad("key"))?
                    .to_string(),
            );
        }
        "finding_cleared" => {
            r.active
                .remove(e.body["key"].as_str().ok_or_else(|| bad("key"))?);
        }
        _ => {}
    }
    Ok(())
}

impl EvidenceLog {
    pub fn open(dir: &Path) -> Result<(Self, Replayed), String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("evidence dir: {e}"))?;
        let path = dir.join("evidence.jsonl");
        let replayed = replay(&path)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("evidence open: {e}"))?;
        Ok((
            Self {
                path,
                file,
                next_seq: replayed.entries + 1,
                head: replayed.head.clone(),
            },
            replayed,
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Добавляет запись и сбрасывает её на диск до возврата. Возвращает hash записи.
    pub fn append(&mut self, kind: &str, body: Json) -> Result<Entry, String> {
        let mut e = Entry {
            seq: self.next_seq,
            prev: self.head.clone(),
            at_unix_ms: now_unix_ms(),
            kind: kind.into(),
            body,
            hash: None,
        };
        let hash = entry_hash(&e);
        e.hash = Some(hash.clone());
        let mut line = serde_json::to_vec(&e).expect("serializable");
        line.push(b'\n');
        self.file
            .write_all(&line)
            .map_err(|err| format!("evidence write: {err}"))?;
        self.file
            .sync_data()
            .map_err(|err| format!("evidence sync: {err}"))?;
        self.next_seq += 1;
        self.head = hash;
        Ok(e)
    }

    pub fn baseline_batch(
        &mut self,
        seq: u64,
        leaves: &BTreeMap<RecordRef, String>,
    ) -> Result<(), String> {
        let list: Vec<(&RecordRef, &String)> = leaves.iter().collect();
        self.append(
            "baseline_batch",
            json!({"batchSequence": seq, "leaves": list}),
        )
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("onelayer-monitor-ev-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn chain_replays_and_detects_edits() {
        let dir = tmp("edit");
        {
            let (mut log, r) = EvidenceLog::open(&dir).unwrap();
            assert_eq!(r.entries, 0);
            log.append("finding", json!({"key": "k1"})).unwrap();
            log.append("finding", json!({"key": "k2"})).unwrap();
            log.append("finding_cleared", json!({"key": "k1"})).unwrap();
        }
        let r = replay(&dir.join("evidence.jsonl")).unwrap();
        assert_eq!(r.entries, 3);
        assert_eq!(r.active.iter().collect::<Vec<_>>(), vec!["k2"]);
        let text = std::fs::read_to_string(dir.join("evidence.jsonl")).unwrap();
        std::fs::write(dir.join("evidence.jsonl"), text.replacen("k2", "k3", 1)).unwrap();
        assert!(replay(&dir.join("evidence.jsonl"))
            .unwrap_err()
            .contains("EVIDENCE_CORRUPT"));
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(
            dir.join("evidence.jsonl"),
            format!("{}\n{}\n", lines[0], lines[2]),
        )
        .unwrap();
        assert!(
            replay(&dir.join("evidence.jsonl")).is_err(),
            "deleted middle entry must be detected"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
