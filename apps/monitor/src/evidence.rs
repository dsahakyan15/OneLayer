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

/// Внешний floor: последняя зафиксированная позиция цепочки, хранится
/// отдельным файлом (не в самом журнале). Усечение/rollback хвоста журнала
/// обнаруживается при открытии, даже если оставшаяся цепочка внутренне
/// согласована.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Floor {
    pub entries: u64,
    pub head: String,
    pub at_unix_ms: i64,
}

#[derive(Debug)]
pub struct EvidenceLog {
    path: PathBuf,
    file: File,
    floor_path: PathBuf,
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

fn read_floor(path: &Path) -> Result<Option<Floor>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| format!("EVIDENCE_FLOOR_CORRUPT {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("evidence floor {}: {e}", path.display())),
    }
}

/// Атомарная запись floor: tmp + fsync файла + rename + fsync каталога.
fn write_floor(path: &Path, floor: &Floor) -> Result<(), String> {
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("floor dir: {e}"))?;
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

/// Проверяет floor против восстановленного журнала.
///
/// `Err` = хвост журнала откатан/удалён, либо floor отсутствует при непустом
/// журнале (`EVIDENCE_FLOOR_MISSING`): удаление floor не должно «обнулять»
/// защиту. Пустой журнал без floor — первый запуск, floor создаётся.
/// Отставание floor (crash между записью строки и floor) не является потерей:
/// вызывающий продвигает floor вперёд.
pub fn check_floor(floor_path: &Path, replayed: &Replayed) -> Result<Option<Floor>, String> {
    let Some(floor) = read_floor(floor_path)? else {
        if replayed.entries > 0 {
            return Err(format!(
                "EVIDENCE_FLOOR_MISSING: journal has {} entries but floor {} is absent (rollback evidence)",
                replayed.entries,
                floor_path.display()
            ));
        }
        return Ok(None);
    };
    if floor.entries > replayed.entries
        || (floor.entries == replayed.entries && floor.head != replayed.head)
    {
        return Err(format!(
            "EVIDENCE_TAIL_ROLLBACK: floor has {} entries head {} but log has {} entries head {}",
            floor.entries, floor.head, replayed.entries, replayed.head
        ));
    }
    Ok(Some(floor))
}

pub fn floor_from(replayed: &Replayed) -> Floor {
    Floor {
        entries: replayed.entries,
        head: replayed.head.clone(),
        at_unix_ms: now_unix_ms(),
    }
}

/// Путь floor по умолчанию: sibling каталога evidence (`<dir>.floor.json`),
/// то есть отдельный файл вне самого журнала.
pub fn default_floor_path(dir: &Path) -> PathBuf {
    let mut s = dir.as_os_str().to_owned();
    s.push(".floor.json");
    PathBuf::from(s)
}

impl EvidenceLog {
    /// Открывает журнал с floor по умолчанию рядом с каталогом evidence.
    pub fn open(dir: &Path) -> Result<(Self, Replayed), String> {
        Self::open_with_floor(dir, &default_floor_path(dir))
    }

    /// `floor_path` обязан быть отдельным путём (не самим журналом). Для
    /// deployment рекомендуется отдельный mount; в lab достаточно отдельного
    /// файла 0600, что исключает незаметный rollback цепочки.
    pub fn open_with_floor(dir: &Path, floor_path: &Path) -> Result<(Self, Replayed), String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("evidence dir: {e}"))?;
        let path = dir.join("evidence.jsonl");
        let replayed = replay(&path)?;
        match check_floor(floor_path, &replayed)? {
            Some(floor) if floor.entries == replayed.entries && floor.head == replayed.head => {}
            _ => write_floor(floor_path, &floor_from(&replayed))?,
        }
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
                floor_path: floor_path.to_path_buf(),
                next_seq: replayed.entries + 1,
                head: replayed.head.clone(),
            },
            replayed,
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn floor_path(&self) -> &Path {
        &self.floor_path
    }

    /// Добавляет запись, сбрасывает её на диск и продвигает floor до возврата.
    /// Возвращает hash записи.
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
        write_floor(
            &self.floor_path,
            &Floor {
                entries: e.seq,
                head: self.head.clone(),
                at_unix_ms: now_unix_ms(),
            },
        )?;
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
        let _ = std::fs::remove_file(default_floor_path(&dir));
    }

    #[test]
    fn floor_deletion_is_refused_with_nonempty_journal() {
        let dir = tmp("floor-missing");
        let floor_path = default_floor_path(&dir);
        {
            let (mut log, _) = EvidenceLog::open(&dir).unwrap();
            log.append("finding", json!({"key": "k1"})).unwrap();
            log.append("finding", json!({"key": "k2"})).unwrap();
        }
        std::fs::remove_file(&floor_path).unwrap();
        let err = EvidenceLog::open(&dir).unwrap_err();
        assert!(err.contains("EVIDENCE_FLOOR_MISSING"), "{err}");
        let replayed = replay(&dir.join("evidence.jsonl")).unwrap();
        assert!(check_floor(&floor_path, &replayed)
            .unwrap_err()
            .contains("EVIDENCE_FLOOR_MISSING"));
        // Пустой журнал без floor — легитимный первый запуск.
        let fresh = tmp("floor-fresh");
        assert!(EvidenceLog::open(&fresh).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&fresh).unwrap();
        let _ = std::fs::remove_file(default_floor_path(&fresh));
    }

    #[test]
    fn floor_detects_tail_truncation_and_head_replacement() {
        let dir = tmp("floor-tail");
        {
            let (mut log, _) = EvidenceLog::open(&dir).unwrap();
            log.append("finding", json!({"key": "k1"})).unwrap();
            log.append("finding", json!({"key": "k2"})).unwrap();
            log.append("finding", json!({"key": "k3"})).unwrap();
        }
        let floor_path = default_floor_path(&dir);
        let floor: Floor =
            serde_json::from_str(&std::fs::read_to_string(&floor_path).unwrap()).unwrap();
        assert_eq!(floor.entries, 3);
        assert_eq!(
            floor.head,
            replay(&dir.join("evidence.jsonl")).unwrap().head
        );

        // Усечение хвоста (внутренне целая цепочка из 2 строк) обнаруживается.
        let text = std::fs::read_to_string(dir.join("evidence.jsonl")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(
            dir.join("evidence.jsonl"),
            format!("{}\n{}\n", lines[0], lines[1]),
        )
        .unwrap();
        let err = EvidenceLog::open(&dir).unwrap_err();
        assert!(err.contains("EVIDENCE_TAIL_ROLLBACK"), "{err}");

        // Полная подмена цепочки на более короткую валидную тоже видна по floor.
        std::fs::write(dir.join("evidence.jsonl"), format!("{}\n", lines[0])).unwrap();
        let err = EvidenceLog::open(&dir).unwrap_err();
        assert!(err.contains("EVIDENCE_TAIL_ROLLBACK"), "{err}");

        // Head не совпадает на той же длине.
        let mut tampered = floor.clone();
        tampered.head = "00".repeat(32);
        std::fs::write(&floor_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        std::fs::write(dir.join("evidence.jsonl"), &text).unwrap();
        let err = EvidenceLog::open(&dir).unwrap_err();
        assert!(err.contains("EVIDENCE_TAIL_ROLLBACK"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
        let _ = std::fs::remove_file(&floor_path);
    }

    #[test]
    fn floor_advances_after_crash_window_and_survives_reopen() {
        let dir = tmp("floor-crash");
        let floor_path = default_floor_path(&dir);
        let head_after_two = {
            let (mut log, _) = EvidenceLog::open(&dir).unwrap();
            log.append("finding", json!({"key": "k1"})).unwrap();
            let e = log.append("finding", json!({"key": "k2"})).unwrap();
            e.hash.unwrap()
        };
        // Имитация crash между записью строки и floor: floor отстал.
        let stale = Floor {
            entries: 1,
            head: head_after_two,
            at_unix_ms: 0,
        };
        std::fs::write(&floor_path, serde_json::to_vec(&stale).unwrap()).unwrap();
        {
            let (mut log, replayed) = EvidenceLog::open(&dir).unwrap();
            assert_eq!(replayed.entries, 2, "отставание floor — не потеря");
            let floor: Floor =
                serde_json::from_str(&std::fs::read_to_string(&floor_path).unwrap()).unwrap();
            assert_eq!(floor.entries, 2);
            log.append("finding", json!({"key": "k3"})).unwrap();
        }
        let r = replay(&dir.join("evidence.jsonl")).unwrap();
        assert_eq!(r.entries, 3);
        std::fs::remove_dir_all(&dir).unwrap();
        let _ = std::fs::remove_file(&floor_path);
    }
}
