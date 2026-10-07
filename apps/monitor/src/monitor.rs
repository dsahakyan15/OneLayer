//! Цикл Monitor: source snapshot → finalized chain → детекция → evidence → реакции.
//!
//! Порядок чтения важен: сначала source (одна read-only транзакция), затем
//! chain. Всё, что Builder записал в source как finalized, к моменту чтения
//! chain уже finalized, поэтому состояние chain не старше source.

use crate::chain::{parse_pubkey, verify_chain, ChainReader, ChainView, Trust};
use crate::detect::{detect, DetectInput, Finding, FindingKind};
use crate::evidence::{default_floor_path, now_unix_ms, EvidenceLog};
use crate::fieldmap::CommitKeys;
use crate::policy::{Policy, Reaction};
use crate::securefs::{read_private, SecureReadPolicy, MAX_CONFIG_BYTES, MAX_KEY_BYTES};
use crate::source::SourceReader;
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub registry_id: String,
    pub program_id: String,
    pub config_pda: String,
    pub rpc_url: String,
    /// libpq-подобная строка подключения отдельной read-only роли Monitor.
    pub source_dsn: String,
    /// JSON `{ "idKey": hex32, "fieldKeyMaster": hex32 }`, права 0600.
    pub keys_file: PathBuf,
    pub evidence_dir: PathBuf,
    /// Отдельный файл внешнего floor цепочки evidence (не сам журнал).
    /// По умолчанию `<evidence_dir>.floor.json`.
    #[serde(default)]
    pub evidence_floor_file: Option<PathBuf>,
    #[serde(default = "default_poll")]
    pub poll_interval_ms: u64,
    #[serde(default)]
    pub policy: Policy,
}

fn default_poll() -> u64 {
    5_000
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = read_private(
            path,
            &SecureReadPolicy {
                max_bytes: MAX_CONFIG_BYTES,
                require_owner: true,
                require_private_mode: true,
                what: "monitor config",
            },
        )?;
        let text = String::from_utf8(bytes)
            .map_err(|_| format!("config {}: not UTF-8", path.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("config {}: {e}", path.display()))
    }

    pub fn trust(&self) -> Result<Trust, String> {
        Trust::new(
            &self.registry_id,
            parse_pubkey(&self.program_id)?,
            parse_pubkey(&self.config_pda)?,
        )
    }

    pub fn floor_path(&self) -> PathBuf {
        self.evidence_floor_file
            .clone()
            .unwrap_or_else(|| default_floor_path(&self.evidence_dir))
    }
}

pub fn load_keys(path: &Path) -> Result<CommitKeys, String> {
    let bytes = read_private(
        path,
        &SecureReadPolicy {
            max_bytes: MAX_KEY_BYTES,
            require_owner: true,
            require_private_mode: true,
            what: "monitor keys",
        },
    )?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| format!("keys: {e}"))?;
    let key = |name: &str| -> Result<[u8; 32], String> {
        let bytes = hex::decode(v[name].as_str().ok_or(format!("keys: {name} missing"))?)
            .map_err(|_| format!("keys: {name} is not hex"))?;
        bytes
            .try_into()
            .map_err(|_| format!("keys: {name} must be 32 bytes"))
    };
    Ok(CommitKeys {
        id_key: key("idKey")?,
        field_key_master: key("fieldKeyMaster")?,
    })
}

#[derive(Debug, Default, Clone)]
pub struct CycleReport {
    pub new_findings: Vec<Finding>,
    pub active: usize,
    pub cleared: usize,
    pub verified_batches: u64,
    pub chain_slot: Option<u64>,
    pub duration_ms: i64,
}

pub struct Monitor<C: ChainReader, S: SourceReader> {
    trust: Trust,
    keys: CommitKeys,
    policy: Policy,
    chain: C,
    source: S,
    log: EvidenceLog,
    alerts_path: PathBuf,
    baseline: crate::detect::Baseline,
    active: BTreeSet<String>,
    /// key → первый момент наблюдения, пока finding в grace-периоде (в памяти).
    pending: BTreeMap<String, i64>,
}

impl<C: ChainReader, S: SourceReader> Monitor<C, S> {
    pub fn new(
        trust: Trust,
        keys: CommitKeys,
        policy: Policy,
        chain: C,
        source: S,
        evidence_dir: &Path,
        floor_path: &Path,
    ) -> Result<Self, String> {
        let (mut log, replayed) = EvidenceLog::open_with_floor(evidence_dir, floor_path)?;
        log.append(
            "monitor_start",
            json!({
                "registryId": trust.registry_id,
                "programId": crate::chain::b58(&trust.program_id),
                "configPda": crate::chain::b58(&trust.config_pda),
                "replayedEntries": replayed.entries,
                "monitorVersion": env!("CARGO_PKG_VERSION"),
            }),
        )?;
        Ok(Self {
            trust,
            keys,
            policy,
            chain,
            source,
            alerts_path: evidence_dir.join("alerts.jsonl"),
            log,
            baseline: replayed.baseline,
            active: replayed.active,
            pending: BTreeMap::new(),
        })
    }

    pub fn evidence_path(&self) -> &Path {
        self.log.path()
    }

    pub fn cycle(&mut self) -> Result<CycleReport, String> {
        let started = now_unix_ms();
        let now = started / 1000;
        let registry = self.trust.registry_id.clone();
        let source = match self.source.snapshot(&registry) {
            Ok(s) => s,
            Err(e) => return self.blind(started, format!("source unavailable: {e}")),
        };
        let chain_view: Result<ChainView, String> = self
            .chain
            .read(&self.trust.program_id, &self.trust.config_pda)
            .map_err(|e| format!("RPC: {e}"))
            .and_then(|raw| verify_chain(&self.trust, &raw));
        let detection = detect(&DetectInput {
            registry_id: &registry,
            keys: &self.keys,
            chain: chain_view.as_ref().map_err(|e| e.clone()),
            source: &source,
            baseline: &self.baseline,
            now_unix: now,
            backlog_threshold_secs: self.policy.backlog_threshold_secs,
        });

        // Собственные наблюдения фиксируются до findings: baseline — только
        // листья, совпавшие с finalized root.
        for (seq, leaves) in &detection.new_batches {
            self.log.baseline_batch(*seq, leaves)?;
            self.baseline.batches.insert(*seq, leaves.clone());
        }
        if !detection.new_observations.is_empty() || !detection.new_events_seen.is_empty() {
            self.log.append(
                "observations",
                json!({"versions": detection.new_observations, "events": detection.new_events_seen}),
            )?;
            self.baseline
                .observed
                .extend(detection.new_observations.iter().cloned());
            self.baseline
                .events_first_seen
                .extend(detection.new_events_seen.iter().cloned());
        }

        let mut report = CycleReport {
            verified_batches: detection.verified_batches,
            chain_slot: chain_view.as_ref().ok().map(|c| c.slot),
            ..Default::default()
        };
        let mut seen_now = BTreeSet::new();
        let mut by_key: BTreeMap<String, Finding> = BTreeMap::new();
        for f in detection.findings {
            by_key.entry(f.key()).or_insert(f);
        }
        for (key, finding) in by_key {
            seen_now.insert(key.clone());
            if self.active.contains(&key) {
                continue;
            }
            let first = *self.pending.entry(key.clone()).or_insert(now);
            if now - first < self.policy.grace_for(finding.kind) {
                continue;
            }
            self.pending.remove(&key);
            self.emit(&key, &finding)?;
            self.active.insert(key);
            report.new_findings.push(finding);
        }
        self.pending.retain(|k, _| seen_now.contains(k));
        let cleared: Vec<String> = self
            .active
            .iter()
            .filter(|k| !seen_now.contains(*k))
            .cloned()
            .collect();
        for key in &cleared {
            // Не «исправление»: finding больше не наблюдается; история и предложения остаются.
            self.log.append("finding_cleared", json!({"key": key}))?;
            self.active.remove(key);
        }
        report.cleared = cleared.len();
        report.active = self.active.len();
        report.duration_ms = now_unix_ms() - started;
        self.log.append(
            "cycle",
            json!({
                "chainSlot": report.chain_slot,
                "chainError": chain_view.as_ref().err(),
                "versions": detection.versions,
                "verifiedBatches": report.verified_batches,
                "newFindings": report.new_findings.len(),
                "active": report.active,
                "cleared": report.cleared,
                "durationMs": report.duration_ms,
            }),
        )?;
        Ok(report)
    }

    fn blind(&mut self, started: i64, reason: String) -> Result<CycleReport, String> {
        let finding = Finding {
            kind: FindingKind::MonitorBlind,
            registry_id: self.trust.registry_id.clone(),
            batch_range: None,
            cursor_range: None,
            records: vec![],
            records_total: 0,
            expected: None,
            actual: None,
            reference: "MONITOR".into(),
            detail: reason,
        };
        let key = finding.key();
        let mut report = CycleReport::default();
        if !self.active.contains(&key) {
            self.emit(&key, &finding)?;
            self.active.insert(key);
            report.new_findings.push(finding);
        }
        report.active = self.active.len();
        report.duration_ms = now_unix_ms() - started;
        Ok(report)
    }

    fn emit(&mut self, key: &str, finding: &Finding) -> Result<(), String> {
        let entry = self.log.append(
            "finding",
            json!({"key": key, "finding": finding, "detectedAtUnixMs": now_unix_ms()}),
        )?;
        let evidence_hash = entry.hash.clone().unwrap_or_default();
        for reaction in self.policy.reactions_for(finding.kind).to_vec() {
            match reaction {
                Reaction::Alert => {
                    let alert = json!({
                        "kind": finding.kind, "registryId": finding.registry_id, "batchRange": finding.batch_range,
                        "cursorRange": finding.cursor_range, "records": finding.records, "recordsTotal": finding.records_total,
                        "expected": finding.expected, "actual": finding.actual, "reference": finding.reference,
                        "detail": finding.detail, "evidenceSeq": entry.seq, "evidenceHash": evidence_hash,
                    });
                    self.log.append("alert", alert.clone())?;
                    let mut f = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .mode(0o600)
                        .open(&self.alerts_path)
                        .map_err(|e| format!("alerts: {e}"))?;
                    writeln!(f, "{alert}").map_err(|e| format!("alerts: {e}"))?;
                    eprintln!("ALERT {alert}");
                }
                Reaction::ProposeIncident => match finding.batch_range {
                    Some([first, last]) => {
                        self.log.append(
                            "incident_proposal",
                            json!({
                                "registryId": finding.registry_id, "firstSuspectBatch": first, "lastSuspectBatch": last,
                                "findingKind": finding.kind, "evidenceHash": evidence_hash, "evidenceSeq": entry.seq,
                                "records": finding.records,
                                "note": "proposal only: open_incident requires an authorized governance signer",
                            }),
                        )?;
                    }
                    None => {
                        self.log.append(
                            "incident_proposal_skipped",
                            json!({"evidenceSeq": entry.seq, "reason": "finding is not scoped to a finalized batch range"}),
                        )?;
                    }
                },
                Reaction::RequestIssuanceHold => {
                    self.log.append(
                        "hold_request",
                        json!({
                            "registryId": finding.registry_id, "batchRange": finding.batch_range, "records": finding.records,
                            "evidenceSeq": entry.seq, "evidenceHash": evidence_hash,
                        }),
                    )?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "onelayer-monitor-cfg-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(path: &Path, mode: u32, text: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
        drop(f);
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    const KEYS: &str = r#"{"idKey":"1111111111111111111111111111111111111111111111111111111111111111","fieldKeyMaster":"2222222222222222222222222222222222222222222222222222222222222222"}"#;

    #[test]
    fn config_and_keys_require_private_regular_files() {
        let dir = tmp("modes");
        let keys = dir.join("keys.json");
        write(&keys, 0o600, KEYS);
        assert!(load_keys(&keys).is_ok());
        write(&keys, 0o640, KEYS);
        assert!(load_keys(&keys).unwrap_err().contains("group/other"));
        write(&keys, 0o644, KEYS);
        assert!(load_keys(&keys).unwrap_err().contains("group/other"));
        std::fs::remove_file(&keys).unwrap();
        assert!(load_keys(&keys).is_err());

        let config = dir.join("monitor.json");
        let body = format!(
            r#"{{"registryId":"r","programId":"6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo","configPda":"{}","rpcUrl":"http://127.0.0.1:1","sourceDsn":"postgresql://x","keysFile":"{}","evidenceDir":"{}"}}"#,
            crate::chain::b58(&crate::chain::config_pda(
                "r",
                &parse_pubkey("6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo").unwrap()
            )),
            keys.display(),
            dir.display()
        );
        write(&config, 0o644, &body);
        assert!(Config::load(&config).unwrap_err().contains("group/other"));
        write(&config, 0o600, &body);
        let loaded = Config::load(&config).unwrap();
        assert_eq!(
            loaded.floor_path(),
            PathBuf::from(format!("{}.floor.json", dir.display()))
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
