//! Детектор: чистая функция от (finalized chain view, read-only source
//! snapshot, собственная история наблюдений Monitor).
//!
//! Источник эталона для опубликованных данных — только chain. Локальные
//! roots/anchors/intent из БД сравниваются с chain как проверяемые артефакты,
//! но никогда не служат эталоном. Для ещё не опубликованных версий эталона в
//! chain нет; для них Monitor использует собственные append-only наблюдения
//! (reference `MONITOR_OBSERVATION`) и инварианты source (`SOURCE_INVARIANT`).

use crate::chain::ChainView;
use crate::fieldmap::{batch_root, leaf, workflow_payload_hash, CommitKeys, LeafCommit};
use crate::source::SourceSnapshot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const INTENT_DOMAIN: &[u8] = b"ONELAYER:WORKFLOW:PUBLICATION:INTENT:V1\n";
const MAX_LISTED_RECORDS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingKind {
    /// Payload версии не совпадает с собственным `payload_hash`/outbox.
    SourceFieldChanged,
    /// Пересчитанный root опубликованного batch отличается от finalized anchor.
    AnchoredRootMismatch,
    /// Число версий в membership опубликованного batch ≠ `leaf_count` anchor.
    MembershipCountMismatch,
    /// Версии записи не непрерывны `1..head` или head не совпадает.
    VersionGap,
    /// Версия без outbox-события: появилась в обход workflow.
    UnauthorizedVersion,
    /// Ранее наблюдённая Monitor-ом версия изменилась.
    ObservedVersionChanged,
    /// Ранее наблюдённая Monitor-ом версия исчезла.
    ObservedVersionMissing,
    /// Локальный root/manifest/anchor hash ≠ finalized chain.
    LocalRootRewritten,
    /// Локальный intent повреждён (hash ≠ bytes) или не согласован с anchor row.
    LocalArtifactTampered,
    /// Finalized anchor совпадает с локальным intent, но anchor row не записан.
    LocalCompletionMissing,
    /// Локальная запись утверждает anchor, которого нет в finalized chain.
    LocalAnchorNotOnChain,
    /// Отсутствует обязательный артефакт (anchor row, intent, outbox, version).
    MissingArtifact,
    /// Разрыв/перекрытие `source_cursor` между finalized anchors.
    CursorGap,
    /// Разрыв в signed source cursor (`wf_source_event`).
    SourceCursorGap,
    /// Неопубликованные события старше порога.
    Backlog,
    /// Версию невозможно отобразить в протокольный лист (проверка невозможна).
    UnverifiableVersion,
    /// Эталон из chain несогласован — вывод о целостности невозможен.
    ChainReferenceInvalid,
    /// Monitor не смог прочитать chain или source.
    MonitorBlind,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordRef {
    pub record_id: String,
    pub version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub kind: FindingKind,
    pub registry_id: String,
    /// Затронутый включительный диапазон finalized batch (если известен).
    pub batch_range: Option<[u64; 2]>,
    pub cursor_range: Option<[u64; 2]>,
    pub records: Vec<RecordRef>,
    pub records_total: usize,
    pub expected: Option<String>,
    pub actual: Option<String>,
    /// Откуда эталон: `CHAIN_FINALIZED@<slot>`, `MONITOR_OBSERVATION`, `SOURCE_INVARIANT`, `POLICY`.
    pub reference: String,
    pub detail: String,
}

impl Finding {
    /// Стабильная идентичность для дедупликации между циклами (без slot/возраста).
    pub fn key(&self) -> String {
        let material = if self.kind == FindingKind::Backlog {
            serde_json::json!([self.kind, self.registry_id, self.actual])
        } else {
            serde_json::json!([
                self.kind,
                self.registry_id,
                self.batch_range,
                self.cursor_range,
                self.records,
                self.expected,
                self.actual
            ])
        };
        hex::encode(Sha256::digest(material.to_string().as_bytes()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Observed {
    pub fingerprint: String,
    pub first_seen_unix: i64,
}

/// Собственная история Monitor (восстанавливается из evidence log).
#[derive(Debug, Clone, Default)]
pub struct Baseline {
    /// batch → (record, version) → leaf hash; фиксируется только после совпадения root с chain.
    pub batches: BTreeMap<u64, BTreeMap<RecordRef, String>>,
    pub observed: BTreeMap<RecordRef, Observed>,
    pub events_first_seen: BTreeMap<String, i64>,
}

#[derive(Debug, Default)]
pub struct Detection {
    pub findings: Vec<Finding>,
    pub new_batches: Vec<(u64, BTreeMap<RecordRef, String>)>,
    pub new_observations: Vec<(RecordRef, Observed)>,
    pub new_events_seen: Vec<(String, i64)>,
    /// Статистика цикла для evidence (`cycle`).
    pub verified_batches: u64,
    pub versions: usize,
}

pub struct DetectInput<'a> {
    pub registry_id: &'a str,
    pub keys: &'a CommitKeys,
    /// `Err(reason)`: эталон недоступен/несогласован; проверки source всё равно выполняются.
    pub chain: Result<&'a ChainView, String>,
    pub source: &'a SourceSnapshot,
    pub baseline: &'a Baseline,
    pub now_unix: i64,
    pub backlog_threshold_secs: i64,
}

fn rr(record_id: &str, version: i64) -> RecordRef {
    RecordRef {
        record_id: record_id.to_string(),
        version,
    }
}

struct Builder<'a> {
    registry_id: &'a str,
    out: Vec<Finding>,
}

impl Builder<'_> {
    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        kind: FindingKind,
        batch_range: Option<[u64; 2]>,
        cursor_range: Option<[u64; 2]>,
        mut records: Vec<RecordRef>,
        expected: Option<String>,
        actual: Option<String>,
        reference: &str,
        detail: String,
    ) {
        records.sort();
        records.dedup();
        let total = records.len();
        records.truncate(MAX_LISTED_RECORDS);
        self.out.push(Finding {
            kind,
            registry_id: self.registry_id.to_string(),
            batch_range,
            cursor_range,
            records,
            records_total: total,
            expected,
            actual,
            reference: reference.to_string(),
            detail,
        });
    }
}

fn fingerprint(
    leaf: &Result<LeafCommit, String>,
    operation: &str,
    payload: Option<&serde_json::Value>,
) -> String {
    match leaf {
        Ok(l) => hex::encode(l.leaf_hash),
        Err(_) => {
            let text = format!(
                "{operation}\n{}",
                payload.map(|p| p.to_string()).unwrap_or_default()
            );
            format!("raw:{}", hex::encode(Sha256::digest(text.as_bytes())))
        }
    }
}

pub fn detect(input: &DetectInput) -> Detection {
    let src = input.source;
    let base = input.baseline;
    let mut b = Builder {
        registry_id: input.registry_id,
        out: Vec::new(),
    };
    let mut det = Detection {
        versions: src.versions.len(),
        ..Default::default()
    };

    // --- 1. Каждая версия: пересчёт листа и payload hash (независимо от Builder).
    let mut leaves: BTreeMap<RecordRef, Result<LeafCommit, String>> = BTreeMap::new();
    let mut versions_by_record: BTreeMap<&str, Vec<i64>> = BTreeMap::new();
    let outbox_by_version: BTreeMap<RecordRef, &crate::source::OutboxRow> = src
        .outbox
        .iter()
        .map(|o| (rr(&o.record_id, o.version), o))
        .collect();
    for v in &src.versions {
        let key = rr(&v.record_id, v.version);
        versions_by_record
            .entry(&v.record_id)
            .or_default()
            .push(v.version);
        let computed = match &v.payload {
            None => Err("payload is not JSON".to_string()),
            Some(p) => {
                if v.version < 1 {
                    Err("non-positive version".to_string())
                } else {
                    leaf(
                        input.keys,
                        input.registry_id,
                        &v.record_id,
                        v.version as u64,
                        &v.operation,
                        p,
                    )
                    .map_err(|e| e.to_string())
                }
            }
        };
        if let Err(reason) = &computed {
            b.push(
                FindingKind::UnverifiableVersion,
                None,
                None,
                vec![key.clone()],
                None,
                None,
                "SOURCE_INVARIANT",
                reason.clone(),
            );
        }
        if let Some(p) = &v.payload {
            match workflow_payload_hash(&v.operation, p) {
                Ok(h) if h != v.payload_hash => b.push(
                    FindingKind::SourceFieldChanged,
                    None,
                    None,
                    vec![key.clone()],
                    Some(v.payload_hash.clone()),
                    Some(h),
                    "SOURCE_INVARIANT",
                    "recomputed payload hash differs from the version's committed payload_hash"
                        .into(),
                ),
                _ => {}
            }
        }
        match outbox_by_version.get(&key) {
            None => b.push(
                FindingKind::UnauthorizedVersion,
                None,
                None,
                vec![key.clone()],
                Some("outbox event committed with the version".into()),
                None,
                "SOURCE_INVARIANT",
                "version row has no workflow outbox event (written outside the approved workflow)"
                    .into(),
            ),
            Some(o) if o.payload_hash != v.payload_hash => b.push(
                FindingKind::SourceFieldChanged,
                None,
                None,
                vec![key.clone()],
                Some(o.payload_hash.clone()),
                Some(v.payload_hash.clone()),
                "SOURCE_INVARIANT",
                "outbox payload_hash differs from version payload_hash".into(),
            ),
            _ => {}
        }
        leaves.insert(key, computed);
    }

    // --- 2. Непрерывность версий и head.
    let heads: BTreeMap<&str, i64> = src.heads.iter().map(|(r, v)| (r.as_str(), *v)).collect();
    let mut all_records: BTreeSet<&str> = heads.keys().copied().collect();
    all_records.extend(versions_by_record.keys().copied());
    for record in all_records {
        let mut present = versions_by_record.get(record).cloned().unwrap_or_default();
        present.sort_unstable();
        let head = heads.get(record).copied();
        let max = present.last().copied().unwrap_or(0);
        let expected_n = head.unwrap_or(max).max(max);
        let missing: Vec<i64> = (1..=expected_n)
            .filter(|v| present.binary_search(v).is_err())
            .collect();
        if !missing.is_empty() || head != Some(max) {
            b.push(
                FindingKind::VersionGap,
                None,
                None,
                missing.iter().map(|v| rr(record, *v)).collect(),
                Some(format!(
                    "versions 1..{} with head {}",
                    head.unwrap_or(0),
                    head.unwrap_or(0)
                )),
                Some(format!("present {present:?}, head {head:?}")),
                "SOURCE_INVARIANT",
                format!("record {record}: versions are not contiguous or head differs"),
            );
        }
    }
    let version_keys: BTreeSet<RecordRef> = leaves.keys().cloned().collect();
    for o in &src.outbox {
        if !version_keys.contains(&rr(&o.record_id, o.version)) {
            b.push(
                FindingKind::MissingArtifact,
                None,
                None,
                vec![rr(&o.record_id, o.version)],
                Some("wf_version row".into()),
                None,
                "SOURCE_INVARIANT",
                format!("outbox event {} has no version row", o.event_id),
            );
        }
    }

    // --- 3. Chain: эталон опубликованных batch.
    let outbox_by_event: BTreeMap<&str, &crate::source::OutboxRow> = src
        .outbox
        .iter()
        .map(|o| (o.event_id.as_str(), o))
        .collect();
    let mut members: BTreeMap<&str, Vec<&crate::source::MemberRow>> = BTreeMap::new();
    for m in &src.members {
        members.entry(m.operation_id.as_str()).or_default().push(m);
    }
    for list in members.values_mut() {
        list.sort_by_key(|m| m.ordinal);
    }
    let op_state: BTreeMap<&str, &str> = src
        .operations
        .iter()
        .map(|o| (o.operation_id.as_str(), o.state.as_str()))
        .collect();
    let mut anchors_by_seq: BTreeMap<u64, &crate::source::LocalAnchor> = BTreeMap::new();
    let mut anchored_ops: BTreeSet<&str> = BTreeSet::new();
    for a in &src.anchors {
        anchored_ops.insert(a.operation_id.as_str());
        match a.batch_sequence.parse::<u64>() {
            Ok(seq) => {
                anchors_by_seq.insert(seq, a);
            }
            Err(_) => b.push(
                FindingKind::LocalArtifactTampered,
                None,
                None,
                vec![],
                None,
                Some(a.batch_sequence.clone()),
                "SOURCE_INVARIANT",
                format!(
                    "anchor row of operation {} has an invalid batch_sequence",
                    a.operation_id
                ),
            ),
        }
        match &a.intent {
            None => b.push(
                FindingKind::MissingArtifact,
                a.batch_sequence.parse().ok().map(|s| [s, s]),
                None,
                vec![],
                Some("wf_publication_intent row".into()),
                None,
                "SOURCE_INVARIANT",
                format!(
                    "publication intent of operation {} is missing",
                    a.operation_id
                ),
            ),
            Some((stored, bytes)) => {
                let mut h = Sha256::new();
                h.update(INTENT_DOMAIN);
                h.update(bytes);
                let actual = hex::encode(h.finalize());
                if &actual != stored || stored != &a.intent_hash {
                    b.push(
                        FindingKind::LocalArtifactTampered,
                        a.batch_sequence.parse().ok().map(|s| [s, s]),
                        None,
                        vec![],
                        Some(a.intent_hash.clone()),
                        Some(actual),
                        "SOURCE_INVARIANT",
                        format!(
                            "intent bytes/hash of operation {} are inconsistent",
                            a.operation_id
                        ),
                    );
                }
            }
        }
    }
    for o in &src.operations {
        if o.state == "FINALIZED" && !anchored_ops.contains(o.operation_id.as_str()) {
            b.push(
                FindingKind::MissingArtifact,
                None,
                None,
                vec![],
                Some("wf_publication_anchor row".into()),
                None,
                "SOURCE_INVARIANT",
                format!(
                    "operation {} is FINALIZED without an anchor row",
                    o.operation_id
                ),
            );
        }
    }

    let mut intents_by_seq: BTreeMap<u64, &str> = BTreeMap::new();
    for (op, seq) in &src.intents {
        if op_state.get(op.as_str()) != Some(&"ABANDONED") {
            if let Ok(seq) = seq.parse::<u64>() {
                intents_by_seq.insert(seq, op.as_str());
            }
        }
    }
    let mut published_events: BTreeSet<&str> = BTreeSet::new();
    let mut version_batch: BTreeMap<RecordRef, u64> = BTreeMap::new();
    match &input.chain {
        Err(reason) => b.push(
            FindingKind::ChainReferenceInvalid,
            None,
            None,
            vec![],
            Some("verified finalized anchor chain".into()),
            None,
            "CHAIN_FINALIZED",
            reason.clone(),
        ),
        Ok(chain) => {
            let reference = format!("CHAIN_FINALIZED@{}", chain.slot);
            let mut expected_start = 1u64;
            for e in &chain.entries {
                let f = &e.fields;
                let seq = f.batch_sequence;
                // Непрерывность source cursor (anchor-chain-v1 §3: проверяет Monitor, не программа).
                let span_ok = f.source_cursor_end >= f.source_cursor_start
                    && f.source_cursor_end - f.source_cursor_start + 1 == u64::from(f.leaf_count);
                if f.source_cursor_start != expected_start || !span_ok {
                    let range = if f.source_cursor_start > expected_start {
                        Some([expected_start, f.source_cursor_start - 1])
                    } else {
                        Some([f.source_cursor_start, f.source_cursor_end])
                    };
                    b.push(
                        FindingKind::CursorGap,
                        Some([seq.saturating_sub(1).max(1), seq]),
                        range,
                        vec![],
                        Some(format!(
                            "cursor start {expected_start}, span = leafCount {}",
                            f.leaf_count
                        )),
                        Some(format!(
                            "cursor {}..{}",
                            f.source_cursor_start, f.source_cursor_end
                        )),
                        &reference,
                        format!("finalized anchor {seq} does not continue the source cursor"),
                    );
                }
                expected_start = f.source_cursor_end.saturating_add(1);

                // Какая локальная операция соответствует anchor: anchor row, иначе intent
                // (окно между finalization и записью anchor row у Builder).
                let local = anchors_by_seq.get(&seq);
                let op_id = local
                    .map(|a| a.operation_id.as_str())
                    .or_else(|| intents_by_seq.get(&seq).copied());
                let Some(op_id) = op_id else {
                    b.push(
                        FindingKind::MissingArtifact,
                        Some([seq, seq]),
                        Some([f.source_cursor_start, f.source_cursor_end]),
                        vec![],
                        Some(hex::encode(f.merkle_root)),
                        None,
                        &reference,
                        format!("finalized anchor {seq} has no local publication record (foreign anchor or deleted evidence)"),
                    );
                    continue;
                };
                let Some(a) = local else {
                    b.push(
                        FindingKind::LocalCompletionMissing,
                        Some([seq, seq]),
                        None,
                        vec![],
                        Some("wf_publication_anchor row".into()),
                        None,
                        &reference,
                        format!("finalized anchor {seq} matches intent of operation {op_id}, but no local anchor row exists"),
                    );
                    verify_membership(
                        &mut b,
                        &mut det,
                        &members,
                        &outbox_by_event,
                        &leaves,
                        base,
                        e,
                        op_id,
                        &reference,
                        &mut published_events,
                        &mut version_batch,
                    );
                    continue;
                };
                let chain_values = [
                    ("merkleRoot", hex::encode(f.merkle_root), &a.merkle_root),
                    (
                        "manifestHash",
                        hex::encode(f.manifest_hash),
                        &a.manifest_hash,
                    ),
                    ("anchorHash", hex::encode(e.anchor_hash), &a.anchor_hash),
                ];
                let differing: Vec<&str> = chain_values
                    .iter()
                    .filter(|(_, c, l)| c != *l)
                    .map(|(n, _, _)| *n)
                    .collect();
                if !differing.is_empty() {
                    b.push(
                        FindingKind::LocalRootRewritten,
                        Some([seq, seq]),
                        None,
                        vec![],
                        Some(
                            chain_values
                                .iter()
                                .map(|(n, c, _)| format!("{n}={c}"))
                                .collect::<Vec<_>>()
                                .join(","),
                        ),
                        Some(
                            chain_values
                                .iter()
                                .map(|(n, _, l)| format!("{n}={l}"))
                                .collect::<Vec<_>>()
                                .join(","),
                        ),
                        &reference,
                        format!(
                            "local anchor record of batch {seq} differs from finalized chain in {}",
                            differing.join(",")
                        ),
                    );
                }
                if op_state.get(op_id) != Some(&"FINALIZED")
                    && op_state.get(op_id) != Some(&"LANDED_DISCREPANCY")
                {
                    b.push(
                        FindingKind::LocalArtifactTampered,
                        Some([seq, seq]),
                        None,
                        vec![],
                        Some("FINALIZED".into()),
                        op_state.get(op_id).map(|s| s.to_string()),
                        &reference,
                        format!(
                            "operation {op_id} of finalized anchor {seq} is not FINALIZED locally"
                        ),
                    );
                }

                verify_membership(
                    &mut b,
                    &mut det,
                    &members,
                    &outbox_by_event,
                    &leaves,
                    base,
                    e,
                    op_id,
                    &reference,
                    &mut published_events,
                    &mut version_batch,
                );
            }
            for (seq, a) in &anchors_by_seq {
                if *seq == 0 || *seq > chain.current_batch_sequence {
                    b.push(
                        FindingKind::LocalAnchorNotOnChain,
                        None,
                        None,
                        vec![],
                        Some(format!("finalized anchor <= {}", chain.current_batch_sequence)),
                        Some(format!("batch {seq} root {}", a.merkle_root)),
                        &reference,
                        format!("local anchor record of operation {} claims batch {seq}, absent from finalized chain", a.operation_id),
                    );
                }
            }
        }
    }

    // --- 4. Собственные наблюдения Monitor: изменение/исчезновение версий.
    for v in &src.versions {
        let key = rr(&v.record_id, v.version);
        let fp = fingerprint(
            leaves.get(&key).expect("inserted above"),
            &v.operation,
            v.payload.as_ref(),
        );
        match base.observed.get(&key) {
            Some(prev) if prev.fingerprint != fp => b.push(
                FindingKind::ObservedVersionChanged,
                version_batch.get(&key).map(|s| [*s, *s]),
                None,
                vec![key.clone()],
                Some(prev.fingerprint.clone()),
                Some(fp),
                "MONITOR_OBSERVATION",
                format!(
                    "version content changed after first observation at unix {}",
                    prev.first_seen_unix
                ),
            ),
            Some(_) => {}
            None => det.new_observations.push((
                key,
                Observed {
                    fingerprint: fp,
                    first_seen_unix: input.now_unix,
                },
            )),
        }
    }
    for (key, prev) in &base.observed {
        if !leaves.contains_key(key) {
            let batch = base
                .batches
                .iter()
                .find(|(_, m)| m.contains_key(key))
                .map(|(s, _)| [*s, *s]);
            b.push(
                FindingKind::ObservedVersionMissing,
                batch,
                None,
                vec![key.clone()],
                Some(prev.fingerprint.clone()),
                None,
                "MONITOR_OBSERVATION",
                format!(
                    "version observed at unix {} is gone from source",
                    prev.first_seen_unix
                ),
            );
        }
    }

    // --- 5. Signed source cursor.
    let mut cursors: BTreeMap<&str, Vec<i64>> = BTreeMap::new();
    for e in &src.source_events {
        cursors
            .entry(e.source_id.as_str())
            .or_default()
            .push(e.cursor);
    }
    let source_heads: BTreeMap<&str, i64> = src
        .source_heads
        .iter()
        .map(|(s, c)| (s.as_str(), *c))
        .collect();
    let mut sources: BTreeSet<&str> = cursors.keys().copied().collect();
    sources.extend(source_heads.keys().copied());
    for s in sources {
        let mut list = cursors.get(s).cloned().unwrap_or_default();
        list.sort_unstable();
        let head = source_heads.get(s).copied().unwrap_or(0);
        let top = head.max(list.last().copied().unwrap_or(0));
        let missing: Vec<i64> = (1..=top)
            .filter(|c| list.binary_search(c).is_err())
            .collect();
        if !missing.is_empty() || list.last().copied().unwrap_or(0) != head {
            b.push(
                FindingKind::SourceCursorGap,
                None,
                missing
                    .first()
                    .zip(missing.last())
                    .map(|(a, z)| [*a as u64, *z as u64]),
                vec![],
                Some(format!("cursors 1..{head}")),
                Some(format!("missing {missing:?}, max {:?}", list.last())),
                "SOURCE_INVARIANT",
                format!("signed source {s} cursor history is not contiguous"),
            );
        }
    }

    // --- 6. Backlog: события, не покрытые finalized anchor.
    let mut backlog: Vec<(i64, &crate::source::OutboxRow)> = Vec::new();
    for o in &src.outbox {
        let first_seen = match base.events_first_seen.get(&o.event_id) {
            Some(t) => *t,
            None => {
                det.new_events_seen
                    .push((o.event_id.clone(), input.now_unix));
                input.now_unix
            }
        };
        if published_events.contains(o.event_id.as_str()) {
            continue;
        }
        let age = (src.db_now_unix - o.created_at_unix).max(input.now_unix - first_seen);
        if age > input.backlog_threshold_secs {
            backlog.push((age, o));
        }
    }
    if input.chain.is_ok() && !backlog.is_empty() {
        backlog.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.event_id.cmp(&b.1.event_id)));
        let oldest = backlog[0];
        b.push(
            FindingKind::Backlog,
            None,
            None,
            backlog
                .iter()
                .map(|(_, o)| rr(&o.record_id, o.version))
                .collect(),
            Some(format!(
                "published within {}s",
                input.backlog_threshold_secs
            )),
            Some(oldest.1.event_id.clone()),
            "POLICY",
            format!(
                "{} unpublished events older than threshold; oldest age {}s",
                backlog.len(),
                oldest.0
            ),
        );
    }

    det.findings = b.out;
    det
}

#[allow(clippy::too_many_arguments)]
fn verify_membership<'s>(
    b: &mut Builder,
    det: &mut Detection,
    members: &BTreeMap<&str, Vec<&'s crate::source::MemberRow>>,
    outbox_by_event: &BTreeMap<&str, &crate::source::OutboxRow>,
    leaves: &BTreeMap<RecordRef, Result<LeafCommit, String>>,
    base: &Baseline,
    e: &crate::chain::ChainEntry,
    op_id: &str,
    reference: &str,
    published_events: &mut BTreeSet<&'s str>,
    version_batch: &mut BTreeMap<RecordRef, u64>,
) {
    let f = &e.fields;
    let seq = f.batch_sequence;
    let list = members.get(op_id).cloned().unwrap_or_default();
    let mut current: BTreeMap<RecordRef, String> = BTreeMap::new();
    let mut computed: Vec<LeafCommit> = Vec::new();
    let mut unresolved: Vec<RecordRef> = Vec::new();
    for m in &list {
        published_events.insert(m.event_id.as_str());
        let Some(o) = outbox_by_event.get(m.event_id.as_str()) else {
            b.push(
                FindingKind::MissingArtifact,
                Some([seq, seq]),
                None,
                vec![],
                Some(format!("outbox event {}", m.event_id)),
                None,
                reference,
                format!("member {} of batch {seq} has no outbox event", m.ordinal),
            );
            continue;
        };
        let key = rr(&o.record_id, o.version);
        version_batch.insert(key.clone(), seq);
        match leaves.get(&key) {
            Some(Ok(l)) => {
                current.insert(key, hex::encode(l.leaf_hash));
                computed.push(l.clone());
            }
            Some(Err(_)) => unresolved.push(key),
            None => {
                b.push(
                    FindingKind::MissingArtifact,
                    Some([seq, seq]),
                    None,
                    vec![key.clone()],
                    Some("wf_version row".into()),
                    None,
                    reference,
                    format!("published version of batch {seq} is missing"),
                );
                unresolved.push(key);
            }
        }
    }
    if list.len() != f.leaf_count as usize {
        b.push(
            FindingKind::MembershipCountMismatch,
            Some([seq, seq]),
            Some([f.source_cursor_start, f.source_cursor_end]),
            current
                .keys()
                .cloned()
                .chain(unresolved.iter().cloned())
                .collect(),
            Some(f.leaf_count.to_string()),
            Some(list.len().to_string()),
            reference,
            format!("batch {seq}: membership rows added or removed"),
        );
    }
    let root = if computed.is_empty() {
        None
    } else {
        batch_root(&computed).ok()
    };
    if unresolved.is_empty() && root == Some(f.merkle_root) {
        det.verified_batches += 1;
        if !base.batches.contains_key(&seq) {
            det.new_batches.push((seq, current));
        }
        return;
    }
    // Локализация: сравнение с листьями, ранее сверенными с этим же anchor.
    let (affected, localized) = match base.batches.get(&seq) {
        Some(prior) => {
            let mut diff: Vec<RecordRef> = prior
                .iter()
                .filter(|(k, v)| current.get(*k) != Some(*v))
                .map(|(k, _)| k.clone())
                .collect();
            diff.extend(current.keys().filter(|k| !prior.contains_key(*k)).cloned());
            diff.extend(unresolved.iter().cloned());
            (diff, true)
        }
        None => (
            current
                .keys()
                .cloned()
                .chain(unresolved.iter().cloned())
                .collect(),
            false,
        ),
    };
    b.push(
                    FindingKind::AnchoredRootMismatch,
                    Some([seq, seq]),
                    Some([f.source_cursor_start, f.source_cursor_end]),
                    affected,
                    Some(hex::encode(f.merkle_root)),
                    Some(root.map(hex::encode).unwrap_or_else(|| "uncomputable".into())),
                    reference,
                    if localized {
                        format!("batch {seq}: source no longer reproduces the finalized root; records localized against the monitor's verified leaves")
                    } else {
                        format!("batch {seq}: source no longer reproduces the finalized root; not localized (no prior verified leaves), whole batch affected")
                    },
                );
}
