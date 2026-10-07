//! Сценарии детектора на синтетическом finalized chain и in-memory source.
//! Без внешних процессов; реальная интеграция — `tests/e2e_validator.rs`.

use crate::chain::tests::{trust, FakeChain};
use crate::chain::{verify_chain, ChainView};
use crate::detect::{detect, Baseline, DetectInput, Detection, FindingKind, RecordRef};
use crate::fieldmap::{batch_root, leaf, workflow_payload_hash, CommitKeys};
use crate::source::{LocalAnchor, MemberRow, OperationRow, OutboxRow, SourceSnapshot, VersionRow};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const REG: &str = "synthetic-detect";
const NOW: i64 = 1_790_000_000;

fn keys() -> CommitKeys {
    CommitKeys {
        id_key: [0x11; 32],
        field_key_master: [0x22; 32],
    }
}

struct World {
    src: SourceSnapshot,
    chain: FakeChain,
    next_event: u32,
}

impl World {
    fn new() -> Self {
        Self {
            src: SourceSnapshot {
                db_now_unix: NOW,
                ..Default::default()
            },
            chain: FakeChain::new(trust(REG)),
            next_event: 0,
        }
    }

    /// Как workflow writer: версия + head + outbox в одной «транзакции».
    fn commit(&mut self, record: &str, payload: Value) -> String {
        let version = self
            .src
            .heads
            .iter()
            .find(|(r, _)| r == record)
            .map(|(_, v)| *v)
            .unwrap_or(0)
            + 1;
        self.src.heads.retain(|(r, _)| r != record);
        self.src.heads.push((record.into(), version));
        let hash = workflow_payload_hash("upsert", &payload).unwrap();
        self.src.versions.push(VersionRow {
            record_id: record.into(),
            version,
            operation: "upsert".into(),
            payload: Some(payload),
            payload_hash: hash.clone(),
        });
        self.next_event += 1;
        let event = format!("00000000-0000-0000-0000-{:012}", self.next_event);
        self.src.outbox.push(OutboxRow {
            event_id: event.clone(),
            record_id: record.into(),
            version,
            payload_hash: hash,
            created_at_unix: NOW - 10,
        });
        event
    }

    /// Как publication worker + программа: membership, intent, anchor row, chain entry.
    fn publish(&mut self, events: &[String]) {
        let seq = self.chain.entries.len() as u64 + 1;
        let op = format!("op-{seq}");
        let mut leaves = Vec::new();
        for (i, e) in events.iter().enumerate() {
            let o = self.src.outbox.iter().find(|o| &o.event_id == e).unwrap();
            let v = self
                .src
                .versions
                .iter()
                .find(|v| v.record_id == o.record_id && v.version == o.version)
                .unwrap();
            leaves.push(
                leaf(
                    &keys(),
                    REG,
                    &v.record_id,
                    v.version as u64,
                    &v.operation,
                    v.payload.as_ref().unwrap(),
                )
                .unwrap(),
            );
            self.src.members.push(MemberRow {
                operation_id: op.clone(),
                ordinal: i as i32,
                event_id: e.clone(),
            });
        }
        let start = self
            .chain
            .entries
            .last()
            .map(|e| e.source_cursor_end + 1)
            .unwrap_or(1);
        let root = batch_root(&leaves).unwrap();
        self.chain.publish(
            root,
            start,
            start + events.len() as u64 - 1,
            events.len() as u32,
        );
        let entry = self.chain.entries.last().unwrap();
        let bytes = format!("intent-{seq}").into_bytes();
        let mut h = Sha256::new();
        h.update(crate::detect::INTENT_DOMAIN);
        h.update(&bytes);
        let intent_hash = hex::encode(h.finalize());
        self.src.operations.push(OperationRow {
            operation_id: op.clone(),
            state: "FINALIZED".into(),
        });
        self.src.intents.push((op.clone(), seq.to_string()));
        self.src.anchors.push(LocalAnchor {
            operation_id: op,
            batch_sequence: seq.to_string(),
            merkle_root: hex::encode(root),
            manifest_hash: hex::encode(entry.manifest_hash),
            anchor_hash: hex::encode(entry.anchor_hash()),
            intent_hash: intent_hash.clone(),
            intent: Some((intent_hash, bytes)),
        });
    }

    fn view(&self) -> ChainView {
        verify_chain(&self.chain.trust, &self.chain.raw()).unwrap()
    }

    fn run(&self, baseline: &Baseline) -> Detection {
        let view = self.view();
        detect(&DetectInput {
            registry_id: REG,
            keys: &keys(),
            chain: Ok(&view),
            source: &self.src,
            baseline,
            now_unix: NOW,
            backlog_threshold_secs: 900,
        })
    }

    fn version_mut(&mut self, record: &str, version: i64) -> &mut VersionRow {
        self.src
            .versions
            .iter_mut()
            .find(|v| v.record_id == record && v.version == version)
            .unwrap()
    }
}

/// Три записи, две публикации; baseline — после первого чистого цикла.
fn published_world() -> (World, Baseline) {
    let mut w = World::new();
    let a = w.commit("parcel-a", json!({"owner": "Synthetic A", "area": 120}));
    let b = w.commit("parcel-b", json!({"owner": "Synthetic B", "tags": ["x"]}));
    w.publish(&[a, b]);
    let a2 = w.commit("parcel-a", json!({"owner": "Synthetic A2", "area": 121}));
    let c = w.commit("parcel-c", json!({"owner": "Synthetic C"}));
    w.publish(&[a2, c]);
    let first = w.run(&Baseline::default());
    assert!(
        first.findings.is_empty(),
        "clean world: {:#?}",
        first.findings
    );
    assert_eq!(first.verified_batches, 2);
    let mut base = Baseline::default();
    base.batches.extend(first.new_batches);
    base.observed.extend(first.new_observations);
    base.events_first_seen.extend(first.new_events_seen);
    (w, base)
}

fn kinds(d: &Detection) -> Vec<FindingKind> {
    let mut k: Vec<FindingKind> = d.findings.iter().map(|f| f.kind).collect();
    k.sort();
    k.dedup();
    k
}

fn find(d: &Detection, kind: FindingKind) -> &crate::detect::Finding {
    d.findings
        .iter()
        .find(|f| f.kind == kind)
        .unwrap_or_else(|| panic!("no {kind:?} in {:#?}", d.findings))
}

fn rec(r: &str, v: i64) -> RecordRef {
    RecordRef {
        record_id: r.into(),
        version: v,
    }
}

#[test]
fn clean_world_has_no_findings_on_repeat() {
    let (w, base) = published_world();
    let d = w.run(&base);
    assert!(d.findings.is_empty(), "{:#?}", d.findings);
    assert!(d.new_batches.is_empty() && d.new_observations.is_empty());
}

#[test]
fn field_change_with_rewritten_payload_hash_is_localized_by_chain() {
    let (mut w, base) = published_world();
    let v = w.version_mut("parcel-b", 1);
    v.payload = Some(json!({"owner": "Mallory", "tags": ["x"]}));
    v.payload_hash = workflow_payload_hash("upsert", v.payload.as_ref().unwrap()).unwrap();
    let hash = v.payload_hash.clone();
    w.src
        .outbox
        .iter_mut()
        .find(|o| o.record_id == "parcel-b")
        .unwrap()
        .payload_hash = hash;
    let d = w.run(&base);
    assert_eq!(
        kinds(&d),
        vec![
            FindingKind::AnchoredRootMismatch,
            FindingKind::ObservedVersionChanged
        ]
    );
    let f = find(&d, FindingKind::AnchoredRootMismatch);
    assert_eq!(f.batch_range, Some([1, 1]));
    assert_eq!(f.records, vec![rec("parcel-b", 1)]);
    assert_eq!(
        f.expected.as_deref(),
        Some(hex::encode(w.chain.entries[0].merkle_root).as_str())
    );
    assert!(f.reference.starts_with("CHAIN_FINALIZED@"));
    assert_eq!(
        find(&d, FindingKind::ObservedVersionChanged).batch_range,
        Some([1, 1])
    );
}

#[test]
fn field_change_without_hash_rewrite_is_also_a_source_invariant_violation() {
    let (mut w, base) = published_world();
    w.version_mut("parcel-c", 1).payload = Some(json!({"owner": "Mallory"}));
    let d = w.run(&base);
    let f = find(&d, FindingKind::SourceFieldChanged);
    assert_eq!(f.records, vec![rec("parcel-c", 1)]);
    assert_eq!(
        find(&d, FindingKind::AnchoredRootMismatch).batch_range,
        Some([2, 2])
    );
}

#[test]
fn version_renumbering_is_detected() {
    let (mut w, base) = published_world();
    w.version_mut("parcel-c", 1).version = 7;
    w.src
        .outbox
        .iter_mut()
        .find(|o| o.record_id == "parcel-c")
        .unwrap()
        .version = 7;
    for h in w.src.heads.iter_mut().filter(|(r, _)| r == "parcel-c") {
        h.1 = 7;
    }
    let d = w.run(&base);
    let k = kinds(&d);
    for expected in [
        FindingKind::AnchoredRootMismatch,
        FindingKind::VersionGap,
        FindingKind::ObservedVersionMissing,
    ] {
        assert!(k.contains(&expected), "{expected:?} in {k:?}");
    }
    let f = find(&d, FindingKind::AnchoredRootMismatch);
    assert_eq!(f.batch_range, Some([2, 2]));
    assert!(f.records.contains(&rec("parcel-c", 1)) && f.records.contains(&rec("parcel-c", 7)));
}

#[test]
fn deleted_published_row_is_detected() {
    let (mut w, base) = published_world();
    w.src
        .versions
        .retain(|v| !(v.record_id == "parcel-a" && v.version == 2));
    w.src
        .outbox
        .retain(|o| !(o.record_id == "parcel-a" && o.version == 2));
    let d = w.run(&base);
    let k = kinds(&d);
    for expected in [
        FindingKind::AnchoredRootMismatch,
        FindingKind::MissingArtifact,
        FindingKind::VersionGap,
        FindingKind::ObservedVersionMissing,
    ] {
        assert!(k.contains(&expected), "{expected:?} in {k:?}");
    }
    assert_eq!(
        find(&d, FindingKind::AnchoredRootMismatch).records,
        vec![rec("parcel-a", 2)]
    );
    // Удаление ещё и membership-строки меняет число листьев.
    w.src
        .members
        .retain(|m| m.event_id != "00000000-0000-0000-0000-000000000003");
    let d = w.run(&base);
    let f = find(&d, FindingKind::MembershipCountMismatch);
    assert_eq!(
        (f.expected.as_deref(), f.actual.as_deref()),
        (Some("2"), Some("1"))
    );
}

#[test]
fn row_added_outside_workflow_is_detected() {
    let (mut w, base) = published_world();
    let payload = json!({"owner": "Injected"});
    w.src.versions.push(VersionRow {
        record_id: "parcel-b".into(),
        version: 2,
        operation: "upsert".into(),
        payload_hash: workflow_payload_hash("upsert", &payload).unwrap(),
        payload: Some(payload),
    });
    let d = w.run(&base);
    assert_eq!(
        find(&d, FindingKind::UnauthorizedVersion).records,
        vec![rec("parcel-b", 2)]
    );
    assert!(
        kinds(&d).contains(&FindingKind::VersionGap),
        "head 1 but version 2 exists"
    );
    // Добавление в опубликованный batch: лишний member.
    w.src.outbox.push(OutboxRow {
        event_id: "extra".into(),
        record_id: "parcel-b".into(),
        version: 2,
        payload_hash: w.src.versions.last().unwrap().payload_hash.clone(),
        created_at_unix: NOW,
    });
    w.src.members.push(MemberRow {
        operation_id: "op-1".into(),
        ordinal: 9,
        event_id: "extra".into(),
    });
    let d = w.run(&base);
    let f = find(&d, FindingKind::AnchoredRootMismatch);
    assert_eq!(
        f.records,
        vec![rec("parcel-b", 2)],
        "localized to the added row"
    );
    assert!(kinds(&d).contains(&FindingKind::MembershipCountMismatch));
}

#[test]
fn rewritten_local_root_is_not_trusted_and_does_not_hide_tampering() {
    let (mut w, base) = published_world();
    w.src.anchors[0].merkle_root = "ab".repeat(32);
    w.src.anchors[0].anchor_hash = "cd".repeat(32);
    let d = w.run(&base);
    assert_eq!(kinds(&d), vec![FindingKind::LocalRootRewritten]);
    let f = find(&d, FindingKind::LocalRootRewritten);
    assert_eq!(f.batch_range, Some([1, 1]));
    assert!(f.detail.contains("merkleRoot") && f.detail.contains("anchorHash"));
    // Подмена данных + согласованная подмена локального root: эталон — chain.
    let v = w.version_mut("parcel-a", 1);
    v.payload = Some(json!({"owner": "Mallory", "area": 120}));
    v.payload_hash = workflow_payload_hash("upsert", v.payload.as_ref().unwrap()).unwrap();
    let h = v.payload_hash.clone();
    w.src
        .outbox
        .iter_mut()
        .find(|o| o.record_id == "parcel-a" && o.version == 1)
        .unwrap()
        .payload_hash = h;
    let d = w.run(&base);
    assert_eq!(
        find(&d, FindingKind::AnchoredRootMismatch).records,
        vec![rec("parcel-a", 1)]
    );
}

#[test]
fn unlocalized_mismatch_without_baseline_names_whole_batch() {
    let (mut w, _) = published_world();
    w.version_mut("parcel-b", 1).payload = Some(json!({"owner": "Mallory", "tags": ["x"]}));
    let d = w.run(&Baseline::default());
    let f = find(&d, FindingKind::AnchoredRootMismatch);
    assert_eq!(f.records, vec![rec("parcel-a", 1), rec("parcel-b", 1)]);
    assert!(f.detail.contains("not localized"));
    assert!(
        d.new_batches.iter().all(|(s, _)| *s != 1),
        "mismatching batch must not become baseline"
    );
}

#[test]
fn cursor_gap_and_foreign_anchor_are_detected() {
    let (mut w, base) = published_world();
    // Неисправный Builder: anchor с пропуском cursor и без локальной записи.
    w.chain.publish([9; 32], 7, 7, 1);
    let d = w.run(&base);
    let gap = find(&d, FindingKind::CursorGap);
    assert_eq!(
        (gap.batch_range, gap.cursor_range),
        (Some([2, 3]), Some([5, 6]))
    );
    let missing = find(&d, FindingKind::MissingArtifact);
    assert_eq!(missing.batch_range, Some([3, 3]));
}

#[test]
fn missing_local_artifacts() {
    let (mut w, base) = published_world();
    w.src.anchors.remove(1);
    let d = w.run(&base);
    // Intent остаётся — это окно завершения Builder или удалённый anchor row.
    assert_eq!(
        find(&d, FindingKind::LocalCompletionMissing).batch_range,
        Some([2, 2])
    );
    assert!(
        kinds(&d).contains(&FindingKind::MissingArtifact),
        "FINALIZED op without anchor row"
    );
    w.src.intents.retain(|(_, s)| s != "2");
    let d = w.run(&base);
    assert!(d
        .findings
        .iter()
        .any(|f| f.kind == FindingKind::MissingArtifact && f.batch_range == Some([2, 2])));
    // Повреждённый intent.
    let (mut w, base) = published_world();
    w.src.anchors[0].intent.as_mut().unwrap().1.push(b'!');
    assert_eq!(
        kinds(&w.run(&base)),
        vec![FindingKind::LocalArtifactTampered]
    );
    w.src.anchors[0].intent = None;
    assert_eq!(kinds(&w.run(&base)), vec![FindingKind::MissingArtifact]);
}

#[test]
fn local_anchor_claiming_unfinalized_batch() {
    let (mut w, base) = published_world();
    let mut fake = w.src.anchors[1].clone();
    fake.operation_id = "op-fake".into();
    fake.batch_sequence = "3".into();
    w.src.anchors.push(fake);
    assert!(kinds(&w.run(&base)).contains(&FindingKind::LocalAnchorNotOnChain));
}

#[test]
fn backlog_uses_threshold_and_monitor_first_seen() {
    let (mut w, mut base) = published_world();
    w.commit("parcel-d", json!({"owner": "Queued"}));
    let d = w.run(&base);
    assert!(d.findings.is_empty(), "age 10s < 900s");
    base.events_first_seen.extend(d.new_events_seen);
    // created_at в БД «свежий», но Monitor видел событие 1000 с назад.
    base.events_first_seen
        .insert("00000000-0000-0000-0000-000000000005".into(), NOW - 1000);
    let d = w.run(&base);
    let f = find(&d, FindingKind::Backlog);
    assert_eq!(f.records, vec![rec("parcel-d", 1)]);
    assert!(f.batch_range.is_none());
}

#[test]
fn source_checks_continue_when_chain_reference_is_invalid() {
    let (mut w, base) = published_world();
    w.version_mut("parcel-a", 1).payload = Some(json!({"owner": "Mallory", "area": 120}));
    let d = detect(&DetectInput {
        registry_id: REG,
        keys: &keys(),
        chain: Err("anchor 1 of 2 missing from ledger segments".into()),
        source: &w.src,
        baseline: &base,
        now_unix: NOW,
        backlog_threshold_secs: 900,
    });
    let k = kinds(&d);
    assert!(k.contains(&FindingKind::ChainReferenceInvalid));
    assert!(k.contains(&FindingKind::SourceFieldChanged));
    assert!(k.contains(&FindingKind::ObservedVersionChanged));
    assert!(
        !k.contains(&FindingKind::Backlog),
        "no backlog verdict without a chain reference"
    );
}

#[test]
fn signed_source_cursor_gap() {
    let (mut w, base) = published_world();
    for c in [1, 2, 4] {
        w.src.source_events.push(crate::source::SourceEventRow {
            source_id: "src".into(),
            cursor: c,
        });
    }
    w.src.source_heads.push(("src".into(), 4));
    let f = w.run(&base);
    assert_eq!(
        find(&f, FindingKind::SourceCursorGap).cursor_range,
        Some([3, 3])
    );
}

#[test]
fn finding_keys_are_stable_across_slots() {
    let (mut w, base) = published_world();
    w.version_mut("parcel-b", 1).payload = Some(json!({"owner": "Mallory", "tags": ["x"]}));
    let a = w.run(&base);
    let mut b = w.run(&base);
    b.findings
        .iter_mut()
        .for_each(|f| f.reference = "CHAIN_FINALIZED@999".into());
    let ka: Vec<String> = a.findings.iter().map(|f| f.key()).collect();
    let kb: Vec<String> = b.findings.iter().map(|f| f.key()).collect();
    assert_eq!(ka, kb);
}
