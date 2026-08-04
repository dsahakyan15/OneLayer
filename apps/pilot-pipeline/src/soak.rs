//! Gate C exit evidence (§5 «Выход Gate C»).
//!
//! The 72-hour synthetic run produces one JSON line per publish cycle. This
//! module owns the invariants that decide whether the run passed, so the verdict
//! is computed from recorded evidence rather than asserted by the operator:
//!
//! * `anchor_sequence_gap_total = 0` — every published batch sequence follows
//!   the previous one, and the anchor chain links to the previous anchor hash;
//! * rebuilding one range yields an identical `manifestHash`;
//! * the event-backed incident index keeps its watermark above the anchor slot
//!   and reflects open and resolved incidents;
//! * no cycle needed manual intervention.
//!
//! A run that is merely short is `Incomplete`, not `Passed`: the duration is a
//! criterion, not a formality.

use serde::{Deserialize, Serialize};

/// Minimum wall-clock coverage required by the Gate C exit criterion.
pub const REQUIRED_RUN_SECONDS: u64 = 72 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleRecord {
    pub cycle: u64,
    /// Unix seconds when the anchor reached `finalized`.
    pub finalized_at: u64,
    pub batch_sequence: u64,
    pub previous_anchor_hash: String,
    pub anchor_hash: String,
    pub manifest_hash: String,
    /// `manifestHash` of an independent rebuild of the same source range.
    pub rebuilt_manifest_hash: String,
    /// Cursor range used by the original and rebuilt batches. Missing values
    /// are reported as a non-reproducible range rather than accepted silently.
    #[serde(default)]
    pub source_cursor_start: Option<u64>,
    #[serde(default)]
    pub source_cursor_end: Option<u64>,
    #[serde(default)]
    pub rebuilt_source_cursor_start: Option<u64>,
    #[serde(default)]
    pub rebuilt_source_cursor_end: Option<u64>,
    pub merkle_root: String,
    pub anchor_slot: u64,
    /// Watermark reported by the incident index at the end of the cycle.
    pub indexed_through_slot: u64,
    /// Incident sequences the index reported as currently open.
    #[serde(default)]
    pub open_incidents: Vec<u64>,
    /// Incident sequences the index reported as resolved.
    #[serde(default)]
    pub resolved_incidents: Vec<u64>,
    /// Result of the incident-index freshness check for this cycle. The field
    /// remains optional only so malformed/legacy JSONL can be parsed and
    /// reported as a finding rather than being treated as a clean check.
    #[serde(default)]
    pub incident_index_status: Option<String>,
    /// Set by the runner when a cycle needed a human to continue.
    #[serde(default)]
    pub manual_intervention: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Finding {
    SequenceGap {
        expected: u64,
        observed: u64,
    },
    ChainBreak {
        batch_sequence: u64,
    },
    ManifestNotReproducible {
        batch_sequence: u64,
    },
    SourceRangeNotReproducible {
        batch_sequence: u64,
    },
    IndexBehindAnchor {
        batch_sequence: u64,
        anchor_slot: u64,
        indexed_through_slot: u64,
    },
    IndexWatermarkRegressed {
        batch_sequence: u64,
        previous: u64,
        observed: u64,
    },
    IncidentIndexNotChecked {
        batch_sequence: u64,
        status: String,
    },
    ManualIntervention {
        cycle: u64,
    },
    TimeWentBackwards {
        cycle: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// Every invariant held and the run covered the required duration.
    Passed,
    /// No invariant was violated, but the run is shorter than required.
    Incomplete {
        observed_seconds: u64,
    },
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoakReport {
    pub cycles: u64,
    pub observed_seconds: u64,
    pub anchor_sequence_gap_total: u64,
    pub manifest_rebuild_checks: u64,
    pub manifest_rebuild_mismatch_total: u64,
    pub source_range_checks: u64,
    pub source_range_mismatch_total: u64,
    pub incident_index_not_checked_total: u64,
    pub incident_open_events: u64,
    pub incident_resolve_events: u64,
    pub findings: Vec<Finding>,
    pub verdict: Verdict,
}

#[derive(Debug, Default)]
pub struct SoakLedger {
    first_finalized_at: Option<u64>,
    last_finalized_at: u64,
    previous: Option<CycleRecord>,
    highest_watermark: u64,
    cycles: u64,
    gaps: u64,
    manifest_mismatches: u64,
    source_range_mismatches: u64,
    incident_index_failures: u64,
    open_incidents: std::collections::BTreeSet<u64>,
    resolved_incidents: std::collections::BTreeSet<u64>,
    findings: Vec<Finding>,
}

impl SoakLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one cycle and appends any invariant violation it introduced.
    pub fn observe(&mut self, record: &CycleRecord) {
        self.cycles += 1;
        if self.first_finalized_at.is_none() {
            self.first_finalized_at = Some(record.finalized_at);
        }
        if record.finalized_at < self.last_finalized_at {
            self.findings.push(Finding::TimeWentBackwards {
                cycle: record.cycle,
            });
        }
        self.last_finalized_at = self.last_finalized_at.max(record.finalized_at);

        if let Some(previous) = &self.previous {
            let expected = previous.batch_sequence + 1;
            if record.batch_sequence != expected {
                self.gaps += 1;
                self.findings.push(Finding::SequenceGap {
                    expected,
                    observed: record.batch_sequence,
                });
            }
            // The chain claim is only meaningful when the sequence is contiguous.
            if record.batch_sequence == expected
                && record.previous_anchor_hash != previous.anchor_hash
            {
                self.findings.push(Finding::ChainBreak {
                    batch_sequence: record.batch_sequence,
                });
            }
        }

        if record.manifest_hash != record.rebuilt_manifest_hash {
            self.manifest_mismatches += 1;
            self.findings.push(Finding::ManifestNotReproducible {
                batch_sequence: record.batch_sequence,
            });
        }
        if !matches!(
            (
                record.source_cursor_start,
                record.source_cursor_end,
                record.rebuilt_source_cursor_start,
                record.rebuilt_source_cursor_end,
            ),
            (Some(start), Some(end), Some(rebuilt_start), Some(rebuilt_end))
                if start <= end && start == rebuilt_start && end == rebuilt_end
        ) {
            self.source_range_mismatches += 1;
            self.findings.push(Finding::SourceRangeNotReproducible {
                batch_sequence: record.batch_sequence,
            });
        }

        if record.indexed_through_slot < record.anchor_slot {
            self.findings.push(Finding::IndexBehindAnchor {
                batch_sequence: record.batch_sequence,
                anchor_slot: record.anchor_slot,
                indexed_through_slot: record.indexed_through_slot,
            });
        }
        if record.indexed_through_slot < self.highest_watermark {
            self.findings.push(Finding::IndexWatermarkRegressed {
                batch_sequence: record.batch_sequence,
                previous: self.highest_watermark,
                observed: record.indexed_through_slot,
            });
        }
        self.highest_watermark = self.highest_watermark.max(record.indexed_through_slot);

        if record.incident_index_status.as_deref() != Some("CHECKED") {
            self.incident_index_failures += 1;
            self.findings.push(Finding::IncidentIndexNotChecked {
                batch_sequence: record.batch_sequence,
                status: record
                    .incident_index_status
                    .clone()
                    .unwrap_or_else(|| "MISSING".into()),
            });
        }

        if record.manual_intervention {
            self.findings.push(Finding::ManualIntervention {
                cycle: record.cycle,
            });
        }

        for sequence in &record.open_incidents {
            self.open_incidents.insert(*sequence);
        }
        for sequence in &record.resolved_incidents {
            self.resolved_incidents.insert(*sequence);
        }

        self.previous = Some(record.clone());
    }

    pub fn report(&self) -> SoakReport {
        let observed_seconds = self
            .first_finalized_at
            .map(|first| self.last_finalized_at.saturating_sub(first))
            .unwrap_or_default();
        let verdict = if !self.findings.is_empty() || self.cycles == 0 {
            Verdict::Failed
        } else if observed_seconds < REQUIRED_RUN_SECONDS {
            Verdict::Incomplete { observed_seconds }
        } else {
            Verdict::Passed
        };
        SoakReport {
            cycles: self.cycles,
            observed_seconds,
            anchor_sequence_gap_total: self.gaps,
            manifest_rebuild_checks: self.cycles,
            manifest_rebuild_mismatch_total: self.manifest_mismatches,
            source_range_checks: self.cycles,
            source_range_mismatch_total: self.source_range_mismatches,
            incident_index_not_checked_total: self.incident_index_failures,
            incident_open_events: self.open_incidents.len() as u64,
            incident_resolve_events: self.resolved_incidents.len() as u64,
            findings: self.findings.clone(),
            verdict,
        }
    }
}

/// Parses a JSONL evidence file, skipping blank lines.
pub fn parse_records(input: &str) -> Result<Vec<CycleRecord>, String> {
    input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str::<CycleRecord>(line).map_err(|error| error.to_string()))
        .collect()
}

pub fn evaluate(records: &[CycleRecord]) -> SoakReport {
    let mut ledger = SoakLedger::new();
    for record in records {
        ledger.observe(record);
    }
    ledger.report()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cycle(index: u64, sequence: u64, previous_hash: &str) -> CycleRecord {
        CycleRecord {
            cycle: index,
            // One cycle per hour keeps a 72-hour run at 73 records.
            finalized_at: 1_800_000_000 + index * 3_600,
            batch_sequence: sequence,
            previous_anchor_hash: previous_hash.into(),
            anchor_hash: format!("{sequence:064}"),
            manifest_hash: format!("m{sequence:063}"),
            rebuilt_manifest_hash: format!("m{sequence:063}"),
            source_cursor_start: Some(1),
            source_cursor_end: Some(2),
            rebuilt_source_cursor_start: Some(1),
            rebuilt_source_cursor_end: Some(2),
            merkle_root: format!("r{sequence:063}"),
            anchor_slot: 400_000_000 + index * 1_000,
            indexed_through_slot: 400_000_100 + index * 1_000,
            open_incidents: Vec::new(),
            resolved_incidents: Vec::new(),
            incident_index_status: Some("CHECKED".into()),
            manual_intervention: false,
        }
    }

    fn run(cycles: u64) -> Vec<CycleRecord> {
        let mut records = Vec::new();
        let mut previous = format!("{:064}", 0);
        for index in 0..cycles {
            let record = cycle(index, index + 1, &previous);
            previous = record.anchor_hash.clone();
            records.push(record);
        }
        records
    }

    #[test]
    fn a_clean_seventy_two_hour_run_passes() {
        let report = evaluate(&run(73));
        assert_eq!(report.verdict, Verdict::Passed);
        assert_eq!(report.anchor_sequence_gap_total, 0);
        assert_eq!(report.manifest_rebuild_checks, 73);
        assert_eq!(report.manifest_rebuild_mismatch_total, 0);
        assert_eq!(report.source_range_checks, 73);
        assert_eq!(report.source_range_mismatch_total, 0);
        assert_eq!(report.incident_index_not_checked_total, 0);
        assert!(report.findings.is_empty());
        assert!(report.observed_seconds >= REQUIRED_RUN_SECONDS);
    }

    #[test]
    fn a_short_but_clean_run_is_incomplete_not_passed() {
        let report = evaluate(&run(10));
        assert!(report.findings.is_empty());
        assert!(matches!(report.verdict, Verdict::Incomplete { .. }));
    }

    #[test]
    fn a_skipped_batch_sequence_is_counted_and_fails_the_run() {
        // One batch is skipped and the run continues from the next sequence, so
        // exactly one discontinuity exists.
        let mut records = run(73);
        for record in records.iter_mut().skip(40) {
            record.batch_sequence += 1;
            record.anchor_hash = format!("{:064}", record.batch_sequence);
        }
        for index in 41..records.len() {
            records[index].previous_anchor_hash = records[index - 1].anchor_hash.clone();
        }
        let report = evaluate(&records);
        assert_eq!(report.anchor_sequence_gap_total, 1);
        assert_eq!(report.verdict, Verdict::Failed);
    }

    #[test]
    fn a_broken_anchor_chain_fails_even_with_contiguous_sequences() {
        let mut records = run(73);
        records[20].previous_anchor_hash = "ff".repeat(32);
        let report = evaluate(&records);
        assert_eq!(report.anchor_sequence_gap_total, 0);
        assert!(report
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::ChainBreak { .. })));
    }

    #[test]
    fn a_non_reproducible_rebuild_fails_the_run() {
        let mut records = run(73);
        records[5].rebuilt_manifest_hash = "different".into();
        let report = evaluate(&records);
        assert!(report
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::ManifestNotReproducible { .. })));
        assert_eq!(report.manifest_rebuild_mismatch_total, 1);
        assert_eq!(report.verdict, Verdict::Failed);
    }

    #[test]
    fn a_different_source_range_fails_the_run() {
        let mut records = run(73);
        records[5].rebuilt_source_cursor_end = Some(3);
        let report = evaluate(&records);
        assert!(report.findings.iter().any(|finding| matches!(
            finding,
            Finding::SourceRangeNotReproducible { batch_sequence: 6 }
        )));
        assert_eq!(report.source_range_mismatch_total, 1);
        assert_eq!(report.verdict, Verdict::Failed);
    }

    #[test]
    fn a_missing_source_range_is_not_a_clean_check() {
        let mut records = run(73);
        records[3].source_cursor_start = None;
        let report = evaluate(&records);
        assert!(report.findings.iter().any(|finding| matches!(
            finding,
            Finding::SourceRangeNotReproducible { batch_sequence: 4 }
        )));
        assert_eq!(report.verdict, Verdict::Failed);
    }

    #[test]
    fn an_index_that_has_not_reached_the_anchor_slot_fails_the_run() {
        let mut records = run(73);
        records[9].indexed_through_slot = records[9].anchor_slot - 1;
        let report = evaluate(&records);
        assert!(report
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::IndexBehindAnchor { .. })));
    }

    #[test]
    fn a_regressing_watermark_fails_the_run() {
        let mut records = run(73);
        records[30].indexed_through_slot = records[29].indexed_through_slot - 5;
        records[30].anchor_slot = records[30].indexed_through_slot - 1;
        let report = evaluate(&records);
        assert!(report
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::IndexWatermarkRegressed { .. })));
    }

    #[test]
    fn manual_intervention_fails_an_otherwise_clean_run() {
        let mut records = run(73);
        records[70].manual_intervention = true;
        assert_eq!(evaluate(&records).verdict, Verdict::Failed);
    }

    #[test]
    fn an_explicitly_stale_index_fails_the_run() {
        let mut records = run(73);
        records[24].incident_index_status = Some("STALE".into());
        let report = evaluate(&records);
        assert!(report.findings.iter().any(|finding| matches!(
            finding,
            Finding::IncidentIndexNotChecked { batch_sequence: 25, status } if status == "STALE"
        )));
        assert_eq!(report.verdict, Verdict::Failed);
    }

    #[test]
    fn missing_index_status_is_not_a_clean_check() {
        let mut records = run(73);
        records[3].incident_index_status = None;
        let report = evaluate(&records);
        assert!(report.findings.iter().any(|finding| matches!(
            finding,
            Finding::IncidentIndexNotChecked { batch_sequence: 4, status } if status == "MISSING"
        )));
        assert_eq!(report.verdict, Verdict::Failed);
    }

    #[test]
    fn open_and_resolved_incidents_are_both_counted() {
        let mut records = run(73);
        records[12].open_incidents = vec![0];
        records[13].open_incidents = vec![0];
        records[20].resolved_incidents = vec![0];
        let report = evaluate(&records);
        assert_eq!(report.incident_open_events, 1);
        assert_eq!(report.incident_resolve_events, 1);
        // A recorded incident is evidence that the index works, not a failure.
        assert_eq!(report.verdict, Verdict::Passed);
    }

    #[test]
    fn an_empty_run_never_passes() {
        assert_eq!(evaluate(&[]).verdict, Verdict::Failed);
    }

    #[test]
    fn jsonl_evidence_round_trips() {
        let records = run(3);
        let encoded = records
            .iter()
            .map(|record| serde_json::to_string(record).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let parsed = parse_records(&format!("{encoded}\n\n")).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[2].batch_sequence, records[2].batch_sequence);
        assert!(parse_records("{ not json }").is_err());
    }
}
