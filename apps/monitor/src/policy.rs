//! Policy реакций. Monitor только фиксирует evidence и выпускает сигналы;
//! он не имеет прав писать в source или подписывать chain-транзакции.
//! Реакции:
//! * `ALERT` — запись `alert` в evidence + строка в `alerts.jsonl` + stderr;
//! * `PROPOSE_INCIDENT` — `incident_proposal` с affected batch range и
//!   `evidenceHash` (hash записи finding) для governance (`open_incident`
//!   подписывает уполномоченный человек, не Monitor);
//! * `REQUEST_ISSUANCE_HOLD` — `hold_request` со scope для остановки выдачи/очереди.

use crate::detect::FindingKind;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Reaction {
    Alert,
    ProposeIncident,
    RequestIssuanceHold,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Policy {
    pub backlog_threshold_secs: i64,
    /// Реакции по виду finding; отсутствующий вид получает `default_reactions`.
    pub reactions: BTreeMap<FindingKind, Vec<Reaction>>,
    pub default_reactions: Vec<Reaction>,
    /// Finding должен наблюдаться непрерывно столько секунд до выпуска
    /// (защита от гонки Builder ↔ Monitor в окне finalization).
    pub grace_secs: BTreeMap<FindingKind, i64>,
}

impl Default for Policy {
    fn default() -> Self {
        use FindingKind::*;
        use Reaction::*;
        let tamper = vec![Alert, ProposeIncident, RequestIssuanceHold];
        let mut reactions = BTreeMap::new();
        for k in [
            AnchoredRootMismatch,
            MembershipCountMismatch,
            ObservedVersionChanged,
            ObservedVersionMissing,
            SourceFieldChanged,
            CursorGap,
            MissingArtifact,
            LocalRootRewritten,
        ] {
            reactions.insert(k, tamper.clone());
        }
        let mut grace_secs = BTreeMap::new();
        grace_secs.insert(LocalCompletionMissing, 120);
        grace_secs.insert(LocalAnchorNotOnChain, 60);
        Self {
            backlog_threshold_secs: 900,
            reactions,
            default_reactions: vec![Alert],
            grace_secs,
        }
    }
}

impl Policy {
    pub fn reactions_for(&self, kind: FindingKind) -> &[Reaction] {
        self.reactions
            .get(&kind)
            .map(Vec::as_slice)
            .unwrap_or(&self.default_reactions)
    }

    pub fn grace_for(&self, kind: FindingKind) -> i64 {
        self.grace_secs.get(&kind).copied().unwrap_or(0)
    }
}
