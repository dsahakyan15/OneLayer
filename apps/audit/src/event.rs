//! Критическое audit-событие: actor/device/action/resource/scope/outcome/time/
//! operationId/integrityRefs. DTO строго проверяется до записи; payload —
//! allowlist-redacted (см. `redact`). Digest привязан к канонической форме и
//! используется как источник per-source hash-цепочки в protected sink.

use crate::canonical::{canonical_json, sha256_hex};
use crate::redact;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

pub const EVENT_DOMAIN: &[u8] = b"ONELAYER:AUDIT:EVENT:V1\n";
const MAX_ACTOR: usize = 128;
const MAX_TEXT: usize = 256;
const MAX_REFS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Outcome {
    Success,
    Failure,
    Denied,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditEvent {
    pub version: u32,
    pub event_id: String,
    pub source: String,
    pub sequence: u64,
    pub registry_id: String,
    pub actor: String,
    pub device: String,
    pub action: String,
    pub resource: String,
    pub scope: String,
    pub outcome: Outcome,
    pub occurred_at_ms: i64,
    pub operation_id: String,
    pub integrity_refs: Vec<String>,
    pub payload: Json,
}

fn plain_text(field: &str, value: &str, max: usize) -> Result<(), String> {
    if value.is_empty() || value.chars().count() > max {
        return Err(format!(
            "AUDIT_EVENT_INVALID: {field} must be 1..{max} chars"
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(format!(
            "AUDIT_EVENT_INVALID: {field} contains control chars"
        ));
    }
    Ok(())
}

fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

impl AuditEvent {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!(
                "AUDIT_EVENT_INVALID: version {} is not supported",
                self.version
            ));
        }
        if !is_uuid(&self.event_id) {
            return Err("AUDIT_EVENT_INVALID: eventId must be a UUID".into());
        }
        plain_text("source", &self.source, MAX_ACTOR)?;
        plain_text("registryId", &self.registry_id, MAX_TEXT)?;
        plain_text("actor", &self.actor, MAX_ACTOR)?;
        plain_text("device", &self.device, MAX_ACTOR)?;
        plain_text("resource", &self.resource, MAX_TEXT)?;
        plain_text("scope", &self.scope, MAX_TEXT)?;
        plain_text("operationId", &self.operation_id, MAX_ACTOR)?;
        if self.sequence == 0 {
            return Err("AUDIT_EVENT_INVALID: sequence must be positive".into());
        }
        let action_ok = self.action.len() >= 2
            && self.action.len() <= 64
            && self.action.starts_with(|c: char| c.is_ascii_uppercase())
            && self
                .action
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        if !action_ok {
            return Err("AUDIT_EVENT_INVALID: action must be SCREAMING_SNAKE".into());
        }
        if self.occurred_at_ms <= 0 || self.occurred_at_ms > 4_102_444_800_000 {
            return Err("AUDIT_EVENT_INVALID: occurredAtMs out of range".into());
        }
        if self.integrity_refs.is_empty() || self.integrity_refs.len() > MAX_REFS {
            return Err(format!(
                "AUDIT_EVENT_INVALID: integrityRefs must be 1..{MAX_REFS} entries"
            ));
        }
        for reference in &self.integrity_refs {
            redact::validate_reference(reference)?;
        }
        redact::validate_payload(&self.payload)?;
        Ok(())
    }

    /// SHA-256 канонической формы события (без domain-обёртки sink).
    pub fn digest(&self) -> String {
        let value = serde_json::to_value(self).expect("serializable");
        sha256_hex(&[EVENT_DOMAIN, canonical_json(&value).as_bytes()])
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use serde_json::json;

    pub fn sample() -> AuditEvent {
        AuditEvent {
            version: 1,
            event_id: "3f2504e0-4f89-41d3-9a0c-0305e82c3301".into(),
            source: "demo-api".into(),
            sequence: 1,
            registry_id: "registry:r".into(),
            actor: "operator-1".into(),
            device: "device-1".into(),
            action: "PUBLICATION_SIGNED".into(),
            resource: "registry:r".into(),
            scope: "registry:r".into(),
            outcome: Outcome::Success,
            occurred_at_ms: 1_790_000_000_000,
            operation_id: "op-1".into(),
            integrity_refs: vec!["sha256:abc".into(), "chain:r#1".into()],
            payload: json!({"reason": "exact plan reviewed", "batchSequence": 1}),
        }
    }

    #[test]
    fn validates_and_digests_stably() {
        let e = sample();
        e.validate().unwrap();
        let mut other = e.clone();
        other.payload = json!({"batchSequence": 1, "reason": "exact plan reviewed"});
        assert_eq!(e.digest(), other.digest(), "key order must not matter");
        other.payload = json!({"reason": "changed"});
        assert_ne!(e.digest(), other.digest());
        assert_eq!(e.digest().len(), 64);
    }

    #[test]
    fn rejects_bad_dto_fields() {
        type Mutation = (Box<dyn Fn(&mut AuditEvent)>, &'static str);
        let cases: Vec<Mutation> = vec![
            (Box::new(|e| e.version = 2), "version"),
            (Box::new(|e| e.event_id = "not-a-uuid".into()), "eventId"),
            (Box::new(|e| e.actor = String::new()), "actor"),
            (Box::new(|e| e.device = "bad\n".into()), "device"),
            (Box::new(|e| e.action = "lower".into()), "action"),
            (Box::new(|e| e.sequence = 0), "sequence"),
            (Box::new(|e| e.occurred_at_ms = 0), "occurredAtMs"),
            (Box::new(|e| e.integrity_refs.clear()), "integrityRefs"),
            (
                Box::new(|e| e.integrity_refs = vec!["no-prefix".into()]),
                "integrityRefs",
            ),
            (
                Box::new(|e| e.payload = json!({"token": "x"})),
                "AUDIT_REDACTION_FORBIDDEN_KEY",
            ),
        ];
        for (mutate, code) in cases {
            let mut e = sample();
            mutate(&mut e);
            let err = e.validate().unwrap_err();
            assert!(err.contains(code), "expected {code} in {err}");
        }
    }
}
