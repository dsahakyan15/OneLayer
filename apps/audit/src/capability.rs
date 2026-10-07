//! Authenticated capabilities: append/read/export/rebuild/status.
//!
//! Токен = `base64url(canonical_json(payload)) + "." + base64url(HMAC-SHA256(key,
//! domain || payload_json))`. Проверка подписи — `Mac::verify_slice`
//! (constant-time). Capability key читается безопасно (см. `securefs`) и не
//! покидает сервис. Default deny: нет токена — 401; токен есть, но операция
//! вне scope — 403.

use crate::canonical::canonical_json;
use crate::securefs::{read_private, SecureReadPolicy, MAX_KEY_BYTES};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

pub const CAP_DOMAIN: &[u8] = b"ONELAYER:AUDIT:CAP:V1\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapOp {
    Append,
    Read,
    Export,
    Rebuild,
    Status,
}

impl CapOp {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "append" => Ok(Self::Append),
            "read" => Ok(Self::Read),
            "export" => Ok(Self::Export),
            "rebuild" => Ok(Self::Rebuild),
            "status" => Ok(Self::Status),
            other => Err(format!("AUDIT_CAPABILITY_REQUIRED: unknown op {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityPayload {
    pub v: u32,
    pub op: CapOp,
    /// Пусто = все источники; иначе точное совпадение.
    #[serde(default)]
    pub sources: Vec<String>,
    /// Пусто = все реестры; иначе точное совпадение.
    #[serde(default)]
    pub registries: Vec<String>,
    pub subject: String,
    #[serde(default)]
    pub device: String,
    pub expires_at_ms: i64,
    pub nonce: String,
}

pub struct CapabilityKey([u8; 32]);

impl std::fmt::Debug for CapabilityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CapabilityKey(<redacted>)")
    }
}

impl CapabilityKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Файл: hex64 или JSON `{"key":"hex64"}`, права 0600, без symlink.
    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = read_private(
            path,
            &SecureReadPolicy {
                max_bytes: MAX_KEY_BYTES,
                what: "audit capability key",
            },
        )?;
        let text = String::from_utf8(bytes)
            .map_err(|_| format!("capability key {}: not UTF-8", path.display()))?;
        let hex_text = if text.trim_start().starts_with('{') {
            let value: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| format!("capability key {}: {e}", path.display()))?;
            value["key"]
                .as_str()
                .ok_or("capability key: missing \"key\"")?
                .to_string()
        } else {
            text.trim().to_string()
        };
        let raw = hex::decode(&hex_text).map_err(|_| "capability key: not hex".to_string())?;
        let key: [u8; 32] = raw
            .try_into()
            .map_err(|_| "capability key: must be 32 bytes".to_string())?;
        Ok(Self(key))
    }

    fn mac(&self, payload_json: &[u8]) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key");
        mac.update(CAP_DOMAIN);
        mac.update(payload_json);
        mac
    }

    pub fn issue(&self, payload: &CapabilityPayload) -> String {
        let value = serde_json::to_value(payload).expect("serializable");
        let json = canonical_json(&value);
        let signature = self.mac(json.as_bytes()).finalize().into_bytes();
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(json.as_bytes()),
            URL_SAFE_NO_PAD.encode(signature)
        )
    }

    pub fn verify(&self, token: &str) -> Result<CapabilityPayload, String> {
        let denied = |why: &str| format!("AUDIT_CAPABILITY_REQUIRED: {why}");
        let (payload_b64, signature_b64) = token
            .split_once('.')
            .ok_or_else(|| denied("malformed token"))?;
        let payload_json = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| denied("bad payload encoding"))?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| denied("bad signature encoding"))?;
        self.mac(&payload_json)
            .verify_slice(&signature)
            .map_err(|_| denied("signature mismatch"))?;
        let payload: CapabilityPayload =
            serde_json::from_slice(&payload_json).map_err(|_| denied("malformed payload"))?;
        if payload.v != 1 {
            return Err(denied("unsupported version"));
        }
        if payload.nonce.is_empty() {
            return Err(denied("missing nonce"));
        }
        Ok(payload)
    }
}

/// Проверяет операцию, источник, реестр и срок действия.
pub fn authorize(
    payload: &CapabilityPayload,
    op: CapOp,
    source: Option<&str>,
    registry: Option<&str>,
    now_ms: i64,
) -> Result<(), String> {
    if now_ms >= payload.expires_at_ms {
        return Err("AUDIT_CAPABILITY_REQUIRED: capability expired".into());
    }
    if payload.op != op {
        return Err(format!(
            "AUDIT_CAPABILITY_SCOPE: capability is for {:?}, not {:?}",
            payload.op, op
        ));
    }
    let in_scope = |allowed: &[String], requested: Option<&str>| match requested {
        None => true,
        Some(value) => allowed.is_empty() || allowed.iter().any(|a| a == value || a == "*"),
    };
    if !in_scope(&payload.sources, source) {
        return Err(format!(
            "AUDIT_CAPABILITY_SCOPE: source {source:?} outside capability"
        ));
    }
    if !in_scope(&payload.registries, registry) {
        return Err(format!(
            "AUDIT_CAPABILITY_SCOPE: registry {registry:?} outside capability"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(op: CapOp) -> CapabilityPayload {
        CapabilityPayload {
            v: 1,
            op,
            sources: vec!["demo-api".into()],
            registries: vec!["r1".into()],
            subject: "operator-1".into(),
            device: "device-1".into(),
            expires_at_ms: 2_000,
            nonce: "n1".into(),
        }
    }

    #[test]
    fn roundtrip_and_scope_enforcement() {
        let key = CapabilityKey::from_bytes([7; 32]);
        let token = key.issue(&payload(CapOp::Append));
        let verified = key.verify(&token).unwrap();
        authorize(
            &verified,
            CapOp::Append,
            Some("demo-api"),
            Some("r1"),
            1_000,
        )
        .unwrap();
        assert!(
            authorize(&verified, CapOp::Read, Some("demo-api"), Some("r1"), 1_000)
                .unwrap_err()
                .contains("AUDIT_CAPABILITY_SCOPE")
        );
        assert!(
            authorize(&verified, CapOp::Append, Some("other"), Some("r1"), 1_000)
                .unwrap_err()
                .contains("AUDIT_CAPABILITY_SCOPE")
        );
        assert!(authorize(
            &verified,
            CapOp::Append,
            Some("demo-api"),
            Some("r2"),
            1_000
        )
        .unwrap_err()
        .contains("AUDIT_CAPABILITY_SCOPE"));
        assert!(authorize(
            &verified,
            CapOp::Append,
            Some("demo-api"),
            Some("r1"),
            2_000
        )
        .unwrap_err()
        .contains("expired"));
    }

    #[test]
    fn rejects_tampered_tokens_and_wrong_key() {
        let key = CapabilityKey::from_bytes([7; 32]);
        let token = key.issue(&payload(CapOp::Read));
        let mut parts = token.split('.');
        let forged_payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload(CapOp::Export)).unwrap());
        let forged = format!("{forged_payload}.{}", parts.next_back().unwrap());
        assert!(key.verify(&forged).is_err());
        assert!(CapabilityKey::from_bytes([8; 32]).verify(&token).is_err());
        assert!(key.verify("garbage").is_err());
        assert!(key.verify("garbage.").is_err());
    }
}
