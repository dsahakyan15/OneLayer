//! Allowlist-redaction audit payload: журнал не содержит tokens, shares,
//! private keys и лишних раскрытых полей. Событие с запрещённым полем
//! отвергается целиком — никакой «частичной» маскировки, которая создавала бы
//! ложное впечатление полного события.

use serde_json::Value as Json;

pub const ALLOWED_KEYS: &[&str] = &[
    "reason",
    "code",
    "detail",
    "recordId",
    "version",
    "batchSequence",
    "operationId",
    "role",
    "username",
    "target",
    "from",
    "to",
    "count",
    "bytes",
    "policy",
    "fields",
    "registryId",
    "channel",
    "outcome",
];

/// Подстрока ключа (lowercase) → запрещённое поле, даже если ключ иначе похож
/// на разрешённый.
pub const DENY_KEY_SUBSTRINGS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "key",
    "share",
    "seed",
    "mnemonic",
    "private",
    "credential",
    "authorization",
    "cookie",
    "bearer",
    "jwt",
    "signature",
    "dsn",
    "session",
];

const MAX_VALUE_CHARS: usize = 512;

/// Значение, похожее на секрет: JWT, длинный hex/base64, PEM, solana secret.
pub fn forbidden_value(value: &str) -> bool {
    if value.contains("-----BEGIN") || value.to_ascii_lowercase().contains("solana:") {
        return true;
    }
    if value.split('.').count() == 3
        && value.split('.').all(|part| {
            part.len() >= 8
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
    {
        return true;
    }
    for token in value.split_whitespace() {
        if token.len() >= 64
            && token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+/=_-".contains(c))
        {
            return true;
        }
    }
    false
}

fn check_value(path: &str, value: &str) -> Result<(), String> {
    if value.chars().count() > MAX_VALUE_CHARS {
        return Err(format!(
            "AUDIT_REDACTION_FORBIDDEN_VALUE: {path} exceeds {MAX_VALUE_CHARS} chars"
        ));
    }
    if value
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(format!(
            "AUDIT_REDACTION_FORBIDDEN_VALUE: {path} contains control characters"
        ));
    }
    if forbidden_value(value) {
        return Err(format!(
            "AUDIT_REDACTION_FORBIDDEN_VALUE: {path} looks like a secret"
        ));
    }
    Ok(())
}

/// Проверяет payload по allowlist. Возвращает code-prefixed ошибку.
pub fn validate_payload(payload: &Json) -> Result<(), String> {
    let Json::Object(map) = payload else {
        return Err("AUDIT_REDACTION_NESTED: payload must be a flat object".into());
    };
    for (key, value) in map {
        let lowered = key.to_ascii_lowercase();
        if DENY_KEY_SUBSTRINGS
            .iter()
            .any(|deny| lowered.contains(deny))
        {
            return Err(format!(
                "AUDIT_REDACTION_FORBIDDEN_KEY: payload.{key} is a forbidden field"
            ));
        }
        if !ALLOWED_KEYS.contains(&key.as_str()) {
            return Err(format!(
                "AUDIT_REDACTION_UNKNOWN_FIELD: payload.{key} is not allowlisted"
            ));
        }
        match value {
            Json::String(s) => check_value(&format!("payload.{key}"), s)?,
            Json::Number(n) => {
                if !(n.is_i64() || n.is_u64()) {
                    return Err(format!(
                        "AUDIT_REDACTION_NESTED: payload.{key} must be an integer"
                    ));
                }
            }
            Json::Bool(_) | Json::Null => {}
            Json::Array(items) if key == "fields" => {
                for (i, item) in items.iter().enumerate() {
                    let Json::String(s) = item else {
                        return Err(format!(
                            "AUDIT_REDACTION_NESTED: payload.{key}[{i}] must be a string"
                        ));
                    };
                    check_value(&format!("payload.{key}[{i}]"), s)?;
                }
            }
            Json::Array(_) => {
                return Err(format!(
                    "AUDIT_REDACTION_NESTED: payload.{key} arrays are not allowlisted"
                ));
            }
            Json::Object(_) => {
                return Err(format!(
                    "AUDIT_REDACTION_NESTED: payload.{key} must be flat"
                ));
            }
        }
    }
    Ok(())
}

/// Проверяет строку-ссылку (integrityRefs): префикс из allowlist, без секретов.
pub fn validate_reference(value: &str) -> Result<(), String> {
    const PREFIXES: &[&str] = &[
        "sha256:",
        "sha384:",
        "chain:",
        "event:",
        "op:",
        "batch:",
        "registry:",
        "anchor:",
        "pg:",
    ];
    if !PREFIXES.iter().any(|p| value.starts_with(p)) {
        return Err(format!(
            "AUDIT_EVENT_INVALID: integrityRefs entry {value:?} has no allowlisted prefix"
        ));
    }
    if value.chars().count() > 256 {
        return Err("AUDIT_EVENT_INVALID: integrityRefs entry too long".into());
    }
    if value.chars().any(char::is_control) || forbidden_value(value) {
        return Err(format!(
            "AUDIT_REDACTION_FORBIDDEN_VALUE: integrityRefs entry {value:?} rejected"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn allows_benign_flat_payload() {
        assert!(validate_payload(&json!({
            "reason": "approval recorded", "count": 3, "fields": ["owner", "area"], "channel": "demo"
        }))
        .is_ok());
    }

    #[test]
    fn rejects_secret_shaped_keys_values_and_unknown_fields() {
        for (payload, code) in [
            (json!({"accessToken": "x"}), "AUDIT_REDACTION_FORBIDDEN_KEY"),
            (json!({"privateKey": "x"}), "AUDIT_REDACTION_FORBIDDEN_KEY"),
            (
                json!({"recoveryShare": "x"}),
                "AUDIT_REDACTION_FORBIDDEN_KEY",
            ),
            (json!({"sessionId": "x"}), "AUDIT_REDACTION_FORBIDDEN_KEY"),
            (
                json!({"reason": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"}),
                "AUDIT_REDACTION_FORBIDDEN_VALUE",
            ),
            (
                json!({"detail": "a".repeat(64)}),
                "AUDIT_REDACTION_FORBIDDEN_VALUE",
            ),
            (json!({"extra": "x"}), "AUDIT_REDACTION_UNKNOWN_FIELD"),
            (json!({"reason": {"nested": 1}}), "AUDIT_REDACTION_NESTED"),
            (json!({"reason": [1]}), "AUDIT_REDACTION_NESTED"),
            (json!({"fields": [1]}), "AUDIT_REDACTION_NESTED"),
            (json!({"count": 1.5}), "AUDIT_REDACTION_NESTED"),
        ] {
            let err = validate_payload(&payload).unwrap_err();
            assert!(err.starts_with(code), "{payload} -> {err}");
        }
    }

    #[test]
    fn references_require_prefix_and_no_secrets() {
        assert!(validate_reference("sha256:abc").is_ok());
        assert!(validate_reference("chain:reg#1").is_ok());
        assert!(validate_reference(&format!("sha256:{}", "a".repeat(64))).is_ok());
        assert!(validate_reference("raw-hex").is_err());
        assert!(validate_reference("sha256:line\nbreak").is_err());
    }
}
