//! Конфигурация audit-сервиса. Файл читается безопасно (0600, без symlink).

use crate::securefs::{read_private, SecureReadPolicy, MAX_CONFIG_BYTES};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditConfig {
    /// `127.0.0.1:<port>`; сервис слушает только loopback.
    pub listen: String,
    pub state_dir: PathBuf,
    pub capability_key_file: PathBuf,
    /// PostgreSQL для rebuildable projection; без него rebuild endpoints
    /// отвечают `AUDIT_REBUILD_UNCONFIGURED`.
    #[serde(default)]
    pub projection_dsn: Option<String>,
    /// Разрешённые source identity (append capability всё равно обязателен).
    #[serde(default)]
    pub sources: Vec<String>,
    /// Разрешённые registry id.
    #[serde(default)]
    pub registries: Vec<String>,
    /// Тестовая/операционная задержка на событие при rebuild (crash-тесты).
    #[serde(default)]
    pub rebuild_delay_ms: u64,
}

impl AuditConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = read_private(
            path,
            &SecureReadPolicy {
                max_bytes: MAX_CONFIG_BYTES,
                what: "audit config",
            },
        )?;
        let text = String::from_utf8(bytes)
            .map_err(|_| format!("audit config {}: not UTF-8", path.display()))?;
        let config: AuditConfig = serde_json::from_str(&text)
            .map_err(|e| format!("audit config {}: {e}", path.display()))?;
        if !config.listen.starts_with("127.0.0.1:") && !config.listen.starts_with("localhost:") {
            return Err("audit config: listen must be loopback (127.0.0.1:<port>)".into());
        }
        Ok(config)
    }
}
