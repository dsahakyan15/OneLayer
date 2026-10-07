//! OneLayer protected audit evidence sink (ticket 13).
//!
//! Отдельный процесс/сервис: строгий DTO критических действий, allowlist
//! redaction, authenticated capabilities (append/read/export/rebuild), защищённый
//! append-only destination с per-source identity/sequence/hash/floor (детекция
//! tail-delete/rollback), идемпотентная crash-safe доставка, rebuildable PG
//! projection из проверенного destination.

pub mod canonical;
pub mod capability;
pub mod config;
pub mod event;
pub mod projection;
pub mod redact;
pub mod securefs;
pub mod server;
pub mod sink;
