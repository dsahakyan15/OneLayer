//! OneLayer Integrity Monitor (ticket 12).
//!
//! Отдельный процесс с отдельными учётными данными: read-only source
//! (PostgreSQL), эталон — finalized chain, независимый пересчёт обязательств
//! через `crates/canonical` + `crates/merkle` (Builder на TypeScript не
//! используется), append-only evidence вне защищаемой БД.

pub mod chain;
pub mod detect;
#[cfg(test)]
mod detect_tests;
pub mod evidence;
pub mod fieldmap;
pub mod http;
pub mod monitor;
pub mod policy;
pub mod securefs;
pub mod source;
