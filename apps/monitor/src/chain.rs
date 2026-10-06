//! Доверенная граница Monitor: finalized state программы `onelayer_registry`.
//!
//! Эталон берётся только из chain (`spec/onchain-state-v1.md`,
//! `spec/anchor-chain-v1.md`): `RegistryConfig` и все
//! `DailyAnchorLedgerSegment` реестра, найденные через `getProgramAccounts`
//! (не через таблицы БД). Цепочка `previous_anchor_hash` пересчитывается от
//! genesis до `RegistryConfig.last_anchor_hash`, поэтому пропуск или подмена
//! entry в ответе RPC обнаруживается, а не принимается как полный эталон.
//! Доверие к самому RPC-узлу остаётся (один endpoint); см. evidence 12.

use crate::http::{post_json, HttpUrl};
use base64::Engine;
use curve25519_dalek::edwards::CompressedEdwardsY;
use onelayer_canonical::anchor::AnchorFields;
use onelayer_canonical::commit::{genesis_anchor_hash, registry_id_hash};
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Duration;

pub type Pubkey = [u8; 32];
pub const LEDGER_CAPACITY: usize = 46;
pub const ENTRY_LEN: usize = 216;
pub const SEGMENT_LEN: usize = 8 + 96 + LEDGER_CAPACITY * ENTRY_LEN; // 10_040
pub const CONFIG_LEN: usize = 8 + 261;

/// Anchor account discriminator: `SHA-256("account:<Name>")[..8]`.
pub fn discriminator(name: &str) -> [u8; 8] {
    let d = Sha256::digest(format!("account:{name}").as_bytes());
    d[..8].try_into().expect("8 bytes")
}

pub fn b58(key: &Pubkey) -> String {
    bs58::encode(key).into_string()
}

pub fn parse_pubkey(text: &str) -> Result<Pubkey, String> {
    let bytes = bs58::decode(text)
        .into_vec()
        .map_err(|e| format!("base58 {text}: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("pubkey {text} is not 32 bytes"))
}

/// `find_program_address`: первый bump от 255 вниз, дающий точку вне кривой ed25519.
pub fn find_pda(seeds: &[&[u8]], program: &Pubkey) -> Option<(Pubkey, u8)> {
    for bump in (0..=255u8).rev() {
        let mut h = Sha256::new();
        for s in seeds {
            h.update(s);
        }
        h.update([bump]);
        h.update(program);
        h.update(b"ProgramDerivedAddress");
        let candidate: Pubkey = h.finalize().into();
        if CompressedEdwardsY(candidate).decompress().is_none() {
            return Some((candidate, bump));
        }
    }
    None
}

pub fn config_pda(registry_id: &str, program: &Pubkey) -> Pubkey {
    find_pda(&[b"registry", &registry_id_hash(registry_id)], program)
        .expect("PDA exists")
        .0
}

fn segment_pda(config: &Pubkey, day_utc: u32, index: u16, program: &Pubkey) -> Pubkey {
    find_pda(
        &[
            b"ledger",
            config,
            &day_utc.to_be_bytes(),
            &index.to_le_bytes(),
        ],
        program,
    )
    .expect("PDA exists")
    .0
}

#[derive(Debug, Clone)]
pub struct RawAccount {
    pub pubkey: Pubkey,
    pub owner: Pubkey,
    pub data: Vec<u8>,
}

/// Сырые finalized данные одного чтения.
#[derive(Debug, Clone)]
pub struct RawChain {
    pub slot: u64,
    pub config: Option<RawAccount>,
    pub segments: Vec<RawAccount>,
}

pub trait ChainReader {
    fn read(&self, program: &Pubkey, config: &Pubkey) -> Result<RawChain, String>;
}

#[derive(Debug, Clone)]
pub struct Trust {
    pub registry_id: String,
    pub program_id: Pubkey,
    pub config_pda: Pubkey,
}

impl Trust {
    /// Закреплённый config PDA должен совпадать с выводом из registry ID.
    pub fn new(registry_id: &str, program_id: Pubkey, config_pda: Pubkey) -> Result<Self, String> {
        if self::config_pda(registry_id, &program_id) != config_pda {
            return Err("configPda is not the registry PDA of programId".into());
        }
        Ok(Self {
            registry_id: registry_id.into(),
            program_id,
            config_pda,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ChainEntry {
    pub fields: AnchorFields,
    pub anchor_hash: [u8; 32],
    pub segment: Pubkey,
    pub day_utc: u32,
    pub segment_index: u16,
    pub entry_index: u16,
}

#[derive(Debug, Clone)]
pub struct ChainView {
    pub slot: u64,
    pub current_batch_sequence: u64,
    pub last_anchor_hash: [u8; 32],
    pub paused: bool,
    /// `entries[i].batch_sequence == i + 1`, связаны от genesis.
    pub entries: Vec<ChainEntry>,
}

fn u16le(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(d[o..o + 2].try_into().unwrap())
}
fn u32le(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}
fn u64le(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}
fn arr32(d: &[u8], o: usize) -> [u8; 32] {
    d[o..o + 32].try_into().unwrap()
}

fn decode_entry(e: &[u8], registry_id_hash: [u8; 32]) -> AnchorFields {
    AnchorFields {
        registry_id_hash,
        batch_sequence: u64le(e, 0),
        registry_version: u64le(e, 8),
        source_cursor_start: u64le(e, 16),
        source_cursor_end: u64le(e, 24),
        merkle_root: arr32(e, 32),
        manifest_hash: arr32(e, 64),
        snapshot_hash: arr32(e, 96),
        previous_anchor_hash: arr32(e, 128),
        leaf_count: u32le(e, 160),
        schema_version: u16le(e, 164),
        flags: u16le(e, 166),
        hash_algorithm: e[168],
        tree_algorithm: e[169],
        operator_pubkey: arr32(e, 176),
        published_at: i64::from_le_bytes(e[208..216].try_into().unwrap()),
    }
}

/// Декодирует и проверяет эталон. Ошибка означает, что доверенная граница не
/// дала согласованного состояния: Monitor не делает вывода «всё в порядке».
pub fn verify_chain(trust: &Trust, raw: &RawChain) -> Result<ChainView, String> {
    let rid_hash = registry_id_hash(&trust.registry_id);
    let config = raw
        .config
        .as_ref()
        .ok_or("RegistryConfig account not found")?;
    let d = &config.data;
    if config.pubkey != trust.config_pda || config.owner != trust.program_id {
        return Err("RegistryConfig owner/address mismatch".into());
    }
    if d.len() < CONFIG_LEN || d[..8] != discriminator("RegistryConfig") || d[8] != 1 {
        return Err("RegistryConfig layout/discriminator/version mismatch".into());
    }
    if arr32(d, 10) != rid_hash {
        return Err("RegistryConfig.registry_id_hash mismatch".into());
    }
    let current = u64le(d, 106);
    let last_anchor_hash = arr32(d, 122);
    let paused = d[172] != 0;

    let mut by_seq: BTreeMap<u64, ChainEntry> = BTreeMap::new();
    let mut days: BTreeMap<u32, Vec<u16>> = BTreeMap::new();
    for seg in &raw.segments {
        let s = &seg.data;
        if seg.owner != trust.program_id
            || s.len() != SEGMENT_LEN
            || s[..8] != discriminator("DailyAnchorLedgerSegment")
        {
            return Err(format!(
                "segment {} owner/layout mismatch",
                b58(&seg.pubkey)
            ));
        }
        if s[8] != 1 || arr32(s, 12) != trust.config_pda {
            return Err(format!(
                "segment {} version/registry mismatch",
                b58(&seg.pubkey)
            ));
        }
        let day = u32le(s, 44);
        let index = u16le(s, 48);
        let count = u16le(s, 50) as usize;
        if u16le(s, 52) as usize != LEDGER_CAPACITY || count > LEDGER_CAPACITY {
            return Err(format!(
                "segment {} capacity/count invalid",
                b58(&seg.pubkey)
            ));
        }
        if segment_pda(&trust.config_pda, day, index, &trust.program_id) != seg.pubkey {
            return Err(format!(
                "segment {} is not the PDA of day {day} index {index}",
                b58(&seg.pubkey)
            ));
        }
        days.entry(day).or_default().push(index);
        for i in 0..count {
            let off = 104 + i * ENTRY_LEN;
            let fields = decode_entry(&s[off..off + ENTRY_LEN], rid_hash);
            let seq = fields.batch_sequence;
            let entry = ChainEntry {
                anchor_hash: fields.anchor_hash(),
                fields,
                segment: seg.pubkey,
                day_utc: day,
                segment_index: index,
                entry_index: i as u16,
            };
            if by_seq.insert(seq, entry).is_some() {
                return Err(format!("batch_sequence {seq} appears twice on chain"));
            }
        }
    }
    for (day, mut idx) in days {
        idx.sort_unstable();
        if idx.iter().enumerate().any(|(i, v)| *v as usize != i) {
            return Err(format!("segments of day {day} are not contiguous: {idx:?}"));
        }
    }
    // Entries после чтения config (минимальный context slot) могут быть новее — их
    // проверит следующий цикл. Всё до current обязано присутствовать.
    let mut entries = Vec::with_capacity(current as usize);
    let mut previous = genesis_anchor_hash(&rid_hash);
    for seq in 1..=current {
        let e = by_seq
            .remove(&seq)
            .ok_or_else(|| format!("anchor {seq} of {current} missing from ledger segments"))?;
        if e.fields.previous_anchor_hash != previous {
            return Err(format!(
                "anchor {seq} does not chain from anchor {}",
                seq - 1
            ));
        }
        previous = e.anchor_hash;
        entries.push(e);
    }
    if previous != last_anchor_hash {
        return Err("recomputed chain head differs from RegistryConfig.last_anchor_hash".into());
    }
    Ok(ChainView {
        slot: raw.slot,
        current_batch_sequence: current,
        last_anchor_hash,
        paused,
        entries,
    })
}

/// JSON-RPC reader: сначала config (slot S), затем сегменты с `minContextSlot = S`.
pub struct RpcChain {
    url: HttpUrl,
    timeout: Duration,
}

impl RpcChain {
    pub fn new(url: &str) -> Result<Self, String> {
        Ok(Self {
            url: HttpUrl::parse(url)?,
            timeout: Duration::from_secs(30),
        })
    }

    fn call(&self, method: &str, params: Json) -> Result<Json, String> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let raw = post_json(&self.url, &serde_json::to_vec(&body).unwrap(), self.timeout)?;
        let mut v: Json =
            serde_json::from_slice(&raw).map_err(|e| format!("{method}: bad JSON: {e}"))?;
        if let Some(err) = v.get("error") {
            return Err(format!("{method}: RPC error {err}"));
        }
        Ok(v["result"].take())
    }
}

fn account_from(pubkey: Pubkey, v: &Json) -> Result<RawAccount, String> {
    let owner = parse_pubkey(v["owner"].as_str().ok_or("account without owner")?)?;
    let data = v["data"][0].as_str().ok_or("account data is not base64")?;
    if v["data"][1].as_str() != Some("base64") {
        return Err("account data encoding is not base64".into());
    }
    let data = base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| format!("base64: {e}"))?;
    Ok(RawAccount {
        pubkey,
        owner,
        data,
    })
}

impl ChainReader for RpcChain {
    fn read(&self, program: &Pubkey, config: &Pubkey) -> Result<RawChain, String> {
        let info = self.call(
            "getAccountInfo",
            json!([b58(config), {"encoding": "base64", "commitment": "finalized"}]),
        )?;
        let slot = info["context"]["slot"]
            .as_u64()
            .ok_or("getAccountInfo without context slot")?;
        let config_account = match &info["value"] {
            Json::Null => None,
            v => Some(account_from(*config, v)?),
        };
        let seg_disc = bs58::encode(discriminator("DailyAnchorLedgerSegment")).into_string();
        let listed = self.call(
            "getProgramAccounts",
            json!([b58(program), {
                "encoding": "base64", "commitment": "finalized", "withContext": true, "minContextSlot": slot,
                "filters": [
                    {"dataSize": SEGMENT_LEN},
                    {"memcmp": {"offset": 0, "bytes": seg_disc}},
                    {"memcmp": {"offset": 12, "bytes": b58(config)}}
                ]
            }]),
        )?;
        let list_slot = listed["context"]["slot"]
            .as_u64()
            .ok_or("getProgramAccounts without context slot")?;
        if list_slot < slot {
            return Err(format!("RPC context regressed: {list_slot} < {slot}"));
        }
        let mut segments = Vec::new();
        for item in listed["value"]
            .as_array()
            .ok_or("getProgramAccounts value is not a list")?
        {
            let pubkey = parse_pubkey(item["pubkey"].as_str().ok_or("segment without pubkey")?)?;
            segments.push(account_from(pubkey, &item["account"])?);
        }
        Ok(RawChain {
            slot,
            config: config_account,
            segments,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn discriminators_match_program_idl() {
        // onchain/idl/onelayer_registry.json
        assert_eq!(
            discriminator("RegistryConfig"),
            [23, 118, 10, 246, 173, 231, 243, 156]
        );
        assert_eq!(
            discriminator("DailyAnchorLedgerSegment"),
            [18, 98, 224, 12, 97, 27, 88, 28]
        );
        assert_eq!(SEGMENT_LEN, 10_040);
    }

    #[test]
    fn pda_is_off_curve_and_trust_rejects_foreign_config() {
        let program = parse_pubkey("6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo").unwrap();
        let pda = config_pda("reg", &program);
        assert!(CompressedEdwardsY(pda).decompress().is_none());
        assert!(Trust::new("reg", program, pda).is_ok());
        assert!(Trust::new("other", program, pda).is_err());
    }

    /// Строит синтетический finalized state (только для тестов детектора).
    pub struct FakeChain {
        pub trust: Trust,
        pub entries: Vec<AnchorFields>,
        pub day: u32,
        pub drop_entry: Option<u64>,
    }

    impl FakeChain {
        pub fn new(trust: Trust) -> Self {
            Self {
                trust,
                entries: Vec::new(),
                day: 20260928,
                drop_entry: None,
            }
        }

        pub fn head(&self) -> [u8; 32] {
            self.entries
                .last()
                .map(|e| e.anchor_hash())
                .unwrap_or_else(|| genesis_anchor_hash(&registry_id_hash(&self.trust.registry_id)))
        }

        pub fn publish(&mut self, root: [u8; 32], start: u64, end: u64, leaf_count: u32) {
            let fields = AnchorFields {
                registry_id_hash: registry_id_hash(&self.trust.registry_id),
                batch_sequence: self.entries.len() as u64 + 1,
                registry_version: 0,
                source_cursor_start: start,
                source_cursor_end: end,
                merkle_root: root,
                manifest_hash: [0x4d; 32],
                snapshot_hash: [0; 32],
                previous_anchor_hash: self.head(),
                leaf_count,
                schema_version: 1,
                flags: 0,
                hash_algorithm: 1,
                tree_algorithm: 1,
                operator_pubkey: [0x0b; 32],
                published_at: 1_790_000_000 + self.entries.len() as i64,
            };
            self.entries.push(fields);
        }

        pub fn raw(&self) -> RawChain {
            let t = &self.trust;
            let mut cfg = vec![0u8; CONFIG_LEN];
            cfg[..8].copy_from_slice(&discriminator("RegistryConfig"));
            cfg[8] = 1;
            cfg[10..42].copy_from_slice(&registry_id_hash(&t.registry_id));
            cfg[106..114].copy_from_slice(&(self.entries.len() as u64).to_le_bytes());
            cfg[122..154].copy_from_slice(&self.head());
            let mut seg = vec![0u8; SEGMENT_LEN];
            seg[..8].copy_from_slice(&discriminator("DailyAnchorLedgerSegment"));
            seg[8] = 1;
            seg[12..44].copy_from_slice(&t.config_pda);
            seg[44..48].copy_from_slice(&self.day.to_le_bytes());
            seg[52..54].copy_from_slice(&(LEDGER_CAPACITY as u16).to_le_bytes());
            let mut n = 0usize;
            for e in &self.entries {
                if Some(e.batch_sequence) == self.drop_entry {
                    continue;
                }
                let o = 104 + n * ENTRY_LEN;
                let w = &mut seg[o..o + ENTRY_LEN];
                w[0..8].copy_from_slice(&e.batch_sequence.to_le_bytes());
                w[8..16].copy_from_slice(&e.registry_version.to_le_bytes());
                w[16..24].copy_from_slice(&e.source_cursor_start.to_le_bytes());
                w[24..32].copy_from_slice(&e.source_cursor_end.to_le_bytes());
                w[32..64].copy_from_slice(&e.merkle_root);
                w[64..96].copy_from_slice(&e.manifest_hash);
                w[96..128].copy_from_slice(&e.snapshot_hash);
                w[128..160].copy_from_slice(&e.previous_anchor_hash);
                w[160..164].copy_from_slice(&e.leaf_count.to_le_bytes());
                w[164..166].copy_from_slice(&e.schema_version.to_le_bytes());
                w[166..168].copy_from_slice(&e.flags.to_le_bytes());
                w[168] = e.hash_algorithm;
                w[169] = e.tree_algorithm;
                w[176..208].copy_from_slice(&e.operator_pubkey);
                w[208..216].copy_from_slice(&e.published_at.to_le_bytes());
                n += 1;
            }
            seg[50..52].copy_from_slice(&(n as u16).to_le_bytes());
            RawChain {
                slot: 1000,
                config: Some(RawAccount {
                    pubkey: t.config_pda,
                    owner: t.program_id,
                    data: cfg,
                }),
                segments: vec![RawAccount {
                    pubkey: segment_pda(&t.config_pda, self.day, 0, &t.program_id),
                    owner: t.program_id,
                    data: seg,
                }],
            }
        }
    }

    pub fn trust(registry: &str) -> Trust {
        let program = parse_pubkey("6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo").unwrap();
        Trust::new(registry, program, config_pda(registry, &program)).unwrap()
    }

    #[test]
    fn verified_view_requires_complete_linked_chain() {
        let mut fake = FakeChain::new(trust("reg-chain"));
        fake.publish([1; 32], 1, 2, 2);
        fake.publish([2; 32], 3, 3, 1);
        let view = verify_chain(&fake.trust, &fake.raw()).unwrap();
        assert_eq!(view.entries.len(), 2);
        fake.drop_entry = Some(1);
        assert!(verify_chain(&fake.trust, &fake.raw())
            .unwrap_err()
            .contains("missing"));
        fake.drop_entry = None;
        let mut raw = fake.raw();
        raw.segments[0].data[104 + 32] ^= 1; // подменённый root первого entry
        assert!(verify_chain(&fake.trust, &raw)
            .unwrap_err()
            .contains("chain"));
        let mut raw = fake.raw();
        raw.segments[0].owner = [3; 32];
        assert!(verify_chain(&fake.trust, &raw).is_err());
        let mut raw = fake.raw();
        raw.config = None;
        assert!(verify_chain(&fake.trust, &raw).is_err());
    }
}
