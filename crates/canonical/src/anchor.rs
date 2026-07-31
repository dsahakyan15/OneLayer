//! `anchor_preimage` и `anchor_hash` — §2.2 плана, `spec/anchor-chain-v1.md`.
//!
//! Единственный нормативный формат для хэширования якоря. Zero-copy layout
//! аккаунта в preimage не участвует: перестановка полей в storage ради
//! выравнивания не должна менять anchor chain. Borsh здесь тоже не при чём —
//! он остаётся только для instruction data.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

pub const DOMAIN_ANCHOR: &[u8] = b"ONELAYER:ANCHOR:V1";
/// Ровно 260 байт: 18 + 32 + 8·4 + 32·4 + 4 + 2 + 2 + 1 + 1 + 32 + 8.
pub const ANCHOR_PREIMAGE_LEN: usize = 260;

/// Поля якоря в порядке preimage. Заполняются: часть — Publisher-ом,
/// `operator_pubkey` и `published_at` — программой (§2.7 п.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorFields {
    pub registry_id_hash: Hash,
    pub batch_sequence: u64,
    pub registry_version: u64,
    pub source_cursor_start: u64,
    pub source_cursor_end: u64,
    pub merkle_root: Hash,
    pub manifest_hash: Hash,
    /// 32 нулевых байта = snapshot отсутствует.
    pub snapshot_hash: Hash,
    pub previous_anchor_hash: Hash,
    pub leaf_count: u32,
    pub schema_version: u16,
    pub flags: u16,
    pub hash_algorithm: u8,
    pub tree_algorithm: u8,
    pub operator_pubkey: [u8; 32],
    pub published_at: i64,
}

impl AnchorFields {
    /// Байты preimage. Длина всегда `ANCHOR_PREIMAGE_LEN`.
    pub fn preimage(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(ANCHOR_PREIMAGE_LEN);
        b.extend_from_slice(DOMAIN_ANCHOR);
        b.extend_from_slice(&self.registry_id_hash);
        b.extend_from_slice(&self.batch_sequence.to_be_bytes());
        b.extend_from_slice(&self.registry_version.to_be_bytes());
        b.extend_from_slice(&self.source_cursor_start.to_be_bytes());
        b.extend_from_slice(&self.source_cursor_end.to_be_bytes());
        b.extend_from_slice(&self.merkle_root);
        b.extend_from_slice(&self.manifest_hash);
        b.extend_from_slice(&self.snapshot_hash);
        b.extend_from_slice(&self.previous_anchor_hash);
        b.extend_from_slice(&self.leaf_count.to_be_bytes());
        b.extend_from_slice(&self.schema_version.to_be_bytes());
        b.extend_from_slice(&self.flags.to_be_bytes());
        b.push(self.hash_algorithm);
        b.push(self.tree_algorithm);
        b.extend_from_slice(&self.operator_pubkey);
        b.extend_from_slice(&self.published_at.to_be_bytes());
        debug_assert_eq!(b.len(), ANCHOR_PREIMAGE_LEN);
        b
    }

    pub fn anchor_hash(&self) -> Hash {
        Sha256::digest(self.preimage()).into()
    }

    /// Проверка непрерывности цепочки на стороне Publisher/Monitor.
    /// On-chain это же условие проверяет программа (§8.4).
    pub fn chains_from(&self, previous: &Hash) -> bool {
        self.previous_anchor_hash == *previous
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::{genesis_anchor_hash, registry_id_hash};

    fn sample() -> AnchorFields {
        AnchorFields {
            registry_id_hash: registry_id_hash("gov.registry.land"),
            batch_sequence: 1,
            registry_version: 1,
            source_cursor_start: 100,
            source_cursor_end: 199,
            merkle_root: [0x11; 32],
            manifest_hash: [0x22; 32],
            snapshot_hash: [0u8; 32],
            previous_anchor_hash: genesis_anchor_hash(&registry_id_hash("gov.registry.land")),
            leaf_count: 42,
            schema_version: 1,
            flags: 0,
            hash_algorithm: 1,
            tree_algorithm: 1,
            operator_pubkey: [0x33; 32],
            published_at: 1_785_000_000,
        }
    }

    #[test]
    fn preimage_is_exactly_260_bytes() {
        assert_eq!(sample().preimage().len(), ANCHOR_PREIMAGE_LEN);
    }

    #[test]
    fn domain_prefix_is_18_bytes_without_terminator() {
        assert_eq!(DOMAIN_ANCHOR.len(), 18);
        assert_eq!(&sample().preimage()[..18], DOMAIN_ANCHOR);
    }

    #[test]
    fn every_field_affects_hash() {
        let base = sample();
        let h = base.anchor_hash();

        let mut v = base.clone();
        v.batch_sequence += 1;
        assert_ne!(v.anchor_hash(), h);

        let mut v = base.clone();
        v.registry_version += 1;
        assert_ne!(v.anchor_hash(), h);

        let mut v = base.clone();
        v.source_cursor_start += 1;
        assert_ne!(v.anchor_hash(), h);

        let mut v = base.clone();
        v.source_cursor_end += 1;
        assert_ne!(v.anchor_hash(), h);

        let mut v = base.clone();
        v.merkle_root[0] ^= 1;
        assert_ne!(v.anchor_hash(), h);

        let mut v = base.clone();
        v.manifest_hash[0] ^= 1;
        assert_ne!(v.anchor_hash(), h);

        let mut v = base.clone();
        v.snapshot_hash[31] = 1;
        assert_ne!(v.anchor_hash(), h);

        let mut v = base.clone();
        v.previous_anchor_hash[0] ^= 1;
        assert_ne!(v.anchor_hash(), h);

        let mut v = base.clone();
        v.leaf_count += 1;
        assert_ne!(v.anchor_hash(), h);

        let mut v = base.clone();
        v.schema_version += 1;
        assert_ne!(v.anchor_hash(), h);

        let mut v = base.clone();
        v.flags = 1;
        assert_ne!(v.anchor_hash(), h);

        let mut v = base.clone();
        v.hash_algorithm = 2;
        assert_ne!(v.anchor_hash(), h);

        let mut v = base.clone();
        v.tree_algorithm = 2;
        assert_ne!(v.anchor_hash(), h);

        let mut v = base.clone();
        v.operator_pubkey[0] ^= 1;
        assert_ne!(v.anchor_hash(), h);

        let mut v = base.clone();
        v.published_at += 1;
        assert_ne!(v.anchor_hash(), h);
    }

    #[test]
    fn fixed_width_fields_cannot_shift_boundaries() {
        // hash_algorithm и tree_algorithm — соседние однобайтовые поля;
        // обмен значениями обязан менять хэш.
        let mut a = sample();
        a.hash_algorithm = 1;
        a.tree_algorithm = 2;
        let mut b = sample();
        b.hash_algorithm = 2;
        b.tree_algorithm = 1;
        assert_ne!(a.anchor_hash(), b.anchor_hash());
    }

    #[test]
    fn negative_published_at_is_two_complement_be() {
        let mut v = sample();
        v.published_at = -1;
        let p = v.preimage();
        assert_eq!(&p[252..260], &[0xff; 8]);
    }

    #[test]
    fn genesis_chain_link() {
        let rh = registry_id_hash("gov.registry.land");
        let g = genesis_anchor_hash(&rh);
        assert!(sample().chains_from(&g));
        assert!(!sample().chains_from(&[0u8; 32]));
    }

    #[test]
    fn absent_snapshot_is_all_zero() {
        let v = sample();
        assert_eq!(v.snapshot_hash, [0u8; 32]);
    }
}
