//! Merkle-дерево OneLayer по `spec/merkle-tree-v1.md`.
//!
//! Правила (нормативно):
//!   leaf_hash = SHA256(0x00 || commitment)
//!   node_hash = SHA256(0x01 || left || right)
//!   непарный узел уровня поднимается на следующий уровень **без хэширования**;
//!   дублирование последнего узла запрещено (иначе деревья разной формы совпадают).
//!
//! Крейт работает с уже готовыми leaf hash: доменное разделение содержимого
//! (`field_commitment` / `record_commitment`) — ответственность `onelayer-canonical`.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

/// Сторона, с которой находится узел-сосед при подъёме по proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

/// Один шаг доказательства включения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: Hash,
    /// Сторона, на которой стоит `sibling` относительно текущего узла.
    pub side: Side,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    Empty,
    IndexOutOfRange { index: usize, len: usize },
}

impl core::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MerkleError::Empty => write!(f, "MERKLE_EMPTY: дерево без листьев не определено"),
            MerkleError::IndexOutOfRange { index, len } => {
                write!(f, "MERKLE_INDEX_OUT_OF_RANGE: index={index}, leaves={len}")
            }
        }
    }
}

impl std::error::Error for MerkleError {}

/// `SHA256(0x00 || commitment)` — RFC 6962 leaf.
pub fn leaf_hash(commitment: &[u8; 32]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(commitment);
    h.finalize().into()
}

/// `SHA256(0x01 || left || right)` — RFC 6962 internal node.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Корень по готовым leaf hash. Порядок листьев задаёт вызывающий
/// (§2.1 плана: по `path_bytes` для field-дерева, по
/// `(record_id_commitment, record_version)` для batch-дерева).
pub fn root(leaves: &[Hash]) -> Result<Hash, MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::Empty);
    }
    let mut level: Vec<Hash> = leaves.to_vec();
    while level.len() > 1 {
        level = fold_level(&level);
    }
    Ok(level[0])
}

/// Доказательство включения листа `index`, снизу вверх.
pub fn proof(leaves: &[Hash], index: usize) -> Result<Vec<ProofStep>, MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::Empty);
    }
    if index >= leaves.len() {
        return Err(MerkleError::IndexOutOfRange {
            index,
            len: leaves.len(),
        });
    }

    let mut steps = Vec::new();
    let mut level: Vec<Hash> = leaves.to_vec();
    let mut pos = index;

    while level.len() > 1 {
        let is_last_unpaired = pos == level.len() - 1 && !level.len().is_multiple_of(2);
        if !is_last_unpaired {
            if pos.is_multiple_of(2) {
                steps.push(ProofStep {
                    sibling: level[pos + 1],
                    side: Side::Right,
                });
            } else {
                steps.push(ProofStep {
                    sibling: level[pos - 1],
                    side: Side::Left,
                });
            }
        }
        // Непарный последний узел поднимается как есть — шага в proof нет.
        pos /= 2;
        level = fold_level(&level);
    }

    Ok(steps)
}

/// Пересчёт корня из листа и proof. Проверка — сравнение с ожидаемым корнем.
pub fn root_from_proof(leaf: &Hash, steps: &[ProofStep]) -> Hash {
    let mut acc = *leaf;
    for step in steps {
        acc = match step.side {
            Side::Right => node_hash(&acc, &step.sibling),
            Side::Left => node_hash(&step.sibling, &acc),
        };
    }
    acc
}

pub fn verify(leaf: &Hash, steps: &[ProofStep], expected_root: &Hash) -> bool {
    root_from_proof(leaf, steps) == *expected_root
}

fn fold_level(level: &[Hash]) -> Vec<Hash> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    let mut i = 0;
    while i + 1 < level.len() {
        next.push(node_hash(&level[i], &level[i + 1]));
        i += 2;
    }
    if i < level.len() {
        next.push(level[i]); // непарный узел поднимается без хэширования
    }
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| {
                let mut c = [0u8; 32];
                c[31] = i as u8;
                leaf_hash(&c)
            })
            .collect()
    }

    #[test]
    fn empty_tree_rejected() {
        assert_eq!(root(&[]), Err(MerkleError::Empty));
    }

    #[test]
    fn single_leaf_root_is_leaf() {
        let l = leaves(1);
        assert_eq!(root(&l).unwrap(), l[0]);
    }

    #[test]
    fn two_leaves() {
        let l = leaves(2);
        assert_eq!(root(&l).unwrap(), node_hash(&l[0], &l[1]));
    }

    #[test]
    fn three_leaves_promote_unpaired() {
        let l = leaves(3);
        // level1 = [H(l0,l1), l2] — l2 поднят без хэширования
        let expected = node_hash(&node_hash(&l[0], &l[1]), &l[2]);
        assert_eq!(root(&l).unwrap(), expected);
    }

    #[test]
    fn five_leaves_promote_on_two_levels() {
        let l = leaves(5);
        // level1 = [H01, H23, l4]; level2 = [H(H01,H23), l4]; root = H(.., l4)
        let h01 = node_hash(&l[0], &l[1]);
        let h23 = node_hash(&l[2], &l[3]);
        let expected = node_hash(&node_hash(&h01, &h23), &l[4]);
        assert_eq!(root(&l).unwrap(), expected);
    }

    #[test]
    fn duplication_would_differ_from_promotion() {
        // Контроль запрета дублирования: дерево из 3 листьев не равно дереву,
        // где последний лист продублирован до 4.
        let l = leaves(3);
        let mut dup = l.clone();
        dup.push(l[2]);
        assert_ne!(root(&l).unwrap(), root(&dup).unwrap());
    }

    #[test]
    fn proofs_verify_for_all_positions_1_to_16() {
        for n in 1..=16usize {
            let l = leaves(n);
            let r = root(&l).unwrap();
            for i in 0..n {
                let p = proof(&l, i).unwrap();
                assert!(verify(&l[i], &p, &r), "n={n}, i={i}");
            }
        }
    }

    #[test]
    fn tampered_leaf_fails_verification() {
        let l = leaves(7);
        let r = root(&l).unwrap();
        let p = proof(&l, 3).unwrap();
        let mut bad = l[3];
        bad[0] ^= 0x01;
        assert!(!verify(&bad, &p, &r));
    }

    #[test]
    fn proof_of_wrong_index_fails() {
        let l = leaves(8);
        let r = root(&l).unwrap();
        let p = proof(&l, 2).unwrap();
        assert!(!verify(&l[5], &p, &r));
    }

    #[test]
    fn index_out_of_range() {
        let l = leaves(4);
        assert_eq!(
            proof(&l, 4),
            Err(MerkleError::IndexOutOfRange { index: 4, len: 4 })
        );
    }
}
