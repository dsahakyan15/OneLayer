//! Обязательства к полям и записям — §2.1 плана, `spec/leaf-v1.md`.
//!
//! Термины разведены нормативно: `*_commitment` — доменно-разделённое
//! обязательство к содержимому, `*_leaf_hash` — RFC 6962-обёртка. Слово «leaf»
//! не употребляется без префикса `field_tree_` или `batch_`.

use crate::cbor::{self, CborError, Value};
use hmac::{Hmac, Mac};
use onelayer_merkle as merkle;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const DOMAIN_FIELDSALT: &[u8] = b"ONELAYER:FIELDSALT:V1";
pub const DOMAIN_FIELD: &[u8] = b"ONELAYER:FIELD:V1";
pub const DOMAIN_RECORD: &[u8] = b"ONELAYER:RECORD:V1";
pub const DOMAIN_GENESIS: &[u8] = b"ONELAYER:GENESIS:V1";

/// Предел из §2.1: длина пути кодируется как `u16_be`.
pub const MAX_PATH_BYTES: usize = 65_535;

pub type Hash = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitError {
    /// Путь длиннее 65535 байт после NFC + UTF-8.
    PathTooLong {
        byte_len: usize,
    },
    /// Дублирующийся путь в наборе полей.
    DuplicatePath(String),
    /// Запись без полей: `field_root` не определён.
    NoFields,
    Cbor(CborError),
}

impl From<CborError> for CommitError {
    fn from(e: CborError) -> Self {
        CommitError::Cbor(e)
    }
}

impl core::fmt::Display for CommitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CommitError::PathTooLong { byte_len } => write!(
                f,
                "CANONICALIZATION_FAILED: byte_len(path)={byte_len} > {MAX_PATH_BYTES}"
            ),
            CommitError::DuplicatePath(p) => {
                write!(f, "CANONICALIZATION_FAILED: дублирующийся путь {p:?}")
            }
            CommitError::NoFields => {
                write!(f, "CANONICALIZATION_FAILED: запись без полей")
            }
            CommitError::Cbor(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CommitError {}

/// Ключ солей версии записи. Случайные 32 байта, хранится только
/// зашифрованно (`record_field_key_encrypted`), не покидает pipeline никогда:
/// ни в сертификате, ни в ответе API.
#[derive(Clone)]
pub struct RecordFieldKey([u8; 32]);

impl RecordFieldKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Только для тестов и golden vectors: боевой ключ приходит из CSPRNG.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// Ключ не печатается: отладочный вывод структуры с ключом — типовой канал утечки.
impl core::fmt::Debug for RecordFieldKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecordFieldKey(<redacted>)")
    }
}

/// `path_bytes = UTF-8(NFC(path))` с проверкой предела длины.
pub fn path_bytes(path: &str) -> Result<Vec<u8>, CommitError> {
    let bytes = cbor::nfc(path).into_bytes();
    if bytes.len() > MAX_PATH_BYTES {
        return Err(CommitError::PathTooLong {
            byte_len: bytes.len(),
        });
    }
    Ok(bytes)
}

/// `field_salt(path) = HMAC-SHA256(record_field_key, DOMAIN || path_bytes)`.
pub fn field_salt(key: &RecordFieldKey, path: &str) -> Result<Hash, CommitError> {
    let pb = path_bytes(path)?;
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC принимает ключ любой длины");
    mac.update(DOMAIN_FIELDSALT);
    mac.update(&pb);
    Ok(mac.finalize().into_bytes().into())
}

/// `field_commitment(path)` — §2.1. Все длины байтовые, после кодирования.
pub fn field_commitment(path: &str, value: &Value, salt: &Hash) -> Result<Hash, CommitError> {
    let pb = path_bytes(path)?;
    let value_cbor = cbor::encode(value)?;

    let mut h = Sha256::new();
    h.update(DOMAIN_FIELD);
    h.update((pb.len() as u16).to_be_bytes());
    h.update(&pb);
    h.update((value_cbor.len() as u32).to_be_bytes());
    h.update(&value_cbor);
    h.update(salt);
    Ok(h.finalize().into())
}

/// `field_tree_leaf_hash = SHA256(0x00 || field_commitment)`.
pub fn field_tree_leaf_hash(commitment: &Hash) -> Hash {
    merkle::leaf_hash(commitment)
}

/// Раскрытое или скрытое поле записи — вход для построения field-дерева.
#[derive(Debug, Clone)]
pub struct FieldEntry {
    pub path: String,
    pub value: Value,
}

/// Полное дерево полей записи: листья отсортированы по `path_bytes` (байтово).
#[derive(Debug)]
pub struct FieldTree {
    /// `(path_bytes, path, field_commitment)` в порядке листьев.
    entries: Vec<(Vec<u8>, String, Hash)>,
    root: Hash,
}

impl FieldTree {
    /// Строит дерево, вычисляя соли из `record_field_key`.
    pub fn build(key: &RecordFieldKey, fields: &[FieldEntry]) -> Result<Self, CommitError> {
        let mut entries = Vec::with_capacity(fields.len());
        for f in fields {
            let salt = field_salt(key, &f.path)?;
            let commitment = field_commitment(&f.path, &f.value, &salt)?;
            entries.push((path_bytes(&f.path)?, f.path.clone(), commitment));
        }
        Self::from_commitments(entries)
    }

    /// Строит дерево из готовых `field_commitment` — путь верификатора, у
    /// которого есть соли только раскрытых полей.
    pub fn from_commitments(
        mut entries: Vec<(Vec<u8>, String, Hash)>,
    ) -> Result<Self, CommitError> {
        if entries.is_empty() {
            return Err(CommitError::NoFields);
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for w in entries.windows(2) {
            if w[0].0 == w[1].0 {
                return Err(CommitError::DuplicatePath(w[0].1.clone()));
            }
        }
        let leaves: Vec<Hash> = entries
            .iter()
            .map(|(_, _, c)| field_tree_leaf_hash(c))
            .collect();
        let root = merkle::root(&leaves).expect("непустой набор проверен выше");
        Ok(Self { entries, root })
    }

    pub fn root(&self) -> Hash {
        self.root
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn commitment_of(&self, path: &str) -> Option<Hash> {
        let pb = cbor::nfc(path).into_bytes();
        self.entries
            .iter()
            .find(|(b, _, _)| *b == pb)
            .map(|(_, _, c)| *c)
    }

    /// Индекс листа по пути — нужен для field-proof раскрытого поля.
    pub fn index_of(&self, path: &str) -> Option<usize> {
        let pb = cbor::nfc(path).into_bytes();
        self.entries.iter().position(|(b, _, _)| *b == pb)
    }

    pub fn leaves(&self) -> Vec<Hash> {
        self.entries
            .iter()
            .map(|(_, _, c)| field_tree_leaf_hash(c))
            .collect()
    }

    /// Доказательство включения поля в `field_root`.
    pub fn proof(&self, path: &str) -> Option<Vec<merkle::ProofStep>> {
        let idx = self.index_of(path)?;
        merkle::proof(&self.leaves(), idx).ok()
    }
}

/// `record_commitment = SHA256(DOMAIN || registry_id_hash || record_id_commitment || u64_be(version) || field_root)`.
pub fn record_commitment(
    registry_id_hash: &Hash,
    record_id_commitment: &Hash,
    record_version: u64,
    field_root: &Hash,
) -> Hash {
    let mut h = Sha256::new();
    h.update(DOMAIN_RECORD);
    h.update(registry_id_hash);
    h.update(record_id_commitment);
    h.update(record_version.to_be_bytes());
    h.update(field_root);
    h.finalize().into()
}

/// `batch_leaf_hash = SHA256(0x00 || record_commitment)`.
pub fn batch_leaf_hash(record_commitment: &Hash) -> Hash {
    merkle::leaf_hash(record_commitment)
}

/// `record_id_commitment = HMAC-SHA256(id_key_vN, registry_id || 0x00 || internal_record_id)`.
/// Разделитель `0x00` обязателен: без него пары (registry_id, record_id) с
/// переносом границы дают одно и то же обязательство.
pub fn record_id_commitment(id_key: &[u8], registry_id: &str, internal_record_id: &str) -> Hash {
    let mut mac = HmacSha256::new_from_slice(id_key).expect("HMAC принимает ключ любой длины");
    mac.update(cbor::nfc(registry_id).as_bytes());
    mac.update(&[0x00]);
    mac.update(cbor::nfc(internal_record_id).as_bytes());
    mac.finalize().into_bytes().into()
}

/// Genesis: `last_anchor_hash = SHA256(DOMAIN || registry_id_hash)` (§2.7 п.7).
pub fn genesis_anchor_hash(registry_id_hash: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(DOMAIN_GENESIS);
    h.update(registry_id_hash);
    h.finalize().into()
}

/// `registry_id_hash = SHA256(UTF-8(NFC(registry_id)))`.
pub fn registry_id_hash(registry_id: &str) -> Hash {
    let mut h = Sha256::new();
    h.update(cbor::nfc(registry_id).as_bytes());
    h.finalize().into()
}

/// Batch-дерево: листья отсортированы по `(record_id_commitment, record_version)`.
#[derive(Debug)]
pub struct BatchTree {
    leaves: Vec<Hash>,
    root: Hash,
}

/// Запись в составе batch.
#[derive(Debug, Clone)]
pub struct BatchRecord {
    pub record_id_commitment: Hash,
    pub record_version: u64,
    pub record_commitment: Hash,
}

impl BatchTree {
    pub fn build(mut records: Vec<BatchRecord>) -> Result<Self, CommitError> {
        if records.is_empty() {
            // §2.5: пустые batch не создаются.
            return Err(CommitError::NoFields);
        }
        records.sort_by(|a, b| {
            a.record_id_commitment
                .cmp(&b.record_id_commitment)
                .then(a.record_version.cmp(&b.record_version))
        });
        let leaves: Vec<Hash> = records
            .iter()
            .map(|r| batch_leaf_hash(&r.record_commitment))
            .collect();
        let root = merkle::root(&leaves).expect("непустой набор проверен выше");
        Ok(Self { leaves, root })
    }

    pub fn root(&self) -> Hash {
        self.root
    }

    pub fn leaves(&self) -> &[Hash] {
        &self.leaves
    }

    pub fn proof(&self, index: usize) -> Result<Vec<merkle::ProofStep>, merkle::MerkleError> {
        merkle::proof(&self.leaves, index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> RecordFieldKey {
        RecordFieldKey::from_bytes([7u8; 32])
    }

    fn fields() -> Vec<FieldEntry> {
        vec![
            FieldEntry {
                path: "status".into(),
                value: Value::Text("ACTIVE".into()),
            },
            FieldEntry {
                path: "area".into(),
                value: Value::Text("1234.50".into()),
            },
            FieldEntry {
                path: "rights/0/type".into(),
                value: Value::Text("OWNERSHIP".into()),
            },
        ]
    }

    #[test]
    fn salt_depends_on_path_and_key() {
        let k1 = key();
        let k2 = RecordFieldKey::from_bytes([8u8; 32]);
        assert_ne!(
            field_salt(&k1, "status").unwrap(),
            field_salt(&k1, "area").unwrap()
        );
        assert_ne!(
            field_salt(&k1, "status").unwrap(),
            field_salt(&k2, "status").unwrap()
        );
    }

    #[test]
    fn salt_is_nfc_stable() {
        let k = key();
        assert_eq!(
            field_salt(&k, "\u{0439}").unwrap(),
            field_salt(&k, "\u{0438}\u{0306}").unwrap()
        );
    }

    #[test]
    fn commitment_changes_with_value_and_salt() {
        let k = key();
        let salt = field_salt(&k, "status").unwrap();
        let a = field_commitment("status", &Value::Text("ACTIVE".into()), &salt).unwrap();
        let b = field_commitment("status", &Value::Text("CLOSED".into()), &salt).unwrap();
        let mut other_salt = salt;
        other_salt[0] ^= 1;
        let c = field_commitment("status", &Value::Text("ACTIVE".into()), &other_salt).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn length_prefixes_prevent_boundary_collision() {
        // Без префиксов длины пара ("ab", "c") и ("a", "bc") склеилась бы.
        let k = key();
        let s1 = field_salt(&k, "ab").unwrap();
        let a = field_commitment("ab", &Value::Text("c".into()), &s1).unwrap();
        let b = field_commitment("a", &Value::Text("bc".into()), &s1).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn field_root_is_order_independent() {
        let k = key();
        let mut reversed = fields();
        reversed.reverse();
        let t1 = FieldTree::build(&k, &fields()).unwrap();
        let t2 = FieldTree::build(&k, &reversed).unwrap();
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn duplicate_path_rejected() {
        let k = key();
        let dup = vec![
            FieldEntry {
                path: "status".into(),
                value: Value::Text("A".into()),
            },
            FieldEntry {
                path: "status".into(),
                value: Value::Text("B".into()),
            },
        ];
        assert_eq!(
            FieldTree::build(&k, &dup).unwrap_err(),
            CommitError::DuplicatePath("status".into())
        );
    }

    #[test]
    fn empty_record_rejected() {
        assert_eq!(
            FieldTree::build(&key(), &[]).unwrap_err(),
            CommitError::NoFields
        );
    }

    #[test]
    fn path_too_long_rejected() {
        let long = "a".repeat(MAX_PATH_BYTES + 1);
        assert_eq!(
            path_bytes(&long).unwrap_err(),
            CommitError::PathTooLong {
                byte_len: MAX_PATH_BYTES + 1
            }
        );
    }

    #[test]
    fn selective_disclosure_proof_verifies() {
        let k = key();
        let tree = FieldTree::build(&k, &fields()).unwrap();
        let root = tree.root();
        for f in fields() {
            // Верификатор знает: значение, соль, proof. Пересчитывает всё сам.
            let salt = field_salt(&k, &f.path).unwrap();
            let commitment = field_commitment(&f.path, &f.value, &salt).unwrap();
            let leaf = field_tree_leaf_hash(&commitment);
            let proof = tree.proof(&f.path).unwrap();
            assert!(
                onelayer_merkle::verify(&leaf, &proof, &root),
                "path={}",
                f.path
            );
        }
    }

    #[test]
    fn tampered_salt_breaks_proof() {
        let k = key();
        let tree = FieldTree::build(&k, &fields()).unwrap();
        let mut salt = field_salt(&k, "status").unwrap();
        salt[0] ^= 0xff;
        let commitment = field_commitment("status", &Value::Text("ACTIVE".into()), &salt).unwrap();
        let leaf = field_tree_leaf_hash(&commitment);
        let proof = tree.proof("status").unwrap();
        assert!(!onelayer_merkle::verify(&leaf, &proof, &tree.root()));
    }

    #[test]
    fn record_id_commitment_separator_matters() {
        let k = [3u8; 32];
        // ("ab","c") и ("a","bc") обязаны различаться благодаря 0x00.
        assert_ne!(
            record_id_commitment(&k, "ab", "c"),
            record_id_commitment(&k, "a", "bc")
        );
    }

    #[test]
    fn record_commitment_binds_record_id_version_and_registry() {
        let rh = registry_id_hash("gov.registry.land");
        let idc = [2u8; 32];
        let fr = [1u8; 32];
        assert_ne!(
            record_commitment(&rh, &idc, 1, &fr),
            record_commitment(&rh, &idc, 2, &fr)
        );
        assert_ne!(
            record_commitment(&rh, &idc, 1, &fr),
            record_commitment(&registry_id_hash("other"), &idc, 1, &fr)
        );
        assert_ne!(
            record_commitment(&rh, &[3u8; 32], 1, &fr),
            record_commitment(&rh, &[4u8; 32], 1, &fr)
        );
    }

    #[test]
    fn batch_tree_is_order_independent_and_proofs_verify() {
        let rh = registry_id_hash("gov.registry.land");
        let records: Vec<BatchRecord> = (0..5u64)
            .map(|i| {
                let mut idc = [0u8; 32];
                idc[0] = (5 - i) as u8; // намеренно обратный порядок
                BatchRecord {
                    record_id_commitment: idc,
                    record_version: 1,
                    record_commitment: record_commitment(&rh, &idc, 1, &[i as u8; 32]),
                }
            })
            .collect();
        let mut shuffled = records.clone();
        shuffled.rotate_left(2);
        let t1 = BatchTree::build(records).unwrap();
        let t2 = BatchTree::build(shuffled).unwrap();
        assert_eq!(t1.root(), t2.root());

        for i in 0..t1.leaves().len() {
            let p = t1.proof(i).unwrap();
            assert!(onelayer_merkle::verify(&t1.leaves()[i], &p, &t1.root()));
        }
    }

    #[test]
    fn empty_batch_rejected() {
        assert_eq!(BatchTree::build(vec![]).unwrap_err(), CommitError::NoFields);
    }

    #[test]
    fn record_field_key_is_not_printed() {
        let k = key();
        let printed = format!("{k:?}");
        assert!(
            !printed.contains("7"),
            "ключ попал в Debug-вывод: {printed}"
        );
        assert!(printed.contains("redacted"));
    }
}
