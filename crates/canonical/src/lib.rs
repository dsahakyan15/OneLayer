//! Rust-реализация канонического слоя OneLayer.
//!
//! Нормативные документы: `spec/canonical-record-v1.md`, `spec/leaf-v1.md`,
//! `spec/merkle-tree-v1.md`, `spec/anchor-chain-v1.md`. Этот крейт и
//! TypeScript-реализация пишутся по документам, а не друг по другу (§4.3):
//! общая библиотека дала бы Monitor-у и Builder-у одинаковую ошибку.

pub mod anchor;
pub mod cbor;
pub mod certificate;
pub mod commit;
pub mod manifest;
pub mod vectors;

pub use anchor::{AnchorFields, ANCHOR_PREIMAGE_LEN};
pub use cbor::{encode, nfc, CborError, Value};
pub use certificate::{
    AnchorReference, CertificateBody, CertificateError, DisclosureMode, FieldProof, MerkleProof,
    SignedCertificate,
};
pub use commit::{
    batch_leaf_hash, field_commitment, field_salt, field_tree_leaf_hash, genesis_anchor_hash,
    record_commitment, record_id_commitment, registry_id_hash, BatchRecord, BatchTree, CommitError,
    FieldEntry, FieldTree, RecordFieldKey,
};
pub use manifest::{ManifestFields, SignedManifest};
