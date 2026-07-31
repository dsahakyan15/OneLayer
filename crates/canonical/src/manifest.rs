//! `BatchManifestV1` — `spec/batch-manifest-v1.md`.

use crate::cbor::{self, CborError, Value};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub type Hash = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFields {
    pub registry_id_hash: Hash,
    pub batch_sequence: u64,
    pub registry_version: u64,
    pub source_cursor_start: u64,
    pub source_cursor_end: u64,
    pub created_at: String,
    pub schema_version: u16,
    pub leaf_count: u32,
    pub merkle_root: Hash,
    pub previous_anchor_hash: Hash,
    pub snapshot_hash: Option<Hash>,
    pub leaves_object_uri: String,
    pub leaves_object_hash: Hash,
    pub builder_version: String,
    pub operator_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedManifest {
    pub manifest_hash: Hash,
    pub operator_public_key: [u8; 32],
    pub manifest_signature: [u8; 64],
}

impl ManifestFields {
    pub fn unsigned_cbor(&self) -> Result<Vec<u8>, CborError> {
        let mut fields = BTreeMap::new();
        fields.insert("manifestVersion".into(), Value::Int(1));
        fields.insert(
            "registryIdHash".into(),
            Value::Bytes(self.registry_id_hash.to_vec()),
        );
        fields.insert(
            "batchSequence".into(),
            Value::Int(self.batch_sequence.into()),
        );
        fields.insert(
            "registryVersion".into(),
            Value::Int(self.registry_version.into()),
        );
        fields.insert(
            "sourceCursorStart".into(),
            Value::Int(self.source_cursor_start.into()),
        );
        fields.insert(
            "sourceCursorEnd".into(),
            Value::Int(self.source_cursor_end.into()),
        );
        fields.insert("createdAt".into(), Value::Text(self.created_at.clone()));
        fields.insert(
            "schemaVersion".into(),
            Value::Int(self.schema_version.into()),
        );
        fields.insert("hashAlgorithm".into(), Value::Text("SHA256".into()));
        fields.insert(
            "treeAlgorithm".into(),
            Value::Text("RFC6962_SHA256_V1".into()),
        );
        fields.insert("leafCount".into(), Value::Int(self.leaf_count.into()));
        fields.insert("merkleRoot".into(), Value::Bytes(self.merkle_root.to_vec()));
        fields.insert(
            "previousAnchorHash".into(),
            Value::Bytes(self.previous_anchor_hash.to_vec()),
        );
        fields.insert(
            "snapshotHash".into(),
            self.snapshot_hash
                .map(|hash| Value::Bytes(hash.to_vec()))
                .unwrap_or(Value::Null),
        );
        fields.insert(
            "leavesObjectUri".into(),
            Value::Text(self.leaves_object_uri.clone()),
        );
        fields.insert(
            "leavesObjectHash".into(),
            Value::Bytes(self.leaves_object_hash.to_vec()),
        );
        fields.insert(
            "builderVersion".into(),
            Value::Text(self.builder_version.clone()),
        );
        fields.insert(
            "operatorKeyId".into(),
            Value::Text(self.operator_key_id.clone()),
        );
        cbor::encode(&Value::Map(fields))
    }

    pub fn manifest_hash(&self) -> Result<Hash, CborError> {
        Ok(Sha256::digest(self.unsigned_cbor()?).into())
    }

    pub fn sign(&self, secret_key: &[u8; 32]) -> Result<SignedManifest, CborError> {
        let signing_key = SigningKey::from_bytes(secret_key);
        let manifest_hash = self.manifest_hash()?;
        Ok(SignedManifest {
            manifest_hash,
            operator_public_key: signing_key.verifying_key().to_bytes(),
            manifest_signature: signing_key.sign(&manifest_hash).to_bytes(),
        })
    }
}

impl SignedManifest {
    pub fn verify(&self) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.operator_public_key) else {
            return false;
        };
        key.verify(
            &self.manifest_hash,
            &ed25519_dalek::Signature::from_bytes(&self.manifest_signature),
        )
        .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(snapshot_hash: Option<Hash>) -> ManifestFields {
        ManifestFields {
            registry_id_hash: [1; 32],
            batch_sequence: 7,
            registry_version: 9,
            source_cursor_start: 100,
            source_cursor_end: 199,
            created_at: "2026-07-31T00:00:00Z".into(),
            schema_version: 1,
            leaf_count: 42,
            merkle_root: [2; 32],
            previous_anchor_hash: [3; 32],
            snapshot_hash,
            leaves_object_uri: "s3://manifests/7/leaves.cbor".into(),
            leaves_object_hash: [4; 32],
            builder_version: "onelayer-pipeline/0.1.0".into(),
            operator_key_id: "pilot-operator-1".into(),
        }
    }

    #[test]
    fn signature_covers_manifest_hash() {
        let signed = sample(None).sign(&[7; 32]).unwrap();
        assert!(signed.verify());
        let mut tampered = signed.clone();
        tampered.manifest_hash[0] ^= 1;
        assert!(!tampered.verify());
    }

    #[test]
    fn snapshot_presence_changes_hash() {
        assert_ne!(
            sample(None).manifest_hash().unwrap(),
            sample(Some([5; 32])).manifest_hash().unwrap()
        );
    }
}
