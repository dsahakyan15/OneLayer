//! `CertificatePackageV1` — `spec/certificate-package-v1.md`.

use crate::cbor::{self, CborError, Value};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use onelayer_merkle::{Hash, ProofStep, Side};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldProof {
    pub path: String,
    pub leaf_index: u32,
    pub siblings: Vec<ProofStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf_index: u32,
    pub leaf_hash: Hash,
    pub siblings: Vec<ProofStep>,
    pub expected_root: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorReference {
    pub batch_sequence: u64,
    pub registry_version: u64,
    pub merkle_root: Hash,
    pub manifest_hash: Hash,
    pub solana_program_id: [u8; 32],
    pub segment_index: u16,
    pub segment_pda: [u8; 32],
    pub transaction_signature: [u8; 64],
    pub anchor_slot: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureMode {
    FullRecord,
    SelectiveFields,
}

impl DisclosureMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullRecord => "FULL_RECORD",
            Self::SelectiveFields => "SELECTIVE_FIELDS",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateBody {
    pub certificate_id: [u8; 16],
    pub registry_id: String,
    pub issued_at: String,
    pub record_id_commitment: Hash,
    pub record_version: u64,
    pub schema_version: u16,
    pub disclosure_mode: DisclosureMode,
    pub disclosed_fields: BTreeMap<String, Value>,
    pub field_salts: BTreeMap<String, Hash>,
    pub field_root: Hash,
    pub field_proofs: Vec<FieldProof>,
    pub batch_proof: MerkleProof,
    pub anchor: AnchorReference,
    pub issuer_key_id: String,
    pub issuer_public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCertificate {
    pub certificate_hash: Hash,
    pub issuer_signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateError {
    Cbor(CborError),
    DisclosurePathsMismatch,
    FullRecordHasProofs,
    EmptyDisclosure,
}

impl From<CborError> for CertificateError {
    fn from(value: CborError) -> Self {
        Self::Cbor(value)
    }
}

impl core::fmt::Display for CertificateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cbor(error) => write!(f, "{error}"),
            Self::DisclosurePathsMismatch => {
                write!(f, "CERTIFICATE_FORMAT_INVALID: disclosure paths mismatch")
            }
            Self::FullRecordHasProofs => write!(
                f,
                "CERTIFICATE_FORMAT_INVALID: FULL_RECORD fieldProofs must be empty"
            ),
            Self::EmptyDisclosure => write!(
                f,
                "CERTIFICATE_FORMAT_INVALID: disclosedFields must not be empty"
            ),
        }
    }
}

impl std::error::Error for CertificateError {}

fn proof_steps(steps: &[ProofStep]) -> Value {
    Value::Array(
        steps
            .iter()
            .map(|step| {
                Value::Map(BTreeMap::from([
                    (
                        "side".into(),
                        Value::Text(match step.side {
                            Side::Left => "LEFT".into(),
                            Side::Right => "RIGHT".into(),
                        }),
                    ),
                    ("hash".into(), Value::Bytes(step.sibling.to_vec())),
                ]))
            })
            .collect(),
    )
}

impl CertificateBody {
    pub fn validate_disclosure(&self) -> Result<(), CertificateError> {
        if self.disclosed_fields.is_empty() {
            return Err(CertificateError::EmptyDisclosure);
        }
        let fields: BTreeSet<&str> = self.disclosed_fields.keys().map(String::as_str).collect();
        let salts: BTreeSet<&str> = self.field_salts.keys().map(String::as_str).collect();
        if fields != salts {
            return Err(CertificateError::DisclosurePathsMismatch);
        }
        match self.disclosure_mode {
            DisclosureMode::FullRecord => {
                if !self.field_proofs.is_empty() {
                    return Err(CertificateError::FullRecordHasProofs);
                }
            }
            DisclosureMode::SelectiveFields => {
                let proofs: BTreeSet<&str> = self
                    .field_proofs
                    .iter()
                    .map(|proof| proof.path.as_str())
                    .collect();
                if fields != proofs || proofs.len() != self.field_proofs.len() {
                    return Err(CertificateError::DisclosurePathsMismatch);
                }
            }
        }
        Ok(())
    }

    fn body_value(&self) -> Result<Value, CertificateError> {
        self.validate_disclosure()?;
        let disclosed_fields = Value::Map(self.disclosed_fields.clone());
        let field_salts = Value::Map(
            self.field_salts
                .iter()
                .map(|(path, salt)| (path.clone(), Value::Bytes(salt.to_vec())))
                .collect(),
        );
        let field_proofs = Value::Array(
            self.field_proofs
                .iter()
                .map(|proof| {
                    Value::Map(BTreeMap::from([
                        ("path".into(), Value::Text(proof.path.clone())),
                        ("leafIndex".into(), Value::Int(proof.leaf_index.into())),
                        ("siblings".into(), proof_steps(&proof.siblings)),
                    ]))
                })
                .collect(),
        );
        let batch_proof = Value::Map(BTreeMap::from([
            (
                "treeAlgorithm".into(),
                Value::Text("RFC6962_SHA256_V1".into()),
            ),
            (
                "leafIndex".into(),
                Value::Int(self.batch_proof.leaf_index.into()),
            ),
            (
                "leafHash".into(),
                Value::Bytes(self.batch_proof.leaf_hash.to_vec()),
            ),
            ("siblings".into(), proof_steps(&self.batch_proof.siblings)),
            (
                "expectedRoot".into(),
                Value::Bytes(self.batch_proof.expected_root.to_vec()),
            ),
        ]));
        let anchor = Value::Map(BTreeMap::from([
            (
                "batchSequence".into(),
                Value::Int(self.anchor.batch_sequence.into()),
            ),
            (
                "registryVersion".into(),
                Value::Int(self.anchor.registry_version.into()),
            ),
            (
                "merkleRoot".into(),
                Value::Bytes(self.anchor.merkle_root.to_vec()),
            ),
            (
                "manifestHash".into(),
                Value::Bytes(self.anchor.manifest_hash.to_vec()),
            ),
            (
                "solanaProgramId".into(),
                Value::Bytes(self.anchor.solana_program_id.to_vec()),
            ),
            (
                "segmentIndex".into(),
                Value::Int(self.anchor.segment_index.into()),
            ),
            (
                "segmentPda".into(),
                Value::Bytes(self.anchor.segment_pda.to_vec()),
            ),
            (
                "transactionSignature".into(),
                Value::Bytes(self.anchor.transaction_signature.to_vec()),
            ),
            (
                "anchorSlot".into(),
                Value::Int(self.anchor.anchor_slot.into()),
            ),
            ("commitmentRequired".into(), Value::Text("finalized".into())),
        ]));
        let issuer = Value::Map(BTreeMap::from([
            ("keyId".into(), Value::Text(self.issuer_key_id.clone())),
            (
                "publicKey".into(),
                Value::Bytes(self.issuer_public_key.to_vec()),
            ),
            ("signatureAlgorithm".into(), Value::Text("Ed25519".into())),
        ]));

        Ok(Value::Map(BTreeMap::from([
            ("format".into(), Value::Text("ONELAYER_CERTIFICATE".into())),
            ("version".into(), Value::Int(1)),
            (
                "certificateId".into(),
                Value::Bytes(self.certificate_id.to_vec()),
            ),
            ("registryId".into(), Value::Text(self.registry_id.clone())),
            ("issuedAt".into(), Value::Text(self.issued_at.clone())),
            (
                "recordIdCommitment".into(),
                Value::Bytes(self.record_id_commitment.to_vec()),
            ),
            (
                "recordVersion".into(),
                Value::Int(self.record_version.into()),
            ),
            (
                "schemaVersion".into(),
                Value::Int(self.schema_version.into()),
            ),
            (
                "disclosureMode".into(),
                Value::Text(self.disclosure_mode.as_str().into()),
            ),
            ("disclosedFields".into(), disclosed_fields),
            ("fieldSalts".into(), field_salts),
            ("fieldRoot".into(), Value::Bytes(self.field_root.to_vec())),
            ("fieldProofs".into(), field_proofs),
            ("batchProof".into(), batch_proof),
            ("anchor".into(), anchor),
            ("issuer".into(), issuer),
        ])))
    }

    pub fn body_cbor(&self) -> Result<Vec<u8>, CertificateError> {
        Ok(cbor::encode(&self.body_value()?)?)
    }

    pub fn certificate_hash(&self) -> Result<Hash, CertificateError> {
        Ok(Sha256::digest(self.body_cbor()?).into())
    }

    pub fn sign(&mut self, secret_key: &[u8; 32]) -> Result<SignedCertificate, CertificateError> {
        let signing_key = SigningKey::from_bytes(secret_key);
        self.issuer_public_key = signing_key.verifying_key().to_bytes();
        let certificate_hash = self.certificate_hash()?;
        Ok(SignedCertificate {
            certificate_hash,
            issuer_signature: signing_key.sign(&certificate_hash).to_bytes(),
        })
    }

    pub fn package_cbor(&self, signature: &[u8; 64]) -> Result<Vec<u8>, CertificateError> {
        let Value::Map(mut fields) = self.body_value()? else {
            unreachable!()
        };
        fields.insert("issuerSignature".into(), Value::Bytes(signature.to_vec()));
        Ok(cbor::encode(&Value::Map(fields))?)
    }
}

impl SignedCertificate {
    pub fn verify(&self, public_key: &[u8; 32]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        key.verify(
            &self.certificate_hash,
            &ed25519_dalek::Signature::from_bytes(&self.issuer_signature),
        )
        .is_ok()
    }
}
