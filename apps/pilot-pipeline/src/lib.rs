use onelayer_canonical::{
    cbor::{self, Value},
    field_salt, record_commitment, record_id_commitment, registry_id_hash, AnchorReference,
    BatchRecord, BatchTree, CertificateBody, CommitError, DisclosureMode, FieldEntry, FieldProof,
    FieldTree, ManifestFields, MerkleProof, RecordFieldKey, SignedCertificate, SignedManifest,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub mod artifacts;
pub mod demo;
pub mod publisher;
pub mod soak;
pub mod store;

pub const BUILDER_VERSION: &str = "onelayer-pipeline/0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeOperation {
    Insert,
    Update,
    Delete,
}

#[derive(Debug, Clone)]
pub struct SyntheticChange {
    pub registry_id: String,
    pub source_cursor: u64,
    pub internal_record_id: String,
    pub operation: ChangeOperation,
    pub fields: Vec<FieldEntry>,
}

#[derive(Debug, Clone)]
pub struct WorkflowEvent {
    pub registry_id: String,
    pub internal_record_id: String,
    pub operation: ChangeOperation,
    pub authorized: bool,
}

#[derive(Debug)]
pub struct CanonicalVersion {
    pub internal_record_id: String,
    pub source_cursor: u64,
    pub record_version: u64,
    pub record_id_commitment: [u8; 32],
    pub record_commitment: [u8; 32],
    pub field_tree: FieldTree,
    fields: Vec<FieldEntry>,
    field_key: RecordFieldKey,
}

#[derive(Debug)]
pub struct BatchArtifact {
    pub registry_id: String,
    pub batch_sequence: u64,
    pub cursor_start: u64,
    pub cursor_end: u64,
    pub records: Vec<CanonicalVersion>,
    pub merkle_root: [u8; 32],
    pub leaves_cbor: Vec<u8>,
    pub manifest: ManifestFields,
    pub signed_manifest: SignedManifest,
}

pub struct BatchBuildRequest<'a> {
    pub batch_sequence: u64,
    pub registry_version: u64,
    pub previous_anchor_hash: [u8; 32],
    pub created_at: &'a str,
    pub leaves_object_uri: &'a str,
    pub operator_key_id: &'a str,
    pub operator_secret_key: &'a [u8; 32],
}

pub struct CertificateRequest<'a> {
    pub internal_record_id: &'a str,
    pub disclosed_paths: &'a [&'a str],
    pub disclosure_mode: DisclosureMode,
    pub certificate_id: [u8; 16],
    pub issued_at: &'a str,
    pub anchor: AnchorReference,
    pub issuer_key_id: &'a str,
    pub issuer_secret_key: &'a [u8; 32],
    pub verifier_base_url: &'a str,
}

pub struct IssuedCertificate {
    pub body: CertificateBody,
    pub signed: SignedCertificate,
    pub package_cbor: Vec<u8>,
    pub qr_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineError {
    DuplicateCursor(u64),
    CursorGap { expected: u64, actual: u64 },
    WorkflowMismatch,
    WorkflowUnauthorized,
    NoPendingChanges,
    InvalidFinalizedCursor,
    RecordNotInBatch,
    DisclosurePathMissing(String),
    Certificate(String),
    InvalidKeyLength,
    Canonical(String),
}

impl core::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateCursor(cursor) => write!(f, "SOURCE_CURSOR_DUPLICATE: {cursor}"),
            Self::CursorGap { expected, actual } => {
                write!(f, "SOURCE_CURSOR_GAP: expected={expected}, actual={actual}")
            }
            Self::WorkflowMismatch => f.write_str("WORKFLOW_EVENT_MISMATCH"),
            Self::WorkflowUnauthorized => f.write_str("WORKFLOW_EVENT_UNAUTHORIZED"),
            Self::NoPendingChanges => f.write_str("EMPTY_BATCH"),
            Self::InvalidFinalizedCursor => f.write_str("FINALIZED_CURSOR_INVALID"),
            Self::RecordNotInBatch => f.write_str("RECORD_NOT_IN_BATCH"),
            Self::DisclosurePathMissing(path) => write!(f, "DISCLOSURE_PATH_MISSING: {path}"),
            Self::Certificate(message) => f.write_str(message),
            Self::InvalidKeyLength => f.write_str("INVALID_KEY_LENGTH"),
            Self::Canonical(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for PipelineError {}

impl From<CommitError> for PipelineError {
    fn from(value: CommitError) -> Self {
        Self::Canonical(value.to_string())
    }
}

#[derive(Debug)]
pub struct PilotPipeline {
    registry_id: String,
    registry_id_hash: [u8; 32],
    schema_version: u16,
    id_key: [u8; 32],
    last_processed_cursor: u64,
    last_anchored_cursor: u64,
    record_versions: BTreeMap<String, u64>,
    pending: Vec<CanonicalVersion>,
}

impl PilotPipeline {
    pub fn new(
        registry_id: impl Into<String>,
        schema_version: u16,
        id_key: [u8; 32],
        last_processed_cursor: u64,
        last_anchored_cursor: u64,
    ) -> Self {
        let registry_id = registry_id.into();
        Self {
            registry_id_hash: registry_id_hash(&registry_id),
            registry_id,
            schema_version,
            id_key,
            last_processed_cursor,
            last_anchored_cursor,
            record_versions: BTreeMap::new(),
            pending: Vec::new(),
        }
    }

    pub fn ingest(
        &mut self,
        change: SyntheticChange,
        workflow: &WorkflowEvent,
        field_key: RecordFieldKey,
    ) -> Result<(), PipelineError> {
        if change.source_cursor <= self.last_processed_cursor {
            return Err(PipelineError::DuplicateCursor(change.source_cursor));
        }
        let expected = self.last_processed_cursor + 1;
        if change.source_cursor != expected {
            return Err(PipelineError::CursorGap {
                expected,
                actual: change.source_cursor,
            });
        }
        if workflow.registry_id != change.registry_id
            || workflow.internal_record_id != change.internal_record_id
            || workflow.operation != change.operation
            || change.registry_id != self.registry_id
        {
            return Err(PipelineError::WorkflowMismatch);
        }
        if !workflow.authorized {
            return Err(PipelineError::WorkflowUnauthorized);
        }

        let record_version = self
            .record_versions
            .get(&change.internal_record_id)
            .copied()
            .unwrap_or(0)
            + 1;
        let field_tree = FieldTree::build(&field_key, &change.fields)?;
        let record_id_commitment =
            record_id_commitment(&self.id_key, &self.registry_id, &change.internal_record_id);
        let record_commitment = record_commitment(
            &self.registry_id_hash,
            &record_id_commitment,
            record_version,
            &field_tree.root(),
        );
        self.pending.push(CanonicalVersion {
            internal_record_id: change.internal_record_id.clone(),
            source_cursor: change.source_cursor,
            record_version,
            record_id_commitment,
            record_commitment,
            field_tree,
            fields: change.fields,
            field_key,
        });
        self.record_versions
            .insert(change.internal_record_id, record_version);
        self.last_processed_cursor = change.source_cursor;
        Ok(())
    }

    pub fn build_batch(
        &mut self,
        request: BatchBuildRequest<'_>,
    ) -> Result<BatchArtifact, PipelineError> {
        if self.pending.is_empty() {
            return Err(PipelineError::NoPendingChanges);
        }
        let cursor_start = self.pending.first().unwrap().source_cursor;
        let cursor_end = self.pending.last().unwrap().source_cursor;
        let mut latest_by_record = BTreeMap::new();
        for record in std::mem::take(&mut self.pending) {
            latest_by_record.insert(record.record_id_commitment, record);
        }
        let mut records: Vec<_> = latest_by_record.into_values().collect();
        records.sort_by(|left, right| {
            left.record_id_commitment
                .cmp(&right.record_id_commitment)
                .then(left.record_version.cmp(&right.record_version))
        });
        let tree = BatchTree::build(
            records
                .iter()
                .map(|record| BatchRecord {
                    record_id_commitment: record.record_id_commitment,
                    record_version: record.record_version,
                    record_commitment: record.record_commitment,
                })
                .collect(),
        )?;
        let leaves_cbor = encode_leaves(&records)?;
        let leaves_object_hash = Sha256::digest(&leaves_cbor).into();
        let manifest = ManifestFields {
            registry_id_hash: self.registry_id_hash,
            batch_sequence: request.batch_sequence,
            registry_version: request.registry_version,
            source_cursor_start: cursor_start,
            source_cursor_end: cursor_end,
            created_at: request.created_at.into(),
            schema_version: self.schema_version,
            leaf_count: records.len() as u32,
            merkle_root: tree.root(),
            previous_anchor_hash: request.previous_anchor_hash,
            snapshot_hash: None,
            leaves_object_uri: request.leaves_object_uri.into(),
            leaves_object_hash,
            builder_version: BUILDER_VERSION.into(),
            operator_key_id: request.operator_key_id.into(),
        };
        let signed_manifest = manifest
            .sign(request.operator_secret_key)
            .map_err(|error| PipelineError::Canonical(error.to_string()))?;
        Ok(BatchArtifact {
            registry_id: self.registry_id.clone(),
            batch_sequence: request.batch_sequence,
            cursor_start,
            cursor_end,
            records,
            merkle_root: tree.root(),
            leaves_cbor,
            manifest,
            signed_manifest,
        })
    }

    pub fn cursor_state(&self) -> (u64, u64) {
        (self.last_processed_cursor, self.last_anchored_cursor)
    }

    pub fn mark_finalized(&mut self, cursor_end: u64) -> Result<(), PipelineError> {
        if cursor_end <= self.last_anchored_cursor || cursor_end > self.last_processed_cursor {
            return Err(PipelineError::InvalidFinalizedCursor);
        }
        self.last_anchored_cursor = cursor_end;
        Ok(())
    }
}

impl BatchArtifact {
    pub fn issue_certificate(
        &self,
        request: CertificateRequest<'_>,
    ) -> Result<IssuedCertificate, PipelineError> {
        if request.anchor.batch_sequence != self.batch_sequence
            || request.anchor.registry_version != self.manifest.registry_version
            || request.anchor.merkle_root != self.merkle_root
            || request.anchor.manifest_hash != self.signed_manifest.manifest_hash
        {
            return Err(PipelineError::Certificate(
                "CERTIFICATE_FORMAT_INVALID: anchor does not match batch".into(),
            ));
        }
        let record_index = self
            .records
            .iter()
            .position(|record| record.internal_record_id == request.internal_record_id)
            .ok_or(PipelineError::RecordNotInBatch)?;
        let record = &self.records[record_index];
        let requested: BTreeSet<String> = request
            .disclosed_paths
            .iter()
            .map(|path| cbor::nfc(path))
            .collect();
        if requested.is_empty() || requested.len() != request.disclosed_paths.len() {
            return Err(PipelineError::Certificate(
                "CERTIFICATE_FORMAT_INVALID: disclosure paths must be unique and non-empty".into(),
            ));
        }
        let available: BTreeMap<String, &Value> = record
            .fields
            .iter()
            .map(|field| (cbor::nfc(&field.path), &field.value))
            .collect();
        for path in &requested {
            if !available.contains_key(path) {
                return Err(PipelineError::DisclosurePathMissing(path.clone()));
            }
        }
        if request.disclosure_mode == DisclosureMode::FullRecord
            && requested != available.keys().cloned().collect()
        {
            return Err(PipelineError::Certificate(
                "CERTIFICATE_FORMAT_INVALID: FULL_RECORD must disclose every field".into(),
            ));
        }

        let disclosed_fields = requested
            .iter()
            .map(|path| (path.clone(), (*available[path]).clone()))
            .collect();
        let field_salts = requested
            .iter()
            .map(|path| {
                field_salt(&record.field_key, path)
                    .map(|salt| (path.clone(), salt))
                    .map_err(PipelineError::from)
            })
            .collect::<Result<_, _>>()?;
        let field_proofs = if request.disclosure_mode == DisclosureMode::FullRecord {
            Vec::new()
        } else {
            requested
                .iter()
                .map(|path| {
                    let leaf_index = record
                        .field_tree
                        .index_of(path)
                        .ok_or_else(|| PipelineError::DisclosurePathMissing(path.clone()))?;
                    let siblings = record
                        .field_tree
                        .proof(path)
                        .ok_or_else(|| PipelineError::DisclosurePathMissing(path.clone()))?;
                    Ok(FieldProof {
                        path: path.clone(),
                        leaf_index: leaf_index as u32,
                        siblings,
                    })
                })
                .collect::<Result<_, PipelineError>>()?
        };
        let tree = BatchTree::build(
            self.records
                .iter()
                .map(|version| BatchRecord {
                    record_id_commitment: version.record_id_commitment,
                    record_version: version.record_version,
                    record_commitment: version.record_commitment,
                })
                .collect(),
        )?;
        let batch_proof = MerkleProof {
            leaf_index: record_index as u32,
            leaf_hash: tree.leaves()[record_index],
            siblings: tree
                .proof(record_index)
                .map_err(|error| PipelineError::Certificate(error.to_string()))?,
            expected_root: tree.root(),
        };
        let mut body = CertificateBody {
            certificate_id: request.certificate_id,
            registry_id: self.registry_id.clone(),
            issued_at: request.issued_at.into(),
            record_id_commitment: record.record_id_commitment,
            record_version: record.record_version,
            schema_version: self.manifest.schema_version,
            disclosure_mode: request.disclosure_mode,
            disclosed_fields,
            field_salts,
            field_root: record.field_tree.root(),
            field_proofs,
            batch_proof,
            anchor: request.anchor,
            issuer_key_id: request.issuer_key_id.into(),
            issuer_public_key: [0; 32],
        };
        let signed = body
            .sign(request.issuer_secret_key)
            .map_err(|error| PipelineError::Certificate(error.to_string()))?;
        let package_cbor = body
            .package_cbor(&signed.issuer_signature)
            .map_err(|error| PipelineError::Certificate(error.to_string()))?;
        let certificate_uuid = uuid_string(&request.certificate_id);
        let qr_url = format!(
            "{}/c/{}?h={}",
            request.verifier_base_url.trim_end_matches('/'),
            certificate_uuid,
            base64url(&signed.certificate_hash)
        );
        Ok(IssuedCertificate {
            body,
            signed,
            package_cbor,
            qr_url,
        })
    }
}

fn uuid_string(bytes: &[u8; 16]) -> String {
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        output.push(ALPHABET[((value >> 18) & 0x3f) as usize] as char);
        output.push(ALPHABET[((value >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[((value >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(value & 0x3f) as usize] as char);
        }
    }
    output
}

fn encode_leaves(records: &[CanonicalVersion]) -> Result<Vec<u8>, PipelineError> {
    let mut seen = BTreeSet::new();
    let values = records
        .iter()
        .map(|record| {
            if !seen.insert((record.record_id_commitment, record.record_version)) {
                return Err(PipelineError::Canonical(
                    "CANONICALIZATION_FAILED: duplicate batch key".into(),
                ));
            }
            Ok(Value::Map(BTreeMap::from([
                (
                    "recordIdCommitment".into(),
                    Value::Bytes(record.record_id_commitment.to_vec()),
                ),
                (
                    "recordVersion".into(),
                    Value::Int(record.record_version.into()),
                ),
                (
                    "recordCommitment".into(),
                    Value::Bytes(record.record_commitment.to_vec()),
                ),
            ])))
        })
        .collect::<Result<Vec<_>, _>>()?;
    cbor::encode(&Value::Array(values)).map_err(|error| PipelineError::Canonical(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(cursor: u64, id: &str) -> SyntheticChange {
        SyntheticChange {
            registry_id: "gov.registry.land".into(),
            source_cursor: cursor,
            internal_record_id: id.into(),
            operation: ChangeOperation::Update,
            fields: vec![FieldEntry {
                path: "status".into(),
                value: Value::Text("ACTIVE".into()),
            }],
        }
    }

    fn workflow(id: &str) -> WorkflowEvent {
        WorkflowEvent {
            registry_id: "gov.registry.land".into(),
            internal_record_id: id.into(),
            operation: ChangeOperation::Update,
            authorized: true,
        }
    }

    fn pipeline() -> PilotPipeline {
        PilotPipeline::new("gov.registry.land", 1, [9; 32], 0, 0)
    }

    #[test]
    fn rejects_duplicate_gap_and_workflow_mismatch() {
        let mut pipeline = pipeline();
        pipeline
            .ingest(
                change(1, "R-1"),
                &workflow("R-1"),
                RecordFieldKey::from_bytes([1; 32]),
            )
            .unwrap();
        assert_eq!(
            pipeline.ingest(
                change(1, "R-1"),
                &workflow("R-1"),
                RecordFieldKey::from_bytes([2; 32])
            ),
            Err(PipelineError::DuplicateCursor(1))
        );
        assert_eq!(
            pipeline.ingest(
                change(3, "R-2"),
                &workflow("R-2"),
                RecordFieldKey::from_bytes([2; 32])
            ),
            Err(PipelineError::CursorGap {
                expected: 2,
                actual: 3
            })
        );
        assert_eq!(
            pipeline.ingest(
                change(2, "R-2"),
                &workflow("wrong"),
                RecordFieldKey::from_bytes([2; 32])
            ),
            Err(PipelineError::WorkflowMismatch)
        );
    }

    #[test]
    fn rebuilding_same_range_is_deterministic() {
        fn build() -> BatchArtifact {
            let mut pipeline = pipeline();
            for (cursor, id, key) in [(1, "R-2", 2), (2, "R-1", 1)] {
                pipeline
                    .ingest(
                        change(cursor, id),
                        &workflow(id),
                        RecordFieldKey::from_bytes([key; 32]),
                    )
                    .unwrap();
            }
            pipeline
                .build_batch(BatchBuildRequest {
                    batch_sequence: 1,
                    registry_version: 2,
                    previous_anchor_hash: [3; 32],
                    created_at: "2026-07-31T00:00:00Z",
                    leaves_object_uri: "file:///pilot/1/leaves.cbor",
                    operator_key_id: "pilot-operator-1",
                    operator_secret_key: &[4; 32],
                })
                .unwrap()
        }

        let first = build();
        let second = build();
        assert_eq!(first.leaves_cbor, second.leaves_cbor);
        assert_eq!(first.merkle_root, second.merkle_root);
        assert_eq!(
            first.signed_manifest.manifest_hash,
            second.signed_manifest.manifest_hash
        );
        assert!(first.signed_manifest.verify());
        let mut pipeline = pipeline();
        pipeline
            .ingest(
                change(1, "R-1"),
                &workflow("R-1"),
                RecordFieldKey::from_bytes([1; 32]),
            )
            .unwrap();
        let batch = pipeline
            .build_batch(BatchBuildRequest {
                batch_sequence: 1,
                registry_version: 1,
                previous_anchor_hash: [0; 32],
                created_at: "2026-07-31T00:00:00Z",
                leaves_object_uri: "file:///pilot/1/leaves.cbor",
                operator_key_id: "pilot-operator-1",
                operator_secret_key: &[4; 32],
            })
            .unwrap();
        assert_eq!(pipeline.cursor_state(), (1, 0));
        pipeline.mark_finalized(batch.cursor_end).unwrap();
        assert_eq!(pipeline.cursor_state(), (1, 1));
    }

    #[test]
    fn restart_resumes_from_persisted_cursor() {
        let mut pipeline = PilotPipeline::new("gov.registry.land", 1, [9; 32], 41, 40);
        pipeline
            .ingest(
                change(42, "R-1"),
                &workflow("R-1"),
                RecordFieldKey::from_bytes([1; 32]),
            )
            .unwrap();
        assert_eq!(pipeline.cursor_state(), (42, 40));
    }

    #[test]
    fn backlog_coalescing_keeps_latest_record_and_full_cursor_range() {
        let mut pipeline = pipeline();
        for (cursor, id, key) in [(1, "R-1", 1), (2, "R-1", 2), (3, "R-2", 3)] {
            pipeline
                .ingest(
                    change(cursor, id),
                    &workflow(id),
                    RecordFieldKey::from_bytes([key; 32]),
                )
                .unwrap();
        }
        let batch = pipeline
            .build_batch(BatchBuildRequest {
                batch_sequence: 1,
                registry_version: 3,
                previous_anchor_hash: [0; 32],
                created_at: "2026-07-31T00:00:00Z",
                leaves_object_uri: "file:///pilot/1/leaves.cbor",
                operator_key_id: "pilot-operator-1",
                operator_secret_key: &[4; 32],
            })
            .unwrap();

        assert_eq!((batch.cursor_start, batch.cursor_end), (1, 3));
        assert_eq!(batch.manifest.leaf_count, 2);
        assert_eq!(
            batch
                .records
                .iter()
                .find(|record| record.internal_record_id == "R-1")
                .unwrap()
                .record_version,
            2
        );
    }

    #[test]
    fn issues_full_and_selective_certificates_without_record_field_key() {
        let mut pipeline = pipeline();
        pipeline
            .ingest(
                change(1, "R-1"),
                &workflow("R-1"),
                RecordFieldKey::from_bytes([1; 32]),
            )
            .unwrap();
        let batch = pipeline
            .build_batch(BatchBuildRequest {
                batch_sequence: 1,
                registry_version: 1,
                previous_anchor_hash: [0; 32],
                created_at: "2026-07-31T00:00:00Z",
                leaves_object_uri: "file:///pilot/1/leaves.cbor",
                operator_key_id: "pilot-operator-1",
                operator_secret_key: &[4; 32],
            })
            .unwrap();
        let anchor = AnchorReference {
            batch_sequence: 1,
            registry_version: 1,
            merkle_root: batch.merkle_root,
            manifest_hash: batch.signed_manifest.manifest_hash,
            solana_program_id: [5; 32],
            segment_index: 0,
            segment_pda: [6; 32],
            transaction_signature: [7; 64],
            anchor_slot: 412_345_678,
        };
        for mode in [DisclosureMode::FullRecord, DisclosureMode::SelectiveFields] {
            let issued = batch
                .issue_certificate(CertificateRequest {
                    internal_record_id: "R-1",
                    disclosed_paths: &["status"],
                    disclosure_mode: mode,
                    certificate_id: [8; 16],
                    issued_at: "2026-07-31T00:00:00Z",
                    anchor: anchor.clone(),
                    issuer_key_id: "pilot-issuer-1",
                    issuer_secret_key: &[9; 32],
                    verifier_base_url: "https://verify.example",
                })
                .unwrap();
            assert!(issued.signed.verify(&issued.body.issuer_public_key));
            assert!(!issued
                .package_cbor
                .windows(32)
                .any(|window| window == [1; 32]));
            assert_eq!(issued.body.field_salts.len(), 1);
            assert!(issued
                .qr_url
                .starts_with("https://verify.example/c/08080808-0808-0808-0808-080808080808?h="));
        }
    }
}
