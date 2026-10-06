CREATE TABLE registry_change_event (
  event_id UUID PRIMARY KEY,
  registry_id TEXT NOT NULL,
  source_cursor BIGINT NOT NULL CHECK (source_cursor >= 0),
  source_tx_id TEXT NOT NULL,
  internal_record_id TEXT NOT NULL,
  operation TEXT NOT NULL CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE')),
  observed_at TIMESTAMPTZ NOT NULL,
  raw_payload_encrypted BYTEA NOT NULL,
  raw_payload_hash BYTEA NOT NULL CHECK (octet_length(raw_payload_hash) = 32),
  UNIQUE (registry_id, source_cursor)
);

CREATE TABLE authorized_workflow_event (
  workflow_event_id TEXT PRIMARY KEY,
  registry_id TEXT NOT NULL,
  internal_record_id TEXT NOT NULL,
  operation_type TEXT NOT NULL,
  case_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  actor_signature BYTEA NOT NULL,
  external_approval_refs JSONB NOT NULL DEFAULT '[]',
  approved_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('AUTHORIZED', 'REVOKED', 'REJECTED'))
);

CREATE TABLE canonical_record_version (
  id UUID PRIMARY KEY,
  registry_id TEXT NOT NULL,
  internal_record_id TEXT NOT NULL,
  record_id_commitment BYTEA NOT NULL CHECK (octet_length(record_id_commitment) = 32),
  record_version BIGINT NOT NULL CHECK (record_version > 0),
  workflow_event_id TEXT NOT NULL REFERENCES authorized_workflow_event(workflow_event_id),
  schema_version SMALLINT NOT NULL CHECK (schema_version > 0),
  canonical_payload_encrypted BYTEA NOT NULL,
  field_root BYTEA NOT NULL CHECK (octet_length(field_root) = 32),
  record_field_key_encrypted BYTEA NOT NULL,
  key_encryption_version TEXT NOT NULL,
  record_commitment BYTEA NOT NULL CHECK (octet_length(record_commitment) = 32),
  batch_leaf_hash BYTEA NOT NULL CHECK (octet_length(batch_leaf_hash) = 32),
  source_cursor BIGINT NOT NULL CHECK (source_cursor >= 0),
  created_at TIMESTAMPTZ NOT NULL,
  UNIQUE (registry_id, internal_record_id, record_version),
  UNIQUE (registry_id, record_id_commitment, record_version)
);

CREATE TABLE anchor_batch (
  registry_id TEXT NOT NULL,
  batch_sequence BIGINT NOT NULL CHECK (batch_sequence > 0),
  registry_version BIGINT NOT NULL CHECK (registry_version > 0),
  cursor_start BIGINT NOT NULL CHECK (cursor_start >= 0),
  cursor_end BIGINT NOT NULL CHECK (cursor_end >= cursor_start),
  leaf_count INTEGER NOT NULL CHECK (leaf_count > 0),
  merkle_root BYTEA NOT NULL CHECK (octet_length(merkle_root) = 32),
  manifest_hash BYTEA NOT NULL CHECK (octet_length(manifest_hash) = 32),
  previous_anchor_hash BYTEA NOT NULL CHECK (octet_length(previous_anchor_hash) = 32),
  anchor_hash BYTEA CHECK (anchor_hash IS NULL OR octet_length(anchor_hash) = 32),
  snapshot_hash BYTEA CHECK (snapshot_hash IS NULL OR octet_length(snapshot_hash) = 32),
  status TEXT NOT NULL CHECK (status IN ('PREPARED', 'SIGNED', 'SUBMITTED', 'FINALIZED', 'DISPUTED', 'FAILED')),
  solana_signature TEXT,
  solana_slot BIGINT CHECK (solana_slot IS NULL OR solana_slot >= 0),
  prepared_at TIMESTAMPTZ NOT NULL,
  finalized_at TIMESTAMPTZ,
  PRIMARY KEY (registry_id, batch_sequence),
  CHECK (status <> 'FINALIZED' OR anchor_hash IS NOT NULL)
);

CREATE TABLE batch_leaf (
  registry_id TEXT NOT NULL,
  batch_sequence BIGINT NOT NULL,
  leaf_index INTEGER NOT NULL CHECK (leaf_index >= 0),
  record_version_id UUID NOT NULL REFERENCES canonical_record_version(id),
  leaf_hash BYTEA NOT NULL CHECK (octet_length(leaf_hash) = 32),
  proof_object_key TEXT,
  PRIMARY KEY (registry_id, batch_sequence, leaf_index),
  FOREIGN KEY (registry_id, batch_sequence)
    REFERENCES anchor_batch(registry_id, batch_sequence)
);

CREATE TABLE certificate (
  certificate_id UUID PRIMARY KEY,
  registry_id TEXT NOT NULL,
  batch_sequence BIGINT NOT NULL,
  record_version_id UUID NOT NULL REFERENCES canonical_record_version(id),
  certificate_version SMALLINT NOT NULL CHECK (certificate_version > 0),
  certificate_hash BYTEA NOT NULL CHECK (octet_length(certificate_hash) = 32),
  issuer_key_id TEXT NOT NULL,
  signature BYTEA NOT NULL CHECK (octet_length(signature) = 64),
  status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'SUPERSEDED', 'REVOKED')),
  issued_at TIMESTAMPTZ NOT NULL,
  superseded_by UUID REFERENCES certificate(certificate_id),
  FOREIGN KEY (registry_id, batch_sequence)
    REFERENCES anchor_batch(registry_id, batch_sequence)
);

CREATE TABLE integrity_incident (
  incident_id UUID PRIMARY KEY,
  registry_id TEXT NOT NULL,
  incident_sequence BIGINT,
  incident_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  internal_record_id TEXT,
  expected_leaf_hash BYTEA CHECK (expected_leaf_hash IS NULL OR octet_length(expected_leaf_hash) = 32),
  observed_leaf_hash BYTEA CHECK (observed_leaf_hash IS NULL OR octet_length(observed_leaf_hash) = 32),
  first_suspect_batch BIGINT,
  last_suspect_batch BIGINT,
  status TEXT NOT NULL CHECK (status IN ('OPEN', 'RESOLVED')),
  evidence_object_key TEXT NOT NULL,
  opened_at TIMESTAMPTZ NOT NULL,
  resolved_at TIMESTAMPTZ,
  resolution TEXT,
  UNIQUE (registry_id, incident_sequence),
  FOREIGN KEY (registry_id, first_suspect_batch)
    REFERENCES anchor_batch(registry_id, batch_sequence)
);

CREATE TABLE publish_queue (
  registry_id TEXT NOT NULL,
  batch_sequence BIGINT NOT NULL,
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  claimed_by TEXT,
  claimed_until TIMESTAMPTZ,
  status TEXT NOT NULL CHECK (status IN ('QUEUED', 'CLAIMED', 'SUBMITTED', 'FINALIZED', 'EXPIRED', 'FAILED')),
  last_error TEXT CHECK (last_error IS NULL OR length(last_error) <= 512),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (registry_id, batch_sequence),
  FOREIGN KEY (registry_id, batch_sequence)
    REFERENCES anchor_batch(registry_id, batch_sequence)
);

CREATE TABLE publish_attempt (
  registry_id TEXT NOT NULL,
  batch_sequence BIGINT NOT NULL,
  attempt_no INTEGER NOT NULL CHECK (attempt_no > 0),
  transaction_b64 TEXT NOT NULL,
  signature TEXT NOT NULL,
  recent_blockhash TEXT NOT NULL,
  submitted_to TEXT[] NOT NULL DEFAULT '{}',
  outcome TEXT NOT NULL CHECK (outcome IN ('SUBMITTED', 'FINALIZED', 'EXPIRED', 'FAILED', 'UNKNOWN')),
  error_code TEXT,
  error_message TEXT CHECK (error_message IS NULL OR length(error_message) <= 512),
  error_payload_hash BYTEA CHECK (error_payload_hash IS NULL OR octet_length(error_payload_hash) = 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at TIMESTAMPTZ,
  PRIMARY KEY (registry_id, batch_sequence, attempt_no),
  FOREIGN KEY (registry_id, batch_sequence)
    REFERENCES publish_queue(registry_id, batch_sequence),
  CHECK (
    (outcome IN ('SUBMITTED', 'UNKNOWN') AND resolved_at IS NULL) OR
    (outcome IN ('FINALIZED', 'EXPIRED', 'FAILED') AND resolved_at IS NOT NULL)
  )
);

CREATE TABLE source_cursor_state (
  registry_id TEXT PRIMARY KEY,
  last_processed BIGINT NOT NULL CHECK (last_processed >= 0),
  last_anchored BIGINT NOT NULL CHECK (last_anchored >= 0 AND last_anchored <= last_processed),
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE audit_event (
  registry_id TEXT NOT NULL,
  audit_sequence BIGINT NOT NULL CHECK (audit_sequence > 0),
  audit_id UUID NOT NULL UNIQUE,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  event_payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (registry_id, audit_sequence)
);

CREATE FUNCTION enforce_publish_attempt_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.registry_id, NEW.batch_sequence, NEW.attempt_no,
      NEW.transaction_b64, NEW.signature, NEW.recent_blockhash,
      NEW.submitted_to, NEW.created_at)
     IS DISTINCT FROM
     (OLD.registry_id, OLD.batch_sequence, OLD.attempt_no,
      OLD.transaction_b64, OLD.signature, OLD.recent_blockhash,
      OLD.submitted_to, OLD.created_at) THEN
    RAISE EXCEPTION 'publish_attempt signed fields are immutable';
  END IF;

  IF OLD.outcome NOT IN ('SUBMITTED', 'UNKNOWN')
     OR NEW.outcome NOT IN ('FINALIZED', 'EXPIRED', 'FAILED') THEN
    RAISE EXCEPTION 'publish_attempt outcome transition is not allowed';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER publish_attempt_update_guard
BEFORE UPDATE ON publish_attempt
FOR EACH ROW EXECUTE FUNCTION enforce_publish_attempt_update();

CREATE FUNCTION reject_row_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER publish_attempt_delete_guard
BEFORE DELETE ON publish_attempt
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TRIGGER audit_event_update_guard
BEFORE UPDATE OR DELETE ON audit_event
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();
