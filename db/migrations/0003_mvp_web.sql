-- Visual MVP (§5.4): event-backed incident index, browser publish flow and
-- certificate lifecycle. Synthetic devnet demo only.

-- OL-C-14: incident index built from finalized IncidentOpened / IncidentResolved.
CREATE TABLE incident_index_state (
  registry_id TEXT PRIMARY KEY,
  registry_config TEXT NOT NULL,
  indexed_through_slot BIGINT NOT NULL DEFAULT 0 CHECK (indexed_through_slot >= 0),
  last_signature TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE incident_index_notice (
  registry_id TEXT NOT NULL REFERENCES incident_index_state(registry_id),
  incident_sequence BIGINT NOT NULL CHECK (incident_sequence >= 0),
  first_suspect_batch BIGINT NOT NULL CHECK (first_suspect_batch > 0),
  last_suspect_batch BIGINT NOT NULL CHECK (last_suspect_batch >= first_suspect_batch),
  incident_type INTEGER NOT NULL CHECK (incident_type >= 0),
  status TEXT NOT NULL CHECK (status IN ('OPEN', 'RESOLVED')),
  opened_slot BIGINT NOT NULL CHECK (opened_slot > 0),
  resolved_slot BIGINT CHECK (resolved_slot IS NULL OR resolved_slot >= opened_slot),
  PRIMARY KEY (registry_id, incident_sequence)
);

CREATE INDEX incident_index_notice_range
  ON incident_index_notice (registry_id, first_suspect_batch, last_suspect_batch, status);

-- Certificate lifecycle: SUPERSEDED / REVOKED drive the verifier statuses of
-- the same name; DISPUTED stays incident-driven.
ALTER TABLE demo_certificate
  DROP CONSTRAINT demo_certificate_status_check,
  ADD CONSTRAINT demo_certificate_status_check
    CHECK (status IN ('ACTIVE', 'DISPUTED', 'SUPERSEDED', 'REVOKED')),
  ADD COLUMN internal_record_id TEXT,
  ADD COLUMN record_version BIGINT CHECK (record_version IS NULL OR record_version > 0),
  ADD COLUMN superseded_by TEXT REFERENCES demo_certificate(certificate_id);

-- Records created through the Admin wizard are marked so fixture-only reset can
-- tell them apart from the seeded fixture rows.
ALTER TABLE synthetic_registry_record
  ADD COLUMN origin TEXT NOT NULL DEFAULT 'FIXTURE' CHECK (origin IN ('FIXTURE', 'ADMIN_UI')),
  ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- OL-C-25/33: one row per publish intent. The signed bytes and the intent hash
-- are immutable; only the state machine advances.
CREATE TABLE demo_publish_intent (
  intent_id UUID PRIMARY KEY,
  registry_id TEXT NOT NULL,
  batch_sequence BIGINT NOT NULL CHECK (batch_sequence > 0),
  idempotency_key TEXT NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9_-]{16,64}$'),
  intent_hash BYTEA NOT NULL CHECK (octet_length(intent_hash) = 32),
  message_base64 TEXT NOT NULL,
  intent_json JSONB NOT NULL,
  state TEXT NOT NULL CHECK (state IN (
    'DRAFT', 'PREPARED', 'SIMULATED', 'SIGNED', 'SUBMITTED', 'FINALIZED', 'ISSUED',
    'SIMULATION_FAILED', 'SIGNING_REJECTED', 'EXPIRED', 'UNKNOWN', 'FAILED'
  )),
  simulation_logs JSONB,
  recent_blockhash TEXT NOT NULL,
  last_valid_block_height BIGINT NOT NULL CHECK (last_valid_block_height > 0),
  expires_at TIMESTAMPTZ NOT NULL,
  signed_transaction_base64 TEXT,
  transaction_signature TEXT,
  anchor_slot BIGINT CHECK (anchor_slot IS NULL OR anchor_slot > 0),
  certificate_id TEXT REFERENCES demo_certificate(certificate_id),
  failure_code TEXT,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (state <> 'ISSUED' OR certificate_id IS NOT NULL),
  CHECK (state NOT IN ('FINALIZED', 'ISSUED') OR (transaction_signature IS NOT NULL AND anchor_slot IS NOT NULL)),
  UNIQUE (registry_id, idempotency_key)
);

CREATE UNIQUE INDEX demo_publish_intent_live_batch
  ON demo_publish_intent (registry_id, batch_sequence)
  WHERE state NOT IN ('SIMULATION_FAILED', 'SIGNING_REJECTED', 'EXPIRED', 'FAILED');

-- Append-only operation timeline shown in the Admin UI. No secrets: payloads
-- carry hashes, states and public identifiers only.
CREATE TABLE demo_operation_event (
  registry_id TEXT NOT NULL,
  operation_sequence BIGSERIAL,
  intent_id UUID REFERENCES demo_publish_intent(intent_id),
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  actor_role TEXT NOT NULL CHECK (actor_role IN ('operator', 'auditor', 'system')),
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (registry_id, operation_sequence)
);

REVOKE UPDATE, DELETE ON demo_operation_event FROM PUBLIC;
