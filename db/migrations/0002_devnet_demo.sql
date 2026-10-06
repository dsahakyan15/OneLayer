CREATE TABLE demo_fixture_marker (
  marker TEXT PRIMARY KEY CHECK (marker = 'ONELAYER_SYNTHETIC_DEVNET_DEMO_V1'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE synthetic_registry_record (
  internal_record_id TEXT PRIMARY KEY CHECK (internal_record_id LIKE 'SYNTHETIC-%'),
  source_cursor BIGINT NOT NULL UNIQUE CHECK (source_cursor > 0),
  record_version BIGINT NOT NULL CHECK (record_version > 0),
  status TEXT NOT NULL,
  record_field_key_hex TEXT NOT NULL CHECK (record_field_key_hex ~ '^[0-9a-f]{64}$'),
  fixture_generation INTEGER NOT NULL DEFAULT 1 CHECK (fixture_generation > 0)
);

CREATE TABLE demo_anchor (
  registry_id TEXT NOT NULL,
  batch_sequence BIGINT NOT NULL CHECK (batch_sequence > 0),
  registry_version BIGINT NOT NULL CHECK (registry_version > 0),
  merkle_root BYTEA NOT NULL CHECK (octet_length(merkle_root) = 32),
  manifest_hash BYTEA NOT NULL CHECK (octet_length(manifest_hash) = 32),
  anchor_hash BYTEA NOT NULL CHECK (octet_length(anchor_hash) = 32),
  program_id TEXT NOT NULL,
  segment_pda TEXT NOT NULL,
  transaction_signature TEXT NOT NULL,
  anchor_slot BIGINT NOT NULL CHECK (anchor_slot > 0),
  commitment TEXT NOT NULL CHECK (commitment = 'finalized'),
  finalized_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (registry_id, batch_sequence)
);

CREATE TABLE demo_certificate (
  certificate_id TEXT PRIMARY KEY CHECK (certificate_id ~ '^[0-9a-f]{32}$'),
  registry_id TEXT NOT NULL,
  batch_sequence BIGINT NOT NULL,
  certificate_hash BYTEA NOT NULL CHECK (octet_length(certificate_hash) = 32),
  package_base64url TEXT NOT NULL CHECK (package_base64url ~ '^[A-Za-z0-9_-]+$'),
  qr_url TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'DISPUTED')),
  issued_at TIMESTAMPTZ NOT NULL,
  FOREIGN KEY (registry_id, batch_sequence)
    REFERENCES demo_anchor(registry_id, batch_sequence)
);

CREATE INDEX integrity_incident_demo_lookup
  ON integrity_incident (registry_id, first_suspect_batch, last_suspect_batch, status);
