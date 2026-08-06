-- Bounded local BackupCenter/Snapshot control plane (OL-C-42…OL-C-44).
-- Centers store encrypted SnapshotPackageV1 envelopes only. Recovery shares,
-- plaintext state and private credentials are intentionally absent from this
-- schema.

ALTER TABLE demo_operation_event
  DROP CONSTRAINT IF EXISTS demo_operation_event_actor_role_check,
  ADD CONSTRAINT demo_operation_event_actor_role_check
    CHECK (actor_role IN ('operator', 'auditor', 'chief_admin', 'system'));

CREATE TABLE backup_center (
  center_id TEXT PRIMARY KEY CHECK (center_id ~ '^BACKUPCENTER-[A-Za-z0-9-]+$'),
  registry_id TEXT NOT NULL,
  name TEXT NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 120),
  scope TEXT NOT NULL DEFAULT 'LOCAL' CHECK (scope = 'LOCAL'),
  local_endpoint TEXT NOT NULL CHECK (local_endpoint ~ '^local://[A-Za-z0-9._/-]+$'),
  volume_name TEXT NOT NULL CHECK (volume_name ~ '^[A-Za-z0-9._-]+$'),
  credential_reference TEXT NOT NULL CHECK (credential_reference ~ '^[A-Za-z0-9._-]+$'),
  credential_version TEXT NOT NULL CHECK (credential_version ~ '^[A-Za-z0-9._-]+$'),
  health_status TEXT NOT NULL DEFAULT 'HEALTHY'
    CHECK (health_status IN ('HEALTHY', 'UNAVAILABLE', 'ERROR')),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  last_health_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by TEXT NOT NULL DEFAULT 'system',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (registry_id, name),
  UNIQUE (registry_id, volume_name),
  UNIQUE (registry_id, credential_reference)
);

CREATE TABLE snapshot (
  snapshot_id UUID PRIMARY KEY,
  registry_id TEXT NOT NULL,
  snapshot_version BIGINT NOT NULL CHECK (snapshot_version > 0),
  format_version INTEGER NOT NULL DEFAULT 1 CHECK (format_version = 1),
  package_format TEXT NOT NULL DEFAULT 'SnapshotPackageV1'
    CHECK (package_format = 'SnapshotPackageV1'),
  snapshot_status TEXT NOT NULL CHECK (snapshot_status IN ('FINALIZED', 'NON_FINALIZED')),
  merkle_root BYTEA NOT NULL CHECK (octet_length(merkle_root) = 32),
  plaintext_hash BYTEA NOT NULL CHECK (octet_length(plaintext_hash) = 32),
  ciphertext_hash BYTEA NOT NULL CHECK (octet_length(ciphertext_hash) = 32),
  encrypted_package BYTEA NOT NULL CHECK (octet_length(encrypted_package) > 0),
  plaintext_length INTEGER NOT NULL CHECK (plaintext_length > 0),
  key_encryption_version TEXT NOT NULL CHECK (octet_length(key_encryption_version) BETWEEN 1 AND 120),
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (registry_id, snapshot_version)
);

CREATE TABLE snapshot_replication_operation (
  operation_id UUID PRIMARY KEY,
  registry_id TEXT NOT NULL,
  snapshot_id UUID NOT NULL REFERENCES snapshot(snapshot_id),
  idempotency_key TEXT,
  operation_status TEXT NOT NULL CHECK (operation_status IN ('COMPLETED', 'PARTIAL')),
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (registry_id, idempotency_key)
);

CREATE TABLE snapshot_replica (
  replica_id UUID PRIMARY KEY,
  snapshot_id UUID NOT NULL REFERENCES snapshot(snapshot_id),
  center_id TEXT NOT NULL REFERENCES backup_center(center_id),
  object_key TEXT NOT NULL CHECK (object_key ~ '^snapshots/[0-9a-f]{32}/snapshot-package-v1\.cbor$'),
  copy_status TEXT NOT NULL CHECK (copy_status IN ('COPIED', 'PENDING_RETRY', 'FAILED')),
  package_bytes BYTEA NOT NULL CHECK (octet_length(package_bytes) > 0),
  ciphertext_hash BYTEA NOT NULL CHECK (octet_length(ciphertext_hash) = 32),
  last_error TEXT CHECK (last_error IS NULL OR octet_length(last_error) <= 512),
  copied_at TIMESTAMPTZ,
  verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (snapshot_id, center_id),
  UNIQUE (center_id, object_key)
);

-- Retention removes the encrypted object row, but this append-only ledger keeps
-- the old immutable folder's provenance (snapshot/hash/center/time).
CREATE TABLE backup_retention_event (
  retention_event_id BIGSERIAL PRIMARY KEY,
  registry_id TEXT NOT NULL,
  center_id TEXT NOT NULL REFERENCES backup_center(center_id),
  snapshot_id UUID NOT NULL,
  snapshot_version BIGINT NOT NULL CHECK (snapshot_version > 0),
  replica_id UUID NOT NULL,
  object_key TEXT NOT NULL,
  snapshot_status TEXT NOT NULL CHECK (snapshot_status IN ('FINALIZED', 'NON_FINALIZED')),
  ciphertext_hash BYTEA NOT NULL CHECK (octet_length(ciphertext_hash) = 32),
  removed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reason TEXT NOT NULL DEFAULT 'RETENTION_WINDOW'
    CHECK (reason = 'RETENTION_WINDOW')
);

CREATE INDEX backup_center_registry_idx ON backup_center (registry_id, active, created_at);
CREATE INDEX snapshot_registry_idx ON snapshot (registry_id, snapshot_version DESC);
CREATE INDEX snapshot_replica_center_idx ON snapshot_replica (center_id, created_at);
CREATE INDEX backup_retention_registry_idx ON backup_retention_event (registry_id, removed_at DESC);

-- Snapshot envelopes are immutable. Retention only removes replica rows and
-- records their provenance in backup_retention_event.
CREATE FUNCTION reject_snapshot_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is immutable', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER snapshot_update_guard
BEFORE UPDATE OR DELETE ON snapshot
FOR EACH ROW EXECUTE FUNCTION reject_snapshot_mutation();

REVOKE UPDATE, DELETE ON snapshot, backup_retention_event FROM PUBLIC;

INSERT INTO backup_center (
  center_id, registry_id, name, local_endpoint, volume_name,
  credential_reference, credential_version, created_by
)
SELECT
  'BACKUPCENTER-' || center_number,
  'gov.registry.land',
  'Local BackupCenter ' || lpad(center_number::text, 2, '0'),
  'local://backup-center-' || lpad(center_number::text, 2, '0'),
  'onelayer-backup-volume-' || lpad(center_number::text, 2, '0'),
  'onelayer-backup-credential-' || lpad(center_number::text, 2, '0'),
  'credential-v1',
  'system'
FROM generate_series(1, 5) AS series(center_number)
ON CONFLICT (center_id) DO NOTHING;
