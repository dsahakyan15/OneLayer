-- 0023: full-state checkpoint V2, independent Backup Center volumes and the
-- isolated recovery ceremony (tickets 14-18). Additive only; the frozen V1
-- snapshot format and its vectors are untouched.
--
-- This schema stores commitments and state, never secrets: no recovery share,
-- no KEK, no plaintext state and no session credential has a column here.

-- ---------------------------------------------------------------------------
-- 1. Backup Centers become real, independently addressable volumes.
-- ---------------------------------------------------------------------------
ALTER TABLE backup_center
  ADD COLUMN storage_backend TEXT NOT NULL DEFAULT 'POSTGRES_INLINE'
    CHECK (storage_backend IN ('POSTGRES_INLINE', 'FILESYSTEM')),
  ADD COLUMN quota_bytes BIGINT CHECK (quota_bytes IS NULL OR quota_bytes > 0);

ALTER TABLE snapshot_replica
  ADD COLUMN storage_backend TEXT NOT NULL DEFAULT 'POSTGRES_INLINE'
    CHECK (storage_backend IN ('POSTGRES_INLINE', 'FILESYSTEM')),
  ADD COLUMN volume_name TEXT,
  ADD COLUMN stored_path TEXT,
  ADD COLUMN read_back_at TIMESTAMPTZ,
  ADD COLUMN object_lock_until TIMESTAMPTZ,
  -- Raw sha256 of the stored object bytes; the envelope hash stays in
  -- ciphertext_hash and is re-checked after decryption.
  ADD COLUMN object_sha256 BYTEA CHECK (object_sha256 IS NULL OR octet_length(object_sha256) = 32);

ALTER TABLE snapshot_replica
  ADD CONSTRAINT snapshot_replica_filesystem_binding CHECK (
    storage_backend = 'POSTGRES_INLINE'
    OR (volume_name IS NOT NULL AND stored_path IS NOT NULL AND read_back_at IS NOT NULL)
  );

-- The central PostgreSQL package bytes are an inline-demo fallback. A
-- filesystem replica is a genuine second copy only after a read-back.
ALTER TABLE snapshot_replica
  DROP CONSTRAINT IF EXISTS snapshot_replica_copy_status_check,
  ADD CONSTRAINT snapshot_replica_copy_status_check
    CHECK (copy_status IN ('COPIED', 'PENDING_RETRY', 'FAILED', 'LOST'));

-- ---------------------------------------------------------------------------
-- 2. External checkpoint manifest (V2). Immutable once recorded.
-- ---------------------------------------------------------------------------
ALTER TABLE snapshot
  ADD COLUMN checkpoint_status TEXT NOT NULL DEFAULT 'NONE'
    CHECK (checkpoint_status IN ('NONE', 'BUILT', 'BOUND_SIMULATED', 'BOUND')),
  ADD COLUMN checkpoint_hash BYTEA CHECK (checkpoint_hash IS NULL OR octet_length(checkpoint_hash) = 32),
  ADD COLUMN capture_boundary JSONB,
  ADD COLUMN binding_batch_sequence BIGINT CHECK (binding_batch_sequence IS NULL OR binding_batch_sequence > 0),
  ADD COLUMN binding_slot BIGINT CHECK (binding_slot IS NULL OR binding_slot > 0);

ALTER TABLE snapshot
  ADD CONSTRAINT snapshot_checkpoint_binding CHECK (
    (checkpoint_status = 'NONE' AND checkpoint_hash IS NULL)
    OR (checkpoint_status <> 'NONE' AND checkpoint_hash IS NOT NULL)
  );

-- 0005 froze the whole snapshot row. The checkpoint binding must be recorded
-- after capture, so the guard now protects every immutable payload column while
-- allowing only the binding/status metadata to advance. The envelope bytes,
-- hashes, length and key version can never change.
CREATE OR REPLACE FUNCTION reject_snapshot_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'snapshot is immutable';
  END IF;
  IF (OLD.snapshot_id, OLD.registry_id, OLD.snapshot_version, OLD.format_version,
      OLD.package_format, OLD.merkle_root, OLD.plaintext_hash, OLD.ciphertext_hash,
      OLD.encrypted_package, OLD.plaintext_length, OLD.key_encryption_version,
      OLD.created_by, OLD.created_at)
     IS DISTINCT FROM
     (NEW.snapshot_id, NEW.registry_id, NEW.snapshot_version, NEW.format_version,
      NEW.package_format, NEW.merkle_root, NEW.plaintext_hash, NEW.ciphertext_hash,
      NEW.encrypted_package, NEW.plaintext_length, NEW.key_encryption_version,
      NEW.created_by, NEW.created_at)
  THEN
    RAISE EXCEPTION 'snapshot payload is immutable';
  END IF;
  RETURN NEW;
END;
$$;

-- The runtime role may only advance the binding metadata columns; a database
-- owner can still bypass triggers, so least-privilege provisioning remains a
-- separate production gate.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'onelayer_runtime') THEN
    EXECUTE 'GRANT UPDATE (checkpoint_status, checkpoint_hash, capture_boundary, '
         || 'binding_batch_sequence, binding_slot, snapshot_status) ON snapshot TO onelayer_runtime';
  END IF;
END $$;

-- The legacy admin approval stays; checkpoint-bound approvals add the exact
-- checkpoint commitment and key version they authorize.
ALTER TABLE restore_approval
  ADD COLUMN checkpoint_hash BYTEA CHECK (checkpoint_hash IS NULL OR octet_length(checkpoint_hash) = 32),
  ADD COLUMN key_encryption_version TEXT,
  ADD COLUMN binding_kind TEXT NOT NULL DEFAULT 'ANCHOR_BATCH'
    CHECK (binding_kind IN ('ANCHOR_BATCH', 'CHECKPOINT_V2'));

CREATE TABLE snapshot_checkpoint_v2 (
  checkpoint_id UUID PRIMARY KEY,
  registry_id TEXT NOT NULL,
  snapshot_id UUID NOT NULL UNIQUE REFERENCES snapshot(snapshot_id),
  format TEXT NOT NULL DEFAULT 'ONELAYER_SNAPSHOT_CHECKPOINT_V2'
    CHECK (format = 'ONELAYER_SNAPSHOT_CHECKPOINT_V2'),
  checkpoint_hash BYTEA NOT NULL CHECK (octet_length(checkpoint_hash) = 32),
  manifest BYTEA NOT NULL CHECK (octet_length(manifest) > 0),
  inventory_hash BYTEA NOT NULL CHECK (octet_length(inventory_hash) = 32),
  boundary_hash BYTEA NOT NULL CHECK (octet_length(boundary_hash) = 32),
  artifacts_hash BYTEA NOT NULL CHECK (octet_length(artifacts_hash) = 32),
  schema_version INTEGER NOT NULL CHECK (schema_version > 0),
  key_encryption_version TEXT NOT NULL CHECK (octet_length(key_encryption_version) BETWEEN 1 AND 64),
  anchor_batch_sequence BIGINT NOT NULL CHECK (anchor_batch_sequence > 0),
  anchor_slot BIGINT NOT NULL CHECK (anchor_slot > 0),
  merkle_root BYTEA NOT NULL CHECK (octet_length(merkle_root) = 32),
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (registry_id, checkpoint_hash)
);

CREATE FUNCTION reject_v2_append_only_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER snapshot_checkpoint_v2_no_update_delete
  BEFORE UPDATE OR DELETE ON snapshot_checkpoint_v2
  FOR EACH ROW EXECUTE FUNCTION reject_v2_append_only_mutation();
CREATE TRIGGER snapshot_checkpoint_v2_no_truncate
  BEFORE TRUNCATE ON snapshot_checkpoint_v2
  FOR EACH STATEMENT EXECUTE FUNCTION reject_v2_append_only_mutation();
REVOKE UPDATE, DELETE, TRUNCATE ON snapshot_checkpoint_v2 FROM PUBLIC;

-- Local drill chain binding. A simulated binding is never on-chain evidence
-- and is labeled as such everywhere it is exposed.
CREATE TABLE checkpoint_binding_simulation (
  simulation_id UUID PRIMARY KEY,
  registry_id TEXT NOT NULL,
  snapshot_id UUID NOT NULL REFERENCES snapshot(snapshot_id),
  checkpoint_hash BYTEA NOT NULL CHECK (octet_length(checkpoint_hash) = 32),
  simulated_batch_sequence BIGINT NOT NULL CHECK (simulated_batch_sequence > 0),
  simulated_slot BIGINT NOT NULL CHECK (simulated_slot > 0),
  label TEXT NOT NULL DEFAULT 'SIMULATED' CHECK (label = 'SIMULATED'),
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (snapshot_id, checkpoint_hash)
);

CREATE TRIGGER checkpoint_binding_simulation_no_update_delete
  BEFORE UPDATE OR DELETE ON checkpoint_binding_simulation
  FOR EACH ROW EXECUTE FUNCTION reject_v2_append_only_mutation();
REVOKE UPDATE, DELETE ON checkpoint_binding_simulation FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- 3. Recovery operation V2: exact binding, expiry and whole state machine.
-- ---------------------------------------------------------------------------
ALTER TABLE recovery_operation DROP CONSTRAINT IF EXISTS recovery_operation_state_check;
ALTER TABLE recovery_operation ADD CONSTRAINT recovery_operation_state_check CHECK (state IN (
  'REQUESTED', 'AWAITING_APPROVAL', 'APPROVED', 'MATERIAL_VERIFIED', 'SHARES_READY',
  'CONTENT_VERIFIED', 'RESTORING', 'VALIDATING', 'VALIDATED', 'RESTORED',
  'CUTOVER_APPROVED', 'ACTIVE', 'FAILED', 'EXPIRED', 'CANCELLED'
));

ALTER TABLE recovery_operation
  ADD COLUMN checkpoint_hash BYTEA CHECK (checkpoint_hash IS NULL OR octet_length(checkpoint_hash) = 32),
  ADD COLUMN binding_kind TEXT NOT NULL DEFAULT 'ANCHOR_BATCH'
    CHECK (binding_kind IN ('ANCHOR_BATCH', 'CHECKPOINT_V2')),
  ADD COLUMN key_encryption_version TEXT,
  ADD COLUMN nonce BYTEA CHECK (nonce IS NULL OR octet_length(nonce) = 16),
  ADD COLUMN expires_at TIMESTAMPTZ;

-- A holder contributes exactly one share for one operation. The contribution
-- row records only the index, the holder, the key version and the digest of
-- the contribution receipt; share bytes are never persisted.
CREATE TABLE recovery_share_contribution (
  contribution_id UUID PRIMARY KEY,
  recovery_operation_id UUID NOT NULL REFERENCES recovery_operation(recovery_operation_id),
  registry_id TEXT NOT NULL,
  holder_id TEXT NOT NULL CHECK (holder_id ~ '^[A-Za-z0-9._-]{1,64}$'),
  share_index SMALLINT NOT NULL CHECK (share_index BETWEEN 1 AND 5),
  key_encryption_version TEXT NOT NULL,
  binding_digest BYTEA NOT NULL CHECK (octet_length(binding_digest) = 32),
  receipt_digest BYTEA NOT NULL CHECK (octet_length(receipt_digest) = 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (recovery_operation_id, share_index),
  UNIQUE (recovery_operation_id, holder_id)
);

CREATE INDEX recovery_share_contribution_operation_idx
  ON recovery_share_contribution (recovery_operation_id, share_index);

-- Durable target import/validation evidence; summary-only is not importable.
CREATE TABLE recovery_target_import (
  import_id UUID PRIMARY KEY,
  recovery_operation_id UUID NOT NULL UNIQUE REFERENCES recovery_operation(recovery_operation_id),
  registry_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  target_kind TEXT NOT NULL CHECK (target_kind IN ('SUMMARY_ONLY', 'IMPORTED')),
  database_identity TEXT,
  table_counts JSONB NOT NULL DEFAULT '{}'::jsonb,
  reference_check TEXT CHECK (reference_check IS NULL OR reference_check IN ('PASS', 'FAIL')),
  commitment_check TEXT CHECK (commitment_check IS NULL OR commitment_check IN ('PASS', 'FAIL')),
  artifact_check TEXT CHECK (artifact_check IS NULL OR artifact_check IN ('PASS', 'FAIL')),
  fenced BOOLEAN NOT NULL DEFAULT false,
  fence_reason TEXT,
  failure_code TEXT,
  imported_at TIMESTAMPTZ,
  validated_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Separate cutover authorization: distinct credential, exact binding, nonce
-- and expiry. The row is immutable.
CREATE TABLE recovery_cutover_approval (
  cutover_approval_id UUID PRIMARY KEY,
  recovery_operation_id UUID NOT NULL UNIQUE REFERENCES recovery_operation(recovery_operation_id),
  registry_id TEXT NOT NULL,
  checkpoint_hash BYTEA NOT NULL CHECK (octet_length(checkpoint_hash) = 32),
  target_id TEXT NOT NULL,
  nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 16),
  expires_at TIMESTAMPTZ NOT NULL,
  approval_digest BYTEA NOT NULL CHECK (octet_length(approval_digest) = 32),
  approval_signature BYTEA NOT NULL CHECK (octet_length(approval_signature) = 64),
  signed_by TEXT NOT NULL,
  signed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER recovery_cutover_approval_no_update_delete
  BEFORE UPDATE OR DELETE ON recovery_cutover_approval
  FOR EACH ROW EXECUTE FUNCTION reject_v2_append_only_mutation();
REVOKE UPDATE, DELETE ON recovery_cutover_approval FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- 4. Custody registry (ticket 16). Public keys and receipts only.
-- ---------------------------------------------------------------------------
CREATE TABLE recovery_holder (
  holder_id TEXT NOT NULL CHECK (holder_id ~ '^[A-Za-z0-9._-]{1,64}$'),
  registry_id TEXT NOT NULL,
  display_name TEXT NOT NULL CHECK (octet_length(display_name) BETWEEN 1 AND 120),
  share_index SMALLINT NOT NULL CHECK (share_index BETWEEN 1 AND 5),
  key_encryption_version TEXT NOT NULL,
  identity_public_key BYTEA NOT NULL CHECK (octet_length(identity_public_key) = 32),
  receipt_digest BYTEA NOT NULL CHECK (octet_length(receipt_digest) = 32),
  receipt_signature BYTEA NOT NULL CHECK (octet_length(receipt_signature) = 64),
  provisioned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (registry_id, holder_id),
  UNIQUE (registry_id, share_index)
);

CREATE FUNCTION recovery_holder_no_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'recovery holders are append-only' USING ERRCODE = '55000';
END;
$$;
CREATE TRIGGER recovery_holder_no_delete
  BEFORE DELETE ON recovery_holder
  FOR EACH ROW EXECUTE FUNCTION recovery_holder_no_delete();
CREATE TRIGGER recovery_holder_no_truncate
  BEFORE TRUNCATE ON recovery_holder
  FOR EACH STATEMENT EXECUTE FUNCTION recovery_holder_no_delete();
REVOKE DELETE, TRUNCATE ON recovery_holder FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- 5. Isolated controller audit. Operation IDs and digests only; never a share,
-- a KEK or plaintext.
-- ---------------------------------------------------------------------------
CREATE TABLE recovery_controller_audit (
  audit_sequence BIGSERIAL PRIMARY KEY,
  registry_id TEXT NOT NULL,
  recovery_operation_id UUID,
  event TEXT NOT NULL CHECK (event ~ '^[A-Z_]{1,64}$'),
  actor TEXT NOT NULL CHECK (octet_length(actor) BETWEEN 1 AND 128),
  detail JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE FUNCTION recovery_controller_audit_no_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'recovery controller audit is append-only' USING ERRCODE = '55000';
END;
$$;
CREATE TRIGGER recovery_controller_audit_no_update
  BEFORE UPDATE OR DELETE ON recovery_controller_audit
  FOR EACH ROW EXECUTE FUNCTION recovery_controller_audit_no_update();
REVOKE UPDATE, DELETE ON recovery_controller_audit FROM PUBLIC;
