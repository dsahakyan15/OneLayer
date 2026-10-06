-- Bounded recovery orchestration. Recovery shares, the recovered KEK and
-- Snapshot plaintext are process-memory values only; none have a column here.

CREATE TABLE recovery_operation (
  recovery_operation_id UUID PRIMARY KEY,
  registry_id TEXT NOT NULL,
  center_id TEXT NOT NULL REFERENCES backup_center(center_id),
  snapshot_id UUID NOT NULL REFERENCES snapshot(snapshot_id),
  target TEXT NOT NULL CHECK (target ~ '^local-demo-[A-Za-z0-9._-]{1,80}$'),
  state TEXT NOT NULL CHECK (state IN ('AWAITING_APPROVAL', 'APPROVED', 'RESTORED', 'FAILED')),
  anchor_batch_sequence BIGINT NOT NULL CHECK (anchor_batch_sequence > 0),
  anchor_slot BIGINT NOT NULL CHECK (anchor_slot > 0),
  merkle_root BYTEA NOT NULL CHECK (octet_length(merkle_root) = 32),
  plaintext_hash BYTEA NOT NULL CHECK (octet_length(plaintext_hash) = 32),
  ciphertext_hash BYTEA NOT NULL CHECK (octet_length(ciphertext_hash) = 32),
  share_threshold SMALLINT NOT NULL DEFAULT 3 CHECK (share_threshold = 3),
  failure_code TEXT,
  created_by TEXT NOT NULL,
  approved_by TEXT,
  approval_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  approved_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ
);

CREATE INDEX recovery_operation_registry_idx
  ON recovery_operation (registry_id, created_at DESC);

CREATE TABLE restore_approval (
  approval_id UUID PRIMARY KEY,
  recovery_operation_id UUID NOT NULL UNIQUE REFERENCES recovery_operation(recovery_operation_id),
  registry_id TEXT NOT NULL,
  snapshot_id UUID NOT NULL REFERENCES snapshot(snapshot_id),
  merkle_root BYTEA NOT NULL CHECK (octet_length(merkle_root) = 32),
  target TEXT NOT NULL CHECK (target ~ '^local-demo-[A-Za-z0-9._-]{1,80}$'),
  approval_digest BYTEA NOT NULL CHECK (octet_length(approval_digest) = 32),
  approval_signature BYTEA NOT NULL CHECK (octet_length(approval_signature) = 64),
  signed_by TEXT NOT NULL,
  signed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE recovery_operation
  ADD CONSTRAINT recovery_operation_approval_fk
  FOREIGN KEY (approval_id) REFERENCES restore_approval(approval_id);

CREATE TABLE recovery_restore_target (
  registry_id TEXT NOT NULL,
  target_id TEXT NOT NULL CHECK (target_id ~ '^local-demo-[A-Za-z0-9._-]{1,80}$'),
  recovery_operation_id UUID NOT NULL UNIQUE REFERENCES recovery_operation(recovery_operation_id),
  snapshot_id UUID NOT NULL REFERENCES snapshot(snapshot_id),
  merkle_root BYTEA NOT NULL CHECK (octet_length(merkle_root) = 32),
  plaintext_hash BYTEA NOT NULL CHECK (octet_length(plaintext_hash) = 32),
  state_summary JSONB NOT NULL,
  restored_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (registry_id, target_id)
);

CREATE INDEX restore_approval_registry_idx
  ON restore_approval (registry_id, signed_at DESC);

-- An approval is an immutable signed authorization. The operation and target
-- rows may advance state, but the approval itself cannot be edited or removed.
CREATE FUNCTION reject_restore_approval_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'restore_approval is immutable';
END;
$$;

CREATE TRIGGER restore_approval_update_guard
BEFORE UPDATE OR DELETE ON restore_approval
FOR EACH ROW EXECUTE FUNCTION reject_restore_approval_mutation();

REVOKE UPDATE, DELETE ON restore_approval FROM PUBLIC;
REVOKE UPDATE, DELETE ON recovery_restore_target FROM PUBLIC;
