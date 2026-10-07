-- 0025: recovery integrity and durable fences (tickets 14-18 review fixes
-- G6/G8/G9/G12/G15). Additive only: no historical migration is modified, and
-- the frozen V1 snapshot format/vectors stay untouched.
--
-- This migration stores commitments, manifests and fence state. It never
-- stores a recovery share, a KEK or plaintext state.

-- ---------------------------------------------------------------------------
-- 1. Snapshot trust transitions (G15): a full-state (V2) snapshot may only be
--    FINALIZED when its checkpoint is BOUND and its capture boundary is known.
--    Checkpoint status is monotonic and a binding must carry its provenance
--    columns.
-- ---------------------------------------------------------------------------
ALTER TABLE snapshot
  ADD COLUMN payload_format TEXT NOT NULL DEFAULT 'ONELAYER_SNAPSHOT_STATE_V1'
    CHECK (payload_format IN ('ONELAYER_SNAPSHOT_STATE_V1', 'ONELAYER_SNAPSHOT_STATE_V2')),
  ADD COLUMN binding_provenance JSONB;

CREATE FUNCTION snapshot_trust_transition_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.payload_format IS DISTINCT FROM OLD.payload_format THEN
      RAISE EXCEPTION 'snapshot payload format is immutable';
    END IF;
    IF OLD.binding_provenance IS NOT NULL
       AND NEW.binding_provenance IS DISTINCT FROM OLD.binding_provenance THEN
      RAISE EXCEPTION 'snapshot binding provenance is write-once';
    END IF;
    IF NEW.checkpoint_status IS DISTINCT FROM OLD.checkpoint_status
       AND NOT (
         (OLD.checkpoint_status = 'NONE' AND NEW.checkpoint_status = 'BUILT')
         OR (OLD.checkpoint_status = 'BUILT' AND NEW.checkpoint_status IN ('BOUND_SIMULATED', 'BOUND'))
         OR (OLD.checkpoint_status = 'BOUND_SIMULATED' AND NEW.checkpoint_status = 'BOUND')
       ) THEN
      RAISE EXCEPTION 'checkpoint status is monotonic (NONE -> BUILT -> BOUND[_SIMULATED])';
    END IF;
  END IF;
  IF NEW.checkpoint_status IN ('BOUND_SIMULATED', 'BOUND') THEN
    IF NEW.checkpoint_hash IS NULL OR NEW.binding_batch_sequence IS NULL OR NEW.binding_slot IS NULL THEN
      RAISE EXCEPTION 'a checkpoint binding requires its hash, batch sequence and slot';
    END IF;
  END IF;
  IF NEW.payload_format = 'ONELAYER_SNAPSHOT_STATE_V2' AND NEW.snapshot_status = 'FINALIZED' THEN
    IF NEW.checkpoint_status IS DISTINCT FROM 'BOUND' THEN
      RAISE EXCEPTION 'a full-state snapshot is FINALIZED only with a BOUND checkpoint';
    END IF;
    IF NEW.capture_boundary IS NULL THEN
      RAISE EXCEPTION 'a full-state snapshot is FINALIZED only with a recorded capture boundary';
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER snapshot_trust_transition_guard
  BEFORE INSERT OR UPDATE ON snapshot
  FOR EACH ROW EXECUTE FUNCTION snapshot_trust_transition_guard();

-- ---------------------------------------------------------------------------
-- 2. Controller-issued cutover nonce/expiry (G8) and threshold hygiene (G16).
-- ---------------------------------------------------------------------------
ALTER TABLE recovery_operation DROP CONSTRAINT IF EXISTS recovery_operation_share_threshold_check;
ALTER TABLE recovery_operation
  ADD CONSTRAINT recovery_operation_share_threshold_check CHECK (share_threshold BETWEEN 3 AND 5),
  ADD COLUMN cutover_nonce BYTEA CHECK (cutover_nonce IS NULL OR octet_length(cutover_nonce) = 16),
  ADD COLUMN cutover_expires_at TIMESTAMPTZ;

-- The isolated controller database does not host the primary's catalog tables
-- (`snapshot`, `backup_center`): the operation binds the snapshot and center by
-- id plus the verified material copied below (manifest, hashes, replica
-- binding), which is the controller's own integrity source (review G6). The
-- cross-database foreign keys are therefore dropped here; on a co-located
-- deployment the application layer still resolves both.
ALTER TABLE recovery_operation
  DROP CONSTRAINT IF EXISTS recovery_operation_snapshot_id_fkey,
  DROP CONSTRAINT IF EXISTS recovery_operation_center_id_fkey;
ALTER TABLE restore_approval
  DROP CONSTRAINT IF EXISTS restore_approval_snapshot_id_fkey;
ALTER TABLE recovery_restore_target
  DROP CONSTRAINT IF EXISTS recovery_restore_target_snapshot_id_fkey;

-- ---------------------------------------------------------------------------
-- 3. Controller-owned recovery material (G6): at createOperation the verified
--    manifest, inventory, artifact set, boundary and replica binding are copied
--    here. The whole ceremony (verify/restore) then runs against the controller
--    database and the selected center volume only, so the primary database may
--    be offline. Append-only.
-- ---------------------------------------------------------------------------
CREATE TABLE recovery_operation_material (
  recovery_operation_id UUID PRIMARY KEY REFERENCES recovery_operation(recovery_operation_id),
  registry_id TEXT NOT NULL,
  snapshot_id UUID NOT NULL,
  checkpoint_hash BYTEA NOT NULL CHECK (octet_length(checkpoint_hash) = 32),
  manifest BYTEA NOT NULL CHECK (octet_length(manifest) > 0),
  inventory JSONB NOT NULL,
  artifacts JSONB NOT NULL,
  boundary JSONB NOT NULL,
  key_encryption_version TEXT NOT NULL CHECK (octet_length(key_encryption_version) BETWEEN 1 AND 120),
  plaintext_hash BYTEA NOT NULL CHECK (octet_length(plaintext_hash) = 32),
  ciphertext_hash BYTEA NOT NULL CHECK (octet_length(ciphertext_hash) = 32),
  center_id TEXT NOT NULL,
  volume_name TEXT NOT NULL,
  credential_reference TEXT NOT NULL,
  object_key TEXT NOT NULL,
  object_sha256 BYTEA NOT NULL CHECK (octet_length(object_sha256) = 32),
  binding_provenance JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE FUNCTION recovery_material_no_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'recovery operation material is append-only' USING ERRCODE = '55000';
END $$;
CREATE TRIGGER recovery_operation_material_no_update_delete
  BEFORE UPDATE OR DELETE ON recovery_operation_material
  FOR EACH ROW EXECUTE FUNCTION recovery_material_no_update();
CREATE TRIGGER recovery_operation_material_no_truncate
  BEFORE TRUNCATE ON recovery_operation_material
  FOR EACH STATEMENT EXECUTE FUNCTION recovery_material_no_update();
REVOKE UPDATE, DELETE, TRUNCATE ON recovery_operation_material FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- 4. Reconciliation record (ticket 18): pending external sends stay blocked
--    until chain reconciliation is recorded and the separate cutover approval
--    activates the target. append-only.
-- ---------------------------------------------------------------------------
CREATE TABLE recovery_target_reconciliation (
  reconciliation_id UUID PRIMARY KEY,
  recovery_operation_id UUID NOT NULL UNIQUE REFERENCES recovery_operation(recovery_operation_id),
  registry_id TEXT NOT NULL,
  checkpoint_hash BYTEA NOT NULL CHECK (octet_length(checkpoint_hash) = 32),
  catch_up_boundary JSONB NOT NULL,
  chain_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  digest BYTEA NOT NULL CHECK (octet_length(digest) = 32),
  recorded_by TEXT NOT NULL CHECK (octet_length(recorded_by) BETWEEN 1 AND 128),
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER recovery_target_reconciliation_no_update_delete
  BEFORE UPDATE OR DELETE ON recovery_target_reconciliation
  FOR EACH ROW EXECUTE FUNCTION recovery_material_no_update();
CREATE TRIGGER recovery_target_reconciliation_no_truncate
  BEFORE TRUNCATE ON recovery_target_reconciliation
  FOR EACH STATEMENT EXECUTE FUNCTION recovery_material_no_update();
REVOKE UPDATE, DELETE, TRUNCATE ON recovery_target_reconciliation FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- 5. Retention hold (G9): retention never unlinks a replica under an explicit
--    hold (set while a recovery operation may still need it).
-- ---------------------------------------------------------------------------
ALTER TABLE snapshot_replica
  ADD COLUMN recovery_hold BOOLEAN NOT NULL DEFAULT FALSE;

-- ---------------------------------------------------------------------------
-- 6. Durable DB-level writer fence (ticket 18 / review gate 3). While a target
--    carries `pending_sends_fenced`, the external-send write path is refused by
--    the database itself; the API/worker must additionally call
--    assertPendingSendsAllowed (apps/recovery/src/fence.ts) so callers see an
--    honest error. The fence is released only by the separately approved
--    cutover (activation).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS recovery_fence (
  registry_id TEXT PRIMARY KEY,
  recovery_operation_id UUID NOT NULL,
  checkpoint_hash BYTEA NOT NULL CHECK (octet_length(checkpoint_hash) = 32),
  fenced BOOLEAN NOT NULL DEFAULT TRUE,
  pending_sends_fenced BOOLEAN NOT NULL DEFAULT TRUE,
  cutover_approved BOOLEAN NOT NULL DEFAULT FALSE,
  reconciled_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE FUNCTION recovery_pending_sends_blocked() RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM recovery_fence WHERE pending_sends_fenced)
$$;

CREATE FUNCTION recovery_fence_block_writes() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF recovery_pending_sends_blocked() THEN
    RAISE EXCEPTION 'recovery fence: external sends are blocked until reconciliation and cutover'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END $$;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['wf_publication_tx','wf_publication_tx_signed','wf_publication_tx_event',
                          'wf_publication_anchor','demo_publish_intent','publish_attempt'] LOOP
    EXECUTE format('CREATE TRIGGER recovery_fence_guard BEFORE INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION recovery_fence_block_writes()', t);
  END LOOP;
END $$;
