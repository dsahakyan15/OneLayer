-- 0022: honest recovery states. A decrypted-and-validated snapshot is no longer
-- reported as RESTORED: VALIDATED means the content was checked (schema,
-- hashes, counts, commitments) but no target database was imported. RESTORED is
-- reserved for an operation that actually imported and verified a target.
-- Legacy rows created before this migration keep their historical label in the
-- table but are reported honestly (SUMMARY_ONLY, not a usable target) because
-- their target holds only a digest/summary.
ALTER TABLE recovery_operation DROP CONSTRAINT IF EXISTS recovery_operation_state_check;
ALTER TABLE recovery_operation ADD CONSTRAINT recovery_operation_state_check
  CHECK (state IN ('AWAITING_APPROVAL', 'APPROVED', 'VALIDATED', 'RESTORED', 'FAILED'));

ALTER TABLE recovery_restore_target
  ADD COLUMN target_kind TEXT NOT NULL DEFAULT 'SUMMARY_ONLY'
    CHECK (target_kind IN ('SUMMARY_ONLY', 'IMPORTED')),
  ADD COLUMN imported_at TIMESTAMPTZ;
