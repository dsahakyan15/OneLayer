-- Ticket 04 / defect D1: the on-chain IncidentNotice stores its suspect range
-- as u64 and the program only enforces first_suspect_batch <= last_suspect_batch
-- (onchain/programs/onelayer-registry/src/lib.rs, open_incident). The old
-- projection required first_suspect_batch > 0 and stored u64 in signed BIGINT,
-- so a valid finalized notice with first = 0 or last > 2^63-1 could never be
-- applied and every refresh rolled back: the index stayed unavailable forever.
--
-- The projection keeps its rows and watermark. Every existing row satisfied the
-- old, stricter constraints, which are a subset of the new domain, so the
-- conversion is exact and every committed row still matches finalized state.
-- A notice that was previously unstorable never committed (its refresh rolled
-- back together with the watermark), so no coverage claim depends on it; the
-- next refresh after this migration picks it up from the unchanged cursor.
-- No reset (unlike 0007) is therefore needed.
--
-- ALTER COLUMN TYPE rewrites the table under ACCESS EXCLUSIVE; concurrent index
-- writers simply wait. Writers of the previous release stay compatible: they
-- bind the values as decimal strings.
-- Runs inside the migration transaction (native runner: psql -1). Do not wait
-- forever behind a long-running reader/writer; retry the migration instead.
SET LOCAL lock_timeout = '15s';

-- numeric(20) has scale 0, so stored values are always integers; the u64
-- range and ordering are enforced below. (A fractional literal would be
-- rounded by the cast before any CHECK runs; writers bind bigint decimal
-- strings only.) The migration is idempotent: a re-run drops and re-adds the
-- same constraints and re-applies the (identical) column type.

-- The 0003 CHECKs were unnamed (generated names differ for the single- and
-- two-column checks), so drop every CHECK that mentions a suspect column.
DO $$
DECLARE constraint_name text;
BEGIN
  FOR constraint_name IN
    SELECT conname FROM pg_constraint
     WHERE conrelid = 'incident_index_notice'::regclass AND contype = 'c'
       AND pg_get_constraintdef(oid) ~ 'suspect_batch'
  LOOP
    EXECUTE format('ALTER TABLE incident_index_notice DROP CONSTRAINT %I', constraint_name);
  END LOOP;
END $$;

ALTER TABLE incident_index_notice
  ALTER COLUMN first_suspect_batch TYPE numeric(20) USING first_suspect_batch::numeric(20),
  ALTER COLUMN last_suspect_batch TYPE numeric(20) USING last_suspect_batch::numeric(20);

ALTER TABLE incident_index_notice
  ADD CONSTRAINT incident_index_notice_first_suspect_batch_u64
    CHECK (first_suspect_batch BETWEEN 0 AND 18446744073709551615),
  ADD CONSTRAINT incident_index_notice_last_suspect_batch_u64
    CHECK (last_suspect_batch BETWEEN 0 AND 18446744073709551615),
  ADD CONSTRAINT incident_index_notice_suspect_range_ordered
    CHECK (first_suspect_batch <= last_suspect_batch);
