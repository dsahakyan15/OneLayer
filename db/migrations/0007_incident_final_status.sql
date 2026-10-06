-- Preserve finalized incident dispositions instead of treating CONFIRMED as
-- a cleared incident. Deploy with old index writers stopped.
ALTER TABLE incident_index_notice
  DROP CONSTRAINT incident_index_notice_status_check,
  ADD CONSTRAINT incident_index_notice_status_check
    CHECK (status IN ('OPEN', 'CONFIRMED', 'FALSE_POSITIVE', 'RESOLVED'));

-- The previous projection both discarded final dispositions and scanned only
-- one page of signatures. Its watermark cannot be reused as proof of coverage.
-- This is a rebuildable projection: source chain events and local monitor
-- findings are not deleted. Verification stays unavailable/stale until rebuild.
DELETE FROM incident_index_notice;
UPDATE incident_index_state
   SET indexed_through_slot = 0,
       last_signature = NULL,
       updated_at = now();
