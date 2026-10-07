-- 0021: link legacy certificate projection rows to workflow publication
-- anchors. Workflow-issued certificates are stored in demo_certificate so the
-- existing public lookup, QR and verifier routes keep working, but they must be
-- distinguishable from legacy synthetic certificates and idempotent per
-- (operation, record version, disclosure). All new columns are nullable:
-- existing rows are untouched.
ALTER TABLE demo_certificate
  ADD COLUMN anchor_operation_id UUID,
  ADD COLUMN anchor_intent_hash TEXT CHECK (anchor_intent_hash IS NULL OR anchor_intent_hash ~ '^[0-9a-f]{64}$');

-- One certificate per (publication operation, record, version, disclosure).
-- Legacy rows keep anchor_operation_id NULL and are not constrained.
CREATE UNIQUE INDEX demo_certificate_workflow_issuance
  ON demo_certificate (registry_id, anchor_operation_id, internal_record_id, record_version, disclosure_mode, disclosed_paths)
  WHERE anchor_operation_id IS NOT NULL;

-- Lookup helper for the honest lifecycle route: current workflow version of a
-- record without scanning the whole registry.
CREATE INDEX wf_version_record_idx ON wf_version (registry_id, record_id, version DESC);
