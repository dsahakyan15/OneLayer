-- Ticket 13: protected audit evidence.
--
-- Additive schema for the critical-action evidence pipeline:
--   * audit_evidence_outbox  — durable source of truth for undelivered critical
--     events; identity/payload immutable, delivery ack moves only NULL -> value;
--   * audit_evidence_projection — rebuildable read model, append-only;
--   * audit_evidence_rebuild_state — durable rebuild cursor/status singleton.
--
-- Grants follow 0016: runtime gets DML by default privileges; append-only
-- tables REVOKE UPDATE/DELETE. onelayer_monitor is deliberately NOT granted
-- these tables: Monitor reads only the protected workflow/publication source.
-- No new role or secret is created here.

CREATE TABLE audit_evidence_source_cursor (
  source_identity text PRIMARY KEY,
  next_sequence bigint NOT NULL CHECK (next_sequence > 0)
);

-- Gap-free per-source sequence allocation inside the caller's transaction:
--   UPDATE audit_evidence_source_cursor SET next_sequence = next_sequence + 1
--    WHERE source_identity = $1 RETURNING next_sequence - 1
-- A rolled-back enqueue rolls back the allocation with it.
INSERT INTO audit_evidence_source_cursor (source_identity, next_sequence)
VALUES ('demo-api', 1)
ON CONFLICT (source_identity) DO NOTHING;

CREATE TABLE audit_evidence_outbox (
  event_id uuid PRIMARY KEY,
  source_identity text NOT NULL,
  source_sequence bigint NOT NULL CHECK (source_sequence > 0),
  registry_id text NOT NULL,
  event_digest text NOT NULL CHECK (event_digest ~ '^[0-9a-f]{64}$'),
  event jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  delivered_at timestamptz,
  destination_seq bigint,
  destination_hash text,
  UNIQUE (source_identity, source_sequence),
  CHECK ((delivered_at IS NULL) = (destination_seq IS NULL))
);

CREATE FUNCTION audit_evidence_outbox_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.event_id, NEW.source_identity, NEW.source_sequence, NEW.registry_id,
      NEW.event_digest, NEW.event, NEW.created_at)
     IS DISTINCT FROM
     (OLD.event_id, OLD.source_identity, OLD.source_sequence, OLD.registry_id,
      OLD.event_digest, OLD.event, OLD.created_at) THEN
    RAISE EXCEPTION 'audit evidence outbox identity/payload is immutable';
  END IF;
  IF OLD.delivered_at IS NOT NULL
     AND (NEW.delivered_at, NEW.destination_seq, NEW.destination_hash)
         IS DISTINCT FROM (OLD.delivered_at, OLD.destination_seq, OLD.destination_hash) THEN
    RAISE EXCEPTION 'audit evidence delivery ack is final';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER audit_evidence_outbox_update_guard
BEFORE UPDATE ON audit_evidence_outbox
FOR EACH ROW EXECUTE FUNCTION audit_evidence_outbox_guard();

CREATE TRIGGER audit_evidence_outbox_delete_guard
BEFORE DELETE ON audit_evidence_outbox
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TABLE audit_evidence_projection (
  source_identity text NOT NULL,
  source_sequence bigint NOT NULL CHECK (source_sequence > 0),
  event_id uuid NOT NULL,
  event_digest text NOT NULL CHECK (event_digest ~ '^[0-9a-f]{64}$'),
  registry_id text NOT NULL,
  event jsonb NOT NULL,
  destination_seq bigint NOT NULL,
  destination_hash text NOT NULL,
  projected_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (source_identity, source_sequence),
  UNIQUE (event_id)
);

CREATE TRIGGER audit_evidence_projection_update_guard
BEFORE UPDATE OR DELETE ON audit_evidence_projection
FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

CREATE TABLE audit_evidence_rebuild_state (
  id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  status text NOT NULL CHECK (status IN ('IDLE', 'REBUILDING', 'COMPLETE', 'FAILED')),
  source_identity text,
  cursor_sequence bigint NOT NULL DEFAULT 0 CHECK (cursor_sequence >= 0),
  head_sequence bigint NOT NULL DEFAULT 0 CHECK (head_sequence >= 0),
  head_hash text,
  floor_sequence bigint NOT NULL DEFAULT 0 CHECK (floor_sequence >= 0),
  started_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  error text,
  CHECK (status <> 'COMPLETE' OR cursor_sequence = head_sequence)
);

INSERT INTO audit_evidence_rebuild_state (id, status)
VALUES (1, 'IDLE')
ON CONFLICT (id) DO NOTHING;

-- Append-only enforcement for the runtime role: 0016 granted default DML to
-- onelayer_runtime for tables created later, so revoke mutation rights here.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'onelayer_runtime') THEN
    REVOKE UPDATE, DELETE ON audit_evidence_projection FROM onelayer_runtime;
    REVOKE DELETE ON audit_evidence_outbox FROM onelayer_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'onelayer_monitor') THEN
    REVOKE ALL ON audit_evidence_source_cursor, audit_evidence_outbox,
      audit_evidence_projection, audit_evidence_rebuild_state FROM onelayer_monitor;
  END IF;
END $$;
