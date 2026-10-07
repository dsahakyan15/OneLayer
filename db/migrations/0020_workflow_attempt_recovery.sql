-- Durable receipts contain request commitments, never payloads or credentials.
CREATE TABLE wf_attempt (
 attempt_id uuid PRIMARY KEY, registry_id text NOT NULL, actor text NOT NULL,
 request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),
 action text NOT NULL CHECK(action IN ('create','edit','submit','approve','reject','commit')),
 record_id text NOT NULL, draft_id uuid REFERENCES wf_draft,
 field_paths jsonb NOT NULL CHECK(jsonb_typeof(field_paths)='array'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX wf_attempt_actor ON wf_attempt(registry_id,actor,created_at);
CREATE INDEX wf_attempt_request ON wf_attempt(registry_id,actor,request_hash);
CREATE TABLE wf_attempt_ack (attempt_id uuid PRIMARY KEY REFERENCES wf_attempt, acknowledged_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON wf_attempt FOR EACH ROW EXECUTE FUNCTION wf_immutable();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON wf_attempt_ack FOR EACH ROW EXECUTE FUNCTION wf_immutable();
CREATE TRIGGER immutable_truncate BEFORE TRUNCATE ON wf_attempt FOR EACH STATEMENT EXECUTE FUNCTION wf_immutable();
CREATE TRIGGER immutable_truncate BEFORE TRUNCATE ON wf_attempt_ack FOR EACH STATEMENT EXECUTE FUNCTION wf_immutable();
CREATE TABLE wf_attempt_cancel (attempt_id uuid PRIMARY KEY REFERENCES wf_attempt, cancelled_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON wf_attempt_cancel FOR EACH ROW EXECUTE FUNCTION wf_immutable();
CREATE TRIGGER immutable_truncate BEFORE TRUNCATE ON wf_attempt_cancel FOR EACH STATEMENT EXECUTE FUNCTION wf_immutable();
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='onelayer_runtime') THEN
 REVOKE UPDATE, DELETE, TRUNCATE ON wf_attempt, wf_attempt_ack, wf_attempt_cancel FROM onelayer_runtime;
 END IF;
END $$;

-- Keyset discovery remains indexed even when most rows are scope-filtered.
CREATE INDEX wf_draft_registry_cursor ON wf_draft(registry_id,draft_id);
