-- Workflow v1 is deliberately separate from legacy demo record writers.
CREATE TABLE wf_record (registry_id text NOT NULL, record_id text NOT NULL, version integer NOT NULL DEFAULT 0, PRIMARY KEY(registry_id,record_id));
CREATE TABLE wf_draft (draft_id uuid PRIMARY KEY, registry_id text NOT NULL, record_id text NOT NULL, creator text NOT NULL, revision integer NOT NULL, base_version integer NOT NULL CHECK(base_version>=0), state text NOT NULL CHECK(state IN ('DRAFT','SUBMITTED','APPROVED','REJECTED','COMMITTED')), approver text, committed_version integer);
CREATE TABLE wf_revision (draft_id uuid NOT NULL REFERENCES wf_draft, revision integer NOT NULL, payload jsonb NOT NULL, payload_hash text NOT NULL, operation text NOT NULL CHECK(operation IN ('upsert','tombstone')), editor text NOT NULL, PRIMARY KEY(draft_id,revision));
CREATE TABLE wf_version (registry_id text NOT NULL, record_id text NOT NULL, version integer NOT NULL, payload jsonb NOT NULL, payload_hash text NOT NULL, operation text NOT NULL, creator text NOT NULL, approver text NOT NULL CHECK(creator<>approver), evidence jsonb NOT NULL, PRIMARY KEY(registry_id,record_id,version));
CREATE TABLE wf_audit (event_id bigserial PRIMARY KEY, registry_id text NOT NULL, actor text NOT NULL, action text NOT NULL, details jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE wf_outbox (event_id uuid PRIMARY KEY, registry_id text NOT NULL, record_id text NOT NULL, version integer NOT NULL, payload_hash text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(registry_id,record_id,version), FOREIGN KEY(registry_id,record_id,version) REFERENCES wf_version);
CREATE TABLE wf_request (registry_id text NOT NULL, actor text NOT NULL, idempotency_key text NOT NULL, request_hash text NOT NULL, response jsonb NOT NULL, PRIMARY KEY(registry_id,actor,idempotency_key));
CREATE TABLE wf_source_cursor (registry_id text NOT NULL, source_id text NOT NULL, cursor bigint NOT NULL DEFAULT 0, PRIMARY KEY(registry_id,source_id));
CREATE TABLE wf_source_event (registry_id text NOT NULL, source_id text NOT NULL, cursor bigint NOT NULL, event_hash text NOT NULL, response jsonb NOT NULL, PRIMARY KEY(registry_id,source_id,cursor));
CREATE FUNCTION wf_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable workflow evidence'; END $$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON wf_revision FOR EACH ROW EXECUTE FUNCTION wf_immutable();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON wf_version FOR EACH ROW EXECUTE FUNCTION wf_immutable();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON wf_audit FOR EACH ROW EXECUTE FUNCTION wf_immutable();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON wf_outbox FOR EACH ROW EXECUTE FUNCTION wf_immutable();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON wf_source_event FOR EACH ROW EXECUTE FUNCTION wf_immutable();
-- These constraints preserve invariants even if a future writer bypasses the router.
ALTER TABLE wf_record ADD CHECK(version>=0);
ALTER TABLE wf_draft ADD CHECK(revision>0), ADD CHECK(approver IS NULL OR approver<>creator);
ALTER TABLE wf_revision ADD CHECK(revision>0), ADD CHECK(payload_hash ~ '^[0-9a-f]{64}$');
ALTER TABLE wf_version ADD CHECK(version>0), ADD CHECK(operation IN ('upsert','tombstone')), ADD CHECK(payload_hash ~ '^[0-9a-f]{64}$');
ALTER TABLE wf_source_cursor ADD CHECK(cursor>=0);
ALTER TABLE wf_source_event ADD CHECK(cursor>0);
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON wf_request FOR EACH ROW EXECUTE FUNCTION wf_immutable();
