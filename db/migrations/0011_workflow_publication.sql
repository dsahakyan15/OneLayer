-- Durable handoff only. Completion is intentionally unavailable until a trusted
-- finalized-chain adapter is integrated; a worker claim is never an anchor.
CREATE TABLE wf_publication (
  operation_id uuid PRIMARY KEY,
  registry_id text NOT NULL UNIQUE,
  owner text NOT NULL,
  fence bigint NOT NULL DEFAULT 1 CHECK(fence>0),
  lease_until timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE wf_publication_item (
  operation_id uuid NOT NULL REFERENCES wf_publication,
  ordinal integer NOT NULL CHECK(ordinal>=0),
  event_id uuid NOT NULL UNIQUE REFERENCES wf_outbox,
  PRIMARY KEY(operation_id,ordinal)
);
CREATE TABLE wf_publication_attempt (
  attempt_id bigserial PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES wf_publication,
  fence bigint NOT NULL CHECK(fence>0),
  worker text NOT NULL,
  action text NOT NULL CHECK(action IN ('CLAIM','RECLAIM','RENEW','RELEASE')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON wf_publication_item FOR EACH ROW EXECUTE FUNCTION wf_immutable();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON wf_publication_attempt FOR EACH ROW EXECUTE FUNCTION wf_immutable();
