-- ADR-0009 (accepted 2026-09-24), tickets 08/09:
-- (A) an operation whose conflicting anchor has unknown origin leaves its block
--     only with archival evidence: our landing (FINALIZED / ANCHOR_MISMATCH) or
--     a proven foreign conflict plus two independent authenticated approvals;
-- (B) an unpublishable committed Record Version is excluded from the
--     publication queue by two authenticated principals independent of the
--     version's authors, bound to the exact version and to an existing
--     correcting version.
--
-- As in 0013, triggers are defence in depth, not a security boundary: the
-- application writers are publication-worker.ts and publication-maintenance.ts.
-- Approver identity comes from the server session (ticket 07); the database
-- cannot verify that a session was real.

-- (A) Archival reconciliation evidence ---------------------------------------
CREATE TABLE wf_publication_archival_check (
  check_id uuid PRIMARY KEY,
  -- Total order of checks; only the newest check of an operation is actionable.
  check_no bigserial NOT NULL UNIQUE,
  operation_id uuid NOT NULL REFERENCES wf_publication,
  archive_id text NOT NULL CHECK(wf_publication_person_ok(archive_id)),
  evidence_ref text NOT NULL CHECK(wf_publication_person_ok(evidence_ref)),
  outcome text NOT NULL CHECK(outcome IN ('OURS_FOUND','FOREIGN_PROVEN','INCONCLUSIVE')),
  -- Canonical JSON exactly as hashed (approvals bind to detail_hash).
  detail_bytes bytea NOT NULL,
  detail_hash text NOT NULL CHECK(detail_hash ~ '^[0-9a-f]{64}$'),
  requested_by text NOT NULL CHECK(wf_publication_person_ok(requested_by)),
  reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 2000),
  fence bigint NOT NULL,
  worker text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX wf_publication_archival_check_op ON wf_publication_archival_check(operation_id, check_no);

CREATE FUNCTION wf_publication_archival_check_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j jsonb; signed_count integer; listed integer;
BEGIN
  PERFORM wf_publication_require_lease(NEW.operation_id, NEW.fence, NEW.worker);
  IF encode(sha256(convert_to('ONELAYER:WORKFLOW:ARCHIVAL-CHECK:V1'||E'\n','UTF8') || NEW.detail_bytes),'hex') <> NEW.detail_hash THEN
    RAISE EXCEPTION 'archival check hash does not cover detail bytes';
  END IF;
  j := convert_from(NEW.detail_bytes,'UTF8')::jsonb;
  IF j->>'operationId' IS DISTINCT FROM NEW.operation_id::text OR j->>'outcome' IS DISTINCT FROM NEW.outcome
     OR j->>'archiveId' IS DISTINCT FROM NEW.archive_id THEN
    RAISE EXCEPTION 'archival check columns disagree with detail bytes';
  END IF;
  SELECT count(*) INTO signed_count FROM wf_publication_tx t JOIN wf_publication_tx_signed s USING(attempt_id) WHERE t.operation_id=NEW.operation_id;
  IF signed_count = 0 THEN RAISE EXCEPTION 'archival reconciliation needs a signed attempt'; END IF;
  -- Every signed attempt of the operation is in the evidence, by signature.
  SELECT count(*) INTO listed FROM wf_publication_tx t JOIN wf_publication_tx_signed s USING(attempt_id)
   WHERE t.operation_id=NEW.operation_id
     AND EXISTS (SELECT 1 FROM jsonb_array_elements(j->'attempts') a WHERE a->>'signature'=s.signature AND a->>'attemptId'=t.attempt_id::text);
  IF listed <> signed_count OR jsonb_array_length(j->'attempts') <> signed_count THEN
    RAISE EXCEPTION 'archival evidence must cover every signed attempt';
  END IF;
  IF NEW.outcome='FOREIGN_PROVEN' AND (j->>'sequenceTaken' IS DISTINCT FROM 'true' OR EXISTS (
       SELECT 1 FROM jsonb_array_elements(j->'attempts') a WHERE a->>'proof' IS NULL OR a->>'proof' NOT IN ('FAILED_ON_CHAIN','ABSENT_AND_EXPIRED'))) THEN
    RAISE EXCEPTION 'a foreign conflict needs every attempt of ours proven not landed';
  END IF;
  IF NEW.outcome='OURS_FOUND' AND (SELECT count(*) FROM jsonb_array_elements(j->'attempts') a WHERE a->>'archive'='SUCCEEDED') <> 1 THEN
    RAISE EXCEPTION 'our landing needs exactly one successful archived attempt';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER archival_check_guard BEFORE INSERT ON wf_publication_archival_check FOR EACH ROW EXECUTE FUNCTION wf_publication_archival_check_guard();

-- Two independent authenticated approvals of one FOREIGN_PROVEN check (ADR-0009 п.4).
CREATE TABLE wf_publication_cancel_approval (
  check_id uuid NOT NULL REFERENCES wf_publication_archival_check,
  operation_id uuid NOT NULL REFERENCES wf_publication,
  ordinal smallint NOT NULL CHECK(ordinal IN (1,2)),
  principal text NOT NULL CHECK(wf_publication_person_ok(principal)),
  role text NOT NULL,
  auth_method text NOT NULL CHECK(auth_method IN ('oidc','password')),
  device_id text,
  evidence_hash text NOT NULL CHECK(evidence_hash ~ '^[0-9a-f]{64}$'),
  approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(check_id, ordinal)
);
CREATE UNIQUE INDEX wf_publication_cancel_approval_person ON wf_publication_cancel_approval(check_id, lower(principal));

CREATE FUNCTION wf_publication_cancel_approval_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c record;
BEGIN
  PERFORM 1 FROM wf_publication WHERE operation_id=NEW.operation_id FOR UPDATE;
  SELECT * INTO c FROM wf_publication_archival_check WHERE check_id=NEW.check_id;
  IF c.operation_id IS DISTINCT FROM NEW.operation_id OR c.outcome<>'FOREIGN_PROVEN' OR c.detail_hash<>NEW.evidence_hash THEN
    RAISE EXCEPTION 'cancellation approval requires the exact FOREIGN_PROVEN evidence';
  END IF;
  IF EXISTS (SELECT 1 FROM wf_publication_archival_check WHERE operation_id=NEW.operation_id AND check_no>c.check_no) THEN
    RAISE EXCEPTION 'cancellation approval must reference the newest archival check';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM wf_publication WHERE operation_id=NEW.operation_id AND state='OPEN') THEN
    RAISE EXCEPTION 'cancellation approval requires an OPEN operation';
  END IF;
  IF NEW.ordinal <> 1 + (SELECT count(*) FROM wf_publication_cancel_approval WHERE check_id=NEW.check_id) THEN
    RAISE EXCEPTION 'approvals are contiguous';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER cancel_approval_guard BEFORE INSERT ON wf_publication_cancel_approval FOR EACH ROW EXECUTE FUNCTION wf_publication_cancel_approval_guard();

-- An anchor may also be proven by an archival transaction lookup.
ALTER TABLE wf_publication_anchor DROP CONSTRAINT wf_publication_anchor_proof_check;
ALTER TABLE wf_publication_anchor ADD CONSTRAINT wf_publication_anchor_proof_check
  CHECK(proof IN ('SIGNATURE_STATUS','LEDGER_ENTRY','ARCHIVAL_TRANSACTION'));

-- Abandonment: optional archival evidence, excluded members, and no successor
-- when every member was excluded.
ALTER TABLE wf_publication_abandonment
  ALTER COLUMN successor_operation_id DROP NOT NULL,
  ADD COLUMN archival_check_id uuid REFERENCES wf_publication_archival_check,
  ADD COLUMN excluded_event_ids uuid[] NOT NULL DEFAULT '{}';
ALTER TABLE wf_publication_discrepancy
  ADD COLUMN archival_check_id uuid REFERENCES wf_publication_archival_check;

-- (B) Version exclusion --------------------------------------------------------

-- Everyone who authored the version: creator, version approver and every draft
-- editor of the committing draft. None of them may approve its exclusion.
CREATE FUNCTION wf_version_authors(reg text, rec text, ver integer) RETURNS SETOF text LANGUAGE sql STABLE AS $$
  SELECT creator FROM wf_version WHERE registry_id=reg AND record_id=rec AND version=ver
  UNION SELECT approver FROM wf_version WHERE registry_id=reg AND record_id=rec AND version=ver
  UNION SELECT r.editor FROM wf_version v JOIN wf_revision r ON r.draft_id::text = v.evidence->>'draftId'
         WHERE v.registry_id=reg AND v.record_id=rec AND v.version=ver
  UNION SELECT d.creator FROM wf_version v JOIN wf_draft d ON d.draft_id::text = v.evidence->>'draftId'
         WHERE v.registry_id=reg AND v.record_id=rec AND v.version=ver
$$;

CREATE TABLE wf_version_exclusion (
  exclusion_id uuid PRIMARY KEY,
  registry_id text NOT NULL,
  record_id text NOT NULL,
  version integer NOT NULL,
  event_id uuid NOT NULL UNIQUE REFERENCES wf_outbox,
  payload_hash text NOT NULL CHECK(payload_hash ~ '^[0-9a-f]{64}$'),
  corrected_by_version integer NOT NULL,
  corrected_payload_hash text NOT NULL CHECK(corrected_payload_hash ~ '^[0-9a-f]{64}$'),
  reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 2000),
  authors text[] NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(registry_id, record_id, version),
  FOREIGN KEY(registry_id, record_id, version) REFERENCES wf_version,
  FOREIGN KEY(registry_id, record_id, corrected_by_version) REFERENCES wf_version,
  CHECK(corrected_by_version > version)
);

CREATE TABLE wf_version_exclusion_approval (
  exclusion_id uuid NOT NULL REFERENCES wf_version_exclusion,
  ordinal smallint NOT NULL CHECK(ordinal IN (1,2)),
  principal text NOT NULL CHECK(wf_publication_person_ok(principal)),
  role text NOT NULL,
  auth_method text NOT NULL CHECK(auth_method IN ('oidc','password')),
  device_id text,
  approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(exclusion_id, ordinal)
);
CREATE UNIQUE INDEX wf_version_exclusion_approval_person ON wf_version_exclusion_approval(exclusion_id, lower(principal));

-- Effective exclusions: both approvals present.
CREATE VIEW wf_version_excluded AS
  SELECT x.* FROM wf_version_exclusion x
   WHERE EXISTS (SELECT 1 FROM wf_version_exclusion_approval a WHERE a.exclusion_id=x.exclusion_id AND a.ordinal=2);

-- True when the event is bound to an anchored or intent-bearing publication.
CREATE FUNCTION wf_event_publication_bound(ev uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM wf_publication_item i JOIN wf_publication p USING(operation_id)
                  WHERE i.event_id=ev AND p.state<>'ABANDONED'
                    AND (p.state IN ('FINALIZED','LANDED_DISCREPANCY') OR EXISTS (SELECT 1 FROM wf_publication_intent n WHERE n.operation_id=p.operation_id)))
$$;

CREATE FUNCTION wf_version_exclusion_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.payload_hash IS DISTINCT FROM (SELECT payload_hash FROM wf_version WHERE registry_id=NEW.registry_id AND record_id=NEW.record_id AND version=NEW.version)
     OR NEW.corrected_payload_hash IS DISTINCT FROM (SELECT payload_hash FROM wf_version WHERE registry_id=NEW.registry_id AND record_id=NEW.record_id AND version=NEW.corrected_by_version)
     OR NOT EXISTS (SELECT 1 FROM wf_outbox WHERE event_id=NEW.event_id AND registry_id=NEW.registry_id AND record_id=NEW.record_id AND version=NEW.version) THEN
    RAISE EXCEPTION 'exclusion must bind the exact version, its outbox event and the correcting version';
  END IF;
  IF EXISTS (SELECT 1 FROM wf_version_exclusion WHERE registry_id=NEW.registry_id AND record_id=NEW.record_id
               AND (version=NEW.corrected_by_version OR corrected_by_version=NEW.version)) THEN
    RAISE EXCEPTION 'a correcting version cannot itself be excluded';
  END IF;
  IF wf_event_publication_bound(NEW.event_id) THEN
    RAISE EXCEPTION 'an anchored or intent-bound version cannot be excluded';
  END IF;
  IF NEW.authors IS DISTINCT FROM ARRAY(SELECT a FROM wf_version_authors(NEW.registry_id,NEW.record_id,NEW.version) a ORDER BY a) THEN
    RAISE EXCEPTION 'exclusion must record the version authors';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER exclusion_guard BEFORE INSERT ON wf_version_exclusion FOR EACH ROW EXECUTE FUNCTION wf_version_exclusion_guard();

CREATE FUNCTION wf_version_exclusion_approval_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE x record;
BEGIN
  -- No row lock: the runtime role has no UPDATE on this append-only table. The
  -- (exclusion_id, ordinal) key rejects a concurrent duplicate ordinal.
  SELECT * INTO x FROM wf_version_exclusion WHERE exclusion_id=NEW.exclusion_id;
  IF EXISTS (SELECT 1 FROM wf_version_authors(x.registry_id,x.record_id,x.version) a WHERE lower(a)=lower(NEW.principal)) THEN
    RAISE EXCEPTION 'an author of the version cannot approve its exclusion';
  END IF;
  IF NEW.ordinal <> 1 + (SELECT count(*) FROM wf_version_exclusion_approval WHERE exclusion_id=NEW.exclusion_id) THEN
    RAISE EXCEPTION 'approvals are contiguous';
  END IF;
  IF wf_event_publication_bound(x.event_id) THEN
    RAISE EXCEPTION 'an anchored or intent-bound version cannot be excluded';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER exclusion_approval_guard BEFORE INSERT ON wf_version_exclusion_approval FOR EACH ROW EXECUTE FUNCTION wf_version_exclusion_approval_guard();

-- Replaced 0013 guards --------------------------------------------------------

-- Membership: additionally, an excluded version never enters a publication.
CREATE OR REPLACE FUNCTION wf_publication_item_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM wf_publication WHERE operation_id=NEW.operation_id AND state='OPEN'
                 AND xmin::text::bigint = txid_current() % 4294967296) THEN
    RAISE EXCEPTION 'membership is fixed when the operation is created';
  END IF;
  IF EXISTS (SELECT 1 FROM wf_publication_item i JOIN wf_publication p USING(operation_id)
             WHERE i.event_id=NEW.event_id AND p.state<>'ABANDONED' AND i.operation_id<>NEW.operation_id) THEN
    RAISE EXCEPTION 'outbox event already belongs to a live or finalized publication';
  END IF;
  IF EXISTS (SELECT 1 FROM wf_version_excluded WHERE event_id=NEW.event_id) THEN
    RAISE EXCEPTION 'an excluded version cannot enter a publication';
  END IF;
  RETURN NEW;
END $$;

-- Intent: additionally, no excluded member.
CREATE OR REPLACE FUNCTION wf_publication_intent_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j jsonb;
BEGIN
  PERFORM wf_publication_require_lease(NEW.operation_id, NEW.fence, NEW.worker);
  IF encode(sha256(convert_to('ONELAYER:WORKFLOW:PUBLICATION:INTENT:V1'||E'\n','UTF8') || NEW.intent_bytes),'hex') <> NEW.intent_hash THEN
    RAISE EXCEPTION 'intent hash does not cover intent bytes';
  END IF;
  j := convert_from(NEW.intent_bytes,'UTF8')::jsonb;
  IF j->>'operationId' IS DISTINCT FROM NEW.operation_id::text OR j->>'registryId' IS DISTINCT FROM NEW.registry_id
     OR (j->>'batchSequence')::numeric IS DISTINCT FROM NEW.batch_sequence
     OR NEW.registry_id IS DISTINCT FROM (SELECT registry_id FROM wf_publication WHERE operation_id=NEW.operation_id) THEN
    RAISE EXCEPTION 'intent columns disagree with intent bytes';
  END IF;
  IF EXISTS (SELECT 1 FROM wf_publication_intent i JOIN wf_publication p USING(operation_id)
             WHERE i.registry_id=NEW.registry_id AND i.batch_sequence=NEW.batch_sequence AND p.state<>'ABANDONED') THEN
    RAISE EXCEPTION 'batch sequence already bound to a live or finalized publication';
  END IF;
  IF EXISTS (SELECT 1 FROM wf_publication_item i JOIN wf_version_excluded x USING(event_id) WHERE i.operation_id=NEW.operation_id) THEN
    RAISE EXCEPTION 'an excluded version cannot be bound to an intent';
  END IF;
  RETURN NEW;
END $$;

-- Abandonment: additionally (ADR-0009) an ambiguous block with a signed attempt
-- that is not proven FAILED needs approved FOREIGN_PROVEN archival evidence, and
-- excluded members / a missing successor must match effective exclusions.
CREATE OR REPLACE FUNCTION wf_publication_abandon_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c record;
BEGIN
  PERFORM wf_publication_require_lease(NEW.operation_id, NEW.fence, NEW.worker);
  IF EXISTS (SELECT 1 FROM wf_publication_anchor WHERE operation_id=NEW.operation_id)
     OR EXISTS (SELECT 1 FROM wf_publication_tx t WHERE t.operation_id=NEW.operation_id AND wf_publication_tx_state(t.attempt_id)='ANCHOR_MISMATCH') THEN
    RAISE EXCEPTION 'a landed publication cannot be abandoned';
  END IF;
  IF NEW.blocked_reason IS DISTINCT FROM (SELECT blocked_reason FROM wf_publication WHERE operation_id=NEW.operation_id) THEN
    RAISE EXCEPTION 'abandonment must record the current block reason';
  END IF;
  IF NEW.archival_check_id IS NOT NULL THEN
    SELECT * INTO c FROM wf_publication_archival_check WHERE check_id=NEW.archival_check_id;
    IF c.operation_id IS DISTINCT FROM NEW.operation_id OR c.outcome<>'FOREIGN_PROVEN'
       OR (SELECT count(*) FROM wf_publication_cancel_approval WHERE check_id=c.check_id) <> 2
       OR EXISTS (SELECT 1 FROM wf_publication_archival_check WHERE operation_id=NEW.operation_id AND check_no>c.check_no) THEN
      RAISE EXCEPTION 'archival cancellation needs the newest FOREIGN_PROVEN check with two approvals';
    END IF;
  ELSIF (NEW.blocked_reason='CHAIN_CONFLICT' OR NEW.blocked_reason LIKE 'ANCHOR_MISMATCH_UNATTRIBUTED%')
     AND EXISTS (SELECT 1 FROM wf_publication_tx t JOIN wf_publication_tx_signed s USING(attempt_id)
                 WHERE t.operation_id=NEW.operation_id AND wf_publication_tx_state(t.attempt_id) IS DISTINCT FROM 'FAILED') THEN
    RAISE EXCEPTION 'an anchor of unknown origin needs archival evidence before abandonment';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(NEW.excluded_event_ids) e(id)
             WHERE NOT EXISTS (SELECT 1 FROM wf_version_excluded x WHERE x.event_id=e.id)
                OR NOT EXISTS (SELECT 1 FROM wf_publication_item i WHERE i.operation_id=NEW.operation_id AND i.event_id=e.id)) THEN
    RAISE EXCEPTION 'excluded members must be effective exclusions of this operation';
  END IF;
  IF NEW.successor_operation_id IS NULL AND EXISTS (SELECT 1 FROM wf_publication_item i WHERE i.operation_id=NEW.operation_id
                                                    AND NOT (i.event_id = ANY(NEW.excluded_event_ids))) THEN
    RAISE EXCEPTION 'only a fully excluded membership has no successor';
  END IF;
  RETURN NEW;
END $$;

-- Operation state: an ABANDONED operation may have no successor (all excluded).
CREATE OR REPLACE FUNCTION wf_publication_state_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'immutable workflow evidence'; END IF;
  IF NEW.operation_id<>OLD.operation_id OR NEW.registry_id<>OLD.registry_id OR NEW.created_at<>OLD.created_at THEN
    RAISE EXCEPTION 'publication identity is immutable';
  END IF;
  IF OLD.state<>'OPEN' THEN RAISE EXCEPTION 'terminal publication is immutable'; END IF;
  IF NEW.fence<OLD.fence THEN RAISE EXCEPTION 'publication fence is monotonic'; END IF;
  IF NEW.context_slot<OLD.context_slot THEN RAISE EXCEPTION 'publication context slot is monotonic'; END IF;
  IF OLD.blocked_reason IS NOT NULL AND NEW.blocked_reason IS DISTINCT FROM OLD.blocked_reason THEN
    RAISE EXCEPTION 'maintenance block is cleared only by abandonment or finalization';
  END IF;
  IF NEW.superseded_by IS DISTINCT FROM OLD.superseded_by AND NEW.state<>'ABANDONED' THEN
    RAISE EXCEPTION 'superseded_by is set only when abandoning';
  END IF;
  IF NEW.state='FINALIZED' AND NOT EXISTS (SELECT 1 FROM wf_publication_anchor WHERE operation_id=NEW.operation_id) THEN
    RAISE EXCEPTION 'publication cannot finalize without a verified anchor';
  END IF;
  IF NEW.state='LANDED_DISCREPANCY' AND NOT EXISTS (SELECT 1 FROM wf_publication_discrepancy WHERE operation_id=NEW.operation_id) THEN
    RAISE EXCEPTION 'landed discrepancy requires a two-person maintenance record';
  END IF;
  IF NEW.state='ABANDONED' AND NOT EXISTS (SELECT 1 FROM wf_publication_abandonment WHERE operation_id=NEW.operation_id
                                          AND successor_operation_id IS NOT DISTINCT FROM NEW.superseded_by) THEN
    RAISE EXCEPTION 'publication cannot be abandoned without a two-person maintenance record';
  END IF;
  RETURN NEW;
END $$;

ALTER TABLE wf_publication_attempt DROP CONSTRAINT wf_publication_attempt_action_check;
ALTER TABLE wf_publication_attempt ADD CONSTRAINT wf_publication_attempt_action_check
  CHECK(action IN ('CLAIM','RECLAIM','RENEW','RELEASE','BLOCK','ABANDON','DISCREPANCY','ARCHIVAL_CHECK'));

-- Append-only evidence, including TRUNCATE; runtime role (0016) gets INSERT/SELECT only.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['wf_publication_archival_check','wf_publication_cancel_approval','wf_version_exclusion','wf_version_exclusion_approval'] LOOP
    EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION wf_immutable()', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION wf_immutable()', t);
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='onelayer_runtime') THEN
      EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON %I FROM onelayer_runtime', t);
    END IF;
  END LOOP;
END $$;
