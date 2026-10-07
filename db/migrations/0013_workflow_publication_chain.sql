-- Ticket 09: deterministic publication intent, append-only transaction attempt
-- journal, trusted finalized-chain completion and a two-person maintenance exit.
--
-- The application writer is `publication-worker.ts`. These triggers are
-- defence in depth against accidental or partial writes; they do not replace
-- database role separation (a role that can write every table consistently can
-- still forge rows). See evidence 09.

-- Operation lifecycle -------------------------------------------------------
ALTER TABLE wf_publication DROP CONSTRAINT wf_publication_registry_id_key;
ALTER TABLE wf_publication
  ADD COLUMN state text NOT NULL DEFAULT 'OPEN' CHECK(state IN ('OPEN','FINALIZED','ABANDONED','LANDED_DISCREPANCY')),
  -- Non-null means the operation needs maintenance; only ABANDONED or a proven
  -- finalized landing ends it. Once set it never changes.
  ADD COLUMN blocked_reason text,
  -- Highest finalized slot the operation's decisions were based on.
  ADD COLUMN context_slot numeric(20) NOT NULL DEFAULT 0 CHECK(context_slot>=0),
  ADD COLUMN superseded_by uuid REFERENCES wf_publication DEFERRABLE INITIALLY DEFERRED;
CREATE UNIQUE INDEX wf_publication_one_open ON wf_publication(registry_id) WHERE state='OPEN';

ALTER TABLE wf_publication_attempt DROP CONSTRAINT wf_publication_attempt_action_check;
ALTER TABLE wf_publication_attempt ADD CONSTRAINT wf_publication_attempt_action_check
  CHECK(action IN ('CLAIM','RECLAIM','RENEW','RELEASE','BLOCK','ABANDON','DISCREPANCY'));

-- An outbox event may belong to several operations only when every earlier one
-- was ABANDONED (membership moved to its successor); journals are never deleted.
ALTER TABLE wf_publication_item DROP CONSTRAINT wf_publication_item_event_id_key;
CREATE INDEX wf_publication_item_event ON wf_publication_item(event_id);

-- Raises unless (operation, fence, worker) is the current unexpired OPEN lease.
-- Locks the operation row first, so the check cannot race a reclaim.
CREATE FUNCTION wf_publication_require_lease(op uuid, f bigint, w text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  PERFORM 1 FROM wf_publication WHERE operation_id=op FOR UPDATE;
  IF NOT EXISTS (SELECT 1 FROM wf_publication WHERE operation_id=op AND state='OPEN' AND fence=f AND owner=w AND lease_until>clock_timestamp()) THEN
    RAISE EXCEPTION 'publication write requires the current fence';
  END IF;
END $$;

CREATE TABLE wf_publication_intent (
  operation_id uuid PRIMARY KEY REFERENCES wf_publication,
  registry_id text NOT NULL,
  batch_sequence numeric(20) NOT NULL CHECK(batch_sequence>0),
  -- Canonical UTF-8 JSON exactly as hashed; jsonb would reorder keys.
  intent_bytes bytea NOT NULL,
  intent_hash text NOT NULL CHECK(intent_hash ~ '^[0-9a-f]{64}$'),
  fence bigint NOT NULL CHECK(fence>0),
  worker text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE wf_publication_tx (
  attempt_id uuid PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES wf_publication_intent,
  attempt_no integer NOT NULL CHECK(attempt_no>0),
  intent_hash text NOT NULL CHECK(intent_hash ~ '^[0-9a-f]{64}$'),
  fence bigint NOT NULL CHECK(fence>0),
  worker text NOT NULL,
  segment_pda text NOT NULL,
  segment_index integer NOT NULL CHECK(segment_index>=0),
  day_utc integer NOT NULL CHECK(day_utc>=19700101),
  recent_blockhash text NOT NULL,
  last_valid_block_height numeric(20) NOT NULL CHECK(last_valid_block_height>=0),
  context_slot numeric(20) NOT NULL CHECK(context_slot>=0),
  -- Reserved before the signer is asked; the signer only sees these bytes.
  message_bytes bytea NOT NULL,
  simulation jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(operation_id,attempt_no)
);

CREATE TABLE wf_publication_tx_signed (
  attempt_id uuid PRIMARY KEY REFERENCES wf_publication_tx,
  signed_bytes bytea NOT NULL,
  signature text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE wf_publication_tx_event (
  event_id bigserial PRIMARY KEY,
  attempt_id uuid NOT NULL REFERENCES wf_publication_tx,
  state text NOT NULL CHECK(state IN ('PREPARED','SIGNED','CANCELLED','SUBMITTED','UNKNOWN','EXPIRED','FAILED','FINALIZED','ANCHOR_MISMATCH')),
  fence bigint NOT NULL CHECK(fence>0),
  worker text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE wf_publication_anchor (
  operation_id uuid PRIMARY KEY REFERENCES wf_publication_intent,
  attempt_id uuid NOT NULL UNIQUE REFERENCES wf_publication_tx,
  registry_id text NOT NULL,
  batch_sequence numeric(20) NOT NULL,
  intent_hash text NOT NULL,
  merkle_root text NOT NULL CHECK(merkle_root ~ '^[0-9a-f]{64}$'),
  manifest_hash text NOT NULL CHECK(manifest_hash ~ '^[0-9a-f]{64}$'),
  anchor_hash text NOT NULL CHECK(anchor_hash ~ '^[0-9a-f]{64}$'),
  signature text NOT NULL UNIQUE,
  -- NULL only when the landing was proven by the ledger entry because the
  -- signature status history was unavailable; issuance must resolve it.
  slot numeric(20),
  proof text NOT NULL CHECK(proof IN ('SIGNATURE_STATUS','LEDGER_ENTRY')),
  segment_pda text NOT NULL,
  fence bigint NOT NULL,
  worker text NOT NULL,
  finalized_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(registry_id,batch_sequence),
  CHECK(proof='LEDGER_ENTRY' OR slot IS NOT NULL)
);

-- Procedural identity hygiene for maintenance participants until ticket 07
-- supplies authenticated principals: printable, single-spaced, trimmed, no
-- zero-width/format characters. (NFKC is applied by the application; the
-- test clusters use SQL_ASCII, where normalize() is unavailable.)
CREATE FUNCTION wf_publication_person_ok(v text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT v IS NOT NULL AND length(v) BETWEEN 1 AND 128 AND v = btrim(v) AND v !~ '[[:cntrl:]]' AND v !~ '\s\s'
    AND position('\xe2808b'::bytea IN convert_to(v,'UTF8'))=0 AND position('\xe2808c'::bytea IN convert_to(v,'UTF8'))=0
    AND position('\xe2808d'::bytea IN convert_to(v,'UTF8'))=0 AND position('\xe2808e'::bytea IN convert_to(v,'UTF8'))=0
    AND position('\xe2808f'::bytea IN convert_to(v,'UTF8'))=0 AND position('\xe281a0'::bytea IN convert_to(v,'UTF8'))=0
    AND position('\xefbbbf'::bytea IN convert_to(v,'UTF8'))=0 AND position('\xc2ad'::bytea IN convert_to(v,'UTF8'))=0
$$;

CREATE TABLE wf_publication_abandonment (
  operation_id uuid PRIMARY KEY REFERENCES wf_publication,
  successor_operation_id uuid NOT NULL UNIQUE,
  requested_by text NOT NULL CHECK(wf_publication_person_ok(requested_by)),
  approved_by text NOT NULL CHECK(wf_publication_person_ok(approved_by)),
  reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 2000),
  incident_ref text,
  blocked_reason text,
  -- Abandoning an operation that is not blocked needs its own justification.
  force_reason text CHECK(force_reason IS NULL OR length(btrim(force_reason)) BETWEEN 10 AND 2000),
  fence bigint NOT NULL,
  worker text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK(lower(requested_by) <> lower(approved_by)),
  CHECK(blocked_reason IS NOT NULL OR force_reason IS NOT NULL)
);

-- Terminal record for "our transaction finalized, but the anchor disagrees
-- with the intent". No successor: the membership stays consumed.
CREATE TABLE wf_publication_discrepancy (
  operation_id uuid PRIMARY KEY REFERENCES wf_publication,
  attempt_id uuid NOT NULL UNIQUE REFERENCES wf_publication_tx,
  signature text NOT NULL,
  blocked_reason text NOT NULL,
  requested_by text NOT NULL CHECK(wf_publication_person_ok(requested_by)),
  approved_by text NOT NULL CHECK(wf_publication_person_ok(approved_by)),
  reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 2000),
  incident_ref text NOT NULL CHECK(wf_publication_person_ok(incident_ref)),
  fence bigint NOT NULL,
  worker text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK(lower(requested_by) <> lower(approved_by))
);

-- Append-only evidence, including TRUNCATE (not covered by row triggers).
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['wf_publication_intent','wf_publication_tx','wf_publication_tx_signed','wf_publication_tx_event','wf_publication_anchor','wf_publication_abandonment','wf_publication_discrepancy'] LOOP
    EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION wf_immutable()', t);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['wf_publication','wf_publication_item','wf_publication_attempt','wf_publication_intent','wf_publication_tx','wf_publication_tx_signed','wf_publication_tx_event','wf_publication_anchor','wf_publication_abandonment','wf_publication_discrepancy'] LOOP
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION wf_immutable()', t);
  END LOOP;
END $$;

-- Operations are born OPEN and unblocked.
CREATE FUNCTION wf_publication_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.state<>'OPEN' OR NEW.blocked_reason IS NOT NULL OR NEW.superseded_by IS NOT NULL OR NEW.context_slot<>0 THEN
    RAISE EXCEPTION 'a publication operation is created OPEN';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER insert_guard BEFORE INSERT ON wf_publication FOR EACH ROW EXECUTE FUNCTION wf_publication_insert_guard();

-- Membership is written only into an OPEN operation created by the current
-- transaction (claim or abandonment successor), never added later.
CREATE FUNCTION wf_publication_item_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM wf_publication WHERE operation_id=NEW.operation_id AND state='OPEN'
                 AND xmin::text::bigint = txid_current() % 4294967296) THEN
    RAISE EXCEPTION 'membership is fixed when the operation is created';
  END IF;
  IF EXISTS (SELECT 1 FROM wf_publication_item i JOIN wf_publication p USING(operation_id)
             WHERE i.event_id=NEW.event_id AND p.state<>'ABANDONED' AND i.operation_id<>NEW.operation_id) THEN
    RAISE EXCEPTION 'outbox event already belongs to a live or finalized publication';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER item_guard BEFORE INSERT ON wf_publication_item FOR EACH ROW EXECUTE FUNCTION wf_publication_item_guard();

CREATE FUNCTION wf_publication_intent_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
  RETURN NEW;
END $$;
CREATE TRIGGER intent_guard BEFORE INSERT ON wf_publication_intent FOR EACH ROW EXECUTE FUNCTION wf_publication_intent_guard();

-- Latest journal state of an attempt (NULL when it has none).
CREATE FUNCTION wf_publication_tx_state(a uuid) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT state FROM wf_publication_tx_event WHERE attempt_id=a ORDER BY event_id DESC LIMIT 1
$$;

CREATE FUNCTION wf_publication_tx_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM wf_publication_require_lease(NEW.operation_id, NEW.fence, NEW.worker);
  IF NEW.intent_hash IS DISTINCT FROM (SELECT intent_hash FROM wf_publication_intent WHERE operation_id=NEW.operation_id) THEN
    RAISE EXCEPTION 'attempt does not reference the stored intent';
  END IF;
  IF NEW.attempt_no <> 1 + (SELECT count(*) FROM wf_publication_tx WHERE operation_id=NEW.operation_id) THEN
    RAISE EXCEPTION 'attempt numbers are contiguous';
  END IF;
  IF EXISTS (SELECT 1 FROM wf_publication_tx t WHERE t.operation_id=NEW.operation_id
             AND wf_publication_tx_state(t.attempt_id) IS DISTINCT FROM 'CANCELLED'
             AND wf_publication_tx_state(t.attempt_id) IS DISTINCT FROM 'EXPIRED'
             AND wf_publication_tx_state(t.attempt_id) IS DISTINCT FROM 'FAILED') THEN
    RAISE EXCEPTION 'a new attempt requires every earlier attempt to be non-landable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER tx_guard BEFORE INSERT ON wf_publication_tx FOR EACH ROW EXECUTE FUNCTION wf_publication_tx_guard();

CREATE FUNCTION wf_publication_signed_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF wf_publication_tx_state(NEW.attempt_id) IS DISTINCT FROM 'PREPARED' THEN
    RAISE EXCEPTION 'signed bytes require a PREPARED reservation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER signed_guard BEFORE INSERT ON wf_publication_tx_signed FOR EACH ROW EXECUTE FUNCTION wf_publication_signed_guard();

-- Mirrors the TypeScript transition map in publication-worker.ts.
CREATE FUNCTION wf_publication_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE prev text; op uuid;
BEGIN
  SELECT operation_id INTO op FROM wf_publication_tx WHERE attempt_id=NEW.attempt_id;
  PERFORM wf_publication_require_lease(op, NEW.fence, NEW.worker);
  prev := wf_publication_tx_state(NEW.attempt_id);
  IF NOT ((prev IS NULL AND NEW.state='PREPARED')
       OR (prev='PREPARED' AND NEW.state IN ('SIGNED','CANCELLED'))
       OR (prev='SIGNED' AND NEW.state IN ('SUBMITTED','UNKNOWN','EXPIRED'))
       OR (prev='SUBMITTED' AND NEW.state IN ('UNKNOWN','EXPIRED','FAILED','FINALIZED','ANCHOR_MISMATCH'))
       OR (prev='UNKNOWN' AND NEW.state IN ('EXPIRED','FAILED','FINALIZED','ANCHOR_MISMATCH'))
       OR (prev='EXPIRED' AND NEW.state IN ('FINALIZED','ANCHOR_MISMATCH'))) THEN
    RAISE EXCEPTION 'illegal publication attempt transition % -> %', coalesce(prev,'<none>'), NEW.state;
  END IF;
  IF NEW.state IN ('SIGNED','FINALIZED') AND NOT EXISTS (SELECT 1 FROM wf_publication_tx_signed WHERE attempt_id=NEW.attempt_id) THEN
    RAISE EXCEPTION 'signed state requires journaled signed bytes';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER event_guard BEFORE INSERT ON wf_publication_tx_event FOR EACH ROW EXECUTE FUNCTION wf_publication_event_guard();

-- An anchor row must agree with the stored intent and a FINALIZED attempt of
-- the same operation, written under the current fence.
CREATE FUNCTION wf_publication_anchor_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j jsonb; i record;
BEGIN
  PERFORM wf_publication_require_lease(NEW.operation_id, NEW.fence, NEW.worker);
  SELECT * INTO i FROM wf_publication_intent WHERE operation_id=NEW.operation_id;
  j := convert_from(i.intent_bytes,'UTF8')::jsonb;
  IF NEW.intent_hash<>i.intent_hash OR NEW.batch_sequence<>i.batch_sequence OR NEW.registry_id<>i.registry_id
     OR NEW.merkle_root IS DISTINCT FROM j->>'merkleRoot' OR NEW.manifest_hash IS DISTINCT FROM j->>'manifestHash' THEN
    RAISE EXCEPTION 'publication anchor disagrees with the stored intent';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM wf_publication_tx t JOIN wf_publication_tx_signed s USING(attempt_id)
                 WHERE t.attempt_id=NEW.attempt_id AND t.operation_id=NEW.operation_id AND t.intent_hash=i.intent_hash
                   AND t.segment_pda=NEW.segment_pda AND s.signature=NEW.signature
                   AND wf_publication_tx_state(t.attempt_id)='FINALIZED') THEN
    RAISE EXCEPTION 'publication anchor requires a finalized attempt';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER anchor_guard BEFORE INSERT ON wf_publication_anchor FOR EACH ROW EXECUTE FUNCTION wf_publication_anchor_guard();

CREATE FUNCTION wf_publication_abandon_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM wf_publication_require_lease(NEW.operation_id, NEW.fence, NEW.worker);
  IF EXISTS (SELECT 1 FROM wf_publication_anchor WHERE operation_id=NEW.operation_id)
     OR EXISTS (SELECT 1 FROM wf_publication_tx t WHERE t.operation_id=NEW.operation_id AND wf_publication_tx_state(t.attempt_id)='ANCHOR_MISMATCH') THEN
    RAISE EXCEPTION 'a landed publication cannot be abandoned';
  END IF;
  IF NEW.blocked_reason IS DISTINCT FROM (SELECT blocked_reason FROM wf_publication WHERE operation_id=NEW.operation_id) THEN
    RAISE EXCEPTION 'abandonment must record the current block reason';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER abandon_guard BEFORE INSERT ON wf_publication_abandonment FOR EACH ROW EXECUTE FUNCTION wf_publication_abandon_guard();

CREATE FUNCTION wf_publication_discrepancy_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM wf_publication_require_lease(NEW.operation_id, NEW.fence, NEW.worker);
  IF NOT EXISTS (SELECT 1 FROM wf_publication_tx t JOIN wf_publication_tx_signed s USING(attempt_id)
                 WHERE t.attempt_id=NEW.attempt_id AND t.operation_id=NEW.operation_id AND s.signature=NEW.signature
                   AND wf_publication_tx_state(t.attempt_id)='ANCHOR_MISMATCH')
     OR NEW.blocked_reason IS DISTINCT FROM (SELECT blocked_reason FROM wf_publication WHERE operation_id=NEW.operation_id) THEN
    RAISE EXCEPTION 'a landed discrepancy requires an ANCHOR_MISMATCH attempt of a blocked operation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER discrepancy_guard BEFORE INSERT ON wf_publication_discrepancy FOR EACH ROW EXECUTE FUNCTION wf_publication_discrepancy_guard();

CREATE FUNCTION wf_publication_state_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
  IF NEW.state='ABANDONED' AND NOT EXISTS (SELECT 1 FROM wf_publication_abandonment WHERE operation_id=NEW.operation_id AND successor_operation_id=NEW.superseded_by) THEN
    RAISE EXCEPTION 'publication cannot be abandoned without a two-person maintenance record';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER state_guard BEFORE UPDATE OR DELETE ON wf_publication FOR EACH ROW EXECUTE FUNCTION wf_publication_state_guard();
