-- Ticket 09 review residual H3: durable per-attempt approval.
--
-- The publisher reserves the exact unsigned attempt bytes (PREPARED) before any
-- signature, and the operator approves a commitment over those bytes plus the
-- reserved lifetime (blockhash / last valid block height), the quoted fee and
-- its bound, the attempt number, the day/segment destination, the cluster and
-- the semantic intent hash. `review` reserves; `run` signs only the reserved
-- bytes under the matching commitment. These columns make that reservation
-- durable and queryable; they never change an existing row (the table is
-- append-only). Pre-existing rows (none on a fresh database) keep NULL and are
-- treated as "no plan": they can still be reconciled/re-sent, but cannot be
-- signed under the approval contract.
ALTER TABLE wf_publication_tx
  ADD COLUMN cluster text,
  ADD COLUMN fee_lamports numeric(20) CHECK(fee_lamports IS NULL OR fee_lamports>=0),
  ADD COLUMN fee_limit_lamports numeric(20) CHECK(fee_limit_lamports IS NULL OR fee_limit_lamports>=0),
  ADD COLUMN plan_hash text CHECK(plan_hash IS NULL OR plan_hash ~ '^[0-9a-f]{64}$');

-- A planned reservation must carry the cluster and the quoted fee, and the
-- quote may not exceed its bound. This is defence in depth: the application
-- computes the plan hash over all of these, but a partial write must fail.
CREATE FUNCTION wf_publication_tx_plan_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.plan_hash IS NOT NULL OR NEW.fee_lamports IS NOT NULL OR NEW.fee_limit_lamports IS NOT NULL OR NEW.cluster IS NOT NULL) THEN
    IF NEW.plan_hash IS NULL OR NEW.cluster IS NULL OR NEW.fee_lamports IS NULL OR NEW.fee_limit_lamports IS NULL THEN
      RAISE EXCEPTION 'attempt plan requires cluster, fee quote, fee limit and plan hash';
    END IF;
    IF NEW.fee_lamports > NEW.fee_limit_lamports THEN
      RAISE EXCEPTION 'attempt fee quote exceeds the approved limit';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER tx_plan_guard BEFORE INSERT ON wf_publication_tx FOR EACH ROW EXECUTE FUNCTION wf_publication_tx_plan_guard();

-- The approval journal is append-only: record the exact approved plan hash with
-- the signature event so the audit trail shows which commitment authorized it.
-- (The event row already carries `detail`; no schema change is needed.)
