-- Ticket 16 follow-up: 0018 created snapshot_key_version with immutability
-- triggers but the table inherited the 0016 default DML grant, so the runtime
-- role held UPDATE and DELETE on it. The triggers refuse those statements, but
-- least privilege should not depend on them remaining installed. 0018
-- may already be recorded in deployment migration journals, so the correction
-- lands here instead of editing it. The runtime role keeps INSERT and SELECT, which
-- the startup binding needs; TRUNCATE was never granted by the defaults and is
-- revoked explicitly to state the full intended privilege set. The guard keeps
-- this migration applicable on a database that has no runtime role.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'onelayer_runtime') THEN
    EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON snapshot_key_version FROM onelayer_runtime';
  END IF;
END $$;
