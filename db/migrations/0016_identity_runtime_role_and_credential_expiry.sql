-- Ticket 07: (1) owner/runtime separation and (2) mandatory service credential
-- expiry. Apply as the schema OWNER (the role that ran 0001-0015). The API and
-- the host CLI connect as a LOGIN role that is a member of onelayer_runtime;
-- that role owns nothing, so it cannot ALTER/DISABLE triggers, TRUNCATE, or
-- DROP, and it has no UPDATE/DELETE on append-only tables.

-- (2) Credential expiry. Existing credentials get the default 90-day lifetime
-- from creation (already-old ones therefore expire). 366 days is a hard ceiling;
-- the configured maximum (ONELAYER_SERVICE_CREDENTIAL_MAX_TTL_DAYS) is lower.
ALTER TABLE service_principal_credential ADD COLUMN expires_at TIMESTAMPTZ;
UPDATE service_principal_credential SET expires_at = created_at + interval '90 days' WHERE expires_at IS NULL;
ALTER TABLE service_principal_credential ALTER COLUMN expires_at SET NOT NULL;
ALTER TABLE service_principal_credential ADD CONSTRAINT service_credential_ttl
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '366 days');

ALTER TABLE service_principal_denial_window DROP CONSTRAINT service_principal_denial_window_reason_check;
ALTER TABLE service_principal_denial_window ADD CONSTRAINT service_principal_denial_window_reason_check CHECK (reason IN (
  'SECRET_MISMATCH','CREDENTIAL_REVOKED','CREDENTIAL_EXPIRED','PRINCIPAL_DISABLED','ACTION_NOT_ALLOWED','REGISTRY_OUT_OF_SCOPE'));

-- (3) Read-only verifier actions, each still bound to an explicit registry scope.
ALTER TABLE service_principal DROP CONSTRAINT service_principal_actions_check;
ALTER TABLE service_principal ADD CONSTRAINT service_principal_actions_check CHECK (
  cardinality(actions) > 0 AND array_position(actions, NULL) IS NULL
  AND actions <@ ARRAY['artifacts.register','integrity.reconcile','certificates.read','incidents.read','anchors.read']::text[]);

-- (1) Runtime role. NOLOGIN: deployments create a LOGIN member, e.g.
--   CREATE ROLE onelayer_api LOGIN PASSWORD '...' IN ROLE onelayer_runtime;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'onelayer_runtime') THEN
    CREATE ROLE onelayer_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM onelayer_runtime;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM onelayer_runtime;
REVOKE CREATE ON SCHEMA public FROM onelayer_runtime;
GRANT USAGE ON SCHEMA public TO onelayer_runtime;
-- No TRUNCATE, REFERENCES or TRIGGER privilege is ever granted.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO onelayer_runtime;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO onelayer_runtime;

-- Append-only tables: INSERT/SELECT only. This covers the identity audit tables
-- and every table guarded by an unconditional immutability trigger.
REVOKE UPDATE, DELETE ON service_principal_event, demo_admin_access_event FROM onelayer_runtime;
DO $$
DECLARE t regclass;
BEGIN
  FOR t IN
    SELECT DISTINCT tg.tgrelid::regclass FROM pg_trigger tg JOIN pg_proc p ON p.oid = tg.tgfoid
     WHERE NOT tg.tgisinternal AND p.proname IN ('wf_immutable', 'service_principal_event_append_only')
       AND (tg.tgtype & 8) <> 0 AND (tg.tgtype & 16) <> 0  -- row trigger on both DELETE and UPDATE
  LOOP
    EXECUTE format('REVOKE UPDATE, DELETE ON %s FROM onelayer_runtime', t);
  END LOOP;
END $$;

-- Tables created later by the same owner get the default DML grant. A later
-- migration that adds an append-only table must REVOKE UPDATE, DELETE itself.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO onelayer_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO onelayer_runtime;
