-- Durable, scoped non-human identities for trusted internal callers. A service
-- principal is never a human admin account or session. Only a SHA-256 digest of
-- the random 256-bit secret is stored; the raw bearer is shown once to the
-- trusted host CLI that provisioned or rotated it.
CREATE TABLE service_principal (
  principal_id TEXT PRIMARY KEY CHECK (principal_id ~ '^[a-z][a-z0-9._-]{2,63}$'),
  actions TEXT[] NOT NULL CHECK (
    cardinality(actions) > 0 AND array_position(actions, NULL) IS NULL
    AND actions <@ ARRAY['artifacts.register','integrity.reconcile']::text[]),
  registry_ids TEXT[] NOT NULL CHECK (
    cardinality(registry_ids) > 0 AND array_position(registry_ids, NULL) IS NULL
    AND NOT ('*' = ANY(registry_ids)) AND NOT ('' = ANY(registry_ids))),
  enabled BOOLEAN NOT NULL DEFAULT true,
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE service_principal_credential (
  credential_id TEXT PRIMARY KEY CHECK (credential_id ~ '^[A-Za-z0-9_-]{22}$'),
  principal_id TEXT NOT NULL REFERENCES service_principal(principal_id),
  secret_hash BYTEA NOT NULL CHECK (octet_length(secret_hash) = 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  revoked_at TIMESTAMPTZ,
  CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
-- At most one live secret: rotation revokes the previous one in the same transaction.
CREATE UNIQUE INDEX service_principal_one_live_credential
  ON service_principal_credential(principal_id) WHERE revoked_at IS NULL;

CREATE TABLE service_principal_event (
  event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES service_principal(principal_id),
  credential_id TEXT,
  actor TEXT NOT NULL CHECK (length(actor) > 0),
  event TEXT NOT NULL CHECK (event IN (
    'PROVISIONED','ROTATED','REVOKED','REQUEST_AUTHORIZED','REQUEST_DENIED')),
  revision BIGINT NOT NULL CHECK (revision > 0),
  service_action TEXT,
  registry_id TEXT,
  reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CHECK ((event IN ('REQUEST_AUTHORIZED','REQUEST_DENIED')) = (service_action IS NOT NULL)),
  CHECK ((event = 'REQUEST_DENIED') = (reason IS NOT NULL)),
  CHECK (registry_id IS NULL OR registry_id ~ '^[a-z][a-z0-9-]{0,62}(\.[a-z][a-z0-9-]{0,62}){1,7}$')
);
CREATE INDEX service_principal_event_principal ON service_principal_event(principal_id, event_id);

-- Denial counters. Only the first denial per credential/reason/action/minute is
-- written to the append-only event log; repeats increment this counter, so a
-- known or revoked credential ID cannot grow the append-only log without bound.
CREATE TABLE service_principal_denial_window (
  credential_id TEXT NOT NULL REFERENCES service_principal_credential(credential_id),
  principal_id TEXT NOT NULL REFERENCES service_principal(principal_id),
  reason TEXT NOT NULL CHECK (reason IN (
    'SECRET_MISMATCH','CREDENTIAL_REVOKED','PRINCIPAL_DISABLED','ACTION_NOT_ALLOWED','REGISTRY_OUT_OF_SCOPE')),
  service_action TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  denials INTEGER NOT NULL DEFAULT 1 CHECK (denials > 0),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (credential_id, reason, service_action, window_start)
);

CREATE FUNCTION service_principal_event_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'service_principal_event is append-only';
END $$;
CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON service_principal_event
  FOR EACH ROW EXECUTE FUNCTION service_principal_event_append_only();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON service_principal_event
  FOR EACH STATEMENT EXECUTE FUNCTION service_principal_event_append_only();
-- Triggers do not bind the table owner (who can disable or drop them). The
-- production owner/runtime role split is documented in docs/admin-access-contract.md.
