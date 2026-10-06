-- Durable identity for the loopback synthetic demo. Password authentication
-- still uses deployment credentials; this is not corporate OIDC provisioning.
CREATE TABLE demo_admin_account (
  username TEXT PRIMARY KEY CHECK (length(username) > 0),
  role TEXT NOT NULL CHECK (role IN ('operator', 'auditor', 'chief_admin')),
  permissions TEXT[] NOT NULL CHECK (array_position(permissions, NULL) IS NULL),
  registry_ids TEXT[] NOT NULL CHECK (array_position(registry_ids, NULL) IS NULL),
  enabled BOOLEAN NOT NULL DEFAULT true,
  access_revision BIGINT NOT NULL DEFAULT 1 CHECK (access_revision > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE demo_admin_session (
  token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  username TEXT NOT NULL REFERENCES demo_admin_account(username),
  access_revision BIGINT NOT NULL CHECK (access_revision > 0),
  csrf_token TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL,
  CHECK (expires_at > created_at)
);
CREATE INDEX demo_admin_session_username ON demo_admin_session(username);
CREATE INDEX demo_admin_session_expiry ON demo_admin_session(expires_at);

CREATE TABLE demo_admin_access_event (
  event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username TEXT NOT NULL REFERENCES demo_admin_account(username),
  actor TEXT NOT NULL CHECK (length(actor) > 0),
  action TEXT NOT NULL CHECK (action IN ('BOOTSTRAP', 'REVOKE', 'ACCESS_CHANGED')),
  access_revision BIGINT NOT NULL,
  access JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
