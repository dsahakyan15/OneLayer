ALTER TABLE demo_admin_account DROP CONSTRAINT demo_admin_account_role_check;
ALTER TABLE demo_admin_account ADD CONSTRAINT demo_admin_account_role_check CHECK
  (role IN ('operator','auditor','chief_admin','registry_worker','registry_approver','identity_admin','key_holder','storage_custodian'));
ALTER TABLE demo_admin_account ADD COLUMN auth_source TEXT NOT NULL DEFAULT 'password' CHECK (auth_source IN ('password','oidc'));
ALTER TABLE demo_admin_account ADD COLUMN oidc_issuer TEXT;
ALTER TABLE demo_admin_account ADD COLUMN oidc_subject TEXT;
ALTER TABLE demo_admin_account ADD COLUMN resource_policy JSONB NOT NULL DEFAULT '{"version":1,"grants":[]}';
ALTER TABLE demo_admin_account ADD CONSTRAINT oidc_identity_binding CHECK
  ((auth_source='password' AND oidc_issuer IS NULL AND oidc_subject IS NULL) OR
   (auth_source='oidc' AND oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL AND length(oidc_issuer)>0 AND length(oidc_subject)>0));
CREATE UNIQUE INDEX demo_admin_oidc_subject ON demo_admin_account(oidc_issuer,oidc_subject) WHERE auth_source='oidc';
CREATE TABLE demo_managed_device (
  device_id TEXT PRIMARY KEY CHECK(length(device_id)>0),
  username TEXT NOT NULL REFERENCES demo_admin_account(username),
  enabled BOOLEAN NOT NULL DEFAULT true,
  revision BIGINT NOT NULL DEFAULT 1 CHECK(revision>0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE demo_admin_session ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'password' CHECK(auth_method IN ('password','oidc'));
ALTER TABLE demo_admin_session ADD COLUMN device_id TEXT REFERENCES demo_managed_device(device_id);
ALTER TABLE demo_admin_session ADD COLUMN device_revision BIGINT;
ALTER TABLE demo_admin_session ADD CONSTRAINT session_device_binding CHECK
 ((auth_method='password' AND device_id IS NULL AND device_revision IS NULL) OR
  (auth_method='oidc' AND device_id IS NOT NULL AND device_revision IS NOT NULL AND device_revision>0));
ALTER TABLE demo_admin_access_event DROP CONSTRAINT demo_admin_access_event_action_check;
ALTER TABLE demo_admin_access_event ADD CONSTRAINT demo_admin_access_event_action_check CHECK
(action IN ('BOOTSTRAP','REVOKE','ACCESS_CHANGED','ACCOUNT_PROVISIONED','DEVICE_ENROLLED','DEVICE_REVOKED','RESOURCE_POLICY_CHANGED'));
