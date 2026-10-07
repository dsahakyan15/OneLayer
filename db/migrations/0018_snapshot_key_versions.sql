-- Ticket 16: a deployment cannot silently replace material under a previously
-- used key version. Only a domain-separated digest is persisted, never a KEK or
-- a recovery share. This is software-lab integrity bookkeeping, not KMS/HSM.
CREATE TABLE snapshot_key_version (
  registry_id text NOT NULL CHECK (registry_id ~ '^[a-z0-9][a-z0-9._-]{0,127}$'),
  key_encryption_version text NOT NULL CHECK (key_encryption_version ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
  key_material_fingerprint bytea NOT NULL CHECK (octet_length(key_material_fingerprint) = 32),
  registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (registry_id, key_encryption_version)
);

CREATE FUNCTION snapshot_key_version_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'snapshot key version bindings are immutable' USING ERRCODE = '55000';
END;
$$;
CREATE TRIGGER snapshot_key_version_no_update_delete
  BEFORE UPDATE OR DELETE ON snapshot_key_version
  FOR EACH ROW EXECUTE FUNCTION snapshot_key_version_immutable();
CREATE TRIGGER snapshot_key_version_no_truncate
  BEFORE TRUNCATE ON snapshot_key_version
  FOR EACH STATEMENT EXECUTE FUNCTION snapshot_key_version_immutable();
-- Runtime needs SELECT/INSERT, never table ownership or UPDATE/DELETE/TRUNCATE.
-- A database owner can disable triggers: least-privilege provisioning is a
-- separate production gate. Do not drop old bindings when rotating versions.
