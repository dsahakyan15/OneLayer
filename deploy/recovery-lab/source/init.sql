CREATE TABLE onelayer_fixture_marker (
  marker TEXT PRIMARY KEY CHECK (marker = 'ONELAYER_SYNTHETIC_FIXTURE_V1')
);
INSERT INTO onelayer_fixture_marker VALUES ('ONELAYER_SYNTHETIC_FIXTURE_V1');

CREATE TABLE synthetic_registry_record (
  internal_record_id TEXT PRIMARY KEY,
  source_cursor BIGINT NOT NULL UNIQUE,
  record_version BIGINT NOT NULL,
  status TEXT NOT NULL,
  record_field_key_hex TEXT NOT NULL CHECK (length(record_field_key_hex) = 64)
);
INSERT INTO synthetic_registry_record VALUES
  ('SYNTHETIC-1', 1, 1, 'ACTIVE', repeat('01', 32)),
  ('SYNTHETIC-2', 2, 1, 'ACTIVE', repeat('02', 32));
