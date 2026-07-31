INSERT INTO demo_fixture_marker(marker)
VALUES ('ONELAYER_SYNTHETIC_DEVNET_DEMO_V1')
ON CONFLICT (marker) DO NOTHING;

INSERT INTO synthetic_registry_record (
  internal_record_id, source_cursor, record_version, status, record_field_key_hex
) VALUES
  ('SYNTHETIC-1', 1, 1, 'ACTIVE', repeat('01', 32)),
  ('SYNTHETIC-2', 2, 1, 'ACTIVE', repeat('02', 32))
ON CONFLICT (internal_record_id) DO UPDATE SET
  source_cursor = EXCLUDED.source_cursor,
  record_version = EXCLUDED.record_version,
  status = EXCLUDED.status,
  record_field_key_hex = EXCLUDED.record_field_key_hex,
  fixture_generation = synthetic_registry_record.fixture_generation + 1;
