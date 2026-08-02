-- Dynamic record fields for the visual MVP (§5.4, OL-C-36…OL-C-39).
--
-- The record used to carry a single `status` field, so every commitment in the
-- demo was a constant. The certificate the user supplies (JSON or CSV against
-- the `land-registry-v1` demo schema) now decides the field set.
--
-- `status` deliberately stays a column of `synthetic_registry_record`: the
-- seeded fixture and the Rust CLI happy path build their leaves from it, and
-- there is no reason to change their format for the UI. Every other path lives
-- here, one row per path of the current record version.

CREATE TABLE synthetic_record_field (
  internal_record_id TEXT NOT NULL
    REFERENCES synthetic_registry_record(internal_record_id) ON DELETE CASCADE,
  path TEXT NOT NULL CHECK (path ~ '^[a-zA-Z][A-Za-z0-9]{0,62}$' AND path <> 'status'),
  -- Mirrors the canonical value types of spec/canonical-record-v1.md §3:
  -- decimal and timestamp are strings on purpose, floats never appear.
  value_type TEXT NOT NULL CHECK (value_type IN ('text', 'decimal', 'timestamp', 'bool', 'hex')),
  value_text TEXT NOT NULL CHECK (octet_length(value_text) BETWEEN 1 AND 512),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (internal_record_id, path)
);

-- Which schema version the record was imported against, and where it came from.
ALTER TABLE synthetic_registry_record
  ADD COLUMN schema_id TEXT NOT NULL DEFAULT 'land-registry-v1',
  ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- OL-C-39: a certificate records how much of the record it discloses. The
-- disclosed paths are also carried by the package itself; this copy only drives
-- the Admin list and detail views.
ALTER TABLE demo_certificate
  ADD COLUMN disclosure_mode TEXT NOT NULL DEFAULT 'FULL_RECORD'
    CHECK (disclosure_mode IN ('FULL_RECORD', 'SELECTIVE_FIELDS')),
  ADD COLUMN disclosed_paths TEXT[] NOT NULL DEFAULT '{}';
