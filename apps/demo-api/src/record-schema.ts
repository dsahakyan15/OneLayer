// Demo registry schema `land-registry-v1` (OL-C-36).
//
// The frozen documents in `spec/` describe the protocol, which is the same for
// any registry; this file describes one concrete registry: which field paths
// exist, what their canonical types are and which of them a record must carry.
// A path outside the list is rejected as `CANONICALIZATION_FAILED` rather than
// dropped, because a silently dropped field would not be covered by the anchor
// (spec/canonical-record-v1.md §4).
import { nfc, type CborValue } from "../../../packages/canonical-ts/src/index.ts";

export const SCHEMA_ID = "land-registry-v1";

/** Canonical value types of spec/canonical-record-v1.md §3 used by this schema. */
export type ValueType = "text" | "decimal" | "timestamp" | "bool" | "hex";

export interface FieldDefinition {
  readonly type: ValueType;
  readonly required: boolean;
  readonly label: string;
  /** Closed value set for enumerated text fields. */
  readonly values?: readonly string[];
  /** Upper bound on `byte_len` after NFC + UTF-8, never on code points. */
  readonly maxBytes?: number;
  /** Digits after the decimal point; the scale is fixed, `"0.10" !== "0.1"`. */
  readonly scale?: number;
  readonly example: string;
  readonly hint: string;
}

/**
 * `status` is part of the schema but is stored as a column of
 * `synthetic_registry_record`, because the seeded fixture and the Rust CLI path
 * build their leaves from it.
 */
export const STATUS_PATH = "status";

export const LAND_REGISTRY_V1: Readonly<Record<string, FieldDefinition>> = {
  status: {
    type: "text",
    required: true,
    label: "Record status",
    values: ["ACTIVE", "ARCHIVED", "PENDING", "DISPUTED"],
    example: "ACTIVE",
    hint: "Lifecycle of the registry record itself.",
  },
  cadastralNumber: {
    type: "text",
    required: true,
    label: "Cadastral number",
    maxBytes: 64,
    example: "01-004-0123-045",
    hint: "Identifier of the parcel in the registry.",
  },
  parcelAddress: {
    type: "text",
    required: false,
    label: "Parcel address",
    maxBytes: 256,
    example: "Yerevan, Arshakunyats 12",
    hint: "Free-form address as recorded by the registry.",
  },
  areaSquareMeters: {
    type: "decimal",
    required: false,
    label: "Area (m²)",
    scale: 2,
    example: "1250.50",
    hint: "Decimal string with exactly two digits after the point.",
  },
  landCategory: {
    type: "text",
    required: false,
    label: "Land category",
    values: ["AGRICULTURAL", "SETTLEMENT", "INDUSTRIAL", "FOREST", "WATER", "RESERVE"],
    example: "SETTLEMENT",
    hint: "Closed list; anything else is rejected.",
  },
  permittedUse: {
    type: "text",
    required: false,
    label: "Permitted use",
    maxBytes: 128,
    example: "Residential construction",
    hint: "What the parcel may be used for.",
  },
  rightType: {
    type: "text",
    required: false,
    label: "Right type",
    values: ["OWNERSHIP", "LEASE", "EASEMENT", "MORTGAGE"],
    example: "OWNERSHIP",
    hint: "Kind of right registered on the parcel.",
  },
  rightRegisteredAt: {
    type: "timestamp",
    required: false,
    label: "Right registered at",
    example: "2026-03-14T09:00:00Z",
    hint: "RFC 3339, UTC, no fractional seconds.",
  },
  encumbered: {
    type: "bool",
    required: false,
    label: "Encumbered",
    example: "false",
    hint: "Whether an encumbrance is registered.",
  },
  holderCommitment: {
    type: "hex",
    required: false,
    label: "Holder commitment",
    example: "a".repeat(64),
    hint: "Commitment to the right holder. The registry never stores the identity itself.",
  },
  documentHash: {
    type: "hex",
    required: false,
    label: "Source document hash",
    example: "b".repeat(64),
    hint: "SHA-256 of the paper or PDF certificate, computed outside the system.",
  },
};

export const SCHEMA_PATHS: readonly string[] = Object.keys(LAND_REGISTRY_V1);

export class SchemaError extends Error {
  readonly code: string;
  readonly path: string | null;
  readonly row: number | null;

  constructor(code: string, path: string | null = null, row: number | null = null) {
    super(code);
    this.code = code;
    this.path = path;
    this.row = row;
  }

  toJSON(): Record<string, unknown> {
    return { code: this.code, path: this.path, row: this.row };
  }
}

export interface ValidatedField {
  path: string;
  type: ValueType;
  /** Canonical text form; what the database stores and what CBOR encodes. */
  value: string;
}

export interface ValidatedRecord {
  internalRecordId: string;
  status: string;
  /** Every path except `status`, sorted by path. */
  fields: ValidatedField[];
}

const TIMESTAMP = /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;
const HEX_32 = /^[0-9a-f]{64}$/;
const RECORD_ID = /^SYNTHETIC-[1-9][0-9]*$/;

function byteLength(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

/**
 * Validates one raw value against its definition and returns the canonical text
 * form. Values arrive as strings from CSV and may arrive as booleans or numbers
 * from JSON; numbers are refused for decimals on purpose, because JSON numbers
 * lose the scale that the commitment depends on.
 */
export function validateValue(path: string, raw: unknown, row: number | null = null): ValidatedField {
  const definition = LAND_REGISTRY_V1[path];
  if (definition === undefined) throw new SchemaError("CANONICALIZATION_FAILED", path, row);

  if (definition.type === "bool") {
    if (raw === true || raw === false) return { path, type: "bool", value: raw ? "true" : "false" };
    if (raw === "true" || raw === "false") return { path, type: "bool", value: raw };
    throw new SchemaError("FIELD_TYPE_INVALID", path, row);
  }

  if (typeof raw !== "string") throw new SchemaError("FIELD_TYPE_INVALID", path, row);
  const value = nfc(raw.trim());
  if (value.length === 0) throw new SchemaError("FIELD_VALUE_EMPTY", path, row);

  switch (definition.type) {
    case "text": {
      if (definition.values !== undefined && !definition.values.includes(value)) {
        throw new SchemaError("FIELD_VALUE_NOT_ALLOWED", path, row);
      }
      if (definition.maxBytes !== undefined && byteLength(value) > definition.maxBytes) {
        throw new SchemaError("FIELD_TOO_LONG", path, row);
      }
      return { path, type: "text", value };
    }
    case "decimal": {
      const scale = definition.scale ?? 2;
      // The scale is part of the value: "0.10" and "0.1" are different
      // commitments, so a shorter fraction is an error rather than a hint.
      const pattern = new RegExp(`^-?(?:0|[1-9][0-9]{0,15})\\.[0-9]{${scale}}$`);
      if (!pattern.test(value) || value === `-0.${"0".repeat(scale)}`) {
        throw new SchemaError("FIELD_DECIMAL_INVALID", path, row);
      }
      return { path, type: "decimal", value };
    }
    case "timestamp": {
      if (!TIMESTAMP.test(value)) throw new SchemaError("FIELD_TIMESTAMP_INVALID", path, row);
      if (Number.isNaN(Date.parse(value))) throw new SchemaError("FIELD_TIMESTAMP_INVALID", path, row);
      return { path, type: "timestamp", value };
    }
    case "hex": {
      if (!HEX_32.test(value)) throw new SchemaError("FIELD_HEX_INVALID", path, row);
      return { path, type: "hex", value };
    }
    default:
      throw new SchemaError("FIELD_TYPE_INVALID", path, row);
  }
}

/**
 * Validates a whole record: every supplied path must exist in the schema and
 * every required path must be present.
 */
export function validateRecord(
  input: { internalRecordId?: unknown; fields?: unknown },
  row: number | null = null,
): ValidatedRecord {
  const internalRecordId = typeof input.internalRecordId === "string" ? nfc(input.internalRecordId.trim()) : "";
  if (!RECORD_ID.test(internalRecordId)) throw new SchemaError("INTERNAL_RECORD_ID_INVALID", "internalRecordId", row);
  const raw = input.fields;
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new SchemaError("FIELDS_INVALID", "fields", row);
  }

  const validated = new Map<string, ValidatedField>();
  for (const [path, value] of Object.entries(raw as Record<string, unknown>)) {
    if (value === undefined || value === null) continue;
    const normalizedPath = nfc(path.trim());
    if (validated.has(normalizedPath)) throw new SchemaError("FIELD_DUPLICATED", normalizedPath, row);
    validated.set(normalizedPath, validateValue(normalizedPath, value, row));
  }
  for (const [path, definition] of Object.entries(LAND_REGISTRY_V1)) {
    if (definition.required && !validated.has(path)) {
      throw new SchemaError("FIELD_REQUIRED_MISSING", path, row);
    }
  }

  const status = validated.get(STATUS_PATH)!.value;
  const fields = [...validated.values()]
    .filter((field) => field.path !== STATUS_PATH)
    .sort((left, right) => Buffer.compare(Buffer.from(left.path, "utf8"), Buffer.from(right.path, "utf8")));
  return { internalRecordId, status, fields };
}

/** Canonical CBOR value for a stored field. */
export function cborValue(field: { type: ValueType; value: string }): CborValue {
  if (field.type === "bool") return { type: "bool", value: field.value === "true" };
  // Decimal, timestamp and hex are text strings in the canonical encoding: all
  // three have semantically distinct representations that a numeric or binary
  // form would normalise away.
  return { type: "text", value: field.value };
}

export interface ImportRow {
  row: number;
  record: ValidatedRecord;
}

export interface ImportReport {
  accepted: ImportRow[];
  rejected: Array<{ row: number; code: string; path: string | null }>;
}

const MAX_IMPORT_ROWS = 200;

/**
 * Splits one CSV line. Supports quoted values with doubled quotes inside, which
 * is what spreadsheets emit for addresses containing commas.
 */
export function splitCsvLine(line: string, row: number): string[] {
  const values: string[] = [];
  let current = "";
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (quoted) {
      if (character === '"') {
        if (line[index + 1] === '"') { current += '"'; index += 1; continue; }
        quoted = false;
        continue;
      }
      current += character;
      continue;
    }
    if (character === '"') { quoted = true; continue; }
    if (character === ",") { values.push(current); current = ""; continue; }
    current += character;
  }
  if (quoted) throw new SchemaError("CSV_QUOTE_UNCLOSED", null, row);
  values.push(current);
  return values;
}

/**
 * CSV import: the first line names the field paths, every later line is one
 * record. A bad line rejects that line and is reported with its number; the
 * remaining lines are still validated, so the operator sees the whole picture
 * instead of the first failure only.
 */
export function parseCsv(text: string): ImportReport {
  const lines = text.split(/\r?\n/).filter((line) => line.trim().length > 0);
  if (lines.length < 2) throw new SchemaError("CSV_EMPTY");
  if (lines.length - 1 > MAX_IMPORT_ROWS) throw new SchemaError("CSV_TOO_MANY_ROWS");
  const header = splitCsvLine(lines[0], 1).map((column) => nfc(column.trim()));
  if (header.length === 0 || new Set(header).size !== header.length) throw new SchemaError("CSV_HEADER_INVALID", null, 1);
  if (!header.includes("internalRecordId")) throw new SchemaError("CSV_HEADER_INVALID", "internalRecordId", 1);

  const report: ImportReport = { accepted: [], rejected: [] };
  for (let index = 1; index < lines.length; index += 1) {
    const row = index + 1;
    try {
      const values = splitCsvLine(lines[index], row);
      if (values.length !== header.length) throw new SchemaError("CSV_COLUMN_COUNT_MISMATCH", null, row);
      const fields: Record<string, unknown> = {};
      let internalRecordId = "";
      header.forEach((column, position) => {
        const value = values[position].trim();
        if (column === "internalRecordId") { internalRecordId = value; return; }
        if (value.length === 0) return;
        fields[column] = value;
      });
      report.accepted.push({ row, record: validateRecord({ internalRecordId, fields }, row) });
    } catch (error) {
      if (!(error instanceof SchemaError)) throw error;
      report.rejected.push({ row: error.row ?? row, code: error.code, path: error.path });
    }
  }
  const seen = new Set<string>();
  for (const entry of report.accepted) {
    if (seen.has(entry.record.internalRecordId)) {
      report.rejected.push({ row: entry.row, code: "RECORD_DUPLICATED", path: "internalRecordId" });
    }
    seen.add(entry.record.internalRecordId);
  }
  report.accepted = report.accepted.filter(
    (entry) => !report.rejected.some((rejection) => rejection.row === entry.row),
  );
  return report;
}

/**
 * JSON import: either one record object or an array of them. Rows are numbered
 * from 1 so the report reads the same way for both formats.
 */
export function parseJsonRecords(input: unknown): ImportReport {
  const items = Array.isArray(input) ? input : [input];
  if (items.length === 0) throw new SchemaError("JSON_EMPTY");
  if (items.length > MAX_IMPORT_ROWS) throw new SchemaError("JSON_TOO_MANY_ROWS");
  const report: ImportReport = { accepted: [], rejected: [] };
  items.forEach((item, index) => {
    const row = index + 1;
    try {
      if (item === null || typeof item !== "object" || Array.isArray(item)) {
        throw new SchemaError("RECORD_INVALID", null, row);
      }
      report.accepted.push({ row, record: validateRecord(item as Record<string, unknown>, row) });
    } catch (error) {
      if (!(error instanceof SchemaError)) throw error;
      report.rejected.push({ row: error.row ?? row, code: error.code, path: error.path });
    }
  });
  return report;
}

/** Schema description served to the UI so the wizard is not a second source. */
export function describeSchema(): Record<string, unknown> {
  return {
    schemaId: SCHEMA_ID,
    fields: Object.entries(LAND_REGISTRY_V1).map(([path, definition]) => ({
      path,
      type: definition.type,
      required: definition.required,
      label: definition.label,
      values: definition.values ?? null,
      maxBytes: definition.maxBytes ?? null,
      scale: definition.scale ?? null,
      example: definition.example,
      hint: definition.hint,
    })),
  };
}
