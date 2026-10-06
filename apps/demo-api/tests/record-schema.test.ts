import assert from "node:assert/strict";
import { test } from "node:test";
import {
  cborValue,
  parseCsv,
  parseJsonRecords,
  SchemaError,
  validateRecord,
  validateValue,
} from "../src/record-schema.ts";

const VALID = {
  internalRecordId: "SYNTHETIC-7",
  fields: {
    status: "ACTIVE",
    cadastralNumber: "01-004-0123-045",
    areaSquareMeters: "1250.50",
    encumbered: false,
    rightRegisteredAt: "2026-03-14T09:00:00Z",
    holderCommitment: "a".repeat(64),
  },
};

test("a certificate matching the schema is accepted and sorted by path", () => {
  const record = validateRecord(VALID);
  assert.equal(record.internalRecordId, "SYNTHETIC-7");
  assert.equal(record.status, "ACTIVE");
  assert.deepEqual(
    record.fields.map((field) => field.path),
    ["areaSquareMeters", "cadastralNumber", "encumbered", "holderCommitment", "rightRegisteredAt"],
  );
  // `status` lives in its own column and never appears twice.
  assert.equal(record.fields.some((field) => field.path === "status"), false);
});

/** Returns the schema error a call raised, failing the test if it raised none. */
function rejection(call: () => unknown): SchemaError {
  try {
    call();
  } catch (error) {
    assert.ok(error instanceof SchemaError, `expected a SchemaError, got ${String(error)}`);
    return error;
  }
  assert.fail("expected a rejection");
}

test("a path outside the schema is rejected, never dropped", () => {
  const error = rejection(() => validateRecord({ ...VALID, fields: { ...VALID.fields, ownerFullName: "Someone" } }));
  assert.equal(error.code, "CANONICALIZATION_FAILED");
  assert.equal(error.path, "ownerFullName");
});

test("a missing required path is rejected", () => {
  const error = rejection(() => validateRecord({ internalRecordId: "SYNTHETIC-7", fields: { status: "ACTIVE" } }));
  assert.equal(error.code, "FIELD_REQUIRED_MISSING");
  assert.equal(error.path, "cadastralNumber");
});

test("decimals keep their scale, because the scale is part of the commitment", () => {
  assert.equal(validateValue("areaSquareMeters", "0.10").value, "0.10");
  for (const value of ["0.1", "1250.5", "1250", "1250.500", "1.2e3", "-0.00"]) {
    assert.throws(() => validateValue("areaSquareMeters", value), SchemaError, `accepted ${value}`);
  }
});

test("timestamps are RFC 3339 UTC without a fractional part", () => {
  assert.equal(validateValue("rightRegisteredAt", "2026-03-14T09:00:00Z").value, "2026-03-14T09:00:00Z");
  for (const value of ["2026-03-14T09:00:00.000Z", "2026-03-14T09:00:00+04:00", "2026-13-14T09:00:00Z", "2026-03-14"]) {
    assert.throws(() => validateValue("rightRegisteredAt", value), SchemaError, `accepted ${value}`);
  }
});

test("enumerated fields accept only their listed values", () => {
  assert.equal(validateValue("landCategory", "FOREST").value, "FOREST");
  assert.throws(() => validateValue("landCategory", "forest"), SchemaError);
  assert.throws(() => validateValue("status", "ANYTHING"), SchemaError);
});

test("numbers are refused where the canonical type is a string", () => {
  // A JSON number would lose the scale the commitment depends on.
  assert.throws(() => validateValue("areaSquareMeters", 1250.5), SchemaError);
  assert.throws(() => validateValue("cadastralNumber", 1004), SchemaError);
  assert.equal(cborValue(validateValue("encumbered", true)).type, "bool");
});

test("strings are normalised to NFC before they are measured", () => {
  const composed = validateValue("parcelAddress", "Ереван, Арша́кунянц").value;
  assert.equal(composed.normalize("NFC"), composed);
  assert.throws(() => validateValue("parcelAddress", "x".repeat(257)), SchemaError);
});

test("CSV import reports the row and the path of every rejection", () => {
  const report = parseCsv([
    "internalRecordId,status,cadastralNumber,parcelAddress,areaSquareMeters",
    'SYNTHETIC-21,ACTIVE,01-004-0123-045,"Yerevan, Arshakunyats 12",1250.50',
    "SYNTHETIC-22,ACTIVE,01-004-0123-046,Yerevan,100.5",
    "SYNTHETIC-23,BROKEN,01-004-0123-047,Yerevan,100.50",
  ].join("\n"));
  assert.equal(report.accepted.length, 1);
  assert.equal(report.accepted[0].record.internalRecordId, "SYNTHETIC-21");
  // The quoted address survives the comma inside it.
  assert.equal(
    report.accepted[0].record.fields.find((field) => field.path === "parcelAddress")?.value,
    "Yerevan, Arshakunyats 12",
  );
  assert.deepEqual(report.rejected, [
    { row: 3, code: "FIELD_DECIMAL_INVALID", path: "areaSquareMeters" },
    { row: 4, code: "FIELD_VALUE_NOT_ALLOWED", path: "status" },
  ]);
});

test("a duplicated record in one CSV import is rejected rather than applied twice", () => {
  const report = parseCsv([
    "internalRecordId,status,cadastralNumber",
    "SYNTHETIC-24,ACTIVE,01-004-0123-048",
    "SYNTHETIC-24,ARCHIVED,01-004-0123-048",
  ].join("\n"));
  assert.equal(report.accepted.length, 1);
  assert.deepEqual(report.rejected, [{ row: 3, code: "RECORD_DUPLICATED", path: "internalRecordId" }]);
});

test("CSV without a data row or without the ID column is refused", () => {
  assert.throws(() => parseCsv("internalRecordId,status"), SchemaError);
  assert.throws(() => parseCsv("status,cadastralNumber\nACTIVE,01-004"), SchemaError);
});

test("JSON import accepts one object or an array and numbers the rows", () => {
  const single = parseJsonRecords(VALID);
  assert.equal(single.accepted.length, 1);
  assert.equal(single.accepted[0].row, 1);

  const many = parseJsonRecords([
    VALID,
    { internalRecordId: "SYNTHETIC-8", fields: { status: "ACTIVE" } },
  ]);
  assert.equal(many.accepted.length, 1);
  assert.deepEqual(many.rejected, [{ row: 2, code: "FIELD_REQUIRED_MISSING", path: "cadastralNumber" }]);
});
