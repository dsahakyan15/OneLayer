import assert from "node:assert/strict";
import test from "node:test";
import { fixtureRoot } from "../src/reconcile.ts";

const rows = [
  { internalRecordId: "SYNTHETIC-1", recordVersion: "1", status: "ACTIVE", recordFieldKeyHex: "01".repeat(32) },
  { internalRecordId: "SYNTHETIC-2", recordVersion: "1", status: "ACTIVE", recordFieldKeyHex: "02".repeat(32) },
];

test("synthetic fixture root is deterministic and tampering changes it", () => {
  const clean = fixtureRoot(rows);
  assert.match(clean, /^[0-9a-f]{64}$/);
  assert.equal(fixtureRoot(rows), clean);
  assert.notEqual(fixtureRoot([{ ...rows[0], status: "TAMPERED" }, rows[1]]), clean);
});

test("non-synthetic records are rejected", () => {
  assert.throws(() => fixtureRoot([{ ...rows[0], internalRecordId: "REAL-1" }]), /non-synthetic/);
});
