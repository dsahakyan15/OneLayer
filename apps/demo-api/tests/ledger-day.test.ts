import assert from "node:assert/strict";
import test from "node:test";
import { ledgerDay } from "../src/ledger-day.ts";

test("ledger day matches the program's YYYYMMDD encoding", () => {
  assert.equal(ledgerDay(new Date(0)), 19700101);
  assert.equal(ledgerDay(new Date("2026-09-24T23:59:59.999Z")), 20260924);
  assert.equal(ledgerDay(new Date("2024-02-29T00:00:00Z")), 20240229);
  assert.equal(ledgerDay(new Date("2026-12-31T23:59:59+05:00")), 20261231);
  assert.throws(() => ledgerDay(new Date(Number.NaN)), RangeError);
});
