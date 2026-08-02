import assert from "node:assert/strict";
import test from "node:test";
import { genesisAnchorHash, registryIdHash, toHex } from "../../../packages/canonical-ts/src/index.ts";
import { buildBatch } from "../src/admin-batch.ts";
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

test("reconcile and the batch builder agree on records with imported fields", () => {
  // R15: two field sets that drift apart would report a clean database as
  // tampered with, so the roots must match byte for byte.
  const fields = [
    { path: "cadastralNumber", type: "text" as const, value: "01-004-0123-045" },
    { path: "areaSquareMeters", type: "decimal" as const, value: "1250.50" },
  ];
  const withFields = [{ ...rows[0], fields }, rows[1]];
  const batch = buildBatch(
    withFields.map((row, index) => ({
      internalRecordId: row.internalRecordId,
      sourceCursor: BigInt(index + 1),
      recordVersion: BigInt(row.recordVersion),
      status: row.status,
      recordFieldKeyHex: row.recordFieldKeyHex,
      fields: (row as { fields?: typeof fields }).fields,
    })),
    {
      registryId: "gov.registry.land",
      batchSequence: 1n,
      registryVersion: 1n,
      previousAnchorHash: genesisAnchorHash(registryIdHash("gov.registry.land")),
      createdAt: "2026-07-31T00:00:00Z",
      operatorKeyId: "synthetic-demo-operator-1",
    },
  );
  assert.equal(fixtureRoot(withFields), toHex(batch.merkleRoot));
  assert.notEqual(fixtureRoot(withFields), fixtureRoot(rows));
});
