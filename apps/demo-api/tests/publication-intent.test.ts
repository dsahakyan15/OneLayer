import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";
import {
  batchLeafHash, buildFieldTree, recordCommitment, recordIdCommitment, registryIdHash, toHex,
} from "../../../packages/canonical-ts/src/index.ts";
import {
  anchorEntryMismatch, buildPublicationIntent, jsonToCbor, verifyStoredIntent, workflowFields,
  type IntentContext,
} from "../src/publication-intent.ts";
import type { PublicationItem } from "../src/workflow-publication.ts";
import { assertPublishablePayload, payloadInput, workflowHash } from "../src/registry-workflow.ts";

const keys = { idKey: new Uint8Array(32).fill(7), fieldKeyMaster: new Uint8Array(32).fill(8) };
const context: IntentContext = {
  operationId: "00000000-0000-4000-8000-000000000001", registryId: "synthetic", programId: "P", configPda: "C",
  operator: "O", operatorKeyId: "k", batchSequence: 4n, registryVersion: 2n, previousAnchorHashHex: "11".repeat(32),
  publishedBefore: 10n, createdAt: "2026-09-24T12:00:00Z", schemaVersion: 1, hashAlgorithm: 1, treeAlgorithm: 1,
};
const item = (recordId: string, version: number, payload: Record<string, unknown>, operation: "upsert" | "tombstone" = "upsert"): PublicationItem =>
  ({ eventId: `${recordId}-${version}`, recordId, version, operation, payload, payloadHash: workflowHash({ operation, payload }) });
const items = [item("b", 1, { owner: "Ann", area: 5, nested: { z: [1, null, true] } }), item("a", 2, {}, "tombstone")];

test("intent bytes are deterministic and cursors follow previously published events", () => {
  const first = buildPublicationIntent(items, context, keys);
  const second = buildPublicationIntent(structuredClone(items), { ...context }, keys);
  assert.ok(first.bytes.equals(second.bytes));
  assert.equal(first.hash, second.hash);
  assert.deepEqual([first.intent.cursorStart, first.intent.cursorEnd, first.intent.leafCount], ["11", "12", 2]);
  // Membership order is part of the intent, but the committed root is not order dependent.
  const reordered = buildPublicationIntent([...items].reverse(), context, keys);
  assert.equal(reordered.intent.merkleRoot, first.intent.merkleRoot);
  assert.notEqual(reordered.hash, first.hash);
});

test("a leaf matches an independent recomputation from the frozen protocol primitives", () => {
  const single = buildPublicationIntent([items[0]], context, keys);
  const fieldKey = createHmac("sha256", keys.fieldKeyMaster).update("ONELAYER:WORKFLOW:FIELDKEY:V1").update(Uint8Array.of(0))
    .update("synthetic").update(Uint8Array.of(0)).update("b").update(Uint8Array.of(0)).update("1").digest();
  const fieldRoot = buildFieldTree(fieldKey, [
    { path: "operation", value: { type: "text", value: "upsert" } },
    { path: "payload.owner", value: { type: "text", value: "Ann" } },
    { path: "payload.area", value: { type: "int", value: "5" } },
    { path: "payload.nested", value: { type: "map", entries: { z: { type: "array", items: [{ type: "int", value: "1" }, { type: "null" }, { type: "bool", value: true }] } } } },
  ]).root;
  const id = recordIdCommitment(keys.idKey, "synthetic", "b");
  const leaf = batchLeafHash(recordCommitment(registryIdHash("synthetic"), id, 1n, fieldRoot));
  assert.equal(single.intent.items[0].fieldRoot, toHex(fieldRoot));
  // A single-leaf RFC 6962 root is the leaf hash itself.
  assert.equal(single.intent.merkleRoot, toHex(leaf));
});

test("payloads without a single protocol representation are rejected", () => {
  assert.throws(() => jsonToCbor(1.5), /PUBLICATION_UNSUPPORTED_VALUE/);
  assert.throws(() => jsonToCbor(2 ** 60), /PUBLICATION_UNSUPPORTED_VALUE/);
  assert.throws(() => jsonToCbor({ "é": 1, "é": 2 }), /NFC key collision/);
  assert.throws(() => workflowFields({ operation: "tombstone", payload: { a: 1 } }), /PUBLICATION_UNSUPPORTED_VALUE/);
  assert.deepEqual(workflowFields({ operation: "tombstone", payload: {} }).map((f) => f.path), ["operation"]);
});

test("read-back verification rejects changed membership, bytes and cursor context", () => {
  const encoded = buildPublicationIntent(items, context, keys);
  const expected = { operationId: context.operationId, registryId: "synthetic", publishedBefore: 10n };
  assert.equal(verifyStoredIntent(encoded, items, keys, expected).merkleRoot, encoded.intent.merkleRoot);
  assert.throws(() => verifyStoredIntent(encoded, [item("b", 1, { owner: "Eve", area: 5, nested: { z: [1, null, true] } }), items[1]], keys, expected), /PUBLICATION_INTENT_MISMATCH: commitment/);
  assert.throws(() => verifyStoredIntent({ ...encoded, bytes: Buffer.concat([encoded.bytes, Buffer.from(" ")]) }, items, keys, expected), /PUBLICATION_INTENT_MISMATCH: hash/);
  assert.throws(() => verifyStoredIntent(encoded, items, keys, { ...expected, publishedBefore: 9n }), /cursor/);
  assert.throws(() => verifyStoredIntent(encoded, items, { ...keys, idKey: new Uint8Array(32) }, expected), /commitment/);
});

test("on-chain entries must match every committed field", () => {
  const { intent } = buildPublicationIntent(items, context, keys);
  const entry = {
    batchSequence: 4n, registryVersion: 2n, sourceCursorStart: 11n, sourceCursorEnd: 12n,
    merkleRoot: Buffer.from(intent.merkleRoot, "hex"), manifestHash: Buffer.from(intent.manifestHash, "hex"),
    snapshotHash: new Uint8Array(32), previousAnchorHash: Buffer.from(intent.previousAnchorHash, "hex"),
    leafCount: 2, schemaVersion: 1, flags: 0, hashAlgorithm: 1, treeAlgorithm: 1, pad0: new Uint8Array(0), operator: "O", publishedAt: 1n,
  } as any;
  assert.equal(anchorEntryMismatch(intent, entry), null);
  assert.equal(anchorEntryMismatch(intent, { ...entry, merkleRoot: new Uint8Array(32) }), "merkleRoot");
  assert.equal(anchorEntryMismatch(intent, { ...entry, operator: "X" }), "operator");
  assert.equal(anchorEntryMismatch(intent, { ...entry, sourceCursorEnd: 13n }), "sourceCursorEnd");
});

test("a nested __proto__ key stays in the commitment (review MAJOR-4 vector)", () => {
  // JSON.parse (like pg for jsonb) creates an own "__proto__" property.
  const alice = JSON.parse('{"a":{"__proto__":{"x":"alice"}}}');
  const mallory = JSON.parse('{"a":{"__proto__":{"x":"mallory"}}}');
  const cbor = jsonToCbor(alice.a) as { type: "map"; entries: Record<string, unknown> };
  assert.deepEqual(Object.keys(cbor.entries), ["__proto__"]);
  const rootOf = (payload: Record<string, unknown>) => buildPublicationIntent([item("r", 1, payload)], context, keys).intent.items[0].fieldRoot;
  assert.notEqual(rootOf(alice), rootOf(mallory));
  // Vector: fixed keys, fixed context → fixed field root.
  assert.equal(rootOf(alice), "9aec9fe47f493148c141bd617b2685b372fa5b9d0ca5a09a21b3de934f015362");
  assert.equal(rootOf(mallory), "98889c320dece9be5bd1d660c97f66cf69bcc95009854ccceea34c80515235ed");
});

test("top-level NFC collisions are a typed error", () => {
  assert.throws(() => workflowFields({ operation: "upsert", payload: { "é": 1, "é": 2 } }),
    (error: any) => error.code === "PUBLICATION_UNSUPPORTED_VALUE" && /NFC key collision/.test(error.message));
});

test("workflow contract V1.1 rejects values the publication mapping cannot commit", () => {
  const code = (payload: unknown) => { try { assertPublishablePayload(payload); return null; } catch (error: any) { return error.code; } };
  assert.equal(code(JSON.parse('{"a":{"__proto__":{"x":1}}}')), "RESERVED_FIELD_NAME");
  assert.equal(code({ a: 1.5 }), "UNSUPPORTED_NUMBER");
  assert.equal(code({ a: [2 ** 60] }), "UNSUPPORTED_NUMBER");
  assert.equal(code({ "é": 1, "é": 2 }), "AMBIGUOUS_FIELD_PATH");
  assert.equal(code({ "a.b": 1 }), "AMBIGUOUS_FIELD_PATH");
  assert.equal(code({ a: { b: [1, "x", null, true] } }), null);
  assert.throws(() => payloadInput({ operation: "upsert", payload: { price: 9.99 } }), /UNSUPPORTED_NUMBER/);
});

test("maintenance identities are normalized before the two-person comparison", async () => {
  const { maintenancePerson } = await import("../src/publication-worker.ts");
  assert.equal(maintenancePerson("Da​ve"), "Dave");
  assert.equal(maintenancePerson("ｄａｖｅ"), "dave");
  assert.equal(maintenancePerson("  carol \t\n smith\u0007 "), "carol smith");
  assert.throws(() => maintenancePerson("​‌"), /MAINTENANCE_IDENTITY_INVALID/);
});
