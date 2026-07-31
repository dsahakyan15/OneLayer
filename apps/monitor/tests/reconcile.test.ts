import assert from "node:assert/strict";
import { test } from "node:test";
import { root } from "../../../packages/merkle-ts/src/index.ts";
import {
  reconcileBatch,
  respondToIncidents,
  type IncidentResponse,
  type ManifestObservation,
  type SourceChange,
  type WorkflowEvent,
} from "../src/reconcile.ts";

const registryId = "gov.registry.land";
const idKey = new Uint8Array(32).fill(9);

function change(cursor: bigint, id: string, key: number, recordVersion = 1n): SourceChange {
  return {
    registryId,
    sourceCursor: cursor,
    internalRecordId: id,
    recordVersion,
    operation: "UPDATE",
    fields: [{ path: "status", value: { type: "text", value: "ACTIVE" } }],
    recordFieldKey: new Uint8Array(32).fill(key),
  };
}

function workflow(source: SourceChange, authorized = true): WorkflowEvent {
  return { registryId, sourceCursor: source.sourceCursor, internalRecordId: source.internalRecordId, operation: source.operation, authorized };
}

function observation(changes: SourceChange[]): ManifestObservation {
  const seed: ManifestObservation = {
    registryId,
    batchSequence: 1n,
    sourceCursorStart: changes[0].sourceCursor,
    sourceCursorEnd: changes.at(-1)!.sourceCursor,
    merkleRoot: new Uint8Array(32),
    anchoredRoot: new Uint8Array(32),
    anchoredSlot: 42n,
    leaves: [],
  };
  const calculated = reconcileBatch(seed, changes, changes.map((entry) => workflow(entry)), idKey);
  return { ...seed, leaves: calculated.calculatedLeaves, merkleRoot: calculated.calculatedRoot, anchoredRoot: calculated.calculatedRoot };
}

test("independent source and workflow readings reproduce the anchored root", () => {
  const changes = [change(1n, "R-2", 2), change(2n, "R-1", 1)];
  const manifest = observation(changes);
  const result = reconcileBatch(manifest, changes, changes.map((entry) => workflow(entry)), idKey);
  assert.deepEqual(result.incidents, []);
  assert.deepEqual(result.calculatedRoot, root(result.calculatedLeaves));
});

test("backlog recomputation coalesces repeated record changes", () => {
  const changes = [change(1n, "R-1", 1), change(2n, "R-1", 2, 2n)];
  const manifest = observation(changes);
  const result = reconcileBatch(manifest, changes, changes.map((entry) => workflow(entry)), idKey);
  assert.deepEqual(result.incidents, []);
  assert.equal(result.calculatedLeaves.length, 1);
});

test("cursor, workflow, and Merkle divergences are localized", () => {
  const changes = [change(1n, "R-1", 1), change(3n, "R-2", 3)];
  const manifest = observation([change(1n, "R-1", 1), change(2n, "R-2", 2)]);
  const extraWorkflow = workflow(change(4n, "R-3", 3));
  const result = reconcileBatch(manifest, changes, [workflow(changes[0], false), extraWorkflow], idKey);
  assert.deepEqual(new Set(result.incidents.map((incident) => incident.kind)), new Set([
    "SOURCE_CURSOR_GAP",
    "WORKFLOW_UNAUTHORIZED",
    "CHANGE_WITHOUT_WORKFLOW",
    "WORKFLOW_WITHOUT_CHANGE",
    "MANIFEST_ROOT_MISMATCH",
  ]));
  assert.ok(result.incidents.find((incident) => incident.kind === "MANIFEST_ROOT_MISMATCH")?.divergentLeafIndexes?.length);
});

test("an incident writes evidence before opening, quarantining, and pausing", async () => {
  const changes = [change(1n, "R-1", 1)];
  const manifest = observation(changes);
  manifest.anchoredRoot = new Uint8Array(32).fill(7);
  const result = reconcileBatch(manifest, changes, changes.map((entry) => workflow(entry)), idKey);
  const calls: string[] = [];
  const response: IncidentResponse = {
    async writeEvidence(_evidence, evidenceHash) { assert.equal(evidenceHash.length, 32); calls.push("evidence"); return "file:///evidence/1.json"; },
    async openIncident(input) { assert.equal(input.evidenceUri, "file:///evidence/1.json"); calls.push("incident"); },
    async quarantineBatch() { calls.push("quarantine"); },
    async pausePublishing() { calls.push("pause"); },
  };
  await respondToIncidents(manifest, result, response);
  assert.deepEqual(calls, ["evidence", "incident", "quarantine", "pause"]);
});
