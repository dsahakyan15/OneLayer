import { createHash, timingSafeEqual } from "node:crypto";
import {
  batchLeafHash,
  buildFieldTree,
  recordCommitment,
  recordIdCommitment,
  registryIdHash,
  type CborValue,
} from "../../../packages/canonical-ts/src/index.ts";
import { root, type Hash } from "../../../packages/merkle-ts/src/index.ts";

export interface SourceChange {
  registryId: string;
  sourceCursor: bigint;
  internalRecordId: string;
  recordVersion: bigint;
  operation: string;
  fields: Array<{ path: string; value: CborValue }>;
  recordFieldKey: Uint8Array;
}

export interface WorkflowEvent {
  registryId: string;
  sourceCursor: bigint;
  internalRecordId: string;
  operation: string;
  authorized: boolean;
}

export interface ManifestObservation {
  registryId: string;
  batchSequence: bigint;
  sourceCursorStart: bigint;
  sourceCursorEnd: bigint;
  merkleRoot: Hash;
  anchoredRoot: Hash;
  anchoredSlot: bigint;
  leaves: Hash[];
}

export type IncidentKind =
  | "SOURCE_CURSOR_GAP"
  | "CHANGE_WITHOUT_WORKFLOW"
  | "WORKFLOW_WITHOUT_CHANGE"
  | "WORKFLOW_UNAUTHORIZED"
  | "MANIFEST_ROOT_MISMATCH"
  | "ANCHOR_ROOT_MISMATCH";

export interface MonitorIncident {
  kind: IncidentKind;
  registryId: string;
  batchSequence: bigint;
  sourceCursor?: bigint;
  divergentLeafIndexes?: number[];
}

export interface ReconciliationResult {
  calculatedRoot: Hash;
  calculatedLeaves: Hash[];
  incidents: MonitorIncident[];
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

function eventKey(event: { sourceCursor: bigint; internalRecordId: string; operation: string }): string {
  return `${event.sourceCursor}:${event.internalRecordId}:${event.operation}`;
}

export function divergentLeafIndexes(expected: Hash[], actual: Hash[]): number[] {
  const indexes: number[] = [];
  const length = Math.max(expected.length, actual.length);
  for (let index = 0; index < length; index += 1) {
    if (expected[index] === undefined || actual[index] === undefined || !equal(expected[index], actual[index])) {
      indexes.push(index);
    }
  }
  return indexes;
}

export function reconcileBatch(
  manifest: ManifestObservation,
  changes: SourceChange[],
  workflowEvents: WorkflowEvent[],
  idKey: Uint8Array,
  previousCursorEnd?: bigint,
): ReconciliationResult {
  const incidents: MonitorIncident[] = [];
  const orderedChanges = changes.slice().sort((left, right) => left.sourceCursor < right.sourceCursor ? -1 : left.sourceCursor > right.sourceCursor ? 1 : 0);
  let expectedCursor = previousCursorEnd === undefined ? manifest.sourceCursorStart : previousCursorEnd + 1n;
  for (const change of orderedChanges) {
    if (change.sourceCursor !== expectedCursor) {
      incidents.push({ kind: "SOURCE_CURSOR_GAP", registryId: manifest.registryId, batchSequence: manifest.batchSequence, sourceCursor: expectedCursor });
      expectedCursor = change.sourceCursor;
    }
    expectedCursor += 1n;
  }
  if (orderedChanges.length === 0 || orderedChanges[0].sourceCursor !== manifest.sourceCursorStart || orderedChanges.at(-1)?.sourceCursor !== manifest.sourceCursorEnd) {
    incidents.push({ kind: "SOURCE_CURSOR_GAP", registryId: manifest.registryId, batchSequence: manifest.batchSequence });
  }

  const workflowsByKey = new Map(workflowEvents.map((event) => [eventKey(event), event]));
  const changesByKey = new Set(orderedChanges.map(eventKey));
  for (const change of orderedChanges) {
    const workflow = workflowsByKey.get(eventKey(change));
    if (workflow === undefined || workflow.registryId !== change.registryId) {
      incidents.push({ kind: "CHANGE_WITHOUT_WORKFLOW", registryId: manifest.registryId, batchSequence: manifest.batchSequence, sourceCursor: change.sourceCursor });
    } else if (!workflow.authorized) {
      incidents.push({ kind: "WORKFLOW_UNAUTHORIZED", registryId: manifest.registryId, batchSequence: manifest.batchSequence, sourceCursor: change.sourceCursor });
    }
  }
  for (const workflow of workflowEvents) {
    if (!changesByKey.has(eventKey(workflow))) {
      incidents.push({ kind: "WORKFLOW_WITHOUT_CHANGE", registryId: manifest.registryId, batchSequence: manifest.batchSequence, sourceCursor: workflow.sourceCursor });
    }
  }

  const latestChanges = new Map<string, SourceChange>();
  for (const change of orderedChanges) latestChanges.set(change.internalRecordId, change);
  const registryHash = registryIdHash(manifest.registryId);
  const calculated = [...latestChanges.values()].map((change) => {
    const recordId = recordIdCommitment(idKey, manifest.registryId, change.internalRecordId);
    const fieldRoot = buildFieldTree(change.recordFieldKey, change.fields).root;
    return {
      recordId,
      recordVersion: change.recordVersion,
      leaf: batchLeafHash(recordCommitment(registryHash, recordId, change.recordVersion, fieldRoot)),
    };
  }).sort((left, right) => Buffer.compare(left.recordId, right.recordId) || (left.recordVersion < right.recordVersion ? -1 : left.recordVersion > right.recordVersion ? 1 : 0));
  const calculatedLeaves = calculated.map((entry) => entry.leaf);
  const calculatedRoot = root(calculatedLeaves);
  if (!equal(calculatedRoot, manifest.merkleRoot)) {
    incidents.push({
      kind: "MANIFEST_ROOT_MISMATCH",
      registryId: manifest.registryId,
      batchSequence: manifest.batchSequence,
      divergentLeafIndexes: divergentLeafIndexes(calculatedLeaves, manifest.leaves),
    });
  }
  if (!equal(manifest.merkleRoot, manifest.anchoredRoot)) {
    incidents.push({ kind: "ANCHOR_ROOT_MISMATCH", registryId: manifest.registryId, batchSequence: manifest.batchSequence });
  }
  return { calculatedRoot, calculatedLeaves, incidents };
}

export interface IncidentResponse {
  writeEvidence(evidence: Uint8Array, evidenceHash: Hash): Promise<string>;
  openIncident(input: { registryId: string; batchSequence: bigint; evidenceUri: string; evidenceHash: Hash }): Promise<void>;
  quarantineBatch(registryId: string, batchSequence: bigint): Promise<void>;
  pausePublishing(registryId: string): Promise<void>;
}

function evidenceBytes(manifest: ManifestObservation, result: ReconciliationResult): Uint8Array {
  return Buffer.from(JSON.stringify({
    registryId: manifest.registryId,
    batchSequence: manifest.batchSequence.toString(),
    anchoredSlot: manifest.anchoredSlot.toString(),
    calculatedRoot: Buffer.from(result.calculatedRoot).toString("hex"),
    manifestRoot: Buffer.from(manifest.merkleRoot).toString("hex"),
    incidents: result.incidents.map((incident) => ({
      ...incident,
      batchSequence: incident.batchSequence.toString(),
      sourceCursor: incident.sourceCursor?.toString(),
    })),
  }));
}

export async function respondToIncidents(
  manifest: ManifestObservation,
  result: ReconciliationResult,
  response: IncidentResponse,
): Promise<void> {
  if (result.incidents.length === 0) return;
  const evidence = evidenceBytes(manifest, result);
  const evidenceHash = createHash("sha256").update(evidence).digest();
  const evidenceUri = await response.writeEvidence(evidence, evidenceHash);
  await response.openIncident({ registryId: manifest.registryId, batchSequence: manifest.batchSequence, evidenceUri, evidenceHash });
  await response.quarantineBatch(manifest.registryId, manifest.batchSequence);
  await response.pausePublishing(manifest.registryId);
}
