// Deterministic publication intent for workflow versions (ticket 09).
//
// The intent is a pure function of the operation's immutable membership and a
// chain/manifest context captured once. All commitments come from the frozen
// protocol builders in `packages/canonical-ts` and `packages/merkle-ts`; this
// module only defines how a workflow payload becomes protocol fields
// (ONELAYER:WORKFLOW:FIELDMAP:V1). Nothing here talks to the database or chain.
import { createHash, createHmac } from "node:crypto";
import {
  batchLeafHash,
  buildFieldTree,
  encode,
  manifestHash as manifestHashOf,
  nfc,
  recordCommitment,
  recordIdCommitment,
  registryIdHash,
  toHex,
  type CborValue,
} from "../../../packages/canonical-ts/src/index.ts";
import { root } from "../../../packages/merkle-ts/src/index.ts";
import type { AnchorEntryV1 } from "../../../packages/onchain-client/src/index.ts";
import { canonicalWorkflow } from "./registry-workflow.ts";
import type { PublicationItem } from "./workflow-publication.ts";

export const INTENT_DOMAIN = "ONELAYER:WORKFLOW:PUBLICATION:INTENT:V1";
export const FIELD_MAPPING = "ONELAYER:WORKFLOW:FIELDMAP:V1";
export const PUBLICATION_BUILDER_VERSION = "onelayer-workflow-publication/1";
export const PUBLICATION_SCHEMA_VERSION = 1;
const FIELD_KEY_DOMAIN = "ONELAYER:WORKFLOW:FIELDKEY:V1";

export class PublicationIntentError extends Error {
  constructor(public code: string, detail?: string) { super(detail ? `${code}: ${detail}` : code); }
}

/** Deployment-owned key material. Production custody is an open decision. */
export interface PublicationKeys {
  /** 32-byte HMAC key for record ID commitments. */
  idKey: Uint8Array;
  /** 32-byte key from which per-version field-salt keys are derived. */
  fieldKeyMaster: Uint8Array;
}

/** Chain and manifest context captured once, before the first attempt. */
export interface IntentContext {
  operationId: string;
  registryId: string;
  programId: string;
  configPda: string;
  operator: string;
  operatorKeyId: string;
  batchSequence: bigint;
  registryVersion: bigint;
  previousAnchorHashHex: string;
  /** Count of events already published by finalized operations of the registry. */
  publishedBefore: bigint;
  createdAt: string;
  schemaVersion: number;
  hashAlgorithm: number;
  treeAlgorithm: number;
}

export interface IntentLeaf {
  ordinal: number;
  eventId: string;
  recordId: string;
  version: number;
  operation: "upsert" | "tombstone";
  payloadHash: string;
  recordIdCommitment: string;
  fieldRoot: string;
  recordCommitment: string;
  leafHash: string;
  leafIndex: number;
}

export interface PublicationIntent {
  version: 1;
  domain: typeof INTENT_DOMAIN;
  fieldMapping: typeof FIELD_MAPPING;
  builderVersion: typeof PUBLICATION_BUILDER_VERSION;
  operationId: string;
  registryId: string;
  programId: string;
  configPda: string;
  operator: string;
  operatorKeyId: string;
  batchSequence: string;
  registryVersion: string;
  previousAnchorHash: string;
  cursorStart: string;
  cursorEnd: string;
  createdAt: string;
  schemaVersion: number;
  hashAlgorithm: number;
  treeAlgorithm: number;
  leafCount: number;
  merkleRoot: string;
  manifestHash: string;
  leavesObjectHash: string;
  items: IntentLeaf[];
}

export interface EncodedIntent {
  intent: PublicationIntent;
  bytes: Buffer;
  hash: string;
}

const HEX32 = /^[0-9a-f]{64}$/;
const u64 = (value: bigint, name: string) => {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) throw new PublicationIntentError("PUBLICATION_CONTEXT_INVALID", name);
};

/** JSON → deterministic CBOR. Floats, unsafe integers and NFC key collisions
 * are rejected: they have no single protocol representation. */
export function jsonToCbor(value: unknown, at = "payload"): CborValue {
  if (value === null) return { type: "null" };
  if (typeof value === "boolean") return { type: "bool", value };
  // A lone surrogate becomes U+FFFD in UTF-8: two values would share one commitment.
  if (typeof value === "string") {
    if (/[\uD800-\uDFFF]/u.test(value)) throw new PublicationIntentError("PUBLICATION_UNSUPPORTED_VALUE", `${at}: ill-formed string`);
    return { type: "text", value };
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new PublicationIntentError("PUBLICATION_UNSUPPORTED_VALUE", at);
    return { type: "int", value: String(value) };
  }
  if (Array.isArray(value)) return { type: "array", items: value.map((item, index) => jsonToCbor(item, `${at}[${index}]`)) };
  if (typeof value === "object") {
    // Null prototype + defineProperty: a key named "__proto__" must stay an own
    // entry, never silently become the prototype (and drop out of the commitment).
    const entries: Record<string, CborValue> = Object.create(null);
    const seen = new Set<string>();
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (/[\uD800-\uDFFF]/u.test(key)) throw new PublicationIntentError("PUBLICATION_UNSUPPORTED_VALUE", `${at}: ill-formed key`);
      const normalized = nfc(key);
      if (seen.has(normalized)) throw new PublicationIntentError("PUBLICATION_UNSUPPORTED_VALUE", `${at}: NFC key collision`);
      seen.add(normalized);
      Object.defineProperty(entries, key, { value: jsonToCbor(child, `${at}.${key}`), enumerable: true, writable: false, configurable: false });
    }
    return { type: "map", entries };
  }
  throw new PublicationIntentError("PUBLICATION_UNSUPPORTED_VALUE", at);
}

/** FIELDMAP:V1: field `operation` carries upsert/tombstone (a tombstone has no
 * other field); every top-level payload key K becomes field `payload.K` with its
 * whole JSON value as CBOR. Workflow keys never contain dots, so the two
 * namespaces cannot collide. */
export function workflowFields(item: Pick<PublicationItem, "operation" | "payload">): Array<{ path: string; value: CborValue }> {
  if (item.operation !== "upsert" && item.operation !== "tombstone") throw new PublicationIntentError("PUBLICATION_UNSUPPORTED_VALUE", "operation");
  const keys = Object.keys(item.payload);
  if (item.operation === "tombstone" && keys.length) throw new PublicationIntentError("PUBLICATION_UNSUPPORTED_VALUE", "tombstone payload");
  const normalized = new Set<string>();
  for (const key of keys) {
    if (!key || key.includes(".") || /[\uD800-\uDFFF]/u.test(key)) throw new PublicationIntentError("PUBLICATION_UNSUPPORTED_VALUE", "payload key");
    // Distinct JSON keys that normalize to one NFC path would collide in the field tree.
    if (normalized.has(nfc(key))) throw new PublicationIntentError("PUBLICATION_UNSUPPORTED_VALUE", "payload: NFC key collision");
    normalized.add(nfc(key));
  }
  return [
    { path: "operation", value: { type: "text", value: item.operation } },
    ...keys.map((key) => ({ path: `payload.${key}`, value: jsonToCbor(item.payload[key], `payload.${key}`) })),
  ];
}

export function recordFieldKey(keys: PublicationKeys, registryId: string, recordId: string, version: number): Uint8Array {
  if (keys.fieldKeyMaster.length !== 32) throw new PublicationIntentError("PUBLICATION_KEYS_INVALID");
  const mac = createHmac("sha256", keys.fieldKeyMaster).update(FIELD_KEY_DOMAIN).update(Uint8Array.of(0));
  mac.update(nfc(registryId)).update(Uint8Array.of(0)).update(nfc(recordId)).update(Uint8Array.of(0)).update(String(version));
  return new Uint8Array(mac.digest());
}

function leavesObjectHash(leaves: readonly IntentLeaf[]): string {
  const encoded = encode({
    type: "array",
    items: leaves.map((leaf) => ({
      type: "map" as const,
      entries: {
        recordIdCommitment: { type: "bytes" as const, hex: leaf.recordIdCommitment },
        recordVersion: { type: "int" as const, value: String(leaf.version) },
        fieldRoot: { type: "bytes" as const, hex: leaf.fieldRoot },
        recordCommitment: { type: "bytes" as const, hex: leaf.recordCommitment },
      },
    })),
  });
  return createHash("sha256").update(encoded).digest("hex");
}

export function encodeIntent(intent: PublicationIntent): EncodedIntent {
  const bytes = Buffer.from(canonicalWorkflow(intent), "utf8");
  return { intent, bytes, hash: intentBytesHash(bytes) };
}

export function intentBytesHash(bytes: Uint8Array): string {
  return createHash("sha256").update(INTENT_DOMAIN + "\n").update(bytes).digest("hex");
}

export const ATTEMPT_PLAN_DOMAIN = "ONELAYER:WORKFLOW:ATTEMPT-PLAN:V1";

/**
 * Durable per-attempt approval commitment (H3). It binds the semantic intent
 * hash together with the exact reserved unsigned message bytes and every
 * lifetime/fee/attempt-plan field the operator must approve before the signer
 * produces a signature. `review` returns this over the bytes it reserved;
 * `run` requires it; the signer independently recomputes it from the decoded
 * message bytes and refuses a mismatch. Frozen protocol formats are untouched:
 * this is an off-chain approval commitment, not a new on-chain instruction.
 */
export interface AttemptPlanCommitment {
  intentHash: string;
  attemptNo: number;
  cluster: string;
  programId: string;
  configPda: string;
  operator: string;
  registryId: string;
  segmentPda: string;
  segmentIndex: number;
  dayUtc: number;
  recentBlockhash: string;
  lastValidBlockHeight: string;
  /** Quoted fee for the reserved message (lamports). */
  feeLamports: string;
  /** Bounded fee constraint: the quote may not exceed it (lamports). */
  feeLimitLamports: string;
  /** Base64 of the exact reserved unsigned message bytes that will be signed. */
  messageBase64: string;
}

export function attemptPlanHash(plan: AttemptPlanCommitment): string {
  const bytes = Buffer.from(canonicalWorkflow({ version: 1, domain: ATTEMPT_PLAN_DOMAIN, plan }), "utf8");
  return createHash("sha256").update(ATTEMPT_PLAN_DOMAIN + "\n").update(bytes).digest("hex");
}

/** Builds the intent. Same membership + context always yields identical bytes. */
export function buildPublicationIntent(items: readonly PublicationItem[], context: IntentContext, keys: PublicationKeys): EncodedIntent {
  if (items.length === 0) throw new PublicationIntentError("PUBLICATION_EMPTY");
  if (keys.idKey.length !== 32) throw new PublicationIntentError("PUBLICATION_KEYS_INVALID");
  if (!HEX32.test(context.previousAnchorHashHex)) throw new PublicationIntentError("PUBLICATION_CONTEXT_INVALID", "previousAnchorHash");
  if (context.schemaVersion !== PUBLICATION_SCHEMA_VERSION) throw new PublicationIntentError("PUBLICATION_SCHEMA_MISMATCH");
  u64(context.batchSequence, "batchSequence"); u64(context.registryVersion, "registryVersion"); u64(context.publishedBefore, "publishedBefore");
  if (context.batchSequence < 1n) throw new PublicationIntentError("PUBLICATION_CONTEXT_INVALID", "batchSequence");
  const registryHash = registryIdHash(context.registryId);
  const leaves = items.map((item, ordinal): IntentLeaf => {
    const tree = buildFieldTree(recordFieldKey(keys, context.registryId, item.recordId, item.version), workflowFields(item));
    const identifier = recordIdCommitment(keys.idKey, context.registryId, item.recordId);
    const commitment = recordCommitment(registryHash, identifier, BigInt(item.version), tree.root);
    return {
      ordinal, eventId: item.eventId, recordId: item.recordId, version: item.version, operation: item.operation,
      payloadHash: item.payloadHash, recordIdCommitment: toHex(identifier), fieldRoot: toHex(tree.root),
      recordCommitment: toHex(commitment), leafHash: toHex(batchLeafHash(commitment)), leafIndex: -1,
    };
  });
  // Leaf order matches the legacy batch builder: record ID commitment, then version.
  const sorted = [...leaves].sort((a, b) => (a.recordIdCommitment < b.recordIdCommitment ? -1 : a.recordIdCommitment > b.recordIdCommitment ? 1 : a.version - b.version));
  sorted.forEach((leaf, index) => {
    if (index && sorted[index - 1].recordIdCommitment === leaf.recordIdCommitment && sorted[index - 1].version === leaf.version) {
      throw new PublicationIntentError("PUBLICATION_DUPLICATE_VERSION");
    }
    leaf.leafIndex = index;
  });
  const merkleRoot = root(sorted.map((leaf) => Buffer.from(leaf.leafHash, "hex")));
  const cursorStart = context.publishedBefore + 1n;
  const cursorEnd = context.publishedBefore + BigInt(items.length);
  u64(cursorEnd, "cursorEnd");
  const leavesHash = leavesObjectHash(sorted);
  const manifest = manifestHashOf({
    registryIdHash: registryHash,
    batchSequence: context.batchSequence,
    registryVersion: context.registryVersion,
    sourceCursorStart: cursorStart,
    sourceCursorEnd: cursorEnd,
    createdAt: context.createdAt,
    schemaVersion: context.schemaVersion,
    leafCount: items.length,
    merkleRoot,
    previousAnchorHash: Buffer.from(context.previousAnchorHashHex, "hex"),
    snapshotHash: null,
    leavesObjectUri: `onelayer-workflow://${encodeURIComponent(context.registryId)}/publication/${context.operationId}/leaves.cbor`,
    leavesObjectHash: Buffer.from(leavesHash, "hex"),
    builderVersion: PUBLICATION_BUILDER_VERSION,
    operatorKeyId: context.operatorKeyId,
  });
  return encodeIntent({
    version: 1, domain: INTENT_DOMAIN, fieldMapping: FIELD_MAPPING, builderVersion: PUBLICATION_BUILDER_VERSION,
    operationId: context.operationId, registryId: context.registryId, programId: context.programId,
    configPda: context.configPda, operator: context.operator, operatorKeyId: context.operatorKeyId,
    batchSequence: context.batchSequence.toString(), registryVersion: context.registryVersion.toString(),
    previousAnchorHash: context.previousAnchorHashHex, cursorStart: cursorStart.toString(), cursorEnd: cursorEnd.toString(),
    createdAt: context.createdAt, schemaVersion: context.schemaVersion, hashAlgorithm: context.hashAlgorithm,
    treeAlgorithm: context.treeAlgorithm, leafCount: items.length, merkleRoot: toHex(merkleRoot),
    manifestHash: toHex(manifest), leavesObjectHash: leavesHash, items: leaves,
  });
}

export function contextOf(intent: PublicationIntent): IntentContext {
  return {
    operationId: intent.operationId, registryId: intent.registryId, programId: intent.programId,
    configPda: intent.configPda, operator: intent.operator, operatorKeyId: intent.operatorKeyId,
    batchSequence: BigInt(intent.batchSequence), registryVersion: BigInt(intent.registryVersion),
    previousAnchorHashHex: intent.previousAnchorHash, publishedBefore: BigInt(intent.cursorStart) - 1n,
    createdAt: intent.createdAt, schemaVersion: intent.schemaVersion, hashAlgorithm: intent.hashAlgorithm,
    treeAlgorithm: intent.treeAlgorithm,
  };
}

/**
 * Read-back check of stored intent evidence: the hash must cover the exact
 * stored bytes, and rebuilding from current immutable membership plus the
 * stored context must reproduce those bytes byte-for-byte.
 */
export function verifyStoredIntent(
  stored: { bytes: Uint8Array; hash: string },
  items: readonly PublicationItem[],
  keys: PublicationKeys,
  expected: { operationId: string; registryId: string; publishedBefore: bigint },
): PublicationIntent {
  if (intentBytesHash(stored.bytes) !== stored.hash) throw new PublicationIntentError("PUBLICATION_INTENT_MISMATCH", "hash");
  let intent: PublicationIntent;
  try { intent = JSON.parse(Buffer.from(stored.bytes).toString("utf8")); }
  catch { throw new PublicationIntentError("PUBLICATION_INTENT_MISMATCH", "encoding"); }
  if (intent.operationId !== expected.operationId || intent.registryId !== expected.registryId) {
    throw new PublicationIntentError("PUBLICATION_INTENT_MISMATCH", "identity");
  }
  const context = contextOf(intent);
  if (context.publishedBefore !== expected.publishedBefore) throw new PublicationIntentError("PUBLICATION_INTENT_MISMATCH", "cursor");
  let rebuilt: EncodedIntent;
  try { rebuilt = buildPublicationIntent(items, context, keys); }
  catch (error) { throw new PublicationIntentError("PUBLICATION_INTENT_MISMATCH", (error as Error).message); }
  if (!rebuilt.bytes.equals(Buffer.from(stored.bytes))) throw new PublicationIntentError("PUBLICATION_INTENT_MISMATCH", "commitment");
  return intent;
}

/** Compares a finalized on-chain ledger entry against every committed intent field. */
export function anchorEntryMismatch(intent: PublicationIntent, entry: AnchorEntryV1): string | null {
  const hex = (value: ArrayLike<number>) => Buffer.from(Uint8Array.from(value)).toString("hex");
  const checks: Array<[string, boolean]> = [
    ["batchSequence", entry.batchSequence === BigInt(intent.batchSequence)],
    ["registryVersion", entry.registryVersion === BigInt(intent.registryVersion)],
    ["sourceCursorStart", entry.sourceCursorStart === BigInt(intent.cursorStart)],
    ["sourceCursorEnd", entry.sourceCursorEnd === BigInt(intent.cursorEnd)],
    ["merkleRoot", hex(entry.merkleRoot) === intent.merkleRoot],
    ["manifestHash", hex(entry.manifestHash) === intent.manifestHash],
    ["previousAnchorHash", hex(entry.previousAnchorHash) === intent.previousAnchorHash],
    ["snapshotHash", hex(entry.snapshotHash) === "00".repeat(32)],
    ["leafCount", entry.leafCount === intent.leafCount],
    ["schemaVersion", entry.schemaVersion === intent.schemaVersion],
    ["flags", entry.flags === 0],
    ["hashAlgorithm", entry.hashAlgorithm === intent.hashAlgorithm],
    ["treeAlgorithm", entry.treeAlgorithm === intent.treeAlgorithm],
    ["operator", entry.operator === intent.operator],
  ];
  return checks.find(([, ok]) => !ok)?.[0] ?? null;
}
