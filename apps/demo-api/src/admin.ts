// Versioned Admin API (OL-C-22, OL-C-25, OL-C-31, OL-C-33).
//
// A thin HTTP adapter over the pilot data: it owns sessions, the publish intent
// lifecycle and certificate issuance. Every route resolves the role from the
// server session; nothing here trusts client state.
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, randomUUID, sign, verify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { getAddressEncoder, type Address } from "@solana/kit";
import {
  anchorHash,
  batchLeafHash,
  buildFieldTree,
  decodeCanonical,
  recordCommitment,
  recordIdCommitment,
  registryIdHash,
  toHex,
} from "../../../packages/canonical-ts/src/index.ts";
import { findLedgerSegmentPda, findRolePda } from "../../../packages/onchain-client/src/index.ts";
import {
  decodeSnapshotPackage,
  recoverRecoveryKek,
  restoreSnapshot,
  type KeyShare,
} from "../../../packages/snapshot-ts/src/index.ts";
import {
  batchReview,
  buildBatch,
  DEMO_ID_KEY,
  fieldsOf,
  issueCertificate,
  type PreparedBatch,
  type SyntheticRecordRow,
} from "./admin-batch.ts";
import {
  prepareAnchorTransaction,
  SignedTransactionError,
  validateSignedTransaction,
} from "./admin-transaction.ts";
import {
  authorize,
  AuthorizationError,
  clearedCookie,
  requireChiefAdmin,
  requireOperator,
  sessionCookie,
  SessionStore,
  type AdminSession,
} from "./admin-session.ts";
import {
  assertTransition,
  intentHash,
  TransitionError,
  type PublishIntent,
  type TransactionState,
} from "./transaction-state.ts";
import type { SolanaPublisherRpc } from "./solana-rpc.ts";
import {
  describeSchema,
  parseCsv,
  parseJsonRecords,
  SCHEMA_ID,
  SchemaError,
  validateRecord,
  type ImportReport,
  type ValidatedField,
  type ValidatedRecord,
} from "./record-schema.ts";
import {
  encryptSnapshotState,
  parseRecoveryShare,
  RETENTION_WINDOW,
  retentionVictims,
  SNAPSHOT_FORMAT,
  SNAPSHOT_KEY_ENCRYPTION_VERSION,
  snapshotObjectKey,
  type SnapshotStateV1,
} from "./backup.ts";
import { workingRegistryStatus } from "./registry-status.ts";

const SEGMENTS_PER_DAY = 3;
const OPERATOR_KEY_ID = "browser-test-operator-1";
const ISSUER_KEY_ID = "synthetic-demo-issuer-1";

export interface AdminContext {
  pool: Pool;
  sessions: SessionStore;
  rpc: SolanaPublisherRpc;
  registryId: string;
  programId: Address;
  configPda: Address;
  issuerSecretKey: Uint8Array;
  /** Process-memory KEK for the bounded MVP snapshot writer. It is never persisted or returned. */
  snapshotKek?: Uint8Array;
  /** Recovery shares are injected by the out-of-band bounded demo setup. */
  recoveryShares?: readonly KeyShare[];
  /** Process-memory signing key for Restore Approval. */
  restoreApprovalPrivateKey?: KeyObject;
  /** Recovered KEKs keyed by operation ID; values are zeroed after use. */
  recoveryKeys?: Map<string, Uint8Array>;
  publicWebBaseUrl: string;
  now: () => Date;
}

export interface AdminRequest {
  method: string;
  path: string;
  query: URLSearchParams;
  body: Record<string, unknown> | null;
  cookieHeader: string | undefined;
  csrfHeader: string | undefined;
  idempotencyKey: string | undefined;
}

export interface AdminResponse {
  status: number;
  body: unknown;
  setCookie?: string;
}

class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message?: string) {
    super(message ?? code);
    this.status = status;
    this.code = code;
  }
}

function text(value: unknown, name: string, pattern: RegExp): string {
  if (typeof value !== "string" || !pattern.test(value)) throw new ApiError(400, `${name.toUpperCase()}_INVALID`);
  return value;
}

async function ensureFixture(pool: Pool): Promise<void> {
  const result = await pool.query("SELECT marker FROM demo_fixture_marker");
  if (result.rows.length !== 1 || result.rows[0].marker !== "ONELAYER_SYNTHETIC_DEVNET_DEMO_V1") {
    throw new ApiError(503, "SYNTHETIC_MARKER_MISSING");
  }
}

async function ensureWorkingRegistry(context: AdminContext): Promise<void> {
  const status = await workingRegistryStatus(context.rpc, context.configPda);
  if (status === "PAUSED") throw new ApiError(409, "REGISTRY_PAUSED");
  if (status === "UNAVAILABLE") throw new ApiError(503, "REGISTRY_STATUS_UNAVAILABLE");
}

async function appendEvent(
  executor: Pool | PoolClient,
  context: AdminContext,
  session: AdminSession | null,
  intentId: string | null,
  eventType: string,
  payload: Record<string, unknown>,
): Promise<void> {
  await executor.query(
    `INSERT INTO demo_operation_event (registry_id, intent_id, event_type, actor, actor_role, payload)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [
      context.registryId,
      intentId,
      eventType,
      session?.username ?? "system",
      session?.role ?? "system",
      JSON.stringify(payload),
    ],
  );
}

const RECORD_QUERY = `
  SELECT r.internal_record_id, r.source_cursor::text, r.record_version::text, r.status,
         r.record_field_key_hex, r.origin, r.schema_id,
         COALESCE(
           json_agg(json_build_object('path', f.path, 'type', f.value_type, 'value', f.value_text)
                    ORDER BY f.path) FILTER (WHERE f.path IS NOT NULL),
           '[]'
         ) AS fields
    FROM synthetic_registry_record r
    LEFT JOIN synthetic_record_field f ON f.internal_record_id = r.internal_record_id
   GROUP BY r.internal_record_id`;

function recordRow(row: any): SyntheticRecordRow {
  return {
    internalRecordId: row.internal_record_id,
    sourceCursor: BigInt(row.source_cursor),
    recordVersion: BigInt(row.record_version),
    status: row.status,
    recordFieldKeyHex: row.record_field_key_hex,
    fields: row.fields as ValidatedField[],
  };
}

async function syntheticRecords(pool: Pool): Promise<SyntheticRecordRow[]> {
  // `internal_record_id` is the primary key, so the remaining columns are
  // functionally dependent on the grouping key.
  const result = await pool.query(`${RECORD_QUERY} ORDER BY r.source_cursor`);
  return result.rows.map(recordRow);
}

interface IntentRow {
  intentId: string;
  batchSequence: bigint;
  state: TransactionState;
  intentHashHex: string;
  messageBase64: string;
  review: Record<string, unknown>;
  recentBlockhash: string;
  lastValidBlockHeight: bigint;
  expiresAt: Date;
  signature: string | null;
  anchorSlot: bigint | null;
  certificateId: string | null;
  failureCode: string | null;
  simulationLogs: string[] | null;
}

function intentRow(row: any): IntentRow {
  return {
    intentId: row.intent_id,
    batchSequence: BigInt(row.batch_sequence),
    state: row.state,
    intentHashHex: row.intent_hash,
    messageBase64: row.message_base64,
    review: row.intent_json,
    recentBlockhash: row.recent_blockhash,
    lastValidBlockHeight: BigInt(row.last_valid_block_height),
    expiresAt: row.expires_at,
    signature: row.transaction_signature,
    anchorSlot: row.anchor_slot === null ? null : BigInt(row.anchor_slot),
    certificateId: row.certificate_id,
    failureCode: row.failure_code,
    simulationLogs: row.simulation_logs,
  };
}

const INTENT_COLUMNS = `intent_id, batch_sequence::text, state, encode(intent_hash,'hex') AS intent_hash,
  message_base64, intent_json, recent_blockhash, last_valid_block_height::text, expires_at,
  transaction_signature, anchor_slot::text, certificate_id, failure_code, simulation_logs`;

async function loadIntent(pool: Pool, intentId: string): Promise<IntentRow> {
  const result = await pool.query(
    `SELECT ${INTENT_COLUMNS} FROM demo_publish_intent WHERE intent_id = $1`,
    [intentId],
  );
  if (result.rows.length === 0) throw new ApiError(404, "INTENT_NOT_FOUND");
  return intentRow(result.rows[0]);
}

async function setState(
  executor: Pool | PoolClient,
  intent: IntentRow,
  next: TransactionState,
  patch: Record<string, unknown> = {},
): Promise<void> {
  assertTransition(intent.state, next);
  await executor.query(
    `UPDATE demo_publish_intent
        SET state = $2,
            transaction_signature = COALESCE($3, transaction_signature),
            signed_transaction_base64 = COALESCE($4, signed_transaction_base64),
            anchor_slot = COALESCE($5, anchor_slot),
            certificate_id = COALESCE($6, certificate_id),
            failure_code = $7,
            simulation_logs = COALESCE($8, simulation_logs),
            updated_at = now()
      WHERE intent_id = $1 AND state = $9`,
    [
      intent.intentId,
      next,
      patch.signature ?? null,
      patch.signedTransaction ?? null,
      patch.anchorSlot ?? null,
      patch.certificateId ?? null,
      patch.failureCode ?? null,
      patch.simulationLogs === undefined ? null : JSON.stringify(patch.simulationLogs),
      intent.state,
    ],
  );
  intent.state = next;
}

function intentResponse(intent: IntentRow, extra: Record<string, unknown> = {}): AdminResponse {
  return {
    status: 200,
    body: {
      intentId: intent.intentId,
      state: intent.state,
      batchSequence: intent.batchSequence.toString(),
      intentHash: intent.intentHashHex,
      review: intent.review,
      recentBlockhash: intent.recentBlockhash,
      lastValidBlockHeight: intent.lastValidBlockHeight.toString(),
      expiresAt: intent.expiresAt,
      transactionSignature: intent.signature,
      anchorSlot: intent.anchorSlot === null ? null : intent.anchorSlot.toString(),
      certificateId: intent.certificateId,
      failureCode: intent.failureCode,
      simulationLogs: intent.simulationLogs,
      ...extra,
    },
  };
}

/** Rebuilds the batch for an intent and refuses to continue if it changed. */
async function rebuildBatch(context: AdminContext, intent: IntentRow): Promise<PreparedBatch> {
  const review = intent.review as any;
  const batch = buildBatch(await syntheticRecords(context.pool), {
    registryId: context.registryId,
    batchSequence: intent.batchSequence,
    registryVersion: BigInt(review.registryVersion),
    previousAnchorHash: Uint8Array.from(Buffer.from(review.previousAnchorHash, "hex")),
    createdAt: review.createdAt,
    operatorKeyId: OPERATOR_KEY_ID,
  });
  if (toHex(batch.merkleRoot) !== review.merkleRoot || toHex(batch.manifestHash) !== review.manifestHash) {
    throw new ApiError(409, "BATCH_CHANGED");
  }
  return batch;
}

async function prepareIntent(
  context: AdminContext,
  session: AdminSession,
  request: AdminRequest,
): Promise<AdminResponse> {
  await ensureFixture(context.pool);
  const idempotencyKey = text(request.idempotencyKey, "idempotencyKey", /^[A-Za-z0-9_-]{16,64}$/);
  const operator = text(request.body?.operator, "operator", /^[1-9A-HJ-NP-Za-km-z]{32,44}$/) as Address;
  const cluster = text(request.body?.cluster, "cluster", /^solana:devnet$/);
  void cluster;

  const existing = await context.pool.query(
    `SELECT ${INTENT_COLUMNS} FROM demo_publish_intent WHERE registry_id = $1 AND idempotency_key = $2`,
    [context.registryId, idempotencyKey],
  );
  // A reload or a double click must never produce a second batch.
  if (existing.rows.length > 0) return intentResponse(intentRow(existing.rows[0]), { replayed: true });

  const config = await context.rpc.getRegistryConfig(context.configPda);
  if (config === null) throw new ApiError(409, "REGISTRY_NOT_INITIALIZED");
  if (config.paused) throw new ApiError(409, "REGISTRY_PAUSED");

  const batchSequence = config.currentBatchSequence + 1n;
  const createdAt = context.now().toISOString().replace(/\.\d{3}Z$/, "Z");
  const batch = buildBatch(await syntheticRecords(context.pool), {
    registryId: context.registryId,
    batchSequence,
    registryVersion: config.currentRegistryVersion,
    previousAnchorHash: new Uint8Array(config.lastAnchorHash),
    createdAt,
    operatorKeyId: OPERATOR_KEY_ID,
  });

  const dayUtc = Math.floor(context.now().getTime() / 86_400_000);
  const segment = await findOpenSegment(context, dayUtc);
  const [rolePda] = await findRolePda(
    { config: context.configPda, operator },
    { programAddress: context.programId },
  );
  const blockhash = await context.rpc.getLatestBlockhash();
  const prepared = prepareAnchorTransaction({
    programId: context.programId,
    configPda: context.configPda,
    rolePda,
    segmentPda: segment.address,
    operator,
    blockhash: blockhash.blockhash,
    lastValidBlockHeight: blockhash.lastValidBlockHeight,
    batchSequence,
    registryVersion: config.currentRegistryVersion,
    cursorStart: batch.cursorStart,
    cursorEnd: batch.cursorEnd,
    merkleRoot: batch.merkleRoot,
    manifestHash: batch.manifestHash,
    previousAnchorHash: new Uint8Array(config.lastAnchorHash),
    leafCount: batch.leafCount,
    schemaVersion: config.schemaVersion,
    hashAlgorithm: config.hashAlgorithm,
    treeAlgorithm: config.treeAlgorithm,
  });

  const intent: PublishIntent = {
    registryId: context.registryId,
    batchSequence,
    registryVersion: config.currentRegistryVersion,
    cursorStart: batch.cursorStart,
    cursorEnd: batch.cursorEnd,
    leafCount: batch.leafCount,
    merkleRootHex: toHex(batch.merkleRoot),
    manifestHashHex: toHex(batch.manifestHash),
    previousAnchorHashHex: toHex(new Uint8Array(config.lastAnchorHash)),
    programId: context.programId,
    configPda: context.configPda,
    rolePda,
    segmentPda: segment.address,
    segmentIndex: segment.index,
    dayUtc,
    feePayer: operator,
    recentBlockhash: blockhash.blockhash,
    lastValidBlockHeight: blockhash.lastValidBlockHeight,
    messageBase64: prepared.messageBase64,
  };
  const simulation = await context.rpc.simulate(prepared.transactionBase64);
  const review = {
    ...batchReview(batch),
    createdAt,
    cluster: "solana:devnet",
    programId: context.programId,
    configPda: context.configPda,
    rolePda,
    segmentPda: segment.address,
    segmentIndex: segment.index,
    dayUtc,
    feePayer: operator,
    accounts: prepared.accounts,
    instructionData: prepared.instructionDataBase64,
    transactionBase64: prepared.transactionBase64,
    simulation: {
      ok: simulation.ok,
      error: simulation.error,
      unitsConsumed: simulation.unitsConsumed,
    },
  };
  const intentId = randomUUID();
  // Blockhash validity, not wall-clock, decides expiry; the timestamp is only
  // shown in the UI.
  const expiresAt = new Date(context.now().getTime() + 90_000);
  await context.pool.query(
    `INSERT INTO demo_publish_intent (
       intent_id, registry_id, batch_sequence, idempotency_key, intent_hash, message_base64,
       intent_json, state, simulation_logs, recent_blockhash, last_valid_block_height, expires_at, created_by
     ) VALUES ($1,$2,$3,$4,decode($5,'hex'),$6,$7,$8,$9,$10,$11,$12,$13)`,
    [
      intentId,
      context.registryId,
      batchSequence.toString(),
      idempotencyKey,
      toHex(intentHash(intent)),
      prepared.messageBase64,
      JSON.stringify(review),
      simulation.ok ? "SIMULATED" : "SIMULATION_FAILED",
      JSON.stringify(simulation.logs),
      blockhash.blockhash,
      blockhash.lastValidBlockHeight.toString(),
      expiresAt.toISOString(),
      session.username,
    ],
  );
  await appendEvent(context.pool, context, session, intentId, simulation.ok ? "BATCH_SIMULATED" : "SIMULATION_FAILED", {
    batchSequence: batchSequence.toString(),
    merkleRoot: toHex(batch.merkleRoot),
    manifestHash: toHex(batch.manifestHash),
  });
  const stored = await loadIntent(context.pool, intentId);
  return { ...intentResponse(stored), status: simulation.ok ? 201 : 422 };
}

async function findOpenSegment(
  context: AdminContext,
  dayUtc: number,
): Promise<{ address: Address; index: number }> {
  for (let index = 0; index < SEGMENTS_PER_DAY; index += 1) {
    const [address] = await findLedgerSegmentPda(
      { config: context.configPda, dayUtc, segmentIndex: index },
      { programAddress: context.programId },
    );
    const segment = await context.rpc.getLedgerSegment(address);
    if (segment === null) {
      if (index === 0) throw new ApiError(409, "LEDGER_SEGMENT_MISSING");
      continue;
    }
    if (segment.sealed === 0 && segment.entryCount < segment.capacity) return { address, index };
  }
  throw new ApiError(409, "LEDGER_SEGMENT_FULL");
}

async function expireIfBlockhashIsStale(context: AdminContext, intent: IntentRow): Promise<boolean> {
  const height = await context.rpc.getBlockHeight();
  if (height <= intent.lastValidBlockHeight) return false;
  await setState(context.pool, intent, "EXPIRED", { failureCode: "BLOCKHASH_EXPIRED" });
  return true;
}

async function submitSignature(
  context: AdminContext,
  session: AdminSession,
  intentId: string,
  body: Record<string, unknown> | null,
): Promise<AdminResponse> {
  const intent = await loadIntent(context.pool, intentId);
  // Re-submitting after finalization answers from storage instead of sending a
  // second transaction.
  if (intent.state === "SUBMITTED" || intent.state === "FINALIZED" || intent.state === "ISSUED") {
    return intentResponse(intent, { replayed: true });
  }
  const signedTransaction = text(body?.signedTransactionBase64, "signedTransaction", /^[A-Za-z0-9+/=]+$/);
  if (await expireIfBlockhashIsStale(context, intent)) {
    return intentResponse(intent, { replayed: false });
  }
  const review = intent.review as any;
  let signature: string;
  try {
    signature = validateSignedTransaction(signedTransaction, intent.messageBase64, review.feePayer as Address);
  } catch (error) {
    if (!(error instanceof SignedTransactionError)) throw error;
    await appendEvent(context.pool, context, session, intent.intentId, "SIGNATURE_REJECTED", { code: error.code });
    throw new ApiError(422, error.code);
  }
  await setState(context.pool, intent, "SIGNED", { signature, signedTransaction });
  await appendEvent(context.pool, context, session, intent.intentId, "TRANSACTION_SIGNED", { signature });
  try {
    await context.rpc.send(signedTransaction);
  } catch (error) {
    // The signature is already known, so the outcome is reconciled by polling
    // rather than by rebuilding and re-signing.
    await setState(context.pool, intent, "UNKNOWN", {
      failureCode: "SUBMIT_RESPONSE_UNKNOWN",
      signature,
    });
    await appendEvent(context.pool, context, session, intent.intentId, "SUBMIT_UNKNOWN", { signature });
    return intentResponse(intent);
  }
  await setState(context.pool, intent, "SUBMITTED", { signature });
  await appendEvent(context.pool, context, session, intent.intentId, "TRANSACTION_SUBMITTED", { signature });
  return intentResponse(intent);
}

async function reconcile(
  context: AdminContext,
  session: AdminSession,
  intentId: string,
): Promise<AdminResponse> {
  const intent = await loadIntent(context.pool, intentId);
  if (intent.state !== "SUBMITTED" && intent.state !== "UNKNOWN") return intentResponse(intent);
  if (intent.signature === null) throw new ApiError(500, "SIGNATURE_MISSING");
  const finalized = await context.rpc.getFinalizedTransaction(intent.signature);
  if (finalized === null) {
    await expireIfBlockhashIsStale(context, intent);
    return intentResponse(intent);
  }
  if (finalized.failed) {
    await setState(context.pool, intent, "FAILED", { failureCode: "TRANSACTION_FAILED" });
    await appendEvent(context.pool, context, session, intent.intentId, "TRANSACTION_FAILED", {});
    return intentResponse(intent);
  }
  await setState(context.pool, intent, "FINALIZED", { anchorSlot: finalized.slot.toString() });
  await appendEvent(context.pool, context, session, intent.intentId, "ANCHOR_FINALIZED", {
    signature: intent.signature,
    slot: finalized.slot.toString(),
  });
  return intentResponse(await loadIntent(context.pool, intentId));
}

async function issueForIntent(
  context: AdminContext,
  session: AdminSession,
  intentId: string,
  body: Record<string, unknown> | null,
): Promise<AdminResponse> {
  await ensureWorkingRegistry(context);
  const intent = await loadIntent(context.pool, intentId);
  if (intent.state === "ISSUED") return intentResponse(intent, { replayed: true });
  if (intent.state !== "FINALIZED") throw new ApiError(409, "ANCHOR_NOT_FINALIZED");
  if (intent.signature === null || intent.anchorSlot === null) throw new ApiError(500, "ANCHOR_INCOMPLETE");
  const internalRecordId = text(body?.internalRecordId, "internalRecordId", /^SYNTHETIC-[1-9][0-9]*$/);
  const disclosedPaths = disclosureRequest(body?.disclosedPaths);
  const batch = await rebuildBatch(context, intent);
  const review = intent.review as any;
  // `operator` and `published_at` are written by the program, so the anchor hash
  // can only be computed from the entry the chain actually stored (§2.2).
  const anchorHashHex = await anchoredEntryHash(context, intent, review);
  const issued = issueCertificate(
    batch,
    {
      solanaProgramId: new Uint8Array(getAddressEncoder().encode(context.programId)),
      segmentIndex: review.segmentIndex,
      segmentPda: new Uint8Array(getAddressEncoder().encode(review.segmentPda as Address)),
      transactionSignature: base58ToBytes(intent.signature),
      anchorSlot: intent.anchorSlot,
    },
    {
      internalRecordId,
      certificateId: new Uint8Array(randomBytes(16)),
      issuedAt: context.now().toISOString().replace(/\.\d{3}Z$/, "Z"),
      issuerKeyId: ISSUER_KEY_ID,
      issuerSecretKey: context.issuerSecretKey,
      publicBaseUrl: context.publicWebBaseUrl,
      disclosedPaths,
    },
  );

  const client = await context.pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO demo_anchor (
         registry_id, batch_sequence, registry_version, merkle_root, manifest_hash, anchor_hash,
         program_id, segment_pda, transaction_signature, anchor_slot, commitment, finalized_at
       ) VALUES ($1,$2,$3,decode($4,'hex'),decode($5,'hex'),decode($6,'hex'),$7,$8,$9,$10,'finalized',now())
       ON CONFLICT (registry_id, batch_sequence) DO UPDATE SET
         merkle_root=EXCLUDED.merkle_root, manifest_hash=EXCLUDED.manifest_hash,
         transaction_signature=EXCLUDED.transaction_signature, anchor_slot=EXCLUDED.anchor_slot`,
      [
        context.registryId,
        intent.batchSequence.toString(),
        review.registryVersion,
        review.merkleRoot,
        review.manifestHash,
        anchorHashHex,
        context.programId,
        review.segmentPda,
        intent.signature,
        intent.anchorSlot.toString(),
      ],
    );
    await client.query(
      `INSERT INTO anchor_batch (
         registry_id, batch_sequence, registry_version, cursor_start, cursor_end, leaf_count,
         merkle_root, manifest_hash, previous_anchor_hash, anchor_hash, status,
         solana_signature, solana_slot, prepared_at, finalized_at
       ) VALUES ($1,$2,$3,$4,$5,$6,decode($7,'hex'),decode($8,'hex'),decode($9,'hex'),decode($12,'hex'),'FINALIZED',$10,$11,now(),now())
       ON CONFLICT (registry_id, batch_sequence) DO UPDATE SET status='FINALIZED',
         solana_signature=EXCLUDED.solana_signature, solana_slot=EXCLUDED.solana_slot, finalized_at=now()`,
      [
        context.registryId,
        intent.batchSequence.toString(),
        review.registryVersion,
        review.cursorStart,
        review.cursorEnd,
        review.leafCount,
        review.merkleRoot,
        review.manifestHash,
        review.previousAnchorHash,
        intent.signature,
        intent.anchorSlot.toString(),
        anchorHashHex,
      ],
    );
    // Older certificates of the same record become SUPERSEDED, which is what the
    // verifier reports for them afterwards.
    await client.query(
      `UPDATE demo_certificate SET status='SUPERSEDED'
        WHERE registry_id=$1 AND internal_record_id=$2 AND status='ACTIVE'`,
      [context.registryId, internalRecordId],
    );
    await client.query(
      `INSERT INTO demo_certificate (
         certificate_id, registry_id, batch_sequence, certificate_hash, package_base64url, qr_url,
         status, issued_at, internal_record_id, record_version, disclosure_mode, disclosed_paths
       ) VALUES ($1,$2,$3,decode($4,'hex'),$5,$6,'ACTIVE',now(),$7,$8,$9,$10)`,
      [
        issued.certificateId,
        context.registryId,
        intent.batchSequence.toString(),
        issued.certificateHash,
        issued.packageBase64url,
        issued.qrUrl,
        internalRecordId,
        issued.recordVersion.toString(),
        issued.disclosureMode,
        issued.disclosedPaths,
      ],
    );
    await client.query(
      `UPDATE demo_publish_intent SET state='ISSUED', certificate_id=$2, updated_at=now()
        WHERE intent_id=$1 AND state='FINALIZED'`,
      [intent.intentId, issued.certificateId],
    );
    await appendEvent(client, context, session, intent.intentId, "CERTIFICATE_ISSUED", {
      certificateId: issued.certificateId,
      certificateHash: issued.certificateHash,
      internalRecordId,
      disclosureMode: issued.disclosureMode,
      disclosedPaths: issued.disclosedPaths,
    });
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
  return {
    status: 201,
    body: {
      intentId: intent.intentId,
      state: "ISSUED",
      certificateId: issued.certificateId,
      certificateHash: issued.certificateHash,
      qrUrl: issued.qrUrl,
      transactionSignature: intent.signature,
      anchorSlot: intent.anchorSlot.toString(),
      explorerUrl: `https://explorer.solana.com/tx/${intent.signature}?cluster=devnet`,
      disclosureMode: issued.disclosureMode,
      disclosedPaths: issued.disclosedPaths,
      fieldCount: issued.fieldCount,
    },
  };
}

/** Optional disclosure selection: absent means the whole record. */
function disclosureRequest(value: unknown): string[] | undefined {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value) || value.length === 0) throw new ApiError(400, "DISCLOSED_PATHS_INVALID");
  return value.map((path) => text(path, "disclosedPath", /^[A-Za-z][A-Za-z0-9]{0,62}$/));
}

/**
 * Reads the finalized ledger segment and recomputes `anchor_hash` from the
 * entry the program wrote. Refusing when the entry is missing or disagrees with
 * the reviewed batch keeps a wrong anchor out of the demo tables.
 */
async function anchoredEntryHash(
  context: AdminContext,
  intent: IntentRow,
  review: any,
): Promise<string> {
  const segment = await context.rpc.getLedgerSegment(review.segmentPda as Address);
  if (segment === null) throw new ApiError(409, "ANCHOR_ACCOUNT_INVALID");
  const entry = segment.entries.find((candidate) => candidate.batchSequence === intent.batchSequence);
  if (entry === undefined) throw new ApiError(409, "ANCHOR_NOT_FOUND");
  if (toHex(new Uint8Array(entry.merkleRoot)) !== review.merkleRoot) {
    throw new ApiError(409, "ANCHOR_ROOT_MISMATCH");
  }
  return toHex(anchorHash({
    registryIdHash: registryIdHash(context.registryId),
    batchSequence: entry.batchSequence,
    registryVersion: entry.registryVersion,
    sourceCursorStart: entry.sourceCursorStart,
    sourceCursorEnd: entry.sourceCursorEnd,
    merkleRoot: new Uint8Array(entry.merkleRoot),
    manifestHash: new Uint8Array(entry.manifestHash),
    snapshotHash: new Uint8Array(entry.snapshotHash),
    previousAnchorHash: new Uint8Array(entry.previousAnchorHash),
    leafCount: entry.leafCount,
    schemaVersion: entry.schemaVersion,
    flags: entry.flags,
    hashAlgorithm: entry.hashAlgorithm,
    treeAlgorithm: entry.treeAlgorithm,
    operatorPubkey: new Uint8Array(getAddressEncoder().encode(entry.operator)),
    publishedAt: entry.publishedAt,
  }));
}

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58ToBytes(value: string): Uint8Array {
  let number = 0n;
  for (const character of value) {
    const index = BASE58.indexOf(character);
    if (index === -1) throw new ApiError(500, "SIGNATURE_INVALID");
    number = number * 58n + BigInt(index);
  }
  const bytes: number[] = [];
  while (number > 0n) {
    bytes.unshift(Number(number % 256n));
    number /= 256n;
  }
  for (const character of value) {
    if (character !== "1") break;
    bytes.unshift(0);
  }
  if (bytes.length !== 64) throw new ApiError(500, "SIGNATURE_INVALID");
  return Uint8Array.from(bytes);
}

/**
 * Writes one validated record and the fields that came with it. Re-importing
 * the same `internalRecordId` produces a new record version rather than a
 * second object, and the field set is replaced wholesale: a path the new
 * certificate omits must disappear from the commitment, not linger.
 */
async function persistRecord(
  context: AdminContext,
  session: AdminSession,
  record: ValidatedRecord,
): Promise<{ internalRecordId: string; recordVersion: string; status: string; origin: string }> {
  const client = await context.pool.connect();
  try {
    await client.query("BEGIN");
    const result = await client.query(
      `INSERT INTO synthetic_registry_record (
         internal_record_id, source_cursor, record_version, status, record_field_key_hex, origin, schema_id
       ) VALUES (
         $1,
         (SELECT COALESCE(max(source_cursor), 0) + 1 FROM synthetic_registry_record),
         1, $2, $3, 'ADMIN_UI', $4
       )
       ON CONFLICT (internal_record_id) DO UPDATE SET
         status = EXCLUDED.status,
         record_version = synthetic_registry_record.record_version + 1,
         schema_id = EXCLUDED.schema_id,
         updated_at = now()
       RETURNING internal_record_id, record_version::text, status, origin`,
      [record.internalRecordId, record.status, randomBytes(32).toString("hex"), SCHEMA_ID],
    );
    await client.query("DELETE FROM synthetic_record_field WHERE internal_record_id = $1", [record.internalRecordId]);
    for (const field of record.fields) {
      await client.query(
        `INSERT INTO synthetic_record_field (internal_record_id, path, value_type, value_text)
         VALUES ($1,$2,$3,$4)`,
        [record.internalRecordId, field.path, field.type, field.value],
      );
    }
    await appendEvent(client, context, session, null, "RECORD_UPSERTED", {
      internalRecordId: record.internalRecordId,
      status: record.status,
      recordVersion: result.rows[0].record_version,
      paths: record.fields.map((field) => field.path),
    });
    await client.query("COMMIT");
    return {
      internalRecordId: result.rows[0].internal_record_id,
      recordVersion: result.rows[0].record_version,
      status: result.rows[0].status,
      origin: result.rows[0].origin,
    };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function schemaError(error: unknown): never {
  if (error instanceof SchemaError) {
    throw new ApiError(422, error.code, JSON.stringify({ path: error.path, row: error.row }));
  }
  throw error;
}

async function createRecord(
  context: AdminContext,
  session: AdminSession,
  body: Record<string, unknown> | null,
): Promise<AdminResponse> {
  await ensureFixture(context.pool);
  let record: ValidatedRecord;
  try {
    // `status` may arrive as a sibling of the other fields or inside `fields`;
    // the schema owns it either way.
    const fields = { ...(body?.fields as Record<string, unknown> | undefined ?? {}) };
    if (typeof body?.status === "string" && fields.status === undefined) fields.status = body.status;
    record = validateRecord({ internalRecordId: body?.internalRecordId, fields });
  } catch (error) {
    schemaError(error);
  }
  return { status: 201, body: await persistRecord(context, session, record) };
}

/**
 * Import of a user-supplied certificate: one JSON object, an array of them or a
 * CSV whose first line names the field paths. `dryRun` validates and reports
 * without touching the database.
 */
async function importRecords(
  context: AdminContext,
  session: AdminSession,
  body: Record<string, unknown> | null,
): Promise<AdminResponse> {
  await ensureFixture(context.pool);
  const format = text(body?.format, "format", /^(?:json|csv)$/);
  const dryRun = body?.dryRun === true;
  let report: ImportReport;
  try {
    if (format === "csv") {
      const content = body?.content;
      if (typeof content !== "string") throw new SchemaError("CSV_CONTENT_INVALID");
      report = parseCsv(content);
    } else {
      const content = typeof body?.content === "string" ? JSON.parse(body.content as string) : body?.records;
      report = parseJsonRecords(content);
    }
  } catch (error) {
    if (error instanceof SyntaxError) throw new ApiError(422, "JSON_INVALID");
    schemaError(error);
  }

  const applied: Array<Record<string, unknown>> = [];
  if (!dryRun) {
    for (const entry of report.accepted) {
      applied.push({ row: entry.row, ...(await persistRecord(context, session, entry.record)) });
    }
    if (report.accepted.length > 0) {
      await appendEvent(context.pool, context, session, null, "RECORDS_IMPORTED", {
        format,
        accepted: report.accepted.length,
        rejected: report.rejected.length,
      });
    }
  }

  return {
    // A dry run reports; only a real import creates records.
    status: dryRun ? 200 : report.accepted.length > 0 ? 201 : 422,
    body: {
      schemaId: SCHEMA_ID,
      dryRun,
      accepted: report.accepted.map((entry) => ({
        row: entry.row,
        internalRecordId: entry.record.internalRecordId,
        status: entry.record.status,
        fields: entry.record.fields,
      })),
      rejected: report.rejected,
      applied,
    },
  };
}

async function preview(context: AdminContext): Promise<AdminResponse> {
  await ensureFixture(context.pool);
  const config = await context.rpc.getRegistryConfig(context.configPda);
  const batch = buildBatch(await syntheticRecords(context.pool), {
    registryId: context.registryId,
    batchSequence: (config?.currentBatchSequence ?? 0n) + 1n,
    registryVersion: config?.currentRegistryVersion ?? 1n,
    previousAnchorHash: new Uint8Array(config?.lastAnchorHash ?? new Uint8Array(32)),
    createdAt: context.now().toISOString().replace(/\.\d{3}Z$/, "Z"),
    operatorKeyId: OPERATOR_KEY_ID,
  });
  // `certificateHash` deliberately absent: it exists only after a finalized
  // anchor and an issued package (§5.4).
  return { status: 200, body: batchReview(batch) };
}

/**
 * One record with its canonical metadata: per-path commitments, the field root
 * and the record commitment. These are the numbers the batch will carry, not a
 * separate calculation for display.
 */
async function recordDetail(context: AdminContext, internalRecordId: string): Promise<AdminResponse> {
  const result = await context.pool.query(`${RECORD_QUERY} HAVING r.internal_record_id = $1`, [internalRecordId]);
  if (result.rows.length === 0) throw new ApiError(404, "RECORD_NOT_FOUND");
  const row = recordRow(result.rows[0]);
  const fields = fieldsOf(row);
  const key = Uint8Array.from(Buffer.from(row.recordFieldKeyHex, "hex"));
  const tree = buildFieldTree(key, fields);
  const identifier = recordIdCommitment(DEMO_ID_KEY, context.registryId, row.internalRecordId);
  const commitment = recordCommitment(
    registryIdHash(context.registryId),
    identifier,
    row.recordVersion,
    tree.root,
  );
  const certificates = await context.pool.query(
    `SELECT certificate_id, batch_sequence::text, status, issued_at, disclosure_mode, disclosed_paths,
            encode(certificate_hash,'hex') AS certificate_hash, qr_url, record_version::text
       FROM demo_certificate
      WHERE registry_id = $1 AND internal_record_id = $2
      ORDER BY issued_at DESC`,
    [context.registryId, internalRecordId],
  );
  return {
    status: 200,
    body: {
      internalRecordId: row.internalRecordId,
      recordVersion: row.recordVersion.toString(),
      sourceCursor: row.sourceCursor.toString(),
      status: row.status,
      origin: result.rows[0].origin,
      schemaId: result.rows[0].schema_id,
      recordIdCommitment: toHex(identifier),
      fieldRoot: toHex(tree.root),
      recordCommitment: toHex(commitment),
      batchLeafHash: toHex(batchLeafHash(commitment)),
      fields: tree.entries.map((entry, index) => ({
        path: entry.path,
        value: fields.find((field) => field.path === entry.path)?.text ?? null,
        fieldCommitment: toHex(entry.commitment),
        fieldLeafIndex: index,
      })),
      certificates: certificates.rows.map((certificate) => ({
        certificateId: certificate.certificate_id,
        batchSequence: certificate.batch_sequence,
        status: certificate.status,
        issuedAt: certificate.issued_at,
        certificateHash: certificate.certificate_hash,
        qrUrl: certificate.qr_url,
        recordVersion: certificate.record_version,
        disclosureMode: certificate.disclosure_mode,
        disclosedPaths: certificate.disclosed_paths,
      })),
    },
  };
}

const DEFAULT_BACKUP_CENTERS = 5;
const ZERO_ROOT = "00".repeat(32);

interface BackupCenterRow {
  center_id: string;
  registry_id: string;
  name: string;
  scope: string;
  local_endpoint: string;
  volume_name: string;
  credential_reference: string;
  credential_version: string;
  health_status: string;
  active: boolean;
  last_health_at: Date;
  created_at: Date;
  folder_object_key: string | null;
  folder_snapshot_id: string | null;
  folder_snapshot_version: string | null;
  folder_status: string | null;
  folder_snapshot_status: string | null;
  folder_plaintext_hash: string | null;
  folder_ciphertext_hash: string | null;
  folder_merkle_root: string | null;
  folder_last_error: string | null;
  folder_created_at: Date | null;
  folder_verified_at: Date | null;
}

function iso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return new Date(String(value)).toISOString();
}

function jsonValue(value: unknown): unknown {
  if (typeof value === "string") {
    try { return JSON.parse(value); } catch { return value; }
  }
  return value;
}

async function ensureBackupCenters(executor: Pool | PoolClient, registryId: string): Promise<void> {
  // The migration seeds the five canonical gov.registry.land centers. This
  // insert also makes a clean test database or a different bounded registry
  // self-healing without creating external/production destinations.
  await executor.query(
    `INSERT INTO backup_center (
       center_id, registry_id, name, local_endpoint, volume_name,
       credential_reference, credential_version, created_by
     )
     SELECT 'BACKUPCENTER-' || center_number || '-' || md5($1 || ':' || center_number::text),
            $1,
            'Local BackupCenter ' || lpad(center_number::text, 2, '0'),
            'local://backup-center-' || lpad(center_number::text, 2, '0'),
            'onelayer-backup-volume-' || lpad(center_number::text, 2, '0'),
            'onelayer-backup-credential-' || lpad(center_number::text, 2, '0'),
            'credential-v1',
            'system'
       FROM generate_series(1, $2::integer) AS series(center_number)
      WHERE NOT EXISTS (
        SELECT 1 FROM backup_center existing
         WHERE existing.registry_id = $1
           AND existing.name = 'Local BackupCenter ' || lpad(center_number::text, 2, '0')
      )`,
    [registryId, DEFAULT_BACKUP_CENTERS],
  );
}

function centerFromRows(rows: BackupCenterRow[]): Record<string, unknown>[] {
  const grouped = new Map<string, Record<string, unknown>>();
  for (const row of rows) {
    let center = grouped.get(row.center_id);
    if (center === undefined) {
      center = {
        centerId: row.center_id,
        id: row.center_id,
        name: row.name,
        scope: row.scope,
        type: "LOCAL",
        endpoint: row.local_endpoint,
        localEndpoint: row.local_endpoint,
        volume: {
          name: row.volume_name,
          reference: row.volume_name,
        },
        volumeName: row.volume_name,
        credentials: {
          reference: row.credential_reference,
          version: row.credential_version,
        },
        credentialReference: row.credential_reference,
        credentialVersion: row.credential_version,
        active: row.active,
        health: {
          status: row.health_status,
          available: row.health_status === "HEALTHY",
          checkedAt: iso(row.last_health_at),
        },
        healthStatus: row.health_status,
        folders: [] as Record<string, unknown>[],
        replicaStatus: {
          copied: 0,
          pendingRetry: 0,
          failed: 0,
          total: 0,
        },
      };
      grouped.set(row.center_id, center);
    }
    if (row.folder_snapshot_id === null) continue;
    const folders = center.folders as Record<string, unknown>[];
    const status = row.folder_status ?? "FAILED";
    folders.push({
      folderId: row.folder_object_key,
      objectKey: row.folder_object_key,
      snapshotId: row.folder_snapshot_id,
      snapshotVersion: row.folder_snapshot_version,
      status,
      copyStatus: status,
      snapshotStatus: row.folder_snapshot_status,
      plaintextHash: row.folder_plaintext_hash,
      ciphertextHash: row.folder_ciphertext_hash,
      merkleRoot: row.folder_merkle_root,
      lastError: row.folder_last_error,
      createdAt: row.folder_created_at === null ? null : iso(row.folder_created_at),
      verifiedAt: row.folder_verified_at === null ? null : iso(row.folder_verified_at),
    });
    const statusCounts = center.replicaStatus as Record<string, number>;
    statusCounts.total += 1;
    if (status === "COPIED") statusCounts.copied += 1;
    else if (status === "PENDING_RETRY") statusCounts.pendingRetry += 1;
    else statusCounts.failed += 1;
  }
  return [...grouped.values()].map((center) => {
    const folders = center.folders as Record<string, unknown>[];
    folders.sort((left, right) =>
      String(right.createdAt).localeCompare(String(left.createdAt)) ||
      String(left.objectKey).localeCompare(String(right.objectKey)),
    );
    center.lastReplicaStatus = folders[0]?.copyStatus ?? "EMPTY";
    return center;
  });
}

async function loadBackupCenters(
  executor: Pool | PoolClient,
  registryId: string,
): Promise<Record<string, unknown>[]> {
  const result = await executor.query(
    `SELECT c.center_id, c.registry_id, c.name, c.scope, c.local_endpoint,
            c.volume_name, c.credential_reference, c.credential_version,
            c.health_status, c.active, c.last_health_at, c.created_at,
            r.object_key AS folder_object_key, r.snapshot_id::text AS folder_snapshot_id,
            s.snapshot_version::text AS folder_snapshot_version,
            r.copy_status AS folder_status, s.snapshot_status AS folder_snapshot_status,
            encode(s.plaintext_hash,'hex') AS folder_plaintext_hash,
            encode(r.ciphertext_hash,'hex') AS folder_ciphertext_hash,
            encode(s.merkle_root,'hex') AS folder_merkle_root,
            r.last_error AS folder_last_error, r.created_at AS folder_created_at,
            r.verified_at AS folder_verified_at
       FROM backup_center c
       LEFT JOIN snapshot_replica r ON r.center_id = c.center_id
       LEFT JOIN snapshot s ON s.snapshot_id = r.snapshot_id
      WHERE c.registry_id = $1
      ORDER BY c.created_at ASC, r.created_at DESC NULLS LAST`,
    [registryId],
  );
  return centerFromRows(result.rows as BackupCenterRow[]);
}

async function loadSnapshotSummaries(
  executor: Pool | PoolClient,
  registryId: string,
): Promise<Record<string, unknown>[]> {
  const result = await executor.query(
    `SELECT s.snapshot_id::text, s.snapshot_version::text, s.format_version,
            s.package_format, s.snapshot_status, encode(s.merkle_root,'hex') AS merkle_root,
            encode(s.plaintext_hash,'hex') AS plaintext_hash,
            encode(s.ciphertext_hash,'hex') AS ciphertext_hash,
            s.plaintext_length, s.key_encryption_version, s.created_by, s.created_at,
            r.center_id, r.object_key, r.copy_status, r.last_error, r.created_at AS replica_created_at,
            r.verified_at
       FROM snapshot s
       LEFT JOIN snapshot_replica r ON r.snapshot_id = s.snapshot_id
      WHERE s.registry_id = $1
      ORDER BY s.snapshot_version DESC, r.center_id ASC`,
    [registryId],
  );
  const snapshots = new Map<string, Record<string, unknown>>();
  for (const row of result.rows) {
    let snapshot = snapshots.get(row.snapshot_id);
    if (snapshot === undefined) {
      snapshot = {
        snapshotId: row.snapshot_id,
        snapshotVersion: row.snapshot_version,
        formatVersion: row.format_version,
        packageFormat: row.package_format,
        snapshotStatus: row.snapshot_status,
        merkleRoot: row.merkle_root,
        plaintextHash: row.plaintext_hash,
        ciphertextHash: row.ciphertext_hash,
        plaintextLength: row.plaintext_length,
        keyEncryptionVersion: row.key_encryption_version,
        createdBy: row.created_by,
        createdAt: iso(row.created_at),
        replicas: [] as Record<string, unknown>[],
      };
      snapshots.set(row.snapshot_id, snapshot);
    }
    if (row.center_id !== null) {
      (snapshot.replicas as Record<string, unknown>[]).push({
        centerId: row.center_id,
        objectKey: row.object_key,
        status: row.copy_status,
        copyStatus: row.copy_status,
        lastError: row.last_error,
        createdAt: iso(row.replica_created_at),
        verifiedAt: row.verified_at === null ? null : iso(row.verified_at),
      });
    }
  }
  return [...snapshots.values()];
}

async function backupOverview(context: AdminContext): Promise<AdminResponse> {
  await ensureFixture(context.pool);
  await ensureBackupCenters(context.pool, context.registryId);
  const [centers, snapshots, retention] = await Promise.all([
    loadBackupCenters(context.pool, context.registryId),
    loadSnapshotSummaries(context.pool, context.registryId),
    context.pool.query(
      `SELECT center_id, count(*)::text AS retired_folders
         FROM backup_retention_event WHERE registry_id = $1 GROUP BY center_id`,
      [context.registryId],
    ),
  ]);
  const retiredByCenter = Object.fromEntries(
    retention.rows.map((row) => [row.center_id, Number(row.retired_folders)]),
  );
  for (const center of centers) {
    center.retiredFolderCount = retiredByCenter[center.centerId as string] ?? 0;
    center.retentionWindow = RETENTION_WINDOW;
  }
  return {
    status: 200,
    body: {
      registryId: context.registryId,
      packageFormat: SNAPSHOT_FORMAT,
      retentionWindow: RETENTION_WINDOW,
      centers,
      backupCenters: centers,
      snapshots,
    },
  };
}

async function snapshotState(executor: Pool | PoolClient, context: AdminContext): Promise<SnapshotStateV1> {
  const [records, recordVersions, certificates, canonicalCertificates, leaves, anchors, batches, events, audit] = await Promise.all([
    executor.query(`${RECORD_QUERY} ORDER BY r.source_cursor`),
    executor.query(
      `SELECT id::text, registry_id, internal_record_id, encode(record_id_commitment,'hex') AS record_id_commitment,
              record_version::text, workflow_event_id, schema_version, encode(canonical_payload_encrypted,'hex') AS canonical_payload_encrypted,
              encode(field_root,'hex') AS field_root, encode(record_field_key_encrypted,'hex') AS record_field_key_encrypted,
              key_encryption_version, encode(record_commitment,'hex') AS record_commitment,
              encode(batch_leaf_hash,'hex') AS batch_leaf_hash, source_cursor::text, created_at
         FROM canonical_record_version WHERE registry_id = $1 ORDER BY internal_record_id, record_version`,
      [context.registryId],
    ),
    executor.query(
      `SELECT certificate_id, registry_id, batch_sequence::text, encode(certificate_hash,'hex') AS certificate_hash,
              package_base64url, qr_url, status, issued_at, internal_record_id,
              record_version::text, disclosure_mode, disclosed_paths
         FROM demo_certificate WHERE registry_id = $1 ORDER BY issued_at, certificate_id`,
      [context.registryId],
    ),
    executor.query(
      `SELECT c.certificate_id::text, c.registry_id, c.batch_sequence::text, encode(c.certificate_hash,'hex') AS certificate_hash,
              encode(c.signature,'hex') AS issuer_signature, c.issuer_key_id, c.status, c.issued_at,
              c.record_version_id::text, v.record_version::text, c.superseded_by::text
         FROM certificate c
         JOIN canonical_record_version v ON v.id = c.record_version_id
        WHERE c.registry_id = $1 ORDER BY c.issued_at, c.certificate_id`,
      [context.registryId],
    ),
    executor.query(
      `SELECT registry_id, batch_sequence::text, leaf_index, record_version_id::text,
              encode(leaf_hash,'hex') AS leaf_hash, proof_object_key
         FROM batch_leaf WHERE registry_id = $1 ORDER BY batch_sequence, leaf_index`,
      [context.registryId],
    ),
    executor.query(
      `SELECT registry_id, batch_sequence::text, registry_version::text,
              encode(merkle_root,'hex') AS merkle_root, encode(manifest_hash,'hex') AS manifest_hash,
              encode(anchor_hash,'hex') AS anchor_hash, program_id, segment_pda,
              transaction_signature, anchor_slot::text, commitment, finalized_at
         FROM demo_anchor WHERE registry_id = $1 ORDER BY batch_sequence`,
      [context.registryId],
    ),
    executor.query(
      `SELECT registry_id, batch_sequence::text, registry_version::text,
              cursor_start::text, cursor_end::text, leaf_count,
              encode(merkle_root,'hex') AS merkle_root, encode(manifest_hash,'hex') AS manifest_hash,
              encode(previous_anchor_hash,'hex') AS previous_anchor_hash,
              encode(anchor_hash,'hex') AS anchor_hash, status, solana_signature,
              solana_slot::text, prepared_at, finalized_at
         FROM anchor_batch WHERE registry_id = $1 ORDER BY batch_sequence`,
      [context.registryId],
    ),
    executor.query(
      `SELECT operation_sequence::text, intent_id, event_type, actor, actor_role, payload, created_at
         FROM demo_operation_event WHERE registry_id = $1 ORDER BY operation_sequence`,
      [context.registryId],
    ),
    executor.query(
      `SELECT audit_sequence::text, audit_id::text, event_type, actor, object_type, object_id,
              event_payload, created_at
         FROM audit_event WHERE registry_id = $1 ORDER BY audit_sequence`,
      [context.registryId],
    ),
  ]);

  const currentRecords = records.rows.map((row) => ({
    internalRecordId: row.internal_record_id,
    sourceCursor: row.source_cursor,
    recordVersion: row.record_version,
    status: row.status,
    origin: row.origin,
    schemaId: row.schema_id,
    fields: jsonValue(row.fields),
  }));
  const recordVersionRows = recordVersions.rows.map((row) => ({ ...row }));
  const certificateRows = certificates.rows.map((row) => ({ ...row }));
  const canonicalCertificateRows = canonicalCertificates.rows.map((row) => ({ ...row }));
  const proofRows = leaves.rows.map((row) => ({ ...row }));
  const anchorRows = anchors.rows.map((row) => ({ ...row }));
  const batchRows = batches.rows.map((row) => ({ ...row }));
  const manifestRows = batches.rows.map((row) => ({
    registryId: row.registry_id,
    batchSequence: row.batch_sequence,
    registryVersion: row.registry_version,
    cursorStart: row.cursor_start,
    cursorEnd: row.cursor_end,
    leafCount: row.leaf_count,
    merkleRoot: row.merkle_root,
    manifestHash: row.manifest_hash,
    previousAnchorHash: row.previous_anchor_hash,
    status: row.status,
  }));
  const operationRows = [
    ...events.rows.map((row) => ({
      sequence: row.operation_sequence,
      intentId: row.intent_id,
      eventType: row.event_type,
      actor: row.actor,
      actorRole: row.actor_role,
      payload: jsonValue(row.payload),
      createdAt: row.created_at,
    })),
    ...audit.rows.map((row) => ({
      sequence: row.audit_sequence,
      auditId: row.audit_id,
      eventType: row.event_type,
      actor: row.actor,
      objectType: row.object_type,
      objectId: row.object_id,
      payload: jsonValue(row.event_payload),
      createdAt: row.created_at,
    })),
  ];

  return {
    registryId: context.registryId,
    capturedAt: context.now().toISOString().replace(/\.\d{3}Z$/, "Z"),
    records: currentRecords,
    recordVersions: recordVersionRows,
    certificatePackages: [...certificateRows, ...canonicalCertificateRows],
    qrMetadata: certificateRows.map((row) => ({
      certificateId: row.certificate_id,
      qrUrl: row.qr_url,
      certificateHash: row.certificate_hash,
      packageBase64Url: row.package_base64url,
      issuedAt: row.issued_at,
    })),
    proofs: proofRows,
    roots: [...anchorRows, ...batchRows],
    manifests: manifestRows,
    anchorReferences: anchorRows,
    operationHistory: operationRows,
  };
}

async function latestSnapshotAnchor(
  executor: Pool | PoolClient,
  registryId: string,
): Promise<{ merkleRoot: string; finalized: boolean }> {
  const [anchor, incident] = await Promise.all([
    executor.query(
      `SELECT encode(merkle_root,'hex') AS merkle_root
         FROM demo_anchor WHERE registry_id = $1 AND commitment = 'finalized'
        ORDER BY batch_sequence DESC LIMIT 1`,
      [registryId],
    ),
    executor.query(
      `SELECT count(*)::text AS open_incidents
         FROM integrity_incident
        WHERE registry_id = $1 AND status = 'OPEN'`,
      [registryId],
    ),
  ]);
  const hasAnchor = anchor.rows.length > 0;
  const noOpenIncident = Number(incident.rows[0]?.open_incidents ?? 0) === 0;
  return {
    merkleRoot: hasAnchor ? anchor.rows[0].merkle_root : ZERO_ROOT,
    finalized: hasAnchor && noOpenIncident,
  };
}

function snapshotKek(context: AdminContext): Uint8Array {
  const key = context.snapshotKek ?? context.issuerSecretKey;
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new ApiError(503, "SNAPSHOT_KEY_UNAVAILABLE");
  return key;
}

function uuidBytes(uuid: string): Uint8Array {
  return Uint8Array.from(Buffer.from(uuid.replaceAll("-", ""), "hex"));
}

async function retentionForCenter(
  executor: PoolClient,
  context: AdminContext,
  session: AdminSession,
  centerId: string,
): Promise<void> {
  const result = await executor.query(
    `SELECT r.replica_id::text, r.snapshot_id::text, s.snapshot_status,
            s.snapshot_version::text, r.object_key, r.created_at,
            encode(r.ciphertext_hash,'hex') AS ciphertext_hash
       FROM snapshot_replica r
       JOIN snapshot s ON s.snapshot_id = r.snapshot_id
      WHERE r.center_id = $1
      ORDER BY r.created_at ASC, r.replica_id ASC
      FOR UPDATE OF r`,
    [centerId],
  );
  const victims = retentionVictims(result.rows.map((row) => ({
    replicaId: row.replica_id,
    snapshotId: row.snapshot_id,
    snapshotStatus: row.snapshot_status,
    createdAt: iso(row.created_at),
  })));
  for (const victim of victims) {
    const row = result.rows.find((candidate) => candidate.replica_id === victim.replicaId);
    if (row === undefined) continue;
    await executor.query(
      `INSERT INTO backup_retention_event (
         registry_id, center_id, snapshot_id, snapshot_version, replica_id, object_key,
         snapshot_status, ciphertext_hash
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,decode($8,'hex'))`,
      [context.registryId, centerId, row.snapshot_id, row.snapshot_version, row.replica_id, row.object_key, row.snapshot_status, row.ciphertext_hash],
    );
    await executor.query("DELETE FROM snapshot_replica WHERE replica_id = $1", [row.replica_id]);
    await appendEvent(executor, context, session, null, "SNAPSHOT_REPLICA_RETIRED", {
      centerId,
      snapshotId: row.snapshot_id,
      snapshotVersion: row.snapshot_version,
      objectKey: row.object_key,
      reason: "RETENTION_WINDOW",
    });
  }
}

async function backupOperationResponse(
  context: AdminContext,
  operationId: string,
  status = 200,
): Promise<AdminResponse> {
  const operation = await context.pool.query(
    `SELECT o.operation_id::text, o.registry_id, o.snapshot_id::text,
            o.idempotency_key, o.operation_status, o.created_by, o.created_at,
            s.snapshot_version::text, s.format_version, s.package_format,
            s.snapshot_status, encode(s.merkle_root,'hex') AS merkle_root,
            encode(s.plaintext_hash,'hex') AS plaintext_hash,
            encode(s.ciphertext_hash,'hex') AS ciphertext_hash,
            s.plaintext_length, s.key_encryption_version, s.created_at AS snapshot_created_at
       FROM snapshot_replication_operation o
       JOIN snapshot s ON s.snapshot_id = o.snapshot_id
      WHERE o.operation_id = $1 AND o.registry_id = $2`,
    [operationId, context.registryId],
  );
  if (operation.rows.length === 0) throw new ApiError(404, "BACKUP_OPERATION_NOT_FOUND");
  const row = operation.rows[0];
  const overview = await backupOverview(context);
  const snapshot = (overview.body as any).snapshots.find((entry: any) => entry.snapshotId === row.snapshot_id);
  const centers = (overview.body as any).centers.map((center: any) => ({
    centerId: center.centerId,
    name: center.name,
    health: center.health,
    status: (snapshot?.replicas ?? []).find((replica: any) => replica.centerId === center.centerId)?.copyStatus ??
      (center.active ? "PENDING_RETRY" : "FAILED"),
    folder: (center.folders ?? []).find((folder: any) => folder.snapshotId === row.snapshot_id) ?? null,
  }));
  return {
    status,
    body: {
      operationId: row.operation_id,
      snapshotId: row.snapshot_id,
      snapshotVersion: row.snapshot_version,
      formatVersion: row.format_version,
      packageFormat: row.package_format,
      snapshotStatus: row.snapshot_status,
      merkleRoot: row.merkle_root,
      plaintextHash: row.plaintext_hash,
      ciphertextHash: row.ciphertext_hash,
      plaintextLength: row.plaintext_length,
      keyEncryptionVersion: row.key_encryption_version,
      createdAt: iso(row.snapshot_created_at),
      operationStatus: row.operation_status,
      replayed: false,
      centers,
      replicas: snapshot?.replicas ?? [],
    },
  };
}

async function refreshBackups(
  context: AdminContext,
  session: AdminSession,
  request: AdminRequest,
): Promise<AdminResponse> {
  await ensureFixture(context.pool);
  const idempotencyKey = request.idempotencyKey === undefined
    ? null
    : text(request.idempotencyKey, "idempotencyKey", /^[A-Za-z0-9_-]{16,64}$/);
  await ensureBackupCenters(context.pool, context.registryId);
  if (idempotencyKey !== null) {
    const existing = await context.pool.query(
      `SELECT operation_id::text FROM snapshot_replication_operation
        WHERE registry_id = $1 AND idempotency_key = $2`,
      [context.registryId, idempotencyKey],
    );
    if (existing.rows.length > 0) {
      const replay = await backupOperationResponse(context, existing.rows[0].operation_id);
      (replay.body as Record<string, unknown>).replayed = true;
      return replay;
    }
  }

  const client = await context.pool.connect();
  let operationId: string | null = null;
  try {
    await client.query("BEGIN");
    if (idempotencyKey !== null) {
      const existing = await client.query(
        `SELECT operation_id::text FROM snapshot_replication_operation
          WHERE registry_id = $1 AND idempotency_key = $2 FOR SHARE`,
        [context.registryId, idempotencyKey],
      );
      if (existing.rows.length > 0) {
        const replayOperationId = existing.rows[0].operation_id as string;
        operationId = replayOperationId;
        await client.query("ROLLBACK");
        const replay = await backupOperationResponse(context, replayOperationId);
        (replay.body as Record<string, unknown>).replayed = true;
        return replay;
      }
    }

    const latest = await client.query(
      `SELECT snapshot_version::text FROM snapshot
        WHERE registry_id = $1 ORDER BY snapshot_version DESC LIMIT 1 FOR UPDATE`,
      [context.registryId],
    );
    const snapshotVersion = BigInt(latest.rows[0]?.snapshot_version ?? "0") + 1n;
    const snapshotId = randomUUID();
    const state = await snapshotState(client, context);
    const anchor = await latestSnapshotAnchor(client, context.registryId);
    const encrypted = encryptSnapshotState({
      registryId: context.registryId,
      snapshotId: uuidBytes(snapshotId),
      snapshotVersion,
      state,
      kek: snapshotKek(context),
      keyEncryptionVersion: SNAPSHOT_KEY_ENCRYPTION_VERSION,
    });
    const packageBytes = Buffer.from(encrypted.encoded);
    await client.query(
      `INSERT INTO snapshot (
         snapshot_id, registry_id, snapshot_version, snapshot_status, merkle_root,
         plaintext_hash, ciphertext_hash, encrypted_package, plaintext_length,
         key_encryption_version, created_by
       ) VALUES ($1,$2,$3,$4,decode($5,'hex'),decode($6,'hex'),decode($7,'hex'),$8,$9,$10,$11)`,
      [
        snapshotId,
        context.registryId,
        snapshotVersion.toString(),
        anchor.finalized ? "FINALIZED" : "NON_FINALIZED",
        anchor.merkleRoot,
        toHex(encrypted.snapshot.plaintextHash),
        toHex(encrypted.snapshot.ciphertextHash),
        packageBytes,
        encrypted.plaintextLength,
        encrypted.snapshot.keyEncryptionVersion,
        session.username,
      ],
    );

    const centers = await client.query(
      `SELECT center_id, health_status, active
         FROM backup_center WHERE registry_id = $1 AND active = TRUE
        ORDER BY created_at, center_id FOR UPDATE`,
      [context.registryId],
    );
    const objectKey = snapshotObjectKey(uuidBytes(snapshotId));
    const replicaStatuses: string[] = [];
    for (const center of centers.rows) {
      const copyStatus = center.health_status === "HEALTHY"
        ? "COPIED"
        : center.health_status === "UNAVAILABLE" ? "PENDING_RETRY" : "FAILED";
      const lastError = copyStatus === "COPIED" ? null :
        copyStatus === "PENDING_RETRY" ? "CENTER_UNAVAILABLE" : "CENTER_HEALTH_ERROR";
      replicaStatuses.push(copyStatus);
      await client.query(
        `INSERT INTO snapshot_replica (
           replica_id, snapshot_id, center_id, object_key, copy_status,
           package_bytes, ciphertext_hash, last_error, copied_at, verified_at
         ) VALUES ($1,$2,$3,$4,$5,$6,decode($7,'hex'),$8,$9,$10)`,
        [
          randomUUID(), snapshotId, center.center_id, objectKey, copyStatus,
          packageBytes, toHex(encrypted.snapshot.ciphertextHash), lastError,
          copyStatus === "COPIED" ? context.now().toISOString() : null,
          copyStatus === "COPIED" ? context.now().toISOString() : null,
        ],
      );
      await retentionForCenter(client, context, session, center.center_id);
    }
    const operationStatus = replicaStatuses.every((status) => status === "COPIED") ? "COMPLETED" : "PARTIAL";
    operationId = randomUUID();
    await client.query(
      `INSERT INTO snapshot_replication_operation (
         operation_id, registry_id, snapshot_id, idempotency_key,
         operation_status, created_by
       ) VALUES ($1,$2,$3,$4,$5,$6)`,
      [operationId, context.registryId, snapshotId, idempotencyKey, operationStatus, session.username],
    );
    await appendEvent(client, context, session, null, "SNAPSHOT_CREATED", {
      operationId,
      snapshotId,
      snapshotVersion: snapshotVersion.toString(),
      packageFormat: SNAPSHOT_FORMAT,
      snapshotStatus: anchor.finalized ? "FINALIZED" : "NON_FINALIZED",
      merkleRoot: anchor.merkleRoot,
      plaintextHash: toHex(encrypted.snapshot.plaintextHash),
      ciphertextHash: toHex(encrypted.snapshot.ciphertextHash),
      centers: centers.rows.map((center, index) => ({ centerId: center.center_id, status: replicaStatuses[index] })),
    });
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
  if (operationId === null) throw new ApiError(500, "BACKUP_OPERATION_MISSING");
  return backupOperationResponse(context, operationId, 201);
}

async function retryBackup(
  context: AdminContext,
  session: AdminSession,
  snapshotId: string,
): Promise<AdminResponse> {
  await ensureFixture(context.pool);
  const snapshot = await context.pool.query(
    `SELECT snapshot_id::text, snapshot_version::text, encrypted_package,
            encode(ciphertext_hash,'hex') AS ciphertext_hash
       FROM snapshot WHERE snapshot_id = $1 AND registry_id = $2`,
    [snapshotId, context.registryId],
  );
  if (snapshot.rows.length === 0) throw new ApiError(404, "SNAPSHOT_NOT_FOUND");
  const packageBytes = Buffer.from(snapshot.rows[0].encrypted_package);
  try {
    // Validates the envelope hash and chunk layout before any center accepts
    // the retry. No plaintext is released by this check.
    decodeSnapshotPackage(packageBytes);
  } catch {
    throw new ApiError(422, "CIPHERTEXT_HASH_MISMATCH");
  }
  const client = await context.pool.connect();
  try {
    await client.query("BEGIN");
    const replicas = await client.query(
      `SELECT r.replica_id::text, r.center_id, c.health_status, r.copy_status
         FROM snapshot_replica r JOIN backup_center c ON c.center_id = r.center_id
        WHERE r.snapshot_id = $1 AND c.registry_id = $2
        FOR UPDATE OF r`,
      [snapshotId, context.registryId],
    );
    for (const replica of replicas.rows) {
      if (replica.copy_status === "COPIED") continue;
      if (replica.health_status !== "HEALTHY") {
        await client.query(
          `UPDATE snapshot_replica SET copy_status = 'PENDING_RETRY', last_error = $2
            WHERE replica_id = $1`,
          [replica.replica_id, replica.health_status === "UNAVAILABLE" ? "CENTER_UNAVAILABLE" : "CENTER_HEALTH_ERROR"],
        );
        continue;
      }
      await client.query(
        `UPDATE snapshot_replica
            SET copy_status = 'COPIED', package_bytes = $2, ciphertext_hash = decode($3,'hex'),
                last_error = NULL, copied_at = COALESCE(copied_at, now()), verified_at = now()
          WHERE replica_id = $1`,
        [replica.replica_id, packageBytes, snapshot.rows[0].ciphertext_hash],
      );
      await appendEvent(client, context, session, null, "SNAPSHOT_REPLICA_RETRIED", {
        snapshotId,
        centerId: replica.center_id,
        status: "COPIED",
      });
      await retentionForCenter(client, context, session, replica.center_id);
    }
    await client.query(
      `UPDATE snapshot_replication_operation
          SET operation_status = CASE WHEN NOT EXISTS (
            SELECT 1 FROM snapshot_replica r JOIN backup_center c ON c.center_id = r.center_id
             WHERE r.snapshot_id = $1 AND c.registry_id = $2 AND r.copy_status <> 'COPIED'
          ) THEN 'COMPLETED' ELSE 'PARTIAL' END
        WHERE snapshot_id = $1 AND registry_id = $2`,
      [snapshotId, context.registryId],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
  const operation = await context.pool.query(
    `SELECT operation_id::text FROM snapshot_replication_operation
      WHERE snapshot_id = $1 AND registry_id = $2 ORDER BY created_at DESC LIMIT 1`,
    [snapshotId, context.registryId],
  );
  if (operation.rows.length === 0) throw new ApiError(500, "BACKUP_OPERATION_MISSING");
  return backupOperationResponse(context, operation.rows[0].operation_id);
}

const DEFAULT_RECOVERY_TARGET = "local-demo-target";
const RECOVERY_UUID = /^[0-9a-f-]{36}$/;
const recoveryKeyFallback = new Map<string, Uint8Array>();
const defaultApprovalPrivateKey = generateKeyPairSync("ed25519").privateKey;

interface RecoveryAnchor {
  batchSequence: string;
  anchorSlot: string;
  transactionSignature: string | null;
  merkleRoot: string;
  finalizedAt: string;
}

interface RecoveryMaterial {
  snapshotId: string;
  snapshotVersion: string;
  snapshotStatus: string;
  centerId: string;
  objectKey: string;
  packageBytes: Uint8Array;
  storedPlaintextHash: string;
  storedCiphertextHash: string;
  storedReplicaCiphertextHash: string;
  storedMerkleRoot: string;
}

interface SnapshotStateSummary {
  records: number;
  recordVersions: number;
  certificatePackages: number;
  qrMetadata: number;
  proofs: number;
  roots: number;
  manifests: number;
  anchorReferences: number;
  operationHistory: number;
}

function recoveryKeys(context: AdminContext): Map<string, Uint8Array> {
  if (context.recoveryKeys !== undefined) return context.recoveryKeys;
  return recoveryKeyFallback;
}

function approvalPrivateKey(context: AdminContext): KeyObject {
  if (context.restoreApprovalPrivateKey !== undefined) return context.restoreApprovalPrivateKey;
  return defaultApprovalPrivateKey;
}

function equalHash(left: string, right: string): boolean {
  return left.length === right.length && left === right;
}

function recoveryTarget(value: unknown): string {
  return text(value === undefined ? DEFAULT_RECOVERY_TARGET : value, "target", /^local-demo-[A-Za-z0-9._-]{1,80}$/);
}

function recoveryId(value: unknown, name: string): string {
  return text(value, name, RECOVERY_UUID);
}

function recoveryShares(value: unknown): KeyShare[] {
  if (!Array.isArray(value) || value.length < 3) throw new ApiError(422, "RECOVERY_SHARES_INSUFFICIENT");
  if (value.length !== 3) throw new ApiError(422, "RECOVERY_SHARE_COUNT");
  const parsed: KeyShare[] = [];
  try {
    for (const entry of value) parsed.push(parseRecoveryShare(entry));
  } catch {
    parsed.forEach((share) => share.bytes.fill(0));
    throw new ApiError(422, "RECOVERY_SHARES_INVALID");
  }
  if (new Set(parsed.map((share) => share.index)).size !== parsed.length) {
    parsed.forEach((share) => share.bytes.fill(0));
    throw new ApiError(422, "RECOVERY_SHARES_INVALID");
  }
  return parsed;
}

async function selectRecoveryAnchor(
  executor: Pool | PoolClient,
  registryId: string,
): Promise<RecoveryAnchor> {
  const result = await executor.query(
    `SELECT a.batch_sequence::text, a.anchor_slot::text, a.transaction_signature,
            encode(a.merkle_root,'hex') AS merkle_root, a.finalized_at
       FROM demo_anchor a
      WHERE a.registry_id = $1
        AND a.commitment = 'finalized'
        AND NOT EXISTS (
          SELECT 1 FROM integrity_incident i
           WHERE i.registry_id = a.registry_id AND i.status = 'OPEN'
             AND (i.first_suspect_batch IS NULL
               OR (i.first_suspect_batch <= a.batch_sequence AND i.last_suspect_batch >= a.batch_sequence))
        )
        AND NOT EXISTS (
          SELECT 1 FROM incident_index_notice n
           WHERE n.registry_id = a.registry_id AND n.status = 'OPEN'
             AND n.first_suspect_batch <= a.batch_sequence AND n.last_suspect_batch >= a.batch_sequence
        )
      ORDER BY a.batch_sequence DESC
      LIMIT 1`,
    [registryId],
  );
  if (result.rows.length === 0) throw new ApiError(409, "RECOVERY_ANCHOR_UNAVAILABLE");
  const row = result.rows[0];
  return {
    batchSequence: row.batch_sequence,
    anchorSlot: row.anchor_slot,
    transactionSignature: row.transaction_signature,
    merkleRoot: row.merkle_root,
    finalizedAt: iso(row.finalized_at),
  };
}

async function loadRecoveryMaterial(
  context: AdminContext,
  centerId: string,
  snapshotId: string,
): Promise<RecoveryMaterial> {
  const result = await context.pool.query(
    `SELECT s.snapshot_id::text, s.snapshot_version::text, s.snapshot_status,
            s.encrypted_package, encode(s.plaintext_hash,'hex') AS plaintext_hash,
            encode(s.ciphertext_hash,'hex') AS snapshot_ciphertext_hash,
            encode(s.merkle_root,'hex') AS merkle_root,
            r.center_id, r.object_key, r.copy_status,
            encode(r.ciphertext_hash,'hex') AS replica_ciphertext_hash
       FROM snapshot s
       JOIN snapshot_replica r ON r.snapshot_id = s.snapshot_id
      WHERE s.registry_id = $1 AND s.snapshot_id = $2 AND r.center_id = $3`,
    [context.registryId, snapshotId, centerId],
  );
  if (result.rows.length === 0) throw new ApiError(404, "RECOVERY_FOLDER_NOT_FOUND");
  const row = result.rows[0];
  if (row.copy_status !== "COPIED") throw new ApiError(409, "RECOVERY_FOLDER_NOT_COPIED");
  return {
    snapshotId: row.snapshot_id,
    snapshotVersion: row.snapshot_version,
    snapshotStatus: row.snapshot_status,
    centerId: row.center_id,
    objectKey: row.object_key,
    packageBytes: Uint8Array.from(Buffer.from(row.encrypted_package)),
    storedPlaintextHash: row.plaintext_hash,
    storedCiphertextHash: row.snapshot_ciphertext_hash,
    storedReplicaCiphertextHash: row.replica_ciphertext_hash,
    storedMerkleRoot: row.merkle_root,
  };
}

function decodeRecoveryPackage(
  context: AdminContext,
  material: RecoveryMaterial,
): ReturnType<typeof decodeSnapshotPackage> {
  let snapshot: ReturnType<typeof decodeSnapshotPackage>;
  try {
    snapshot = decodeSnapshotPackage(material.packageBytes);
  } catch {
    throw new ApiError(422, "CIPHERTEXT_HASH_MISMATCH");
  }
  if (
    snapshot.registryId !== context.registryId ||
    toHex(snapshot.snapshotId) !== toHex(uuidBytes(material.snapshotId)) ||
    snapshot.snapshotVersion !== BigInt(material.snapshotVersion)
  ) {
    throw new ApiError(422, "SNAPSHOT_BINDING_MISMATCH");
  }
  const packageCiphertextHash = toHex(snapshot.ciphertextHash);
  if (
    !equalHash(packageCiphertextHash, material.storedCiphertextHash) ||
    !equalHash(packageCiphertextHash, material.storedReplicaCiphertextHash)
  ) {
    throw new ApiError(422, "CIPHERTEXT_HASH_MISMATCH");
  }
  if (!equalHash(toHex(snapshot.plaintextHash), material.storedPlaintextHash)) {
    throw new ApiError(422, "PLAINTEXT_HASH_MISMATCH");
  }
  return snapshot;
}

function snapshotStateSummary(plaintext: Uint8Array, registryId: string): SnapshotStateSummary {
  let value: ReturnType<typeof decodeCanonical>;
  try {
    value = decodeCanonical(plaintext);
  } catch {
    throw new ApiError(422, "SNAPSHOT_STATE_INVALID");
  }
  if (value.type !== "map") throw new ApiError(422, "SNAPSHOT_STATE_INVALID");
  const format = value.entries.format;
  const version = value.entries.version;
  const stateRegistry = value.entries.registryId;
  if (
    format?.type !== "text" || format.value !== "ONELAYER_SNAPSHOT_STATE_V1" ||
    version?.type !== "int" || version.value !== "1" ||
    stateRegistry?.type !== "text" || stateRegistry.value !== registryId
  ) {
    throw new ApiError(422, "SNAPSHOT_STATE_INVALID");
  }
  const required = [
    "records",
    "recordVersions",
    "certificatePackages",
    "qrMetadata",
    "proofs",
    "roots",
    "manifests",
    "anchorReferences",
    "operationHistory",
  ] as const;
  const summary = {} as SnapshotStateSummary;
  for (const field of required) {
    const entry = value.entries[field];
    if (entry?.type !== "array") throw new ApiError(422, "SNAPSHOT_STATE_INVALID");
    summary[field] = entry.items.length;
  }
  return summary;
}

async function recoveryOperationResponse(
  context: AdminContext,
  operationId: string,
  status = 200,
  extra: Record<string, unknown> = {},
): Promise<AdminResponse> {
  const result = await context.pool.query(
    `SELECT o.recovery_operation_id::text, o.registry_id, o.center_id,
            o.snapshot_id::text, s.snapshot_version::text, s.snapshot_status,
            o.target, o.state, o.anchor_batch_sequence::text, o.anchor_slot::text,
            encode(o.merkle_root,'hex') AS merkle_root,
            encode(o.plaintext_hash,'hex') AS plaintext_hash,
            encode(o.ciphertext_hash,'hex') AS ciphertext_hash,
            o.share_threshold, o.failure_code, o.created_by, o.approved_by,
            o.approval_id::text, o.created_at, o.approved_at, o.completed_at,
            a.transaction_signature, a.finalized_at,
            p.approval_digest, p.approval_signature, p.signed_at,
            t.target_id, t.state_summary, t.restored_at
       FROM recovery_operation o
       JOIN snapshot s ON s.snapshot_id = o.snapshot_id
       LEFT JOIN demo_anchor a
         ON a.registry_id = o.registry_id AND a.batch_sequence = o.anchor_batch_sequence
       LEFT JOIN restore_approval p ON p.approval_id = o.approval_id
       LEFT JOIN recovery_restore_target t ON t.recovery_operation_id = o.recovery_operation_id
      WHERE o.recovery_operation_id = $1 AND o.registry_id = $2`,
    [operationId, context.registryId],
  );
  if (result.rows.length === 0) throw new ApiError(404, "RECOVERY_OPERATION_NOT_FOUND");
  const row = result.rows[0];
  const body: Record<string, unknown> = {
    recoveryOperationId: row.recovery_operation_id,
    operationId: row.recovery_operation_id,
    registryId: row.registry_id,
    centerId: row.center_id,
    snapshotId: row.snapshot_id,
    snapshotVersion: row.snapshot_version,
    snapshotStatus: row.snapshot_status,
    target: row.target,
    state: row.state,
    status: row.state,
    anchor: {
      batchSequence: row.anchor_batch_sequence,
      anchorSlot: row.anchor_slot,
      transactionSignature: row.transaction_signature,
      merkleRoot: row.merkle_root,
      finalizedAt: iso(row.finalized_at),
    },
    selectedAnchor: {
      batchSequence: row.anchor_batch_sequence,
      anchorSlot: row.anchor_slot,
      transactionSignature: row.transaction_signature,
      merkleRoot: row.merkle_root,
      finalizedAt: iso(row.finalized_at),
    },
    merkleRoot: row.merkle_root,
    plaintextHash: row.plaintext_hash,
    ciphertextHash: row.ciphertext_hash,
    shareThreshold: row.share_threshold,
    validation: row.state === "FAILED" ? null : {
      threshold: `${row.share_threshold}-of-5`,
      ciphertextHash: "MATCH",
      plaintextHash: "MATCH",
      merkleRoot: "MATCH",
    },
    failureCode: row.failure_code,
    createdBy: row.created_by,
    approvedBy: row.approved_by,
    createdAt: iso(row.created_at),
    approvedAt: row.approved_at === null ? null : iso(row.approved_at),
    completedAt: row.completed_at === null ? null : iso(row.completed_at),
    approval: row.approval_id === null ? null : {
      approvalId: row.approval_id,
      snapshotId: row.snapshot_id,
      merkleRoot: row.merkle_root,
      target: row.target,
      approvalDigest: Buffer.from(row.approval_digest).toString("hex"),
      approvalSignature: Buffer.from(row.approval_signature).toString("base64url"),
      signedBy: row.approved_by,
      signedAt: row.signed_at === null ? null : iso(row.signed_at),
    },
    restoredTarget: row.target_id === null ? null : {
      targetId: row.target_id,
      stateSummary: jsonValue(row.state_summary),
      restoredAt: iso(row.restored_at),
      plaintextCleared: true,
    },
    ...extra,
  };
  return { status, body };
}

async function recoveryOperationList(context: AdminContext): Promise<AdminResponse> {
  const result = await context.pool.query(
    `SELECT recovery_operation_id::text FROM recovery_operation
      WHERE registry_id = $1 ORDER BY created_at DESC LIMIT 20`,
    [context.registryId],
  );
  const operations = [];
  for (const row of result.rows) {
    const response = await recoveryOperationResponse(context, row.recovery_operation_id);
    operations.push(response.body);
  }
  return { status: 200, body: { operations } };
}

async function failRecoveryOperation(
  context: AdminContext,
  session: AdminSession | null,
  operationId: string,
  code: string,
): Promise<void> {
  const key = recoveryKeys(context).get(operationId);
  if (key !== undefined) {
    key.fill(0);
    recoveryKeys(context).delete(operationId);
  }
  await context.pool.query(
    `UPDATE recovery_operation
        SET state = 'FAILED', failure_code = $2, completed_at = now()
      WHERE recovery_operation_id = $1 AND state NOT IN ('RESTORED', 'FAILED')`,
    [operationId, code],
  );
  await appendEvent(context.pool, context, session, null, "RECOVERY_FAILED", {
    recoveryOperationId: operationId,
    code,
  });
}

function approvalDigest(context: AdminContext, operation: {
  recoveryOperationId: string;
  snapshotId: string;
  merkleRoot: string;
  target: string;
}): Uint8Array {
  return createHash("sha256").update([
    "ONELAYER_RESTORE_APPROVAL_V1",
    context.registryId,
    operation.recoveryOperationId,
    operation.snapshotId,
    operation.merkleRoot,
    operation.target,
  ].join("\0")).digest();
}

async function prepareRecovery(
  context: AdminContext,
  session: AdminSession,
  request: AdminRequest,
): Promise<AdminResponse> {
  await ensureFixture(context.pool);
  const body = request.body ?? {};
  const centerId = text(body.centerId ?? body.backupCenterId, "centerId", /^BACKUPCENTER-[A-Za-z0-9-]+$/);
  const snapshotId = recoveryId(body.snapshotId, "snapshotId");
  const target = recoveryTarget(body.target);
  let supplied: KeyShare[] = [];
  let recoveredKek: Uint8Array | null = null;
  let retained = false;
  try {
    supplied = recoveryShares(body.recoveryShares ?? body.shares);
    try {
      recoveredKek = recoverRecoveryKek(supplied);
    } catch {
      throw new ApiError(422, "RECOVERY_SHARES_INVALID");
    }
    const [material, anchor] = await Promise.all([
      loadRecoveryMaterial(context, centerId, snapshotId),
      selectRecoveryAnchor(context.pool, context.registryId),
    ]);
    if (material.snapshotStatus !== "FINALIZED") throw new ApiError(409, "SNAPSHOT_NOT_FINALIZED");
    if (!equalHash(material.storedMerkleRoot, anchor.merkleRoot)) {
      throw new ApiError(422, "MERKLE_ROOT_MISMATCH");
    }
    const snapshot = decodeRecoveryPackage(context, material);
    let plaintext: Uint8Array | null = null;
    try {
      try {
        plaintext = restoreSnapshot(snapshot, recoveredKek);
      } catch (error) {
        if (error instanceof TypeError && error.message.includes("plaintext hash mismatch")) {
          throw new ApiError(422, "PLAINTEXT_HASH_MISMATCH");
        }
        throw new ApiError(422, "DECRYPTION_FAILED");
      }
      snapshotStateSummary(plaintext, context.registryId);
    } finally {
      plaintext?.fill(0);
    }

    const operationId = randomUUID();
    const client = await context.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `INSERT INTO recovery_operation (
           recovery_operation_id, registry_id, center_id, snapshot_id, target,
           state, anchor_batch_sequence, anchor_slot, merkle_root,
           plaintext_hash, ciphertext_hash, share_threshold, created_by
         ) VALUES ($1,$2,$3,$4,$5,'AWAITING_APPROVAL',$6,$7,decode($8,'hex'),decode($9,'hex'),decode($10,'hex'),3,$11)`,
        [
          operationId,
          context.registryId,
          centerId,
          snapshotId,
          target,
          anchor.batchSequence,
          anchor.anchorSlot,
          anchor.merkleRoot,
          material.storedPlaintextHash,
          material.storedCiphertextHash,
          session.username,
        ],
      );
      await appendEvent(client, context, session, null, "RECOVERY_CHECKS_PASSED", {
        recoveryOperationId: operationId,
        centerId,
        snapshotId,
        target,
        anchorBatchSequence: anchor.batchSequence,
        anchorSlot: anchor.anchorSlot,
        merkleRoot: anchor.merkleRoot,
        plaintextHash: material.storedPlaintextHash,
        ciphertextHash: material.storedCiphertextHash,
        shareThreshold: "3-of-5",
      });
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    recoveryKeys(context).set(operationId, recoveredKek);
    retained = true;
    return recoveryOperationResponse(context, operationId, 201);
  } finally {
    supplied.forEach((share) => share.bytes.fill(0));
    if (request.body !== null) {
      request.body.recoveryShares = [];
      request.body.shares = [];
    }
    if (!retained) recoveredKek?.fill(0);
  }
}

async function approveRecovery(
  context: AdminContext,
  session: AdminSession,
  operationId: string,
  body: Record<string, unknown> | null,
): Promise<AdminResponse> {
  const current = await context.pool.query(
    `SELECT recovery_operation_id::text, snapshot_id::text,
            encode(merkle_root,'hex') AS merkle_root, target, state
       FROM recovery_operation WHERE recovery_operation_id = $1 AND registry_id = $2`,
    [operationId, context.registryId],
  );
  if (current.rows.length === 0) throw new ApiError(404, "RECOVERY_OPERATION_NOT_FOUND");
  const operation = current.rows[0];
  if (operation.state === "APPROVED" || operation.state === "RESTORED") {
    return recoveryOperationResponse(context, operationId, 200, { replayed: true });
  }
  if (operation.state !== "AWAITING_APPROVAL") throw new ApiError(409, "RESTORE_APPROVAL_INVALID_STATE");
  if (!recoveryKeys(context).has(operationId)) {
    await failRecoveryOperation(context, session, operationId, "RECOVERY_KEY_UNAVAILABLE");
    throw new ApiError(409, "RECOVERY_KEY_UNAVAILABLE");
  }
  const requestedSnapshotId = body?.snapshotId === undefined ? operation.snapshot_id : recoveryId(body.snapshotId, "snapshotId");
  const requestedRoot = body?.merkleRoot === undefined ? operation.merkle_root : text(body.merkleRoot, "merkleRoot", /^[0-9a-f]{64}$/);
  const requestedTarget = body?.target === undefined ? operation.target : recoveryTarget(body.target);
  if (
    requestedSnapshotId !== operation.snapshot_id ||
    requestedRoot !== operation.merkle_root ||
    requestedTarget !== operation.target
  ) {
    await failRecoveryOperation(context, session, operationId, "RESTORE_BINDING_MISMATCH");
    throw new ApiError(409, "RESTORE_BINDING_MISMATCH");
  }

  const digest = approvalDigest(context, {
    recoveryOperationId: operation.recovery_operation_id,
    snapshotId: operation.snapshot_id,
    merkleRoot: operation.merkle_root,
    target: operation.target,
  });
  const signature = sign(null, digest, approvalPrivateKey(context));
  const approvalId = randomUUID();
  const client = await context.pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO restore_approval (
         approval_id, recovery_operation_id, registry_id, snapshot_id,
         merkle_root, target, approval_digest, approval_signature, signed_by
       ) VALUES ($1,$2,$3,$4,decode($5,'hex'),$6,decode($7,'hex'),$8,$9)`,
      [
        approvalId,
        operation.recovery_operation_id,
        context.registryId,
        operation.snapshot_id,
        operation.merkle_root,
        operation.target,
        Buffer.from(digest).toString("hex"),
        signature,
        session.username,
      ],
    );
    await client.query(
      `UPDATE recovery_operation
          SET state = 'APPROVED', approved_by = $2, approval_id = $3, approved_at = now()
        WHERE recovery_operation_id = $1 AND state = 'AWAITING_APPROVAL'`,
      [operation.recovery_operation_id, session.username, approvalId],
    );
    await appendEvent(client, context, session, null, "RESTORE_APPROVED", {
      recoveryOperationId: operation.recovery_operation_id,
      approvalId,
      snapshotId: operation.snapshot_id,
      merkleRoot: operation.merkle_root,
      target: operation.target,
      approvalDigest: Buffer.from(digest).toString("hex"),
    });
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
  return recoveryOperationResponse(context, operationId, 201);
}

async function restoreRecovery(
  context: AdminContext,
  session: AdminSession,
  operationId: string,
): Promise<AdminResponse> {
  const current = await context.pool.query(
    `SELECT recovery_operation_id::text, snapshot_id::text, center_id, target,
            state, anchor_batch_sequence::text, anchor_slot::text,
            encode(merkle_root,'hex') AS merkle_root,
            encode(plaintext_hash,'hex') AS plaintext_hash,
            encode(ciphertext_hash,'hex') AS ciphertext_hash,
            approval_id::text
       FROM recovery_operation WHERE recovery_operation_id = $1 AND registry_id = $2`,
    [operationId, context.registryId],
  );
  if (current.rows.length === 0) throw new ApiError(404, "RECOVERY_OPERATION_NOT_FOUND");
  const operation = current.rows[0];
  if (operation.state === "RESTORED") return recoveryOperationResponse(context, operationId, 200, { replayed: true });
  if (operation.state !== "APPROVED" || operation.approval_id === null) {
    throw new ApiError(409, "RESTORE_APPROVAL_REQUIRED");
  }
  const keyStore = recoveryKeys(context);
  const recoveredKek = keyStore.get(operationId);
  if (recoveredKek === undefined) {
    await failRecoveryOperation(context, session, operationId, "RECOVERY_KEY_UNAVAILABLE");
    throw new ApiError(409, "RECOVERY_KEY_UNAVAILABLE");
  }
  keyStore.delete(operationId);
  let plaintext: Uint8Array | null = null;
  try {
    const approvalResult = await context.pool.query(
      `SELECT snapshot_id::text, encode(merkle_root,'hex') AS merkle_root, target,
              approval_digest, approval_signature
         FROM restore_approval
        WHERE approval_id = $1 AND recovery_operation_id = $2 AND registry_id = $3`,
      [operation.approval_id, operation.recovery_operation_id, context.registryId],
    );
    if (approvalResult.rows.length !== 1) throw new ApiError(409, "RESTORE_APPROVAL_INVALID");
    const approval = approvalResult.rows[0];
    const expectedDigest = approvalDigest(context, {
      recoveryOperationId: operation.recovery_operation_id,
      snapshotId: operation.snapshot_id,
      merkleRoot: operation.merkle_root,
      target: operation.target,
    });
    let signatureValid = false;
    try {
      signatureValid = verify(
        null,
        expectedDigest,
        createPublicKey(approvalPrivateKey(context)),
        Buffer.from(approval.approval_signature),
      );
    } catch {
      signatureValid = false;
    }
    if (
      approval.snapshot_id !== operation.snapshot_id ||
      approval.merkle_root !== operation.merkle_root ||
      approval.target !== operation.target ||
      !equalHash(Buffer.from(approval.approval_digest).toString("hex"), toHex(expectedDigest)) ||
      !signatureValid
    ) {
      throw new ApiError(409, "RESTORE_APPROVAL_INVALID");
    }
    const anchor = await selectRecoveryAnchor(context.pool, context.registryId);
    if (anchor.batchSequence !== operation.anchor_batch_sequence || !equalHash(anchor.merkleRoot, operation.merkle_root)) {
      throw new ApiError(409, "RECOVERY_ANCHOR_CHANGED");
    }
    const material = await loadRecoveryMaterial(context, operation.center_id, operation.snapshot_id);
    if (material.snapshotStatus !== "FINALIZED") throw new ApiError(409, "SNAPSHOT_NOT_FINALIZED");
    if (!equalHash(material.storedMerkleRoot, operation.merkle_root)) {
      throw new ApiError(422, "MERKLE_ROOT_MISMATCH");
    }
    if (!equalHash(material.storedPlaintextHash, operation.plaintext_hash) || !equalHash(material.storedCiphertextHash, operation.ciphertext_hash)) {
      throw new ApiError(422, "SNAPSHOT_HASH_METADATA_MISMATCH");
    }
    const snapshot = decodeRecoveryPackage(context, material);
    try {
      plaintext = restoreSnapshot(snapshot, recoveredKek);
    } catch (error) {
      if (error instanceof TypeError && error.message.includes("plaintext hash mismatch")) {
        throw new ApiError(422, "PLAINTEXT_HASH_MISMATCH");
      }
      throw new ApiError(422, "DECRYPTION_FAILED");
    }
    const stateSummary = snapshotStateSummary(plaintext, context.registryId);
    const client = await context.pool.connect();
    try {
      await client.query("BEGIN");
      // The bounded local target consumes the complete validated state inside
      // this transaction, then retains only an auditable digest/summary. The
      // plaintext itself is never a target column and is zeroed in finally.
      await client.query(
        `INSERT INTO recovery_restore_target (
           registry_id, target_id, recovery_operation_id, snapshot_id,
           merkle_root, plaintext_hash, state_summary
         ) VALUES ($1,$2,$3,$4,decode($5,'hex'),decode($6,'hex'),$7)
         ON CONFLICT (registry_id, target_id) DO UPDATE SET
           recovery_operation_id = EXCLUDED.recovery_operation_id,
           snapshot_id = EXCLUDED.snapshot_id,
           merkle_root = EXCLUDED.merkle_root,
           plaintext_hash = EXCLUDED.plaintext_hash,
           state_summary = EXCLUDED.state_summary,
           restored_at = now()`,
        [
          context.registryId,
          operation.target,
          operation.recovery_operation_id,
          operation.snapshot_id,
          operation.merkle_root,
          operation.plaintext_hash,
          JSON.stringify(stateSummary),
        ],
      );
      await client.query(
        `UPDATE recovery_operation
            SET state = 'RESTORED', completed_at = now()
          WHERE recovery_operation_id = $1 AND state = 'APPROVED'`,
        [operation.recovery_operation_id],
      );
      await appendEvent(client, context, session, null, "RESTORE_COMPLETED", {
        recoveryOperationId: operation.recovery_operation_id,
        snapshotId: operation.snapshot_id,
        merkleRoot: operation.merkle_root,
        target: operation.target,
        stateSummary,
        plaintextCleared: true,
      });
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    return recoveryOperationResponse(context, operationId, 201);
  } catch (error) {
    const code = error instanceof ApiError ? error.code : "RESTORE_FAILED";
    await failRecoveryOperation(context, session, operationId, code);
    if (error instanceof ApiError) throw error;
    throw new ApiError(422, code);
  } finally {
    plaintext?.fill(0);
    recoveredKek.fill(0);
  }
}

async function createBackupCenter(
  context: AdminContext,
  session: AdminSession,
  body: Record<string, unknown> | null,
): Promise<AdminResponse> {
  await ensureFixture(context.pool);
  if (body?.scope !== undefined && body.scope !== "LOCAL") throw new ApiError(400, "EXTERNAL_BACKUP_CENTER_UNSUPPORTED");
  if (body?.endpoint !== undefined && (typeof body.endpoint !== "string" || !body.endpoint.startsWith("local://"))) {
    throw new ApiError(400, "EXTERNAL_BACKUP_CENTER_UNSUPPORTED");
  }
  const requestedName = body?.name === undefined ? null : text(body.name, "name", /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,118}$/);
  await ensureBackupCenters(context.pool, context.registryId);
  const count = await context.pool.query(
    "SELECT count(*)::text AS total FROM backup_center WHERE registry_id = $1",
    [context.registryId],
  );
  const ordinal = Number(count.rows[0]?.total ?? 0) + 1;
  const name = requestedName ?? `Local BackupCenter ${String(ordinal).padStart(2, "0")}`;
  const centerId = `BACKUPCENTER-${ordinal}`;
  const suffix = randomUUID().replaceAll("-", "");
  await context.pool.query(
    `INSERT INTO backup_center (
       center_id, registry_id, name, local_endpoint, volume_name,
       credential_reference, credential_version, created_by
     ) VALUES ($1,$2,$3,$4,$5,$6,'credential-v1',$7)`,
    [
      centerId,
      context.registryId,
      name,
      `local://backup-center-${suffix}`,
      `onelayer-backup-volume-${suffix}`,
      `onelayer-backup-credential-${suffix}`,
      session.username,
    ],
  );
  await appendEvent(context.pool, context, session, null, "BACKUP_CENTER_CREATED", {
    centerId,
    name,
    scope: "LOCAL",
  });
  const centers = await loadBackupCenters(context.pool, context.registryId);
  const created = centers.find((center) => center.centerId === centerId);
  return { status: 201, body: created ?? { centerId, name, scope: "LOCAL" } };
}

async function setBackupCenterHealth(
  context: AdminContext,
  session: AdminSession,
  centerId: string,
  body: Record<string, unknown> | null,
): Promise<AdminResponse> {
  const requestedStatus = body?.status ?? body?.healthStatus;
  const healthStatus = typeof body?.available === "boolean"
    ? body.available ? "HEALTHY" : "UNAVAILABLE"
    : requestedStatus === "HEALTHY" || requestedStatus === "UNAVAILABLE" || requestedStatus === "ERROR"
      ? requestedStatus
      : null;
  if (healthStatus === null) throw new ApiError(400, "AVAILABILITY_INVALID");
  const result = await context.pool.query(
    `UPDATE backup_center SET health_status = $3, last_health_at = now()
      WHERE center_id = $1 AND registry_id = $2 RETURNING center_id`,
    [centerId, context.registryId, healthStatus],
  );
  if (result.rows.length === 0) throw new ApiError(404, "BACKUP_CENTER_NOT_FOUND");
  await appendEvent(context.pool, context, session, null, "BACKUP_CENTER_HEALTH_CHANGED", {
    centerId,
    healthStatus,
  });
  return backupOverview(context);
}

/** Live counters for the Admin dashboard; every number comes from a query. */
async function dashboard(context: AdminContext): Promise<AdminResponse> {
  const [records, certificates, anchor, incidents, intents] = await Promise.all([
    context.pool.query(
      `SELECT count(*)::text AS records,
              coalesce(sum(record_version), 0)::text AS versions,
              count(*) FILTER (WHERE origin = 'ADMIN_UI')::text AS imported
         FROM synthetic_registry_record`,
    ),
    context.pool.query(
      `SELECT status, disclosure_mode, count(*)::text AS total
         FROM demo_certificate WHERE registry_id = $1 GROUP BY status, disclosure_mode`,
      [context.registryId],
    ),
    context.pool.query(
      `SELECT batch_sequence::text, anchor_slot::text, transaction_signature, finalized_at,
              encode(merkle_root,'hex') AS merkle_root
         FROM demo_anchor WHERE registry_id = $1 ORDER BY batch_sequence DESC LIMIT 1`,
      [context.registryId],
    ),
    context.pool.query(
      `SELECT count(*)::text AS open_onchain FROM incident_index_notice
        WHERE registry_id = $1 AND status = 'OPEN'`,
      [context.registryId],
    ),
    context.pool.query(
      `SELECT state, count(*)::text AS total FROM demo_publish_intent
        WHERE registry_id = $1 GROUP BY state`,
      [context.registryId],
    ),
  ]);
  const byStatus: Record<string, number> = {};
  let selective = 0;
  for (const row of certificates.rows) {
    byStatus[row.status] = (byStatus[row.status] ?? 0) + Number(row.total);
    if (row.disclosure_mode === "SELECTIVE_FIELDS") selective += Number(row.total);
  }
  return {
    status: 200,
    body: {
      registryId: context.registryId,
      cluster: "solana:devnet",
      schemaId: SCHEMA_ID,
      records: {
        total: records.rows[0].records,
        versions: records.rows[0].versions,
        imported: records.rows[0].imported,
      },
      certificates: { byStatus, selective },
      lastAnchor: anchor.rows.length === 0 ? null : {
        batchSequence: anchor.rows[0].batch_sequence,
        anchorSlot: anchor.rows[0].anchor_slot,
        transactionSignature: anchor.rows[0].transaction_signature,
        merkleRoot: anchor.rows[0].merkle_root,
        finalizedAt: anchor.rows[0].finalized_at,
        explorerUrl: `https://explorer.solana.com/tx/${anchor.rows[0].transaction_signature}?cluster=devnet`,
      },
      openIncidents: incidents.rows[0].open_onchain,
      intents: Object.fromEntries(intents.rows.map((row) => [row.state, Number(row.total)])),
    },
  };
}

export async function routeAdmin(context: AdminContext, request: AdminRequest): Promise<AdminResponse> {
  try {
    return await dispatch(context, request);
  } catch (error) {
    if (error instanceof ApiError) return { status: error.status, body: { code: error.code } };
    if (error instanceof AuthorizationError) return { status: error.status, body: { code: error.code } };
    if (error instanceof TransitionError) return { status: 409, body: { code: error.code } };
    if (error instanceof RangeError || error instanceof TypeError) {
      return { status: 400, body: { code: "REQUEST_INVALID", message: error.message } };
    }
    throw error;
  }
}

async function dispatch(context: AdminContext, request: AdminRequest): Promise<AdminResponse> {
  if (request.path === "/v1/admin/session" && request.method === "POST") {
    const session = context.sessions.login(request.body?.username, request.body?.password);
    if (session === null) return { status: 401, body: { code: "INVALID_CREDENTIALS" } };
    return {
      status: 201,
      setCookie: sessionCookie(session),
      body: { role: session.role, username: session.username, csrfToken: session.csrfToken, expiresAt: new Date(session.expiresAt).toISOString() },
    };
  }

  if (request.path === "/v1/admin/session" && request.method === "DELETE") {
    const session = authorize(context.sessions, request);
    context.sessions.destroy(session.sessionId);
    return { status: 204, body: null, setCookie: clearedCookie() };
  }

  const session = authorize(context.sessions, request);

  if (request.path === "/v1/admin/session" && request.method === "GET") {
    return {
      status: 200,
      body: { role: session.role, username: session.username, csrfToken: session.csrfToken },
    };
  }

  if (request.path === "/v1/admin/schema" && request.method === "GET") {
    return { status: 200, body: describeSchema() };
  }

  if (request.path === "/v1/admin/dashboard" && request.method === "GET") {
    return dashboard(context);
  }

  if (request.path === "/v1/admin/backup-centers" && request.method === "GET") {
    return backupOverview(context);
  }

  if (
    (request.path === "/v1/admin/snapshots" || request.path === "/v1/admin/snapshots/refresh" ||
      request.path === "/v1/admin/backup-centers/refresh") &&
    request.method === "GET"
  ) {
    return backupOverview(context);
  }

  if (
    (request.path === "/v1/admin/snapshots" || request.path === "/v1/admin/snapshots/refresh" ||
      request.path === "/v1/admin/backup-centers/refresh") &&
    request.method === "POST"
  ) {
    return refreshBackups(context, requireOperator(session), request);
  }

  if (request.path === "/v1/admin/backup-centers" && request.method === "POST") {
    return createBackupCenter(context, requireOperator(session), request.body);
  }

  const backupCenterHealth = /^\/v1\/admin\/backup-centers\/([A-Za-z0-9-]+)\/(?:health|availability)$/.exec(request.path);
  if (backupCenterHealth !== null && request.method === "POST") {
    return setBackupCenterHealth(context, requireOperator(session), backupCenterHealth[1], request.body);
  }

  if (
    (request.path === "/v1/admin/recovery/operations" || request.path === "/v1/admin/recovery") &&
    request.method === "GET"
  ) {
    return recoveryOperationList(context);
  }
  if (
    (request.path === "/v1/admin/recovery/prepare" || request.path === "/v1/admin/recovery/operations") &&
    request.method === "POST"
  ) {
    return prepareRecovery(context, requireOperator(session), request);
  }
  const recoveryPath = /^\/v1\/admin\/recovery\/(?:operations\/)?([0-9a-f-]{36})(?:\/(approve|approval|restore))?$/.exec(request.path);
  if (recoveryPath !== null) {
    const [, operationId, action] = recoveryPath;
    if (request.method === "GET" && action === undefined) return recoveryOperationResponse(context, operationId);
    if (request.method === "POST" && (action === "approve" || action === "approval")) {
      return approveRecovery(context, requireChiefAdmin(session), operationId, request.body);
    }
    if (request.method === "POST" && action === "restore") {
      return restoreRecovery(context, requireOperator(session), operationId);
    }
  }

  const snapshotPath = /^\/v1\/admin\/snapshots\/([0-9a-f-]{36})(?:\/(retry))?$/.exec(request.path);
  if (snapshotPath !== null) {
    if (request.method === "GET") {
      const overview = await backupOverview(context);
      const snapshot = (overview.body as any).snapshots.find((entry: any) => entry.snapshotId === snapshotPath[1]);
      if (snapshot === undefined) throw new ApiError(404, "SNAPSHOT_NOT_FOUND");
      return { status: 200, body: snapshot };
    }
    if (request.method === "POST" && snapshotPath[2] === "retry") {
      return retryBackup(context, requireOperator(session), snapshotPath[1]);
    }
  }

  if (
    request.method === "DELETE" &&
    (/^\/v1\/admin\/(?:snapshots|backup-centers)(?:\/|$)/.test(request.path))
  ) {
    throw new ApiError(403, "BACKUP_DELETE_FORBIDDEN");
  }

  if (request.path === "/v1/admin/records" && request.method === "GET") {
    const result = await context.pool.query(`${RECORD_QUERY} ORDER BY r.source_cursor`);
    return {
      status: 200,
      body: {
        schemaId: SCHEMA_ID,
        records: result.rows.map((row) => ({
          internalRecordId: row.internal_record_id,
          recordVersion: row.record_version,
          status: row.status,
          origin: row.origin,
          sourceCursor: row.source_cursor,
          schemaId: row.schema_id,
          fields: row.fields,
        })),
      },
    };
  }

  if (request.path === "/v1/admin/records" && request.method === "POST") {
    return createRecord(context, requireOperator(session), request.body);
  }

  if (request.path === "/v1/admin/records/import" && request.method === "POST") {
    return importRecords(context, requireOperator(session), request.body);
  }

  const recordPath = /^\/v1\/admin\/records\/(SYNTHETIC-[1-9][0-9]*)$/.exec(request.path);
  if (recordPath !== null && request.method === "GET") {
    return recordDetail(context, recordPath[1]);
  }

  if (request.path === "/v1/admin/preview" && request.method === "GET") {
    return preview(context);
  }

  if (request.path === "/v1/admin/publish-intents" && request.method === "POST") {
    return prepareIntent(context, requireOperator(session), request);
  }

  const intentPath = /^\/v1\/admin\/publish-intents\/([0-9a-f-]{36})(\/[a-z]+)?$/.exec(request.path);
  if (intentPath !== null) {
    const [, intentId, action] = intentPath;
    if (request.method === "GET" && action === undefined) {
      return intentResponse(await loadIntent(context.pool, intentId));
    }
    requireOperator(session);
    if (request.method === "POST" && action === "/signature") {
      return submitSignature(context, session, intentId, request.body);
    }
    if (request.method === "POST" && action === "/reconciliation") {
      return reconcile(context, session, intentId);
    }
    if (request.method === "POST" && action === "/certificate") {
      return issueForIntent(context, session, intentId, request.body);
    }
    if (request.method === "POST" && action === "/rejection") {
      const intent = await loadIntent(context.pool, intentId);
      await setState(context.pool, intent, "SIGNING_REJECTED", { failureCode: "WALLET_REJECTED" });
      await appendEvent(context.pool, context, session, intentId, "SIGNING_REJECTED", {});
      return intentResponse(intent);
    }
  }

  if (request.path === "/v1/admin/certificates" && request.method === "GET") {
    const result = await context.pool.query(
      `SELECT certificate_id, batch_sequence::text, status, issued_at, qr_url,
              internal_record_id, record_version::text, encode(certificate_hash,'hex') AS certificate_hash,
              disclosure_mode, disclosed_paths
         FROM demo_certificate WHERE registry_id = $1 ORDER BY issued_at DESC`,
      [context.registryId],
    );
    return {
      status: 200,
      body: {
        certificates: result.rows.map((row) => ({
          certificateId: row.certificate_id,
          batchSequence: row.batch_sequence,
          status: row.status,
          issuedAt: row.issued_at,
          qrUrl: row.qr_url,
          internalRecordId: row.internal_record_id,
          recordVersion: row.record_version,
          certificateHash: row.certificate_hash,
          disclosureMode: row.disclosure_mode,
          disclosedPaths: row.disclosed_paths,
        })),
      },
    };
  }

  if (request.path === "/v1/admin/timeline" && request.method === "GET") {
    const result = await context.pool.query(
      `SELECT operation_sequence::text, intent_id, event_type, actor, actor_role, payload, created_at
         FROM demo_operation_event WHERE registry_id = $1
        ORDER BY operation_sequence DESC LIMIT 200`,
      [context.registryId],
    );
    return {
      status: 200,
      body: {
        events: result.rows.map((row) => ({
          sequence: row.operation_sequence,
          intentId: row.intent_id,
          eventType: row.event_type,
          actor: row.actor,
          actorRole: row.actor_role,
          payload: row.payload,
          createdAt: row.created_at,
        })),
      },
    };
  }

  return { status: 404, body: { code: "NOT_FOUND" } };
}
