// Versioned Admin API (OL-C-22, OL-C-25, OL-C-31, OL-C-33).
//
// A thin HTTP adapter over the pilot data: it owns sessions, the publish intent
// lifecycle and certificate issuance. Every route resolves the role from the
// server session; nothing here trusts client state.
import { randomBytes, randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { getAddressEncoder, type Address } from "@solana/kit";
import {
  anchorHash,
  batchLeafHash,
  buildFieldTree,
  recordCommitment,
  recordIdCommitment,
  registryIdHash,
  toHex,
} from "../../../packages/canonical-ts/src/index.ts";
import { findLedgerSegmentPda, findRolePda } from "../../../packages/onchain-client/src/index.ts";
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
