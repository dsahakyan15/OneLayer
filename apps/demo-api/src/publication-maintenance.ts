// ADR-0009 human decisions over the workflow publication queue (tickets 08/09).
//
// Both decisions are taken by two authenticated principals (server sessions of
// ticket 07, permission `publication.maintenance` for the registry). Identity
// comes only from the session, never from the request body. Decisions are
// append-only rows (migration 0017) plus a wf_audit entry in the same
// transaction; the publisher executes them in `WorkflowPublisher.step`.
//
// (B) Version exclusion: POST /v2/admin/workflow/exclusions proposes and is the
//     first approval; POST /v2/admin/workflow/exclusions/:id/approve by a second,
//     different principal makes it effective. Neither approver may be an author
//     of the version (creator, version approver, draft editors). The decision
//     binds the exact version (record, version, outbox event, payload hash) and
//     an existing, later, publishable correcting version (or tombstone).
// (A) Archival cancellation: POST /v2/admin/workflow/publication/archival-checks/
//     :checkId/approve binds the operation and the evidence hash of the newest
//     FOREIGN_PROVEN archival check; two different principals are required.
//     Running the archival investigation itself is a trusted worker call
//     (`WorkflowPublisher.reconcileWithArchive`), not an HTTP route.
import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { buildFieldTree } from '../../../packages/canonical-ts/src/index.ts';
import { requirePermission, type AdminSession } from './admin-session.ts';
import { workflowFields } from './publication-intent.ts';
import { normalizeResourcePolicy } from './resource-access.ts';
import { assertWorkflowAttemptBinding, assertPublishablePayload, WorkflowError, workflowHash, workflowTransaction } from './registry-workflow.ts';
import { lockRegistryPublication, PublicationError } from './workflow-publication.ts';

type Request = { method: string; path: string; body: Record<string, unknown> | null; idempotencyKey?: string };
type Response = { status: number; body: unknown };

const UUID = '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}';
const HEX64 = /^[0-9a-f]{64}$/;
const EXCLUSIONS = new RegExp(`^/v2/admin/workflow/exclusions(?:/(${UUID})(?:/(approve))?)?$`);
const OPERATION = new RegExp(`^/v2/admin/workflow/publication/operations/(${UUID})$`);
const CHECK_APPROVE = new RegExp(`^/v2/admin/workflow/publication/archival-checks/(${UUID})/approve$`);

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
function exactBody(body: Record<string, unknown> | null, keys: string[]): Record<string, unknown> {
  if (!body || Object.keys(body).sort().join('\0') !== [...keys].sort().join('\0')) throw new WorkflowError(400, 'REQUEST_INVALID');
  return body;
}
function positiveVersion(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > 2147483647) throw new WorkflowError(400, 'INVALID_VERSION');
  return Number(value);
}
function hash(value: unknown): string {
  if (typeof value !== 'string' || !HEX64.test(value)) throw new WorkflowError(400, 'REQUEST_INVALID');
  return value;
}
function reasonText(value: unknown): string {
  const text = typeof value === 'string' ? value.normalize('NFKC').replace(/[\p{Cc}\p{Cf}]/gu, ' ').replace(/\s+/gu, ' ').trim() : '';
  if (text.length < 10 || text.length > 2000) throw new WorkflowError(400, 'MAINTENANCE_REASON_REQUIRED');
  return text;
}
function recordId(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-zA-Z0-9_.:-]{1,128}$/.test(value)) throw new WorkflowError(400, 'INVALID_ID');
  return value;
}

/** The decision concerns the whole version: require a read grant covering the
 * record with every field. Denied and absent answer the same 404. */
function requireRecordWide(session: AdminSession, registryId: string, record: string, notFound: string): void {
  let ok = false;
  try {
    ok = normalizeResourcePolicy(session.resourcePolicy).grants.some(grant => grant.registryId === registryId
      && grant.actions.includes('records.read') && (grant.recordIds === 'all' || grant.recordIds.includes(record)) && grant.fieldPaths === 'all');
  } catch { ok = false; }
  if (!ok) throw new WorkflowError(404, notFound);
}

/** Publishable by FIELDMAP:V1 (what the publisher would build). */
export function publicationMappable(version: { operation: string; payload: Record<string, unknown> }): boolean {
  try {
    const fields = workflowFields(version as { operation: 'upsert' | 'tombstone'; payload: Record<string, unknown> });
    buildFieldTree(new Uint8Array(32), fields);
    return true;
  } catch { return false; }
}
/** A correcting version must satisfy the current input contract as well. */
function validCorrection(version: { operation: string; payload: Record<string, unknown> }): boolean {
  try { assertPublishablePayload(version.payload); } catch { return false; }
  return publicationMappable(version);
}

function principal(session: AdminSession) {
  return { principal: session.username, role: session.role, authMethod: session.authMethod ?? 'password', deviceId: session.deviceId ?? null };
}

async function audit(c: PoolClient, registryId: string, actor: string, action: string, details: unknown) {
  await c.query('INSERT INTO wf_audit(registry_id,actor,action,details) VALUES($1,$2,$3,$4)', [registryId, actor, action, JSON.stringify(details)]);
}

/** Idempotency-Key scoped to registry and session username (same table as drafts). */
async function idempotent(c: PoolClient, registryId: string, session: AdminSession, req: Request, run: () => Promise<Response>, reauthorize: (prior: any) => void): Promise<Response> {
  await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [JSON.stringify([registryId, session.username, req.idempotencyKey])]);
  const requestHash = workflowHash({ method: req.method, path: req.path, body: req.body ?? {} });
  await assertWorkflowAttemptBinding(c,registryId,session.username,req.idempotencyKey!,requestHash);
  const replay = await c.query('SELECT request_hash,response FROM wf_request WHERE registry_id=$1 AND actor=$2 AND idempotency_key=$3', [registryId, session.username, req.idempotencyKey]);
  if (replay.rowCount) {
    if (replay.rows[0].request_hash !== requestHash) throw new WorkflowError(409, 'IDEMPOTENCY_CONFLICT');
    reauthorize(replay.rows[0].response);
    return replay.rows[0].response;
  }
  const response = await run();
  await c.query('INSERT INTO wf_request VALUES($1,$2,$3,$4,$5)', [registryId, session.username, req.idempotencyKey, requestHash, JSON.stringify(response)]);
  return response;
}

/** Maps guard/uniqueness violations raised by 0017 under concurrency to 409. */
function conflict(error: unknown, code: string): never {
  const pg = error as { code?: string };
  if (pg && (pg.code === '23505' || pg.code === 'P0001')) throw new WorkflowError(409, code);
  throw error;
}

async function versionRow(c: PoolClient | Pool, registryId: string, record: string, version: number) {
  return (await c.query(`SELECT v.record_id,v.version,v.payload,v.payload_hash,v.operation,o.event_id FROM wf_version v
    JOIN wf_outbox o USING(registry_id,record_id,version) WHERE v.registry_id=$1 AND v.record_id=$2 AND v.version=$3`, [registryId, record, version])).rows[0];
}

async function exclusionView(c: PoolClient | Pool, exclusionId: string) {
  const x = (await c.query('SELECT * FROM wf_version_exclusion WHERE exclusion_id=$1', [exclusionId])).rows[0];
  const approvals = (await c.query('SELECT ordinal,principal,role,auth_method,approved_at FROM wf_version_exclusion_approval WHERE exclusion_id=$1 ORDER BY ordinal', [exclusionId])).rows;
  return {
    exclusionId: x.exclusion_id, recordId: x.record_id, version: x.version, eventId: x.event_id, payloadHash: x.payload_hash,
    correctedByVersion: x.corrected_by_version, correctedPayloadHash: x.corrected_payload_hash, reason: x.reason,
    state: approvals.length === 2 ? 'EXCLUDED' : 'PROPOSED',
    approvals: approvals.map(a => ({ ordinal: a.ordinal, principal: a.principal, role: a.role, authMethod: a.auth_method, approvedAt: a.approved_at.toISOString() })),
  };
}

async function proposeExclusion(c: PoolClient, registryId: string, session: AdminSession, raw: Record<string, unknown> | null): Promise<Response> {
  const body = exactBody(raw, ['recordId', 'version', 'payloadHash', 'correctedByVersion', 'correctedPayloadHash', 'reason']);
  const record = recordId(body.recordId), version = positiveVersion(body.version), correctedBy = positiveVersion(body.correctedByVersion);
  const payloadHash = hash(body.payloadHash), correctedHash = hash(body.correctedPayloadHash), reason = reasonText(body.reason);
  requireRecordWide(session, registryId, record, 'RECORD_VERSION_NOT_FOUND');
  // Serializes with queue claims and other exclusion decisions of the registry.
  await lockRegistryPublication(c, registryId);
  const target = await versionRow(c, registryId, record, version);
  if (!target) throw new WorkflowError(404, 'RECORD_VERSION_NOT_FOUND');
  if (target.payload_hash !== payloadHash) throw new WorkflowError(409, 'EXCLUSION_BINDING_MISMATCH');
  const correction = correctedBy > version ? await versionRow(c, registryId, record, correctedBy) : undefined;
  if (!correction) throw new WorkflowError(409, 'EXCLUSION_CORRECTION_MISSING');
  if (correction.payload_hash !== correctedHash) throw new WorkflowError(409, 'EXCLUSION_BINDING_MISMATCH');
  if (publicationMappable(target)) throw new WorkflowError(409, 'EXCLUSION_VERSION_PUBLISHABLE');
  if (!validCorrection(correction)) throw new WorkflowError(409, 'EXCLUSION_CORRECTION_UNPUBLISHABLE');
  const authors: string[] = (await c.query('SELECT coalesce(array_agg(a ORDER BY a),\'{}\') AS authors FROM wf_version_authors($1,$2,$3) a', [registryId, record, version])).rows[0].authors;
  if (authors.some(author => same(author, session.username))) throw new WorkflowError(403, 'EXCLUSION_AUTHOR_APPROVAL');
  const existing = await c.query(`SELECT 1 FROM wf_version_exclusion WHERE registry_id=$1 AND record_id=$2 AND version=$3`, [registryId, record, version]);
  if (existing.rowCount) throw new WorkflowError(409, 'EXCLUSION_EXISTS');
  const correctionTaken = await c.query(`SELECT 1 FROM wf_version_exclusion WHERE registry_id=$1 AND record_id=$2 AND (version=$3 OR corrected_by_version=$4)`, [registryId, record, correctedBy, version]);
  if (correctionTaken.rowCount) throw new WorkflowError(409, 'EXCLUSION_CORRECTION_CONFLICT');
  if ((await c.query('SELECT wf_event_publication_bound($1) AS bound', [target.event_id])).rows[0].bound) throw new WorkflowError(409, 'EXCLUSION_VERSION_BOUND');
  const exclusionId = randomUUID();
  const who = principal(session);
  try {
    await c.query(`INSERT INTO wf_version_exclusion(exclusion_id,registry_id,record_id,version,event_id,payload_hash,corrected_by_version,corrected_payload_hash,reason,authors)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [exclusionId, registryId, record, version, target.event_id, payloadHash, correctedBy, correctedHash, reason, authors]);
    await c.query(`INSERT INTO wf_version_exclusion_approval(exclusion_id,ordinal,principal,role,auth_method,device_id) VALUES($1,1,$2,$3,$4,$5)`,
      [exclusionId, who.principal, who.role, who.authMethod, who.deviceId]);
  } catch (error) { conflict(error, 'EXCLUSION_CONFLICT'); }
  await audit(c, registryId, session.username, 'VERSION_EXCLUSION_PROPOSED', { exclusionId, recordId: record, version, eventId: target.event_id, payloadHash,
    correctedByVersion: correctedBy, correctedPayloadHash: correctedHash, reason, authors, approval: { ordinal: 1, ...who } });
  return { status: 201, body: await exclusionView(c, exclusionId) };
}

async function approveExclusion(c: PoolClient, registryId: string, session: AdminSession, exclusionId: string, raw: Record<string, unknown> | null): Promise<Response> {
  const body = exactBody(raw, ['payloadHash', 'correctedByVersion']);
  const payloadHash = hash(body.payloadHash), correctedBy = positiveVersion(body.correctedByVersion);
  await lockRegistryPublication(c, registryId);
  const x = (await c.query('SELECT * FROM wf_version_exclusion WHERE exclusion_id=$1 AND registry_id=$2', [exclusionId, registryId])).rows[0];
  if (!x) throw new WorkflowError(404, 'EXCLUSION_NOT_FOUND');
  requireRecordWide(session, registryId, x.record_id, 'EXCLUSION_NOT_FOUND');
  if (x.payload_hash !== payloadHash || x.corrected_by_version !== correctedBy) throw new WorkflowError(409, 'EXCLUSION_BINDING_MISMATCH');
  const approvals = (await c.query('SELECT principal FROM wf_version_exclusion_approval WHERE exclusion_id=$1 ORDER BY ordinal', [exclusionId])).rows;
  if (approvals.some(a => same(a.principal, session.username))) throw new WorkflowError(409, 'APPROVER_NOT_INDEPENDENT');
  if (approvals.length >= 2) throw new WorkflowError(409, 'EXCLUSION_ALREADY_EFFECTIVE');
  const authors: string[] = (await c.query('SELECT coalesce(array_agg(a ORDER BY a),\'{}\') AS authors FROM wf_version_authors($1,$2,$3) a', [registryId, x.record_id, x.version])).rows[0].authors;
  if ([...authors, ...x.authors].some((author: string) => same(author, session.username))) throw new WorkflowError(403, 'EXCLUSION_AUTHOR_APPROVAL');
  if ((await c.query('SELECT wf_event_publication_bound($1) AS bound', [x.event_id])).rows[0].bound) throw new WorkflowError(409, 'EXCLUSION_VERSION_BOUND');
  const who = principal(session);
  try {
    await c.query(`INSERT INTO wf_version_exclusion_approval(exclusion_id,ordinal,principal,role,auth_method,device_id) VALUES($1,2,$2,$3,$4,$5)`,
      [exclusionId, who.principal, who.role, who.authMethod, who.deviceId]);
  } catch (error) { conflict(error, 'EXCLUSION_ALREADY_EFFECTIVE'); }
  await audit(c, registryId, session.username, 'VERSION_EXCLUDED_FROM_PUBLICATION', { exclusionId, recordId: x.record_id, version: x.version, eventId: x.event_id,
    payloadHash, correctedByVersion: correctedBy, correctedPayloadHash: x.corrected_payload_hash, reason: x.reason, approvers: [approvals[0].principal, who.principal], approval: { ordinal: 2, ...who } });
  return { status: 200, body: await exclusionView(c, exclusionId) };
}

async function approveCancellation(c: PoolClient, registryId: string, session: AdminSession, checkId: string, raw: Record<string, unknown> | null): Promise<Response> {
  const body = exactBody(raw, ['operationId', 'evidenceHash']);
  const evidenceHash = hash(body.evidenceHash);
  if (typeof body.operationId !== 'string') throw new WorkflowError(400, 'REQUEST_INVALID');
  const check = (await c.query(`SELECT k.*,p.registry_id FROM wf_publication_archival_check k JOIN wf_publication p USING(operation_id) WHERE k.check_id=$1`, [checkId])).rows[0];
  if (!check || check.registry_id !== registryId) throw new WorkflowError(404, 'ARCHIVAL_CHECK_NOT_FOUND');
  if (body.operationId !== check.operation_id || evidenceHash !== check.detail_hash) throw new WorkflowError(409, 'EVIDENCE_BINDING_MISMATCH');
  // Serializes approvals of this operation with each other and with worker writes.
  const op = (await c.query('SELECT state FROM wf_publication WHERE operation_id=$1 FOR UPDATE', [check.operation_id])).rows[0];
  if (check.outcome !== 'FOREIGN_PROVEN') throw new WorkflowError(409, 'ARCHIVAL_CHECK_NOT_APPROVABLE');
  const newer = await c.query('SELECT 1 FROM wf_publication_archival_check WHERE operation_id=$1 AND check_no>$2', [check.operation_id, check.check_no]);
  if (newer.rowCount) throw new WorkflowError(409, 'ARCHIVAL_CHECK_SUPERSEDED');
  if (op.state !== 'OPEN') throw new WorkflowError(409, 'PUBLICATION_NOT_OPEN');
  const approvals = (await c.query('SELECT principal FROM wf_publication_cancel_approval WHERE check_id=$1 ORDER BY ordinal', [checkId])).rows;
  if (approvals.some(a => same(a.principal, session.username))) throw new WorkflowError(409, 'APPROVER_NOT_INDEPENDENT');
  if (approvals.length >= 2) throw new WorkflowError(409, 'CANCELLATION_ALREADY_APPROVED');
  const who = principal(session);
  const ordinal = approvals.length + 1;
  try {
    await c.query(`INSERT INTO wf_publication_cancel_approval(check_id,operation_id,ordinal,principal,role,auth_method,device_id,evidence_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [checkId, check.operation_id, ordinal, who.principal, who.role, who.authMethod, who.deviceId, evidenceHash]);
  } catch (error) { conflict(error, 'CANCELLATION_ALREADY_APPROVED'); }
  await audit(c, registryId, session.username, 'PUBLICATION_CANCELLATION_APPROVED', { checkId, operationId: check.operation_id, evidenceHash, ordinal, ...who });
  return { status: 200, body: { checkId, operationId: check.operation_id, evidenceHash, approvals: ordinal, state: ordinal === 2 ? 'APPROVED' : 'PENDING_SECOND_APPROVAL' } };
}

async function operationView(pool: Pool, registryId: string, operationId: string): Promise<Response> {
  const op = (await pool.query('SELECT operation_id,registry_id,state,blocked_reason,superseded_by FROM wf_publication WHERE operation_id=$1', [operationId])).rows[0];
  if (!op || op.registry_id !== registryId) throw new WorkflowError(404, 'OPERATION_NOT_FOUND');
  const attempts = (await pool.query(`SELECT t.attempt_no,s.signature,wf_publication_tx_state(t.attempt_id) AS state FROM wf_publication_tx t
    LEFT JOIN wf_publication_tx_signed s USING(attempt_id) WHERE t.operation_id=$1 ORDER BY t.attempt_no`, [operationId])).rows;
  const checks = (await pool.query(`SELECT check_id,outcome,detail_bytes,detail_hash,archive_id,evidence_ref,requested_by,reason,created_at
    FROM wf_publication_archival_check WHERE operation_id=$1 ORDER BY check_no`, [operationId])).rows;
  const approvals = (await pool.query('SELECT check_id,ordinal,principal,role,approved_at FROM wf_publication_cancel_approval WHERE operation_id=$1 ORDER BY check_id,ordinal', [operationId])).rows;
  return { status: 200, body: {
    operationId, state: op.state, blockedReason: op.blocked_reason, supersededBy: op.superseded_by,
    attempts: attempts.map(a => ({ attemptNo: a.attempt_no, state: a.state, signature: a.signature })),
    archivalChecks: checks.map((k, index) => ({ checkId: k.check_id, outcome: k.outcome, evidenceHash: k.detail_hash, evidence: JSON.parse(k.detail_bytes.toString('utf8')),
      archiveId: k.archive_id, evidenceRef: k.evidence_ref, requestedBy: k.requested_by, reason: k.reason, createdAt: k.created_at.toISOString(), newest: index === checks.length - 1,
      approvals: approvals.filter(a => a.check_id === k.check_id).map(a => ({ ordinal: a.ordinal, principal: a.principal, role: a.role, approvedAt: a.approved_at.toISOString() })) })),
  } };
}

/** Dispatcher for the ADR-0009 routes; null when the path is not one of them. */
export async function routePublicationMaintenance(ctx: { pool: Pool; registryId: string }, req: Request, session: AdminSession): Promise<Response | null> {
  const exclusion = EXCLUSIONS.exec(req.path), operation = OPERATION.exec(req.path), check = CHECK_APPROVE.exec(req.path);
  if (!exclusion && !operation && !check) return null;
  const reading = req.method === 'GET';
  if (operation) {
    if (!reading) throw new WorkflowError(405, 'METHOD_NOT_ALLOWED');
    requirePermission(session, ctx.registryId, 'publication.read');
    return operationView(ctx.pool, ctx.registryId, operation[1]);
  }
  if (exclusion && reading) {
    if (!exclusion[1] || exclusion[2]) throw new WorkflowError(405, 'METHOD_NOT_ALLOWED');
    requirePermission(session, ctx.registryId, 'records.read');
    const x = (await ctx.pool.query('SELECT record_id FROM wf_version_exclusion WHERE exclusion_id=$1 AND registry_id=$2', [exclusion[1], ctx.registryId])).rows[0];
    if (!x) throw new WorkflowError(404, 'EXCLUSION_NOT_FOUND');
    requireRecordWide(session, ctx.registryId, x.record_id, 'EXCLUSION_NOT_FOUND');
    return { status: 200, body: await exclusionView(ctx.pool, exclusion[1]) };
  }
  if (req.method !== 'POST' || (exclusion && exclusion[1] && !exclusion[2])) throw new WorkflowError(405, 'METHOD_NOT_ALLOWED');
  requirePermission(session, ctx.registryId, 'publication.maintenance');
  if (!req.idempotencyKey || !/^[\w.:-]{1,128}$/.test(req.idempotencyKey)) throw new WorkflowError(400, 'IDEMPOTENCY_KEY_REQUIRED');
  return workflowTransaction(ctx.pool, c => idempotent(c, ctx.registryId, session, req, () => {
    if (check) return approveCancellation(c, ctx.registryId, session, check[1], req.body);
    if (exclusion![1]) return approveExclusion(c, ctx.registryId, session, exclusion![1], req.body);
    return proposeExclusion(c, ctx.registryId, session, req.body);
  }, prior => {
    // A replay still needs record-wide scope over the excluded record.
    const record = (prior?.body as { recordId?: unknown } | undefined)?.recordId;
    if (typeof record === 'string') requireRecordWide(session, ctx.registryId, record, 'RECORD_VERSION_NOT_FOUND');
  }));
}

/** Effective exclusion of a committed version, for read models. An excluded
 * version is never published, never gets a certificate and is never CURRENT. */
export async function versionExclusion(db: Pool | PoolClient, registryId: string, record: string, version: number) {
  const x = (await db.query('SELECT exclusion_id,corrected_by_version,reason FROM wf_version_excluded WHERE registry_id=$1 AND record_id=$2 AND version=$3', [registryId, record, version])).rows[0];
  return x ? { state: 'EXCLUDED_FROM_PUBLICATION' as const, exclusionId: x.exclusion_id as string, correctedByVersion: x.corrected_by_version as number,
    reason: x.reason as string, published: false as const, certificateEligible: false as const, current: false as const } : null;
}

/** Gate every workflow Certificate Package issuance path must call before
 * building a package: the version must not be excluded and must belong to a
 * FINALIZED publication with a stored anchor. (Issuance itself is still open
 * in ticket 09; this is the contract it must satisfy.) */
export async function assertWorkflowVersionCertifiable(db: Pool | PoolClient, registryId: string, record: string, version: number) {
  if (await versionExclusion(db, registryId, record, version)) throw new PublicationError('VERSION_EXCLUDED_FROM_PUBLICATION', { recordId: record, version });
  const anchor = (await db.query(`SELECT a.operation_id,a.batch_sequence::text AS batch_sequence,a.anchor_hash,a.proof,a.slot::text AS slot
      FROM wf_outbox o JOIN wf_publication_item i USING(event_id) JOIN wf_publication p ON p.operation_id=i.operation_id AND p.state='FINALIZED'
      JOIN wf_publication_anchor a ON a.operation_id=p.operation_id
     WHERE o.registry_id=$1 AND o.record_id=$2 AND o.version=$3`, [registryId, record, version])).rows[0];
  if (!anchor) throw new PublicationError('VERSION_NOT_ANCHORED', { recordId: record, version });
  return { operationId: anchor.operation_id as string, batchSequence: anchor.batch_sequence as string, anchorHash: anchor.anchor_hash as string, proof: anchor.proof as string, slot: anchor.slot as string | null };
}
