import { createHash, randomUUID, verify, type KeyObject } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { requirePermission, AuthorizationError, type AdminSession } from './admin-session.ts';
import { requireResourceAccess } from './resource-access.ts';
import { routePublicationMaintenance, versionExclusion } from './publication-maintenance.ts';
import { routeWorkflowAttempts } from './workflow-attempts.ts';

export class WorkflowError extends Error {
  constructor(public status: number, public code: string) { super(code); }
}
/** Nesting beyond this is refused (400) instead of exhausting the call stack. */
const CANONICAL_MAX_DEPTH = 256;
export function canonicalWorkflow(value: unknown, depth = 0): string {
  if (depth > CANONICAL_MAX_DEPTH) throw new WorkflowError(400, 'UNSUPPORTED_NESTING');
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(item => canonicalWorkflow(item, depth + 1)).join(',') + ']';
  if (typeof value === 'object' && value && Object.getPrototypeOf(value) === Object.prototype) {
    return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonicalWorkflow((value as Record<string, unknown>)[k], depth + 1)).join(',') + '}';
  }
  throw new WorkflowError(400, 'INVALID_JSON');
}
export const workflowHash = (value: unknown): string => createHash('sha256').update('ONELAYER:WORKFLOW:JSON:V1\n' + canonicalWorkflow(value)).digest('hex');
/** Deepest accepted payload nesting (contract V1.2). */
export const PAYLOAD_MAX_DEPTH = 32;
/** Lone UTF-16 surrogates are replaced by U+FFFD in the UTF-8 commitment (two
 * different values would commit identically) and U+0000 cannot be stored in
 * PostgreSQL jsonb, so neither is publishable. */
const unsupportedString = (text: string) => /[\uD800-\uDFFF]/u.test(text) || text.includes('\u0000');
/** Contract V1.1/V1.2 payload rules, enforced on draft input and again at commit:
 * non-empty undotted keys, no `__proto__` key, no sibling keys that collide
 * after NFC normalization, only safe-integer numbers (no floats), (V1.2) only
 * well-formed strings without U+0000 in keys and values, and at most
 * PAYLOAD_MAX_DEPTH levels of nesting. These are exactly the values the
 * publication field mapping can commit to unambiguously. */
export function assertPublishablePayload(value: unknown, depth = 0): void {
  if (depth > PAYLOAD_MAX_DEPTH) throw new WorkflowError(400, 'UNSUPPORTED_NESTING');
  if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new WorkflowError(400, 'UNSUPPORTED_NUMBER');
  if (typeof value === 'string' && unsupportedString(value)) throw new WorkflowError(400, 'UNSUPPORTED_STRING');
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) { for (const item of value) assertPublishablePayload(item, depth + 1); return; }
  const normalized = new Set<string>();
  for (const key of Object.keys(value)) {
    if (!key || key.includes('.')) throw new WorkflowError(400, 'AMBIGUOUS_FIELD_PATH');
    if (key === '__proto__') throw new WorkflowError(400, 'RESERVED_FIELD_NAME');
    if (unsupportedString(key)) throw new WorkflowError(400, 'UNSUPPORTED_STRING');
    const nfc = key.normalize('NFC');
    if (normalized.has(nfc)) throw new WorkflowError(400, 'AMBIGUOUS_FIELD_PATH');
    normalized.add(nfc);
    assertPublishablePayload((value as Record<string, unknown>)[key], depth + 1);
  }
}
export function payloadInput(body: Record<string, unknown>): {payload: Record<string, unknown>; operation: string; hash: string} {
  const operation = body.operation;
  const payload = body.payload;
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) || !['upsert','tombstone'].includes(String(operation))) throw new WorkflowError(400,'INVALID_PAYLOAD');
  assertPublishablePayload(payload);
  if (operation === 'tombstone' && Object.keys(payload).length) throw new WorkflowError(400,'TOMBSTONE_PAYLOAD');
  if (Buffer.byteLength(canonicalWorkflow(payload)) > 65536) throw new WorkflowError(413,'PAYLOAD_TOO_LARGE');
  return {payload: payload as Record<string, unknown>, operation: String(operation), hash: workflowHash({operation,payload})};
}
const integer = (v: unknown): number => { if (!Number.isSafeInteger(v) || Number(v)<0) throw new WorkflowError(400,'INVALID_VERSION'); return Number(v); };
const identifier = (v: unknown): string => { if(typeof v !== 'string' || !/^[a-zA-Z0-9_.:-]{1,128}$/.test(v)) throw new WorkflowError(400,'INVALID_ID'); return v; };
export async function workflowTransaction<T>(pool: Pool, fn: (client: PoolClient)=>Promise<T>): Promise<T> {
  const client = await pool.connect();
  try { await client.query('BEGIN'); const result=await fn(client); await client.query('COMMIT'); return result; }
  catch(error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
}
export async function appendWorkflowVersion(client: PoolClient, data: {registryId:string;recordId:string;baseVersion:number;payload:unknown;payloadHash:string;operation:string;creator:string;approver:string;evidence:unknown}) {
  // Drafts stored before contract V1.1 are re-checked here, at commit.
  assertPublishablePayload(data.payload);
  await client.query('INSERT INTO wf_record(registry_id,record_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[data.registryId,data.recordId]);
  const result=await client.query('UPDATE wf_record SET version=version+1 WHERE registry_id=$1 AND record_id=$2 AND version=$3 RETURNING version',[data.registryId,data.recordId,data.baseVersion]);
  if(!result.rowCount) throw new WorkflowError(409,'BASE_VERSION_CONFLICT');
  const version=result.rows[0].version;
  await client.query('INSERT INTO wf_version VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[data.registryId,data.recordId,version,JSON.stringify(data.payload),data.payloadHash,data.operation,data.creator,data.approver,JSON.stringify(data.evidence)]);
  await client.query('INSERT INTO wf_outbox(event_id,registry_id,record_id,version,payload_hash) VALUES($1,$2,$3,$4,$5)',[randomUUID(),data.registryId,data.recordId,version,data.payloadHash]);
  await audit(client,data.registryId,data.approver,'COMMIT',{recordId:data.recordId,version,payloadHash:data.payloadHash,evidence:data.evidence});
  return {recordId:data.recordId,version,payloadHash:data.payloadHash};
}
async function audit(c:PoolClient, registry:string,actor:string,action:string,details:unknown) { await c.query('INSERT INTO wf_audit(registry_id,actor,action,details) VALUES($1,$2,$3,$4)',[registry,actor,action,JSON.stringify(details)]); }
export function workflowScope(session:AdminSession, registryId:string,recordId:string,payload:Record<string,unknown>,write:boolean) {
  // Leaf and parent keys are all checked; nested fields cannot hide under an allowed parent.
  const paths:string[]=[];
  function walk(v:unknown,prefix='') { if(v && typeof v==='object') for(const [k,item] of Object.entries(v)) { if (!k || k.includes('.')) throw new WorkflowError(400,'AMBIGUOUS_FIELD_PATH'); const p=prefix ? `${prefix}.${k}`:k; paths.push(p); walk(item,p); } }
  walk(payload);
  requireResourceAccess(session.resourcePolicy,{registryId,recordId,fieldPaths:paths,action:write?'records.write':'records.read'});
}
/** Must run under the shared registry/actor/key transaction lock, including
 * maintenance routes that use the same immutable request-result namespace. */
export async function assertWorkflowAttemptBinding(c:PoolClient,registryId:string,actor:string,key:string,requestHash:string) {
  // Legacy opaque keys cannot be prepared receipt IDs; avoid a history scan.
  if(!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(key)) return;
  const prepared=await c.query('SELECT a.request_hash,k.attempt_id AS cancelled FROM wf_attempt a LEFT JOIN wf_attempt_cancel k USING(attempt_id) WHERE a.registry_id=$1 AND a.actor=$2 AND a.attempt_id=$3::uuid',[registryId,actor,key]);
  if(prepared.rows[0]?.cancelled) throw new WorkflowError(409,'ATTEMPT_CANCELLED');
  if(prepared.rowCount&&prepared.rows[0].request_hash!==requestHash) throw new WorkflowError(409,'IDEMPOTENCY_CONFLICT');
}
export async function routeWorkflow(ctx:{pool:Pool;registryId:string},req:{method:string;path:string;body:Record<string,unknown>|null;idempotencyKey?:string;query?:URLSearchParams},session:AdminSession):Promise<{status:number;body:unknown}> {
  try {
    // Capture caller-owned JSON before a connection wait; hash and persisted bytes must agree.
    req = { ...req, body: req.body === null ? null : JSON.parse(canonicalWorkflow(req.body)) };
    const attempts = await routeWorkflowAttempts(ctx, req, session);
    if (attempts) return attempts;
    // ADR-0009 exclusions and publication maintenance approvals.
    const maintenance = await routePublicationMaintenance(ctx, req, session);
    if (maintenance) return maintenance;
    const recordMatch = /^\/v2\/admin\/workflow\/records\/([a-zA-Z0-9_.:-]{1,128})\/versions\/(latest|[1-9][0-9]*)$/.exec(req.path);
    if (recordMatch) {
      if (req.method !== 'GET') throw new WorkflowError(405, 'METHOD_NOT_ALLOWED');
      requirePermission(session, ctx.registryId, 'records.read');
      const [, recordId, version] = recordMatch;
      if (version !== 'latest' && (!Number.isSafeInteger(Number(version)) || Number(version) > 2147483647)) {
        throw new WorkflowError(400, 'INVALID_VERSION');
      }
      const result = await ctx.pool.query(
        `SELECT record_id,version,payload,payload_hash,operation FROM wf_version
         WHERE registry_id=$1 AND record_id=$2 AND ($3::integer IS NULL OR version=$3)
         ORDER BY version DESC LIMIT 1`, [ctx.registryId, recordId, version === 'latest' ? null : Number(version)]);
      const row = result.rows[0];
      if (!row) throw new WorkflowError(404, 'RECORD_VERSION_NOT_FOUND');
      try { workflowScope(session, ctx.registryId, recordId, row.payload, false); }
      catch (error) {
        if (error instanceof AuthorizationError) throw new WorkflowError(404, 'RECORD_VERSION_NOT_FOUND');
        throw error;
      }
      // Committed workflow state is not proof of a finalized chain anchor. An
      // excluded version stays visible, marked as never publishable (ADR-0009).
      const exclusion = await versionExclusion(ctx.pool, ctx.registryId, recordId, row.version);
      return { status: 200, body: { recordId: row.record_id, version: row.version,
        payload: row.payload, payloadHash: row.payload_hash, operation: row.operation, state: 'COMMITTED',
        ...(exclusion ? { exclusion } : {}) } };
    }
    if (req.path === '/v2/admin/workflow/drafts' && req.method === 'GET') {
      requirePermission(session,ctx.registryId,'records.read');
      const after=req.query?.get('after') ?? null;
      if (after!==null&&!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(after)) throw new WorkflowError(400,'INVALID_CURSOR');
      const drafts:Record<string,unknown>[]=[];
      let cursor=after;
      // Only an authorized draft UUID can become a public cursor. Hidden rows
      // are scanned internally in bounded batches; no counts or ids escape.
      for(let batch=0;batch<100;batch++) {
        const rows=(await ctx.pool.query(`SELECT d.*,r.payload,r.payload_hash,r.operation FROM wf_draft d
          JOIN wf_revision r ON r.draft_id=d.draft_id AND r.revision=d.revision
          WHERE d.registry_id=$1 AND ($2::uuid IS NULL OR d.draft_id>$2::uuid)
          ORDER BY d.draft_id LIMIT 100`,[ctx.registryId,cursor])).rows;
        for(const row of rows) {
          cursor=row.draft_id;
          try {workflowScope(session,ctx.registryId,row.record_id,row.payload,false);}
          catch(error) {if(error instanceof AuthorizationError) continue;throw error;}
          if(drafts.length===50) return {status:200,body:{drafts,nextCursor:drafts[49].draft_id}};
          const {payload,...summary}=row;
          drafts.push(summary);
        }
        if(rows.length<100) return {status:200,body:{drafts,nextCursor:null}};
      }
      throw new WorkflowError(503,'DRAFT_LIST_BUSY');
    }
    const match=/^\/v2\/admin\/workflow\/drafts(?:\/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:\/(edit|submit|approve|reject|commit))?)?$/.exec(req.path);
    if(!match) throw new WorkflowError(404,'NOT_FOUND');
    const [,id,action]=match; const body=req.body??{};
    const reading=req.method==='GET'&&id&&!action;
    if(!reading && (req.method!=='POST'||(id&&!action))) throw new WorkflowError(405,'METHOD_NOT_ALLOWED');
    requirePermission(session,ctx.registryId,reading?'records.read':action==='approve'||action==='reject'?'records.approve':'records.draft');
    if(!reading && (!req.idempotencyKey || !/^[\w.:-]{1,128}$/.test(req.idempotencyKey))) throw new WorkflowError(400,'IDEMPOTENCY_KEY_REQUIRED');
    return await workflowTransaction(ctx.pool,async c=>{
      const requestHash=workflowHash({method:req.method,path:req.path,body});
      if(!reading) {
        await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[JSON.stringify([ctx.registryId,session.username,req.idempotencyKey])]);
        await assertWorkflowAttemptBinding(c,ctx.registryId,session.username,req.idempotencyKey!,requestHash);
        const replay=await c.query('SELECT * FROM wf_request WHERE registry_id=$1 AND actor=$2 AND idempotency_key=$3',[ctx.registryId,session.username,req.idempotencyKey]);
        if(replay.rowCount) { if(replay.rows[0].request_hash!==requestHash) throw new WorkflowError(409,'IDEMPOTENCY_CONFLICT'); const prior = replay.rows[0].response;
          const priorDraft = await c.query('SELECT d.record_id,r.payload FROM wf_draft d JOIN wf_revision r ON r.draft_id=d.draft_id AND r.revision=d.revision WHERE d.draft_id=$1 AND d.registry_id=$2',[prior.body.draftId,ctx.registryId]);
          if (!priorDraft.rowCount) throw new WorkflowError(404,'DRAFT_NOT_FOUND');
          workflowScope(session,ctx.registryId,priorDraft.rows[0].record_id,priorDraft.rows[0].payload,true);
          // Replays return historical evidence: authorize the exact revision and removed base fields too.
          const bound = await c.query('SELECT r.payload,v.payload AS base_payload FROM wf_draft d JOIN wf_revision r ON r.draft_id=d.draft_id AND r.revision=$3 LEFT JOIN wf_version v ON v.registry_id=d.registry_id AND v.record_id=d.record_id AND v.version=d.base_version WHERE d.draft_id=$1 AND d.registry_id=$2',[prior.body.draftId,ctx.registryId,prior.body.revision]);
          if (!bound.rowCount) throw new WorkflowError(404,'DRAFT_NOT_FOUND');
          workflowScope(session,ctx.registryId,priorDraft.rows[0].record_id,bound.rows[0].payload,true);
          if (bound.rows[0].base_payload) workflowScope(session,ctx.registryId,priorDraft.rows[0].record_id,bound.rows[0].base_payload,true);
          return prior; }
      }
      let response:{status:number;body:unknown};
      if(!id) {
        const recordId=identifier(body.recordId), baseVersion=integer(body.baseVersion), input=payloadInput(body); workflowScope(session,ctx.registryId,recordId,input.payload,true);
        const current=await c.query('SELECT h.version,v.payload FROM wf_record h LEFT JOIN wf_version v ON v.registry_id=h.registry_id AND v.record_id=h.record_id AND v.version=h.version WHERE h.registry_id=$1 AND h.record_id=$2 FOR UPDATE OF h',[ctx.registryId,recordId]);
        if(current.rows[0]?.payload) workflowScope(session,ctx.registryId,recordId,current.rows[0].payload,true);
        if((current.rows[0]?.version??0)!==baseVersion) throw new WorkflowError(409,'BASE_VERSION_CONFLICT');
        const draftId=randomUUID();
        await c.query("INSERT INTO wf_draft(draft_id,registry_id,record_id,creator,revision,base_version,state) VALUES($1,$2,$3,$4,1,$5,'DRAFT')",[draftId,ctx.registryId,recordId,session.username,baseVersion]);
        await c.query('INSERT INTO wf_revision VALUES($1,1,$2,$3,$4,$5)',[draftId,JSON.stringify(input.payload),input.hash,input.operation,session.username]);
        await audit(c,ctx.registryId,session.username,'DRAFT',{draftId,revision:1,payloadHash:input.hash,baseVersion});
        response={status:201,body:{draftId,revision:1,payloadHash:input.hash,baseVersion,state:'DRAFT'}};
      } else {
        // Lock before joining: after a concurrent revision update, the join's old
        // statement snapshot can otherwise lose the new revision during lock recheck.
        await c.query('SELECT draft_id FROM wf_draft WHERE draft_id=$1 AND registry_id=$2 FOR UPDATE',[id,ctx.registryId]);
        const found=await c.query('SELECT d.*,r.payload,r.payload_hash,r.operation FROM wf_draft d JOIN wf_revision r ON r.draft_id=d.draft_id AND r.revision=d.revision WHERE d.draft_id=$1 AND d.registry_id=$2',[id,ctx.registryId]);
        if(!found.rowCount) throw new WorkflowError(404,'DRAFT_NOT_FOUND');
        const d=found.rows[0];
        try { workflowScope(session,ctx.registryId,d.record_id,d.payload,!reading); }
        catch (error) {
          if (reading && error instanceof AuthorizationError) throw new WorkflowError(404,'DRAFT_NOT_FOUND');
          throw error;
        }
        if(reading) return {status:200,body:d};
        const base=await c.query('SELECT payload FROM wf_version WHERE registry_id=$1 AND record_id=$2 AND version=$3',[ctx.registryId,d.record_id,d.base_version]);
        if(base.rows[0]) workflowScope(session,ctx.registryId,d.record_id,base.rows[0].payload,true);
        if(integer(body.expectedRevision)!==d.revision) throw new WorkflowError(409,'REVISION_CONFLICT');
        if(d.state==='COMMITTED') throw new WorkflowError(409,'ALREADY_COMMITTED');
        let state=d.state, revision=d.revision, hash=d.payload_hash, committed:unknown;
        if(action==='edit') {
          const input=payloadInput(body); workflowScope(session,ctx.registryId,d.record_id,input.payload,true); revision++; hash=input.hash; state='DRAFT';
          await c.query('INSERT INTO wf_revision VALUES($1,$2,$3,$4,$5,$6)',[id,revision,JSON.stringify(input.payload),hash,input.operation,session.username]);
          await c.query('UPDATE wf_draft SET revision=$2,state=$3,approver=NULL WHERE draft_id=$1',[id,revision,state]);
        } else {
          if(body.payloadHash!==hash||integer(body.baseVersion)!==d.base_version) throw new WorkflowError(409,'APPROVAL_BINDING_MISMATCH');
          if(action==='submit') { if(state!=='DRAFT') throw new WorkflowError(409,'INVALID_STATE'); state='SUBMITTED'; }
          else if(action==='approve'||action==='reject') {
            if(state!=='SUBMITTED') throw new WorkflowError(409,'INVALID_STATE');
            const contributors=await c.query('SELECT 1 FROM wf_revision WHERE draft_id=$1 AND editor=$2',[id,session.username]);
            if(d.creator===session.username||contributors.rowCount) throw new WorkflowError(403,'SELF_APPROVAL');
            state=action==='approve'?'APPROVED':'REJECTED';
            await c.query('UPDATE wf_draft SET approver=$2 WHERE draft_id=$1',[id,session.username]);
          } else if(action==='commit') {
            if(state!=='APPROVED') throw new WorkflowError(409,'APPROVAL_REQUIRED');
            const current=await c.query('SELECT h.version,v.payload FROM wf_record h LEFT JOIN wf_version v ON v.registry_id=h.registry_id AND v.record_id=h.record_id AND v.version=h.version WHERE h.registry_id=$1 AND h.record_id=$2 FOR UPDATE OF h',[ctx.registryId,d.record_id]);
            if(current.rows[0]?.payload) workflowScope(session,ctx.registryId,d.record_id,current.rows[0].payload,true);
            committed=await appendWorkflowVersion(c,{registryId:ctx.registryId,recordId:d.record_id,baseVersion:d.base_version,payload:d.payload,payloadHash:hash,operation:d.operation,creator:d.creator,approver:d.approver,evidence:{draftId:id,revision,payloadHash:hash,baseVersion:d.base_version}});
            state='COMMITTED';
          }
          await c.query('UPDATE wf_draft SET state=$2,committed_version=$3 WHERE draft_id=$1',[id,state,state==='COMMITTED'?d.base_version+1:null]);
        }
        await audit(c,ctx.registryId,session.username,String(action).toUpperCase(),{draftId:id,revision,payloadHash:hash,baseVersion:d.base_version});
        response={status:200,body:{draftId:id,revision,payloadHash:hash,baseVersion:d.base_version,state,...(committed?{committed}: {})}};
      }
      await c.query('INSERT INTO wf_request VALUES($1,$2,$3,$4,$5)',[ctx.registryId,session.username,req.idempotencyKey,requestHash,JSON.stringify(response)]);
      return response;
    });
  } catch(e) { if(e instanceof WorkflowError || e instanceof AuthorizationError) return {status:e.status,body:{error:e.code}}; throw e; }
}


/** Deployment-owned keys bind stable human identities, never caller supplied keys/booleans. */
export interface WorkflowSourceTrust {
  registryId: string;
  sourceId: string;
  sourceKey: KeyObject;
  people: ReadonlyMap<string, { key: KeyObject; permissions: readonly ('draft' | 'approve')[] }>;
}
export interface WorkflowSourceEvent {
  version: 1;
  registryId: string;
  sourceId: string;
  cursor: number;
  recordId: string;
  baseVersion: number;
  operation: 'upsert' | 'tombstone';
  payload: Record<string, unknown>;
  payloadHash: string;
  creator: string;
  approver: string;
}
export function sourceSigningBytes(event: WorkflowSourceEvent): Buffer {
  return Buffer.from('ONELAYER:WORKFLOW:SOURCE:V1\n' + canonicalWorkflow(event));
}
export async function ingestWorkflowSource(pool: Pool, trust: WorkflowSourceTrust, envelope: {
  event: WorkflowSourceEvent; sourceSignature: string; creatorSignature: string; approverSignature: string;
}) {
  // Snapshot before the first await; caller mutation must never change verified or persisted bytes.
  envelope = JSON.parse(canonicalWorkflow(envelope));
  const e = envelope.event;
  if (!e || e.version !== 1 || e.registryId !== trust.registryId || e.sourceId !== trust.sourceId) throw new WorkflowError(403, 'SOURCE_SCOPE');
  identifier(e.recordId); integer(e.baseVersion);
  if (integer(e.cursor) === 0) throw new WorkflowError(400, 'INVALID_CURSOR');
  const input = payloadInput(e as unknown as Record<string, unknown>);
  if (input.hash !== e.payloadHash) throw new WorkflowError(409, 'APPROVAL_BINDING_MISMATCH');
  if (e.creator === e.approver) throw new WorkflowError(403, 'SELF_APPROVAL');
  const creator = trust.people.get(e.creator), approver = trust.people.get(e.approver);
  if (creator && approver && creator.key.export({type:'spki',format:'der'}).equals(approver.key.export({type:'spki',format:'der'}))) throw new WorkflowError(403,'SELF_APPROVAL');
  const bytes = sourceSigningBytes(e);
  const valid = (key: KeyObject | undefined, signature: unknown) => {
    if (!key || key.asymmetricKeyType !== 'ed25519' || typeof signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(signature)) return false;
    try { return verify(null, bytes, key, Buffer.from(signature, 'base64url')); } catch { return false; }
  };
  if (!creator?.permissions.includes('draft') || !approver?.permissions.includes('approve') ||
      !valid(trust.sourceKey, envelope.sourceSignature) || !valid(creator.key, envelope.creatorSignature) ||
      !valid(approver.key, envelope.approverSignature)) throw new WorkflowError(403, 'SOURCE_SIGNATURE');
  return workflowTransaction(pool, async c => {
    await c.query('INSERT INTO wf_source_cursor(registry_id,source_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[e.registryId,e.sourceId]);
    const cursor = await c.query('SELECT cursor FROM wf_source_cursor WHERE registry_id=$1 AND source_id=$2 FOR UPDATE',[e.registryId,e.sourceId]);
    const hash = workflowHash(e);
    const previous = await c.query('SELECT event_hash,response FROM wf_source_event WHERE registry_id=$1 AND source_id=$2 AND cursor=$3',[e.registryId,e.sourceId,e.cursor]);
    if (previous.rowCount) {
      if (previous.rows[0].event_hash !== hash) throw new WorkflowError(409,'SOURCE_EQUIVOCATION');
      return previous.rows[0].response;
    }
    if (BigInt(e.cursor) !== BigInt(cursor.rows[0].cursor) + 1n) throw new WorkflowError(409,'SOURCE_CURSOR_GAP');
    const response = await appendWorkflowVersion(c,{registryId:e.registryId,recordId:e.recordId,baseVersion:e.baseVersion,payload:e.payload,payloadHash:e.payloadHash,operation:e.operation,creator:e.creator,approver:e.approver,evidence:envelope});
    await c.query('INSERT INTO wf_source_event VALUES($1,$2,$3,$4,$5)',[e.registryId,e.sourceId,e.cursor,hash,JSON.stringify(response)]);
    await c.query('UPDATE wf_source_cursor SET cursor=$3 WHERE registry_id=$1 AND source_id=$2',[e.registryId,e.sourceId,e.cursor]);
    return response;
  });
}
