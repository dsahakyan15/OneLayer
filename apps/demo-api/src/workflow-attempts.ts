import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { AuthorizationError, requirePermission, type AdminSession } from './admin-session.ts';
import { requireResourceAccess } from './resource-access.ts';
import { WorkflowError, workflowHash, workflowScope, workflowTransaction, payloadInput } from './registry-workflow.ts';

type Request = {method:string;path:string;body:Record<string,unknown>|null};
const ROOT='/v2/admin/workflow/attempts';
const UUID='[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}';
const TARGET=new RegExp(`^/v2/admin/workflow/drafts(?:/(${UUID})/(edit|submit|approve|reject|commit))?$`);
const ACK=new RegExp(`^${ROOT}/(${UUID})/(ack|cancel)$`);
const permission=(action:string)=>action==='approve'||action==='reject'?'records.approve':'records.draft';
function fields(payload:unknown,prefix='',result=new Set<string>()):Set<string> {
 if(payload&&typeof payload==='object') for(const [key,value] of Object.entries(payload)) {
  const path=prefix?`${prefix}.${key}`:key; result.add(path); fields(value,path,result);
 }
 return result;
}
function authorize(session:AdminSession,registryId:string,row:any) {
 requirePermission(session,registryId,'records.read'); requirePermission(session,registryId,permission(row.action));
 for(const action of ['records.read','records.write'] as const) requireResourceAccess(session.resourcePolicy,
  {registryId,recordId:row.record_id,fieldPaths:row.field_paths,action});
}
async function view(c:PoolClient,registryId:string,session:AdminSession,row:any) {
 authorize(session,registryId,row);
 const response=(await c.query('SELECT response FROM wf_request WHERE registry_id=$1 AND actor=$2 AND idempotency_key=$3',
  [registryId,session.username,row.attempt_id])).rows[0]?.response;
 const draftId=response?.body?.draftId??row.draft_id;
 if(draftId) {
  const draft=(await c.query(`SELECT d.record_id,r.payload FROM wf_draft d JOIN wf_revision r ON r.draft_id=d.draft_id AND r.revision=d.revision
   WHERE d.registry_id=$1 AND d.draft_id=$2`,[registryId,draftId])).rows[0];
  if(!draft) throw new WorkflowError(404,'ATTEMPT_NOT_FOUND');
  workflowScope(session,registryId,draft.record_id,draft.payload,false);
  workflowScope(session,registryId,draft.record_id,draft.payload,true);
 }
 return {attemptId:row.attempt_id,idempotencyKey:row.attempt_id,state:response?'COMPLETED':'PREPARED',
  draftId:draftId??null,action:row.action,recordId:row.record_id};
}
/** Preparing a receipt never executes an operation; acknowledging never erases
 * the original immutable idempotency result. No browser persistence is needed. */
export async function routeWorkflowAttempts(ctx:{pool:Pool;registryId:string},req:Request,session:AdminSession) {
 if(req.path!==ROOT&&!req.path.startsWith(ROOT+'/')) return null;
 const ack=ACK.exec(req.path);
 if(req.path!==ROOT&&!ack) throw new WorkflowError(404,'NOT_FOUND');
 if(req.method!=='POST'&&!(req.method==='GET'&&req.path===ROOT)) throw new WorkflowError(405,'METHOD_NOT_ALLOWED');
 requirePermission(session,ctx.registryId,'records.read');
 return workflowTransaction(ctx.pool,async c=>{
  // One actor lock protects duplicate preparations and the pending quota.
  await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
   [JSON.stringify(['workflow-attempts',ctx.registryId,session.username])]);
  if(ack) {
   if(req.body&&Object.keys(req.body).length) throw new WorkflowError(400,'INVALID_ATTEMPT');
   const row=(await c.query('SELECT * FROM wf_attempt WHERE registry_id=$1 AND actor=$2 AND attempt_id=$3',
    [ctx.registryId,session.username,ack[1]])).rows[0];
   if(!row) throw new WorkflowError(404,'ATTEMPT_NOT_FOUND');
   await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[JSON.stringify([ctx.registryId,session.username,row.attempt_id])]);
   const receipt=await view(c,ctx.registryId,session,row);
   const cancelled=(await c.query('SELECT 1 FROM wf_attempt_cancel WHERE attempt_id=$1',[row.attempt_id])).rowCount;
   if(ack[2]==='cancel') {
    if(receipt.state==='COMPLETED') throw new WorkflowError(409,'ATTEMPT_ALREADY_COMPLETED');
    await c.query('INSERT INTO wf_attempt_cancel(attempt_id) VALUES($1) ON CONFLICT DO NOTHING',[row.attempt_id]);
    return {status:200,body:{cancelled:true}};
   }
   if(cancelled) throw new WorkflowError(409,'ATTEMPT_CANCELLED');
   if(receipt.state!=='COMPLETED') throw new WorkflowError(409,'ATTEMPT_UNCONFIRMED');
   await c.query('INSERT INTO wf_attempt_ack(attempt_id) VALUES($1) ON CONFLICT DO NOTHING',[row.attempt_id]);
   return {status:200,body:{acknowledged:true}};
  }
  if(req.method==='GET') {
   const rows=(await c.query(`SELECT a.* FROM wf_attempt a LEFT JOIN wf_attempt_ack k USING(attempt_id) LEFT JOIN wf_attempt_cancel z USING(attempt_id)
    WHERE a.registry_id=$1 AND a.actor=$2 AND k.attempt_id IS NULL AND z.attempt_id IS NULL ORDER BY a.created_at,a.attempt_id`,
    [ctx.registryId,session.username])).rows;
   const attempts=[];
   for(const row of rows) {
    try {attempts.push(await view(c,ctx.registryId,session,row));}
    catch(error) {if(!(error instanceof AuthorizationError||error instanceof WorkflowError&&error.status===404)) throw error;}
   }
   return {status:200,body:{attempts}};
  }
  const input=req.body;
  if(!input||Object.keys(input).sort().join(',')!=='body,path'||typeof input.path!=='string'||
   !input.body||typeof input.body!=='object'||Array.isArray(input.body)) throw new WorkflowError(400,'INVALID_ATTEMPT');
  const match=TARGET.exec(input.path);
  if(!match) throw new WorkflowError(400,'INVALID_ATTEMPT');
  const body=input.body as Record<string,unknown>,action=match[2]??'create';
  requirePermission(session,ctx.registryId,permission(action));
  const requestHash=workflowHash({method:'POST',path:input.path,body});
  const existing=(await c.query(`SELECT a.* FROM wf_attempt a LEFT JOIN wf_attempt_ack k USING(attempt_id) LEFT JOIN wf_attempt_cancel z USING(attempt_id)
   WHERE a.registry_id=$1 AND a.actor=$2 AND a.request_hash=$3 AND k.attempt_id IS NULL AND z.attempt_id IS NULL`,
   [ctx.registryId,session.username,requestHash])).rows[0];
  if(existing) return {status:200,body:await view(c,ctx.registryId,session,existing)};
  const fieldPaths=new Set<string>();
  let recordId:string;
  if(!match[1]) {
   if(typeof body.recordId!=='string'||!/^[a-zA-Z0-9_.:-]{1,128}$/.test(body.recordId)||
    !Number.isSafeInteger(body.baseVersion)||Number(body.baseVersion)<0) throw new WorkflowError(400,'INVALID_ATTEMPT');
   recordId=body.recordId;
  } else {
   const draft=(await c.query(`SELECT d.record_id,d.base_version,r.payload FROM wf_draft d JOIN wf_revision r ON r.draft_id=d.draft_id AND r.revision=d.revision
    WHERE d.registry_id=$1 AND d.draft_id=$2`,[ctx.registryId,match[1]])).rows[0];
   if(!draft) throw new WorkflowError(404,'DRAFT_NOT_FOUND');
   recordId=draft.record_id;
   workflowScope(session,ctx.registryId,recordId,draft.payload,false);
   workflowScope(session,ctx.registryId,recordId,draft.payload,true);
   fields(draft.payload,'',fieldPaths);
   const base=(await c.query('SELECT payload FROM wf_version WHERE registry_id=$1 AND record_id=$2 AND version=$3',
    [ctx.registryId,recordId,draft.base_version])).rows[0];
   if(base) fields(base.payload,'',fieldPaths);
   if(!Number.isSafeInteger(body.expectedRevision)||Number(body.expectedRevision)<1) throw new WorkflowError(400,'INVALID_VERSION');
  }
  if(action==='create'||action==='edit') fields(payloadInput(body).payload,'',fieldPaths);
  const current=(await c.query(`SELECT v.payload FROM wf_record h JOIN wf_version v ON v.registry_id=h.registry_id AND v.record_id=h.record_id AND v.version=h.version
   WHERE h.registry_id=$1 AND h.record_id=$2`,[ctx.registryId,recordId])).rows[0];
  if(current) fields(current.payload,'',fieldPaths);
  const row={attempt_id:randomUUID(),action,record_id:recordId,draft_id:match[1]??null,field_paths:[...fieldPaths]};
  authorize(session,ctx.registryId,row);
  // Invisible historical receipts must not permanently lock out a principal
  // whose resource policy was narrowed. Retain them as evidence, but charge
  // only receipts the principal can currently recover or cancel.
  const pending=(await c.query(`SELECT a.* FROM wf_attempt a LEFT JOIN wf_attempt_ack k USING(attempt_id) LEFT JOIN wf_attempt_cancel z USING(attempt_id)
   WHERE a.registry_id=$1 AND a.actor=$2 AND k.attempt_id IS NULL AND z.attempt_id IS NULL`,[ctx.registryId,session.username])).rows;
  let count=0;
  for(const entry of pending) {
   try {await view(c,ctx.registryId,session,entry);count++;}
   catch(error) {if(!(error instanceof AuthorizationError||error instanceof WorkflowError&&error.status===404)) throw error;}
   if(count>=100) throw new WorkflowError(429,'ATTEMPT_LIMIT_REACHED');
  }
  await c.query(`INSERT INTO wf_attempt(attempt_id,registry_id,actor,request_hash,action,record_id,draft_id,field_paths)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,[row.attempt_id,ctx.registryId,session.username,requestHash,action,recordId,row.draft_id,JSON.stringify(row.field_paths)]);
  return {status:200,body:await view(c,ctx.registryId,session,row)};
 });
}
