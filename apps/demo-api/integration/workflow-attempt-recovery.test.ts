import assert from 'node:assert/strict';
import test from 'node:test';
import { Pool } from 'pg';
import { isolatedPostgres } from './support/postgres.ts';
import { routeWorkflow } from '../src/registry-workflow.ts';
import type { AdminSession } from '../src/admin-session.ts';
const ROOT='/v2/admin/workflow/attempts', DRAFTS='/v2/admin/workflow/drafts';
const session=(username='alice'):AdminSession=>({username,sessionId:username,role:'operator',csrfToken:'synthetic',expiresAt:Date.now()+60000,
 permissions:['records.read','records.draft','records.approve'],registryIds:['synthetic'],resourcePolicy:{version:1,grants:[
 {registryId:'synthetic',recordIds:'all',fieldPaths:'all',actions:['records.read','records.write']}]}});
const body={recordId:'restart-safe',baseVersion:0,operation:'upsert',payload:{owner:'Synthetic'}};
test('durable receipts survive lost responses and fresh connections; acknowledgements preserve replay',{timeout:60000},async t=>{
 const {pool,connectionString}=await isolatedPostgres(t);
 const call=(path:string,body:Record<string,unknown>|null=null,method='POST',key?:string,who=session(),db=pool)=>
 routeWorkflow({pool:db,registryId:'synthetic'},{method,path,body,idempotencyKey:key},who);
 const prepare=()=>call(ROOT,{path:DRAFTS,body});
 const results=await Promise.all([prepare(),prepare(),prepare()]);
 results.forEach(r=>assert.equal(r.status,200)); const receipt=results[0].body as any;
 assert.equal(receipt.state,'PREPARED'); assert.equal(receipt.draftId,null);
 assert.equal(new Set(results.map(r=>(r.body as any).idempotencyKey)).size,1);
 assert.equal((await call(`${ROOT}/${receipt.attemptId}/ack`,{})).status,409);
 assert.equal((await call(DRAFTS,{...body,recordId:'changed'},'POST',receipt.idempotencyKey)).status,409);
 assert.equal((await pool.query('SELECT count(*) FROM wf_draft')).rows[0].count,'0');
 const maintenance=session();maintenance.permissions=[...maintenance.permissions,'publication.maintenance'];
 const differentRoute=await call('/v2/admin/workflow/exclusions',{},'POST',receipt.idempotencyKey,maintenance);
 assert.equal(differentRoute.status,409);assert.deepEqual(differentRoute.body,{error:'IDEMPOTENCY_CONFLICT'});
 assert.equal((await pool.query('SELECT count(*) FROM wf_request WHERE idempotency_key=$1',[receipt.idempotencyKey])).rows[0].count,'0');
 const original=await call(DRAFTS,body,'POST',receipt.idempotencyKey); assert.equal(original.status,201);
 const fresh=new Pool({connectionString});
 try {
 const recovered=await call(ROOT,null,'GET',undefined,session(),fresh);
 const attempts=(recovered.body as any).attempts;
 assert.equal(attempts.length,1); assert.equal(attempts[0].state,'COMPLETED');
 assert.equal(attempts[0].draftId,(original.body as any).draftId);
 assert.equal(JSON.stringify(recovered.body).includes('Synthetic'),false);
 assert.deepEqual(await call(DRAFTS,body,'POST',receipt.idempotencyKey,session(),fresh),original);
 } finally {await fresh.end();}
 assert.equal(((await prepare()).body as any).idempotencyKey,receipt.idempotencyKey);
 assert.equal((await call(`${ROOT}/${receipt.attemptId}/ack`,{})).status,200);
 assert.equal((await call(`${ROOT}/${receipt.attemptId}/ack`,{})).status,200);
 assert.deepEqual((await call(ROOT,null,'GET')).body,{attempts:[]});
 const next=(await prepare()).body as any;
 assert.notEqual(next.idempotencyKey,receipt.idempotencyKey);
 assert.equal((await call(`${ROOT}/${next.attemptId}/cancel`,{})).status,200);
 assert.deepEqual(await call(DRAFTS,body,'POST',receipt.idempotencyKey),original);
 assert.equal((await pool.query('SELECT count(*) FROM wf_draft')).rows[0].count,'1');
 for(const table of ['wf_attempt','wf_attempt_ack','wf_attempt_cancel']) {
 await assert.rejects(pool.query(`DELETE FROM ${table}`),/immutable/);
 await assert.rejects(pool.query(`TRUNCATE ${table} CASCADE`),/immutable/);
 }
});
test('receipts hide foreign and revoked evidence; preparations enforce exact routes',{timeout:60000},async t=>{
 const {pool}=await isolatedPostgres(t);
 const call=(path:string,body:Record<string,unknown>|null=null,method='POST',who=session(),key?:string)=>
 routeWorkflow({pool,registryId:'synthetic'},{method,path,body,idempotencyKey:key},who);
 const receipt=(await call(ROOT,{path:DRAFTS,body})).body as any;
 const created=await call(DRAFTS,body,'POST',session(),receipt.idempotencyKey); assert.equal(created.status,201);
 assert.deepEqual((await call(ROOT,null,'GET',session('bob'))).body,{attempts:[]});
 assert.equal((await call(`${ROOT}/${receipt.attemptId}/ack`,{},'POST',session('bob'))).status,404);
 const denied=session(); denied.resourcePolicy={version:1,grants:[]};
 assert.deepEqual((await call(ROOT,null,'GET',denied)).body,{attempts:[]});
 assert.equal((await call(ROOT,{path:DRAFTS,body},'POST',denied)).status,403);
 assert.equal((await call(`${ROOT}/${receipt.attemptId}/ack`,{},'POST',denied)).status,403);
 const other=session(); other.registryIds=['other']; assert.equal((await call(ROOT,null,'GET',other)).status,403);
 const noRead=session(); noRead.permissions=['records.draft']; assert.equal((await call(ROOT,null,'GET',noRead)).status,403);
 for(const path of ['/v1/admin/publish',DRAFTS+'/invalid/edit',DRAFTS+'?x=1']) assert.equal((await call(ROOT,{path,body})).status,400);
 assert.equal((await call(ROOT+'/invalid/ack',{})).status,404);
 assert.equal((await call(ROOT,null,'DELETE')).status,405);
 assert.equal((await call(`${ROOT}/${receipt.attemptId}/ack`,{extra:true})).status,400);
 const draft=created.body as any,editBody={expectedRevision:1,operation:'upsert',payload:{}};
 const edit=(await call(ROOT,{path:`${DRAFTS}/${draft.draftId}/edit`,body:editBody})).body as any;
 assert.equal((await call(`${DRAFTS}/${draft.draftId}/edit`,editBody,'POST',session(),edit.idempotencyKey)).status,200);
 const narrow=session(); narrow.resourcePolicy={version:1,grants:[{registryId:'synthetic',recordIds:'all',fieldPaths:[],actions:['records.read','records.write']}]};
 assert.deepEqual((await call(ROOT,null,'GET',narrow)).body,{attempts:[]});
});

test('cancellation fences late and concurrent mutation without losing completed evidence',{timeout:60000},async t=>{
 const {pool}=await isolatedPostgres(t);
 const call=(path:string,body:Record<string,unknown>|null=null,key?:string,method='POST')=>
 routeWorkflow({pool,registryId:'synthetic'},{method,path,body,idempotencyKey:key},session());
 const prepare=async(recordId:string)=>(await call(ROOT,{path:DRAFTS,body:{...body,recordId}})).body as any;
 const receipt=await prepare('cancelled');
 assert.equal((await call(`${ROOT}/${receipt.attemptId}/cancel`,{})).status,200);
 assert.equal((await call(`${ROOT}/${receipt.attemptId}/cancel`,{})).status,200);
 assert.equal((await call(DRAFTS,{...body,recordId:'cancelled'},receipt.idempotencyKey)).status,409);
 assert.equal((await pool.query('SELECT count(*) FROM wf_draft')).rows[0].count,'0');
 const maintenance=session();maintenance.permissions=[...maintenance.permissions,'publication.maintenance'];
 const wrongPath=await routeWorkflow({pool,registryId:'synthetic'},{method:'POST',path:'/v2/admin/workflow/exclusions',body:{},idempotencyKey:receipt.idempotencyKey},maintenance);
 assert.equal(wrongPath.status,409);assert.deepEqual(wrongPath.body,{error:'ATTEMPT_CANCELLED'});
 assert.deepEqual((await call(ROOT,null,undefined,'GET')).body,{attempts:[]});
 assert.notEqual((await prepare('cancelled')).idempotencyKey,receipt.idempotencyKey);
 // Hold the actual mutation key lock: send and cancel race on independent connections.
 const race=await prepare('race'),lock=await pool.connect();
 await lock.query('BEGIN');
 await lock.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[JSON.stringify(['synthetic','alice',race.idempotencyKey])]);
 const sending=call(DRAFTS,{...body,recordId:'race'},race.idempotencyKey);
 const cancelling=call(`${ROOT}/${race.attemptId}/cancel`,{});
 await lock.query('COMMIT');lock.release();
 const [sent,cancelled]=await Promise.all([sending,cancelling]);
 assert.ok(sent.status===201&&cancelled.status===409||sent.status===409&&cancelled.status===200);
 const n=(await pool.query("SELECT count(*)::integer AS n FROM wf_draft WHERE record_id='race'")).rows[0].n;
 assert.equal(n,sent.status===201?1:0);
 if(sent.status===201) assert.deepEqual(await call(DRAFTS,{...body,recordId:'race'},race.idempotencyKey),sent);
 else assert.equal((await call(DRAFTS,{...body,recordId:'race'},race.idempotencyKey)).status,409);
});

test('draft discovery is paginated on visible UUIDs and never leaks hidden ids or payloads',{timeout:60000},async t=>{
 const {pool}=await isolatedPostgres(t);
 const call=(req:any,who=session())=>routeWorkflow({pool,registryId:'synthetic'},req,who);
 for(let n=0;n<52;n++) {
  const response=await call({method:'POST',path:DRAFTS,body:{...body,recordId:`visible-${n}`},idempotencyKey:`list-${n}`});
  assert.equal(response.status,201);
 }
 const hidden=await call({method:'POST',path:DRAFTS,body:{...body,recordId:'hidden'},idempotencyKey:'hidden'});
 const who=session('approver');who.permissions=['records.read','records.approve'];
 who.resourcePolicy={version:1,grants:[{registryId:'synthetic',recordIds:Array.from({length:52},(_,n)=>`visible-${n}`),fieldPaths:'all',actions:['records.read']}]};
 const first=await call({method:'GET',path:DRAFTS,body:null},who);
 assert.equal(first.status,200);const page=first.body as any;
 assert.equal(page.drafts.length,50);assert.equal(page.nextCursor,page.drafts[49].draft_id);
 assert.equal(JSON.stringify(page).includes((hidden.body as any).draftId),false);
 assert.equal(JSON.stringify(page).includes('Synthetic'),false);
 assert.ok(page.drafts.every((d:any)=>!Object.hasOwn(d,'payload')));
 const second=(await call({method:'GET',path:DRAFTS,body:null,query:new URLSearchParams({after:page.nextCursor})},who)).body as any;
 assert.equal(second.drafts.length,2);assert.equal(second.nextCursor,null);
 assert.equal(new Set([...page.drafts,...second.drafts].map((d:any)=>d.draft_id)).size,52);
 const denied=session();denied.resourcePolicy={version:1,grants:[]};
 assert.deepEqual((await call({method:'GET',path:DRAFTS,body:null},denied)).body,{drafts:[],nextCursor:null});
 assert.equal((await call({method:'GET',path:DRAFTS,body:null,query:new URLSearchParams({after:'invalid'})})).status,400);
});

test('quota excludes newly forbidden receipts while keeping durable evidence',{timeout:60000},async t=>{
 const {pool}=await isolatedPostgres(t);
 const call=(recordId:string,who=session())=>routeWorkflow({pool,registryId:'synthetic'},
 {method:'POST',path:ROOT,body:{path:DRAFTS,body:{...body,recordId}}},who);
 for(let n=0;n<100;n++) assert.equal((await call(`old-${n}`)).status,200);
 assert.equal((await call('over-limit')).status,429);
 const narrow=session();narrow.resourcePolicy={version:1,grants:[{registryId:'synthetic',recordIds:['new-access'],fieldPaths:'all',actions:['records.read','records.write']}]};
 assert.deepEqual((await routeWorkflow({pool,registryId:'synthetic'},{method:'GET',path:ROOT,body:null},narrow)).body,{attempts:[]});
 assert.equal((await call('new-access',narrow)).status,200);
 assert.equal((await pool.query('SELECT count(*)::integer AS n FROM wf_attempt')).rows[0].n,101);
});
