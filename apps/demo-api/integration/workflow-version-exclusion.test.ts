import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { FakeChain, TestSigner, publisher, stepReviewed } from './support/publication-fake-chain.ts';
import { isolatedPostgres } from './support/postgres.ts';
import { routeWorkflow, workflowHash, appendWorkflowVersion, workflowTransaction } from '../src/registry-workflow.ts';
import { versionExclusion } from '../src/publication-maintenance.ts';
import { WorkflowPublicationStore } from '../src/workflow-publication.ts';
import type { AdminSession } from '../src/admin-session.ts';

const session = (username: string): AdminSession => ({username,sessionId:username,role:'registry_approver',csrfToken:'synthetic',expiresAt:Date.now()+60000,permissions:['records.read','publication.maintenance'],registryIds:['synthetic'],resourcePolicy:{version:1,grants:[{registryId:'synthetic',recordIds:'all',fieldPaths:'all',actions:['records.read']}]}});

for (const alreadyClaimed of [false,true]) test(`legacy exclusion preserves immutable history (already claimed: ${alreadyClaimed})`, {timeout:60000}, async t => {
  const {pool}=await isolatedPostgres(t);
  const payload={value:1.5}, payloadHash=workflowHash({operation:'upsert',payload});
  // Reproduce a version persisted under the legacy V1 contract, without mutating history.
  await pool.query("INSERT INTO wf_record VALUES('synthetic','legacy',1)");
  await pool.query("INSERT INTO wf_version VALUES('synthetic','legacy',1,$1,$2,'upsert','author','original-approver','{}')",[payload,payloadHash]);
  await pool.query("INSERT INTO wf_outbox(event_id,registry_id,record_id,version,payload_hash) VALUES($1,'synthetic','legacy',1,$2)",[randomUUID(),payloadHash]);
  const correction=await workflowTransaction(pool,c=>appendWorkflowVersion(c,{registryId:'synthetic',recordId:'legacy',baseVersion:1,operation:'tombstone',payload:{},payloadHash:workflowHash({operation:'tombstone',payload:{}}),creator:'author',approver:'original-approver',evidence:{synthetic:true}}));
  const store=new WorkflowPublicationStore(pool);
  const original=alreadyClaimed ? (await store.claim('synthetic','worker'))! : null;
  const chain=new FakeChain(), signer=new TestSigner(), worker=publisher(pool,chain,signer);
  if(original) await assert.rejects(stepReviewed(worker, original),/PUBLICATION_UNPUBLISHABLE_VERSION/);
  const body={recordId:'legacy',version:1,payloadHash,correctedByVersion:2,correctedPayloadHash:correction.payloadHash,reason:'Legacy number cannot be published; corrected with tombstone.'};
  const call=async (who:AdminSession,path:string,body:Record<string,unknown>,key=randomUUID())=>{ const result=await routeWorkflow({pool,registryId:'synthetic'},{method:'POST',path:'/v2/admin/workflow/exclusions'+path,body,idempotencyKey:key},who); if(result.status>=400) throw new Error((result.body as {error:string}).error); return result; };
  await assert.rejects(call({...session('unauthorized'),permissions:['records.read']},'',body),/FORBIDDEN/);
  await assert.rejects(call({...session('scoped'),resourcePolicy:{version:1,grants:[]}},'',body),/RECORD_VERSION_NOT_FOUND/);
  for(const who of ['author','original-approver','AUTHOR']) await assert.rejects(call(session(who),'',body),/EXCLUSION_AUTHOR_APPROVAL/);
  await assert.rejects(call(session('first'),'',{...body,correctedPayloadHash:'0'.repeat(64)}),/EXCLUSION_BINDING_MISMATCH/);
  await assert.rejects(call(session('first'),'',{...body,correctedByVersion:3}),/EXCLUSION_CORRECTION_MISSING/);
  const key=randomUUID();
  const proposal=await call(session('first'),'',body,key);
  assert.deepEqual(await call(session('first'),'',body,key),proposal);
  await assert.rejects(call({...session('first'),resourcePolicy:{version:1,grants:[]}},'',body,key),/RECORD_VERSION_NOT_FOUND/);
  const id=(proposal.body as any).exclusionId;
  assert.equal((proposal.body as any).state,'PROPOSED');
  assert.equal(await versionExclusion(pool,'synthetic','legacy',1),null);
  const approve={payloadHash,correctedByVersion:2};
  await assert.rejects(call(session('FIRST'),`/${id}/approve`,approve),/APPROVER_NOT_INDEPENDENT/);
  await assert.rejects(call(session('author'),`/${id}/approve`,approve),/EXCLUSION_AUTHOR_APPROVAL/);
  await assert.rejects(call(session('second'),`/${id}/approve`,{...approve,payloadHash:'0'.repeat(64)}),/EXCLUSION_BINDING_MISMATCH/);
  const concurrent=await Promise.allSettled(['second','third'].map(who=>call(session(who),`/${id}/approve`,approve)));
  assert.equal(concurrent.filter(r=>r.status==='fulfilled').length,1);
  assert.equal(concurrent.filter(r=>r.status==='rejected').length,1);
  assert.deepEqual(await versionExclusion(pool,'synthetic','legacy',1),{state:'EXCLUDED_FROM_PUBLICATION',exclusionId:id,correctedByVersion:2,reason:body.reason,published:false,certificateEligible:false,current:false});
  if(original) {
    const result=await stepReviewed(worker, original);
    assert.equal(result.status,'SUPERSEDED');
    assert.equal((await pool.query('SELECT state FROM wf_publication WHERE operation_id=$1',[original.operationId])).rows[0].state,'ABANDONED');
    assert.equal((await pool.query('SELECT count(*) FROM wf_publication_item WHERE operation_id=$1',[original.operationId])).rows[0].count,'2');
    assert.equal(chain.sent.length,0); assert.equal(signer.requests.length,0);
  }
  const lease=(await store.claim('synthetic','worker'))!;
  assert.deepEqual((await store.items(lease)).map(v=>v.version),[2]);
  assert.equal((await pool.query('SELECT count(*) FROM wf_outbox')).rows[0].count,'2');
  assert.deepEqual((await pool.query("SELECT payload FROM wf_version WHERE version=1")).rows[0].payload,payload);
  assert.equal((await pool.query("SELECT count(*) FROM wf_audit WHERE action IN ('VERSION_EXCLUSION_PROPOSED','VERSION_EXCLUDED_FROM_PUBLICATION')")).rows[0].count,'2');
  for(const table of ['wf_version_exclusion','wf_version_exclusion_approval']) {
    await assert.rejects(pool.query(`DELETE FROM ${table}`),/immutable/);
    await assert.rejects(pool.query(`TRUNCATE ${table} CASCADE`),/immutable/);
  }
  await assert.rejects(call(session('fourth'),'',{...body,version:2,payloadHash:correction.payloadHash,correctedByVersion:2}),/EXCLUSION_CORRECTION_MISSING/);
});

test('exclusion refuses publishable targets and invalid legacy corrections', {timeout:60000}, async t => {
  const {pool}=await isolatedPostgres(t);
  const hashes:string[]=[];
  await pool.query("INSERT INTO wf_record VALUES('synthetic','legacy',3)");
  for(const [index,payload] of [{value:1.5},{value:2.5},{value:3}].entries()) {
    const hash=workflowHash({operation:'upsert',payload}); hashes.push(hash);
    await pool.query("INSERT INTO wf_version VALUES('synthetic','legacy',$1,$2,$3,'upsert','author','original-approver','{}')",[index+1,payload,hash]);
    await pool.query("INSERT INTO wf_outbox(event_id,registry_id,record_id,version,payload_hash) VALUES($1,'synthetic','legacy',$2,$3)",[randomUUID(),index+1,hash]);
  }
  const call=(version:number,correctedByVersion:number)=>routeWorkflow({pool,registryId:'synthetic'},{method:'POST',path:'/v2/admin/workflow/exclusions',idempotencyKey:randomUUID(),body:{recordId:'legacy',version,payloadHash:hashes[version-1],correctedByVersion,correctedPayloadHash:hashes[correctedByVersion-1],reason:'Synthetic corrective version for legacy data.'}},session('independent'));
  assert.deepEqual(await call(1,2),{status:409,body:{error:'EXCLUSION_CORRECTION_UNPUBLISHABLE'}});
  const correction=await workflowTransaction(pool,c=>appendWorkflowVersion(c,{registryId:'synthetic',recordId:'legacy',baseVersion:3,operation:'tombstone',payload:{},payloadHash:workflowHash({operation:'tombstone',payload:{}}),creator:'author',approver:'original-approver',evidence:{synthetic:true}}));
  hashes.push(correction.payloadHash);
  assert.deepEqual(await call(3,4),{status:409,body:{error:'EXCLUSION_VERSION_PUBLISHABLE'}});
  assert.equal((await pool.query('SELECT count(*) FROM wf_version_exclusion')).rows[0].count,'0');
});
