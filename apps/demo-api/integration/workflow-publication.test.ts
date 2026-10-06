import assert from 'node:assert/strict';
import test from 'node:test';
import { Pool } from 'pg';
import { isolatedPostgres } from './support/postgres.ts';
import { appendWorkflowVersion, workflowHash, workflowTransaction } from '../src/registry-workflow.ts';
import { WorkflowPublicationStore } from '../src/workflow-publication.ts';

const append = (pool: Pool, recordId: string, baseVersion = 0, registryId = 'synthetic') => workflowTransaction(pool,c => appendWorkflowVersion(c,{registryId,recordId,baseVersion,operation:'upsert',payload:{value:baseVersion+1},payloadHash:workflowHash({operation:'upsert',payload:{value:baseVersion+1}}),creator:'alice',approver:'bob',evidence:{synthetic:true}}));
test('publication survives worker crash with immutable membership and fenced exclusive leases', {timeout:60000},async t => {
  const {pool,connectionString}=await isolatedPostgres(t);
  await append(pool,'first'); await append(pool,'first',1); await append(pool,'second');
  const store = new WorkflowPublicationStore(pool);
  assert.equal(await store.claim('empty','worker'),null);
  const concurrent=await Promise.all([store.claim('synthetic','worker-a',30000,2),store.claim('synthetic','worker-b',30000,2)]);
  assert.equal(concurrent.filter(Boolean).length,1);
  const original=concurrent.find(Boolean)!;
  const items=await store.items(original);
  assert.deepEqual(items.map(i=>[i.recordId,i.version]),[['first',1],['first',2]]);
  await append(pool,'later');
  assert.deepEqual(await store.items(original),items);
  assert.equal(await store.claim('synthetic',original.worker),null);
  const renewed=await store.renew(original);
  assert.equal(renewed.fence,original.fence);
  // Simulate loss of the process after a committed claim. Reconnect through a
  // fresh pool, then expire using DB time without wall-clock flakiness.
  await pool.query("UPDATE wf_publication SET lease_until=clock_timestamp()-interval '1 second'");
  const replacementPool=new Pool({connectionString}); replacementPool.on('error',()=>{});
  t.after(async()=>{ if (!replacementPool.ended) await replacementPool.end(); });
  const replacement=new WorkflowPublicationStore(replacementPool);
  const reclaimed=(await replacement.claim('synthetic','worker-c'))!;
  assert.equal(reclaimed.operationId,original.operationId);
  assert.equal(BigInt(reclaimed.fence),BigInt(original.fence)+1n);
  assert.deepEqual(await replacement.items(reclaimed),items);
  for (const stale of [()=>store.items(original),()=>store.renew(original),()=>store.release(original)]) await assert.rejects(stale,{message:'PUBLICATION_LEASE_LOST'});
  await assert.rejects(store.items({...reclaimed,registryId:'other'}),{message:'PUBLICATION_LEASE_LOST'});
  await replacement.release(reclaimed);
  await assert.rejects(replacement.renew(reclaimed),{message:'PUBLICATION_LEASE_LOST'});
  const again=(await store.claim('synthetic','worker-a'))!;
  assert.equal(again.operationId,original.operationId);
  assert.deepEqual(await store.items(again),items);
  const mutable={...again};
  const pending=store.items(mutable);
  mutable.registryId='attacker-changed'; mutable.worker='other'; mutable.fence='999';
  assert.deepEqual(await pending,items);
  assert.equal((await pool.query('SELECT count(*) FROM wf_outbox')).rows[0].count,'4');
  assert.equal((await pool.query('SELECT count(*) FROM wf_publication')).rows[0].count,'1');
  assert.deepEqual((await pool.query('SELECT action FROM wf_publication_attempt ORDER BY attempt_id')).rows.map(r=>r.action),['CLAIM','RENEW','RECLAIM','RELEASE','RECLAIM']);
  for(const table of ['wf_publication_item','wf_publication_attempt']) await assert.rejects(pool.query(`DELETE FROM ${table}`),/immutable/);
  await append(pool,'other',0,'other');
  assert.ok(await store.claim('other','worker-a'));
  await replacementPool.end();
});

test('publication claim is atomic and rejects inconsistent committed payload evidence',{timeout:60000},async t=>{
  const {pool}=await isolatedPostgres(t);
  await append(pool,'record');
  const store=new WorkflowPublicationStore(pool);
  await pool.query("CREATE FUNCTION synthetic_claim_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic crash'; END $$; CREATE TRIGGER synthetic_failure BEFORE INSERT ON wf_publication_attempt FOR EACH ROW EXECUTE FUNCTION synthetic_claim_failure()");
  await assert.rejects(store.claim('synthetic','worker'),/synthetic crash/);
  assert.equal((await pool.query('SELECT count(*) FROM wf_publication')).rows[0].count,'0');
  assert.equal((await pool.query('SELECT count(*) FROM wf_publication_item')).rows[0].count,'0');
  await pool.query('DROP TRIGGER synthetic_failure ON wf_publication_attempt');
  const lease=(await store.claim('synthetic','worker'))!;
  // Privileged test-only corruption; application writers cannot alter evidence.
  await pool.query('ALTER TABLE wf_version DISABLE TRIGGER immutable');
  await pool.query("UPDATE wf_version SET payload='{}'");
  await pool.query('ALTER TABLE wf_version ENABLE TRIGGER immutable');
  await assert.rejects(store.items(lease),{message:'PUBLICATION_PAYLOAD_MISMATCH'});
  await assert.rejects(store.claim('synthetic','worker',0),{message:'INVALID_LEASE_DURATION'});
});

test('lease expiration is checked after acquiring a contended row lock',{timeout:60000},async t=>{
  const {pool}=await isolatedPostgres(t); await append(pool,'record');
  const store=new WorkflowPublicationStore(pool);
  const lease=(await store.claim('synthetic','worker',500))!;
  const blocker=await pool.connect();
  try {
    await blocker.query('BEGIN');
    await blocker.query('SELECT operation_id FROM wf_publication FOR UPDATE');
    const renewing=store.renew(lease);
    // Wait beyond expiry while holding a row lock without changing the row.
    await blocker.query('SELECT pg_sleep(0.7)');
    await blocker.query('COMMIT');
    await assert.rejects(renewing,{message:'PUBLICATION_LEASE_LOST'});
  } finally { await blocker.query('ROLLBACK'); blocker.release(); }
});
