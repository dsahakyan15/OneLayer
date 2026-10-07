import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { isolatedPostgres } from './support/postgres.ts';
import { WorkflowPublicationStore } from '../src/workflow-publication.ts';
import { WorkflowPublicationRuntime } from '../src/workflow-runtime.ts';
import { append, FakeChain, TestSigner, CONFIG_PDA, KEYS, PROGRAM_ID, REGISTRY, TEST_CLUSTER, TEST_GENESIS, approvalService, APPROVAL_ACTOR, APPROVAL_DEVICE } from './support/publication-fake-chain.ts';

test('targeted reconciliation renews/reclaims its lease without claiming a different operation', {timeout:60000}, async t => {
  const {pool} = await isolatedPostgres(t);
  await append(pool, 'lease-demo', {value:1});
  const runtime = new WorkflowPublicationRuntime(pool, new FakeChain(), new TestSigner(), {
    registryId:REGISTRY,programId:PROGRAM_ID,configPda:CONFIG_PDA,operatorKeyId:'test',keys:KEYS,
    cluster:TEST_CLUSTER,genesisHash:TEST_GENESIS,
  }, approvalService());
  const {operationId} = await runtime.review(REGISTRY, 'worker');
  const store = new WorkflowPublicationStore(pool);
  const original = (await store.leaseFor(REGISTRY,'worker'))!;
  await pool.query("UPDATE wf_publication SET lease_until=clock_timestamp()+interval '1 second' WHERE operation_id=$1",[operationId]);
  await runtime.review(REGISTRY,'worker',operationId);
  const renewed = (await store.leaseFor(REGISTRY,'worker'))!;
  assert.equal(renewed.fence,original.fence);
  assert.ok(Date.parse(renewed.leaseUntil)-Date.now()>20000);
  await pool.query("UPDATE wf_publication SET lease_until=clock_timestamp()-interval '1 second' WHERE operation_id=$1",[operationId]);
  const eventsBefore = (await pool.query('SELECT count(*)::int AS n FROM wf_publication_attempt')).rows[0].n;
  assert.deepEqual(await runtime.run(REGISTRY,'worker',undefined,randomUUID()),{status:'IDLE'});
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM wf_publication_attempt')).rows[0].n,eventsBefore);
  await runtime.review(REGISTRY,'worker',operationId);
  const reclaimed = (await store.leaseFor(REGISTRY,'worker'))!;
  assert.equal(reclaimed.operationId,operationId);
  assert.equal(BigInt(reclaimed.fence),BigInt(original.fence)+1n);
  const ready = await runtime.review(REGISTRY,'worker',operationId);
  await runtime.run(REGISTRY,'worker',{attemptPlanHash:ready.review.attemptPlanHash!,actor:APPROVAL_ACTOR,device:APPROVAL_DEVICE},operationId);
  assert.equal((await runtime.run(REGISTRY,'worker',undefined,operationId)).status,'FINALIZED');
  await append(pool, 'next-queued-record', {value:2});
  assert.deepEqual(await runtime.run(REGISTRY,'worker',undefined,operationId),{status:'IDLE'});
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM wf_publication')).rows[0].n,1);
});
