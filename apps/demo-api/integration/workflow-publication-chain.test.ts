// Ticket 09: intent, fenced attempt journal, reconciliation, trusted finalized
// completion and maintenance exit against real PostgreSQL and an in-process
// fake chain. The fake decodes the actual signed wire bytes and applies a
// SUBSET of the registry program's publish checks (blockhash validity,
// signature presence, paused, sequence, previous-anchor chain, ledger day). It
// does not verify ed25519 signatures, roles, segment PDAs or capacity; the
// live-validator test covers the real program.
import assert from 'node:assert/strict';
import test from 'node:test';
import { Pool } from 'pg';
import { isolatedPostgres } from './support/postgres.ts';
import { workflowHash } from '../src/registry-workflow.ts';
import { WorkflowPublicationStore } from '../src/workflow-publication.ts';
import { intentBytesHash } from '../src/publication-intent.ts';
import { append, count, expire, FakeChain, NOON, opState, publisher, REGISTRY, states, stepReviewed, TestSigner } from './support/publication-fake-chain.ts';

test('timeout-after-send reconciles the landed transaction; FINALIZED unblocks the next operation', { timeout: 60000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  await append(pool, 'first', { owner: 'A', area: 10 }); await append(pool, 'second', { owner: 'B', tags: ['x', 1, true, null] });
  const chain = new FakeChain(); const signer = new TestSigner(); const worker = publisher(pool, chain, signer);
  const store = new WorkflowPublicationStore(pool);
  const lease = (await store.claim(REGISTRY, 'worker-a'))!;
  chain.mode = 'land-then-throw';
  const first = await stepReviewed(worker, lease);
  assert.equal(first.status, 'UNKNOWN');
  chain.mode = 'land';
  // Entry not (yet) visible to the node answering the segment read: retryable, not a mismatch.
  chain.blankSegmentReads = 1;
  await assert.rejects(stepReviewed(worker, lease), { message: 'PUBLICATION_ANCHOR_NOT_VISIBLE' });
  assert.equal((await opState(pool, lease.operationId)).blocked_reason, null);
  const done = await stepReviewed(worker, lease);
  assert.equal(done.status, 'FINALIZED');
  assert.equal(done.signature, first.signature);
  assert.equal(chain.sent.length, 1, 'reconciliation found the landed signature instead of resending');
  assert.deepEqual(await states(pool), ['1:PREPARED', '1:SIGNED', '1:UNKNOWN', '1:FINALIZED']);
  // The signer saw exactly the reserved message; the journal holds exactly what was sent.
  const row = (await pool.query('SELECT s.signed_bytes,t.message_bytes,t.intent_hash FROM wf_publication_tx t JOIN wf_publication_tx_signed s USING(attempt_id)')).rows[0];
  assert.equal(row.signed_bytes.toString('base64'), chain.sent[0]);
  assert.equal(row.message_bytes.toString('base64'), signer.requests[0].messageBase64);
  const intentRow = (await pool.query('SELECT intent_bytes,intent_hash FROM wf_publication_intent')).rows[0];
  assert.equal(intentBytesHash(intentRow.intent_bytes), intentRow.intent_hash);
  assert.equal(row.intent_hash, intentRow.intent_hash);
  const intent = JSON.parse(intentRow.intent_bytes.toString());
  assert.equal(Buffer.from(chain.segment.entries[0].merkleRoot).toString('hex'), intent.merkleRoot);
  const anchor = (await pool.query('SELECT * FROM wf_publication_anchor')).rows[0];
  assert.equal(anchor.batch_sequence, '1'); assert.equal(anchor.merkle_root, intent.merkleRoot);
  assert.equal(anchor.anchor_hash, Buffer.from(chain.config.lastAnchorHash).toString('hex'));
  assert.equal((await opState(pool, lease.operationId)).state, 'FINALIZED');
  await assert.rejects(stepReviewed(worker, lease), { message: 'PUBLICATION_LEASE_LOST' });
  await assert.rejects(pool.query("UPDATE wf_publication SET state='OPEN'"), /terminal publication is immutable/);

  assert.equal(await store.claim(REGISTRY, 'worker-a'), null, 'nothing new to publish');
  await append(pool, 'third', { owner: 'C' });
  const next = (await store.claim(REGISTRY, 'worker-a'))!;
  assert.notEqual(next.operationId, lease.operationId);
  assert.deepEqual((await store.items(next)).map(i => i.recordId), ['third']);
  assert.equal((await stepReviewed(worker, next)).status, 'SUBMITTED');
  assert.equal((await stepReviewed(worker, next)).status, 'FINALIZED');
  const nextIntent = JSON.parse((await pool.query('SELECT intent_bytes FROM wf_publication_intent WHERE operation_id=$1', [next.operationId])).rows[0].intent_bytes.toString());
  assert.deepEqual([nextIntent.batchSequence, nextIntent.cursorStart, nextIntent.cursorEnd, nextIntent.previousAnchorHash], ['2', '3', '3', anchor.anchor_hash]);
  assert.equal(chain.config.currentBatchSequence, 2n);
});

test('crash between journal and send, stale fence, two workers and database guards', { timeout: 60000 }, async t => {
  const { pool, connectionString } = await isolatedPostgres(t);
  await append(pool, 'record', { value: 1 });
  const chain = new FakeChain(); const signer = new TestSigner();
  let crash = true;
  const workerA = publisher(pool, chain, signer, { afterAttemptStored: async () => { if (crash) { crash = false; throw new Error('synthetic crash before send'); } } });
  const leaseA = (await new WorkflowPublicationStore(pool).claim(REGISTRY, 'worker-a'))!;
  await assert.rejects(stepReviewed(workerA, leaseA), /synthetic crash before send/);
  assert.equal(chain.sent.length, 0);
  assert.deepEqual(await states(pool), ['1:PREPARED', '1:SIGNED']);
  const journaled = (await pool.query('SELECT signature FROM wf_publication_tx_signed')).rows[0].signature;

  await expire(pool);
  const poolB = new Pool({ connectionString }); poolB.on('error', () => {});
  t.after(async () => { if (!poolB.ended) await poolB.end(); });
  const leaseB = (await new WorkflowPublicationStore(poolB).claim(REGISTRY, 'worker-b'))!;
  assert.equal(leaseB.operationId, leaseA.operationId);
  const workerB = publisher(poolB, chain, signer);
  await assert.rejects(stepReviewed(workerA, leaseA), { message: 'PUBLICATION_LEASE_LOST' });
  assert.equal(chain.sent.length, 0);
  // Direct journal writes under a stale fence, or out of sequence, are refused by the database.
  const attemptId = (await pool.query('SELECT attempt_id FROM wf_publication_tx')).rows[0].attempt_id;
  await assert.rejects(pool.query("INSERT INTO wf_publication_tx_event(attempt_id,state,fence,worker) VALUES($1,'SUBMITTED',$2,'worker-a')", [attemptId, leaseA.fence]), /current fence/);
  await assert.rejects(pool.query("INSERT INTO wf_publication_tx_event(attempt_id,state,fence,worker) VALUES($1,'PREPARED',$2,'worker-b')", [attemptId, leaseB.fence]), /illegal publication attempt transition SIGNED -> PREPARED/);
  await assert.rejects(pool.query("UPDATE wf_publication SET fence=fence-1"), /fence is monotonic/);
  for (const table of ['wf_publication_tx_event', 'wf_publication_item', 'wf_publication_attempt', 'wf_publication']) await assert.rejects(pool.query(`TRUNCATE ${table} CASCADE`), /immutable/);

  const resumed = await stepReviewed(workerB, leaseB);
  assert.equal(resumed.status, 'SUBMITTED');
  assert.equal(resumed.signature, journaled, 'the journaled bytes are sent, not a re-signed transaction');
  assert.equal(signer.requests.length, 1);
  assert.equal((await stepReviewed(workerB, leaseB)).status, 'FINALIZED');
  assert.equal(await count(pool, 'SELECT count(*) FROM wf_publication_tx'), 1);
  assert.equal(chain.segment.entryCount, 1);
  const events = (await pool.query('SELECT worker,state FROM wf_publication_tx_event ORDER BY event_id')).rows;
  assert.deepEqual(events.map(e => [e.worker, e.state]), [['worker-a', 'PREPARED'], ['worker-a', 'SIGNED'], ['worker-b', 'SUBMITTED'], ['worker-b', 'FINALIZED']]);

  // No generic transition to FINALIZED: the state guard needs an anchor, and the
  // anchor guard needs a FINALIZED attempt agreeing with the stored intent.
  await append(pool, 'record', { value: 2 }, 1);
  const open = (await new WorkflowPublicationStore(pool).claim(REGISTRY, 'worker-a'))!;
  await assert.rejects(pool.query("UPDATE wf_publication SET state='FINALIZED' WHERE operation_id=$1", [open.operationId]), /without a verified anchor/);
  await assert.rejects(pool.query("INSERT INTO wf_publication_intent(operation_id,registry_id,batch_sequence,intent_bytes,intent_hash,fence,worker) VALUES($1,'synthetic',9,'\\x7b7d',repeat('0',64),$2,'worker-a')", [open.operationId, open.fence]), /intent hash does not cover intent bytes/);
  await poolB.end();
});

test('expired blockhash starts a new attempt of the same operation; concurrent steps are serialized', { timeout: 60000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  await append(pool, 'record', { value: 1 });
  const chain = new FakeChain(); const signer = new TestSigner(); const worker = publisher(pool, chain, signer);
  const other = publisher(pool, chain, signer);
  const lease = (await new WorkflowPublicationStore(pool).claim(REGISTRY, 'worker-a'))!;
  chain.mode = 'drop';
  const racing = await Promise.allSettled([stepReviewed(worker, lease), stepReviewed(other, lease)]);
  assert.equal(racing.filter(r => r.status === 'fulfilled').length, 1);
  assert.match(String((racing.find(r => r.status === 'rejected') as PromiseRejectedResult).reason), /PUBLICATION_STEP_BUSY/);
  assert.equal(await count(pool, 'SELECT count(*) FROM wf_publication_tx'), 1);
  assert.equal(signer.requests.length, 1);
  const firstSig = (await pool.query('SELECT signature FROM wf_publication_tx_signed')).rows[0].signature;
  assert.equal((await stepReviewed(worker, lease)).status, 'PENDING', 'still valid: wait, do not re-sign');

  chain.advance(151n); chain.mode = 'land';
  const retry = await stepReviewed(worker, lease);
  assert.equal(retry.status, 'SUBMITTED');
  assert.equal(retry.attemptNo, 2);
  assert.notEqual(retry.signature, firstSig);
  assert.equal((await stepReviewed(worker, lease)).status, 'FINALIZED');
  assert.equal(chain.segment.entryCount, 1, 'one logical anchor');
  const attempts = (await pool.query('SELECT operation_id,intent_hash FROM wf_publication_tx ORDER BY attempt_no')).rows;
  assert.equal(new Set(attempts.map(a => a.operation_id + a.intent_hash)).size, 1);
  assert.deepEqual(await states(pool), ['1:PREPARED', '1:SIGNED', '1:SUBMITTED', '1:EXPIRED', '2:PREPARED', '2:SIGNED', '2:SUBMITTED', '2:FINALIZED']);
  await chain.send(chain.sent[0]).catch(() => {});
  assert.equal(chain.segment.entryCount, 1, 'the expired transaction can no longer land');
});

test('RPC lag and pruned history never produce a second attempt; pruned status completes by ledger-entry proof', { timeout: 60000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  await append(pool, 'record', { value: 1 });
  const chain = new FakeChain(); const signer = new TestSigner(); const worker = publisher(pool, chain, signer);
  const lease = (await new WorkflowPublicationStore(pool).claim(REGISTRY, 'worker-a', 300000))!;
  chain.mode = 'land-then-throw';
  const first = await stepReviewed(worker, lease);
  assert.equal(first.status, 'UNKNOWN');
  const landedAt = chain.landed.get(first.signature!)!.slot;
  chain.mode = 'land';
  chain.advance(200n);
  // A lagging status node (behind the height we observed) is rejected, not trusted.
  chain.statusLag = 50n;
  await assert.rejects(stepReviewed(worker, lease), { message: 'RPC_CONTEXT_STALE' });
  assert.deepEqual(await states(pool), ['1:PREPARED', '1:SIGNED', '1:UNKNOWN']);
  chain.statusLag = null;
  // Pruned status history -> EXPIRED at slot X. The landing search that follows
  // must read at >= X: here a node behind the landing answers it, and must be refused
  // (reading at the stale watermark would see an empty registry and start attempt 2).
  chain.pruned.add(first.signature!);
  // Call 1 (step start) and calls >= 3 (landing search) hit the lagging node; call 2
  // (reconcile, which decides EXPIRED at slot X) hits a fresh one.
  chain.slotCalls = 0; chain.nodeLag = landedAt - 1n; chain.lagWhen = call => call !== 2;
  await assert.rejects(stepReviewed(worker, lease), { message: 'RPC_CONTEXT_STALE' });
  assert.deepEqual(await states(pool), ['1:PREPARED', '1:SIGNED', '1:UNKNOWN', '1:EXPIRED']);
  assert.equal(await count(pool, 'SELECT count(*) FROM wf_publication_tx'), 1);
  chain.lagWhen = null; chain.nodeLag = null;
  // Maintenance: not blocked -> needs force; with force still refused, the landing is ours.
  await assert.rejects(worker.abandonForMaintenance(lease, { requestedBy: 'carol', approvedBy: 'dave', reason: 'try to abandon a landed operation' }), { message: 'MAINTENANCE_NOT_BLOCKED' });
  await assert.rejects(worker.abandonForMaintenance(lease, { requestedBy: 'carol', approvedBy: 'dave', reason: 'try to abandon a landed operation', forceReason: 'operator insists on forcing this' }), { message: 'PUBLICATION_FINALIZED_LANDING' });
  // One inconsistent (empty) segment read is re-read, not taken as a foreign anchor.
  chain.blankSegmentReads = 1;
  const done = await stepReviewed(worker, lease);
  assert.equal(done.status, 'FINALIZED');
  assert.equal(done.status === 'FINALIZED' && done.proof, 'LEDGER_ENTRY');
  assert.deepEqual(await states(pool), ['1:PREPARED', '1:SIGNED', '1:UNKNOWN', '1:EXPIRED', '1:FINALIZED']);
  const event = (await pool.query("SELECT detail FROM wf_publication_tx_event WHERE state='FINALIZED'")).rows[0].detail;
  assert.equal(event.proof, 'LEDGER_ENTRY'); assert.match(event.rationale, /manifestHash .*operationId/);
  const anchor = (await pool.query('SELECT slot,proof,signature FROM wf_publication_anchor')).rows[0];
  assert.deepEqual([anchor.slot, anchor.proof, anchor.signature], [null, 'LEDGER_ENTRY', first.signature]);
  assert.equal(chain.sent.length, 1);
});

test('our landed transaction with a discrepancy is terminal: no completion loop, no successor, recorded incident', { timeout: 90000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  await append(pool, 'record', { value: 1 });
  const chain = new FakeChain(); const signer = new TestSigner(); const worker = publisher(pool, chain, signer);
  const store = new WorkflowPublicationStore(pool);
  const lease = (await store.claim(REGISTRY, 'worker-a', 300000))!;
  chain.tamperRoot = true;
  assert.equal((await stepReviewed(worker, lease)).status, 'SUBMITTED');
  chain.tamperRoot = false;
  await assert.rejects(stepReviewed(worker, lease), { message: 'ANCHOR_COMMITMENT_MISMATCH' });
  assert.deepEqual(await states(pool), ['1:PREPARED', '1:SIGNED', '1:SUBMITTED', '1:ANCHOR_MISMATCH']);
  assert.deepEqual(await opState(pool, lease.operationId), { state: 'OPEN', blocked_reason: 'ANCHOR_MISMATCH:merkleRoot' });
  await assert.rejects(stepReviewed(worker, lease), { message: 'PUBLICATION_MAINTENANCE_REQUIRED' });
  // Our signature finalized successfully: never "foreign", never abandoned (a successor would anchor twice).
  await assert.rejects(worker.abandonForMaintenance(lease, { requestedBy: 'carol', approvedBy: 'dave', reason: 'mismatched anchor, incident INC-1' }), { message: 'PUBLICATION_FINALIZED_LANDING' });
  await assert.rejects(worker.recordLandedDiscrepancy(lease, { requestedBy: 'dave', approvedBy: 'Da​ve', reason: 'root differs on chain', incidentRef: 'INC-1' }), { message: 'MAINTENANCE_SELF_APPROVAL' });
  await assert.rejects(worker.recordLandedDiscrepancy(lease, { requestedBy: 'carol', approvedBy: 'dave', reason: 'root differs on chain' }), { message: 'MAINTENANCE_INCIDENT_REQUIRED' });
  await assert.rejects(pool.query("UPDATE wf_publication SET state='LANDED_DISCREPANCY' WHERE operation_id=$1", [lease.operationId]), /two-person maintenance record/);
  await worker.recordLandedDiscrepancy(lease, { requestedBy: 'carol', approvedBy: 'dave', reason: 'root differs on chain', incidentRef: 'INC-1' });
  assert.equal((await opState(pool, lease.operationId)).state, 'LANDED_DISCREPANCY');
  assert.equal(await count(pool, "SELECT count(*) FROM wf_publication WHERE superseded_by IS NOT NULL"), 0);
  assert.equal(await count(pool, "SELECT count(*) FROM wf_audit WHERE action='PUBLICATION_LANDED_DISCREPANCY'"), 1);
  assert.equal(await store.claim(REGISTRY, 'worker-a'), null, 'the landed membership is not published again');

  // Second operation: fields match but the program's anchor hash disagrees (N1 loop case).
  await append(pool, 'later', { value: 2 });
  const second = (await store.claim(REGISTRY, 'worker-a', 300000))!;
  chain.tamperAnchorHash = true;
  assert.equal((await stepReviewed(worker, second)).status, 'SUBMITTED');
  chain.tamperAnchorHash = false;
  await assert.rejects(stepReviewed(worker, second), { message: 'ANCHOR_COMMITMENT_MISMATCH' });
  assert.equal((await opState(pool, second.operationId)).blocked_reason, 'ANCHOR_MISMATCH:anchorHash');
  for (let i = 0; i < 2; i += 1) await assert.rejects(stepReviewed(worker, second), { message: 'PUBLICATION_MAINTENANCE_REQUIRED' });
  await assert.rejects(worker.abandonForMaintenance(second, { requestedBy: 'carol', approvedBy: 'dave', reason: 'anchor hash differs on chain' }), { message: 'PUBLICATION_FINALIZED_LANDING' });
  await worker.recordLandedDiscrepancy(second, { requestedBy: 'carol', approvedBy: 'dave', reason: 'anchor hash differs on chain', incidentRef: 'INC-2' });

  await append(pool, 'third', { value: 3 });
  const third = (await store.claim(REGISTRY, 'worker-a', 300000))!;
  assert.equal((await stepReviewed(worker, third)).status, 'SUBMITTED');
  assert.equal((await stepReviewed(worker, third)).status, 'FINALIZED');
  const intent = JSON.parse((await pool.query('SELECT intent_bytes FROM wf_publication_intent WHERE operation_id=$1', [third.operationId])).rows[0].intent_bytes.toString());
  assert.deepEqual([intent.batchSequence, intent.cursorStart], ['3', '3'], 'cursor continues after landed discrepancies');
});

test('paused registry, signing rejection, substituted bytes, corrupted intent, failed-attempt limit, day boundary and foreign sequence', { timeout: 90000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  await append(pool, 'record', { value: 1 });
  const chain = new FakeChain(); const signer = new TestSigner(); const worker = publisher(pool, chain, signer, { maxFailedAttempts: 2 });
  const store = new WorkflowPublicationStore(pool);
  const lease = (await store.claim(REGISTRY, 'worker-a', 300000))!;

  chain.mutate(s => { s.config.paused = true; });
  await assert.rejects(stepReviewed(worker, lease), { message: 'REGISTRY_PAUSED' });
  assert.equal(await count(pool, 'SELECT count(*) FROM wf_publication_intent'), 0);
  chain.mutate(s => { s.config.paused = false; });

  signer.reject = true;
  await assert.rejects(stepReviewed(worker, lease), { message: 'SIGNING_REJECTED' });
  signer.reject = false; signer.substitute = true;
  await assert.rejects(stepReviewed(worker, lease), { message: 'SIGNED_TRANSACTION_MESSAGE_MISMATCH' });
  signer.substitute = false;
  assert.deepEqual(await states(pool), ['1:PREPARED', '1:CANCELLED', '2:PREPARED', '2:CANCELLED']);
  assert.equal(await count(pool, 'SELECT count(*) FROM wf_publication_tx_signed'), 0);
  assert.equal(chain.sent.length, 0);

  const original = (await pool.query('SELECT intent_bytes,intent_hash FROM wf_publication_intent')).rows[0];
  const forged = Buffer.from(original.intent_bytes.toString().replace(/"merkleRoot":"[0-9a-f]{64}"/, `"merkleRoot":"${'ab'.repeat(32)}"`));
  await pool.query('ALTER TABLE wf_publication_intent DISABLE TRIGGER immutable');
  await pool.query('UPDATE wf_publication_intent SET intent_bytes=$1', [forged]);
  await assert.rejects(stepReviewed(worker, lease), { message: 'PUBLICATION_INTENT_MISMATCH' });
  await pool.query('UPDATE wf_publication_intent SET intent_hash=$1', [intentBytesHash(forged)]);
  await assert.rejects(stepReviewed(worker, lease), { message: 'PUBLICATION_INTENT_MISMATCH' });
  await pool.query('UPDATE wf_publication_intent SET intent_bytes=$1,intent_hash=$2', [original.intent_bytes, original.intent_hash]);
  await pool.query('ALTER TABLE wf_publication_intent ENABLE TRIGGER immutable');

  await assert.rejects(worker.abandonForMaintenance(lease, { requestedBy: 'carol', approvedBy: 'dave', reason: 'nothing is blocked here' }), { message: 'MAINTENANCE_NOT_BLOCKED' });
  chain.time = BigInt(Date.parse('2026-09-24T23:58:30Z') / 1000);
  await assert.rejects(stepReviewed(worker, lease), { message: 'PUBLICATION_LEDGER_DAY_BOUNDARY' });
  chain.time = NOON;

  // If the journal write fails, nothing is signed or sent.
  await pool.query("CREATE FUNCTION synthetic_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic journal failure'; END $$; CREATE TRIGGER synthetic_fail BEFORE INSERT ON wf_publication_tx FOR EACH ROW EXECUTE FUNCTION synthetic_fail()");
  const asked = signer.requests.length;
  await assert.rejects(stepReviewed(worker, lease), /synthetic journal failure/);
  assert.equal(signer.requests.length, asked); assert.equal(chain.sent.length, 0);
  await pool.query('DROP TRIGGER synthetic_fail ON wf_publication_tx');

  chain.mode = 'fail';
  assert.equal((await stepReviewed(worker, lease)).status, 'SUBMITTED');
  assert.equal((await stepReviewed(worker, lease)).status, 'FAILED');
  assert.equal((await stepReviewed(worker, lease)).status, 'SUBMITTED');
  assert.equal((await stepReviewed(worker, lease)).status, 'FAILED');
  assert.equal((await opState(pool, lease.operationId)).blocked_reason, 'FAILED_ATTEMPT_LIMIT');
  await assert.rejects(stepReviewed(worker, lease), { message: 'PUBLICATION_MAINTENANCE_REQUIRED' });
  await worker.abandonForMaintenance(lease, { requestedBy: 'carol', approvedBy: 'dave', reason: 'repeated program failures under investigation' });

  // Foreign publisher takes the successor's sequence before any attempt of ours.
  chain.mode = 'land';
  const successor = (await store.claim(REGISTRY, 'worker-a', 300000))!;
  signer.reject = true;
  await assert.rejects(stepReviewed(worker, successor), { message: 'SIGNING_REJECTED' });
  signer.reject = false;
  const intent = JSON.parse((await pool.query('SELECT intent_bytes FROM wf_publication_intent WHERE operation_id=$1', [successor.operationId])).rows[0].intent_bytes.toString());
  chain.execute({ batchSequence: BigInt(intent.batchSequence), registryVersion: 3n, sourceCursorStart: 1n, sourceCursorEnd: 1n, merkleRoot: new Uint8Array(32).fill(9), manifestHash: new Uint8Array(32), snapshotHash: new Uint8Array(32), previousAnchorHash: chain.config.lastAnchorHash, leafCount: 1, schemaVersion: 1, flags: 0, hashAlgorithm: 1, treeAlgorithm: 1 }, signer.address);
  await assert.rejects(stepReviewed(worker, successor), { message: 'PUBLICATION_CHAIN_CONFLICT' });
  assert.equal((await opState(pool, successor.operationId)).blocked_reason, 'CHAIN_CONFLICT');
  assert.equal(chain.sent.length, 2);
  // Foreign anchor, none of ours landed: abandonment moves the membership on.
  const moved = await worker.abandonForMaintenance(successor, { requestedBy: 'carol', approvedBy: 'dave', reason: 'foreign anchor occupies our sequence', incidentRef: 'INC-3' });
  const third = (await store.claim(REGISTRY, 'worker-b', 300000))!;
  assert.equal(third.operationId, moved.successorOperationId);
  assert.equal((await stepReviewed(worker, third)).status, 'SUBMITTED');
  assert.equal((await stepReviewed(worker, third)).status, 'FINALIZED');
  assert.equal((await pool.query('SELECT batch_sequence FROM wf_publication_anchor')).rows[0].batch_sequence, '2');
});

test('unpublishable V1 version stops the queue with a typed error; abandon marks a failed SIGNED attempt FAILED; membership is fixed', { timeout: 60000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  // A pre-V1.1 float, written as V1 allowed it (the commit path now rejects it).
  await assert.rejects(append(pool, 'price', { amount: 9.99 }), /UNSUPPORTED_NUMBER/);
  const payload = { amount: 9.99 };
  await pool.query("INSERT INTO wf_version VALUES('synthetic','price',1,$1,$2,'upsert','alice','bob','{}')", [JSON.stringify(payload), workflowHash({ operation: 'upsert', payload })]);
  await pool.query("INSERT INTO wf_outbox(event_id,registry_id,record_id,version,payload_hash) VALUES(gen_random_uuid(),'synthetic','price',1,$1)", [workflowHash({ operation: 'upsert', payload })]);
  const chain = new FakeChain(); const signer = new TestSigner(); const worker = publisher(pool, chain, signer);
  const store = new WorkflowPublicationStore(pool);
  const lease = (await store.claim(REGISTRY, 'worker-a', 300000))!;
  const eventId = (await pool.query("SELECT event_id FROM wf_outbox WHERE record_id='price'")).rows[0].event_id;
  await assert.rejects(stepReviewed(worker, lease), (error: any) => error.code === 'PUBLICATION_UNPUBLISHABLE_VERSION'
    && error.detail.eventId === eventId && error.detail.recordId === 'price' && error.detail.version === 1);
  // Membership cannot be edited after creation, and operations are born OPEN.
  await assert.rejects(pool.query('INSERT INTO wf_publication_item VALUES($1,99,$2)', [lease.operationId, eventId]), /membership is fixed/);
  await assert.rejects(pool.query("INSERT INTO wf_publication(operation_id,registry_id,owner,lease_until,state) VALUES(gen_random_uuid(),'x','w',now(),'FINALIZED')"), /created OPEN/);

  // Separate registry state: a SIGNED attempt whose transaction finalized with an error.
  await pool.query("UPDATE wf_publication SET lease_until=clock_timestamp() WHERE operation_id=$1", [lease.operationId]);
  const fresh = await isolatedPostgres(t);
  await append(fresh.pool, 'record', { value: 1 });
  const chain2 = new FakeChain();
  const crashing = publisher(fresh.pool, chain2, signer, { afterAttemptStored: async (attemptId) => {
    const bytes = (await fresh.pool.query('SELECT signed_bytes FROM wf_publication_tx_signed WHERE attempt_id=$1', [attemptId])).rows[0].signed_bytes;
    chain2.mode = 'fail'; await chain2.send(bytes.toString('base64')); chain2.mode = 'land';
    throw new Error('synthetic crash after an out-of-band send');
  } });
  const lease2 = (await new WorkflowPublicationStore(fresh.pool).claim(REGISTRY, 'worker-a', 300000))!;
  await assert.rejects(stepReviewed(crashing, lease2), /synthetic crash/);
  const plain = publisher(fresh.pool, chain2, signer);
  await plain.abandonForMaintenance(lease2, { requestedBy: 'carol', approvedBy: 'dave', reason: 'retire the failed attempt', forceReason: 'failed transaction, operator requests retry' });
  assert.deepEqual(await states(fresh.pool), ['1:PREPARED', '1:SIGNED', '1:UNKNOWN', '1:FAILED']);
});

