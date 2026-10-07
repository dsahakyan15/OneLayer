import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { isolatedPostgres } from './support/postgres.ts';
import { append, count, FakeChain, opState, publisher, REGISTRY, stepReviewed, TestSigner } from './support/publication-fake-chain.ts';
import { WorkflowPublicationStore } from '../src/workflow-publication.ts';
import { ARCHIVAL_CHECK_DOMAIN, type ArchivalChain } from '../src/publication-worker.ts';
import { canonicalWorkflow } from '../src/registry-workflow.ts';
import { routePublicationMaintenance } from '../src/publication-maintenance.ts';
import type { AdminSession } from '../src/admin-session.ts';
import { ArchivalRpc } from '../src/publication-rpc.ts';

const request = { requestedBy: 'investigator', reason: 'investigate pruned transaction history', evidenceRef: 'synthetic-archive-1' };
const force = { requestedBy: 'carol', approvedBy: 'dave', reason: 'investigate conflicting anchor', forceReason: 'operator explicitly requests cancellation' };
const archive = (chain: FakeChain, lookup: ArchivalChain['transaction'] = async signature => chain.landed.get(signature) ?? null): ArchivalChain => ({
  archiveId: 'synthetic-full-history', historyFromSlot: async () => 0n, finalizedSlot: async () => chain.slot, transaction: lookup,
});

for (const mismatch of [false, true]) test(`archival own landing with pruned status: mismatch=${mismatch}`, async t => {
  const { pool } = await isolatedPostgres(t);
  await append(pool, 'record', { value: 1 });
  const chain = new FakeChain(); chain.tamperRoot = mismatch;
  const worker = publisher(pool, chain, new TestSigner());
  const lease = (await new WorkflowPublicationStore(pool).claim(REGISTRY, 'worker', 300000))!;
  await stepReviewed(worker, lease);
  for (const signature of chain.landed.keys()) chain.pruned.add(signature);
  chain.advance(200n);
  const rawRpc = new ArchivalRpc('https://synthetic.invalid', 'synthetic-program', 'ordinary-rpc', async (_url, init) => {
    const rpc = JSON.parse(String(init?.body));
    const result = rpc.method === 'getSlot' ? Number(chain.slot) : rpc.method === 'getFirstAvailableBlock' ? 0 : null;
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result }), { status: 200 });
  });
  const incomplete = await worker.reconcileWithArchive(lease, rawRpc, request);
  assert.equal(incomplete.outcome, 'INCONCLUSIVE', 'ordinary RPC cannot attest gap-free history even with an old first block and current tip');
  if (incomplete.outcome === 'INCONCLUSIVE') assert.deepEqual(incomplete.unresolved, ['1:UNRESOLVED:HISTORY_COMPLETENESS_UNKNOWN']);
  if (mismatch) {
    await assert.rejects(stepReviewed(worker, lease), /ANCHOR_COMMITMENT_MISMATCH|PUBLICATION_CHAIN_CONFLICT/);
    await assert.rejects(worker.abandonForMaintenance(lease, force), /PUBLICATION_ARCHIVAL_RECONCILIATION_REQUIRED/);
    await assert.rejects(pool.query(`INSERT INTO wf_publication_abandonment(operation_id,successor_operation_id,requested_by,approved_by,reason,blocked_reason,force_reason,fence,worker)
      SELECT operation_id,$2,'carol','dave','investigate conflicting anchor',blocked_reason,'force cancellation',fence,owner FROM wf_publication WHERE operation_id=$1`, [lease.operationId, randomUUID()]), /unknown origin needs archival evidence/);
  }
  const result = await worker.reconcileWithArchive(lease, archive(chain), request);
  assert.equal(result.outcome, mismatch ? 'ANCHOR_MISMATCH' : 'FINALIZED');
  if (mismatch) {
    await assert.rejects(worker.abandonForMaintenance(lease, force), /PUBLICATION_FINALIZED_LANDING/);
    await worker.recordLandedDiscrepancy(lease, { ...force, incidentRef: 'synthetic-incident' });
    assert.equal((await opState(pool, lease.operationId)).state, 'LANDED_DISCREPANCY');
  }
  assert.equal(await count(pool, 'SELECT count(*) FROM wf_publication'), 1);
  assert.equal(chain.sent.length, 1);
});

test('foreign cancellation needs complete archival evidence and two distinct approvals of the newest exact evidence', async t => {
  const { pool } = await isolatedPostgres(t);
  await append(pool, 'record', { value: 1 });
  const chain = new FakeChain(); chain.mode = 'drop';
  const worker = publisher(pool, chain, new TestSigner());
  const lease = (await new WorkflowPublicationStore(pool).claim(REGISTRY, 'worker', 300000))!;
  await stepReviewed(worker, lease);
  // Occupy the sequence with a different anchor while our signed bytes never land.
  chain.mutate(s => { s.config.currentBatchSequence = 1n; s.config.lastAnchorHash = new Uint8Array(32).fill(9); });
  const source = archive(chain, async () => null);
  assert.equal((await worker.reconcileWithArchive(lease, source, request)).outcome, 'INCONCLUSIVE', 'live blockhash is insufficient');
  chain.advance(200n);
  assert.equal((await worker.reconcileWithArchive(lease, { ...source, historyFromSlot: async () => 101n }, request)).outcome, 'INCONCLUSIVE');
  assert.equal((await worker.reconcileWithArchive(lease, { ...source, finalizedSlot: async () => 100n }, request)).outcome, 'INCONCLUSIVE');
  const proof = await worker.reconcileWithArchive(lease, source, request);
  assert.equal(proof.outcome, 'FOREIGN_PROVEN');
  if (proof.outcome !== 'FOREIGN_PROVEN') throw new Error('missing foreign proof');
  await assert.rejects(worker.abandonForMaintenance(lease, force), /PUBLICATION_ARCHIVAL_RECONCILIATION_REQUIRED/);
  const session = (username: string): AdminSession => ({ username, sessionId: username, csrfToken: 'synthetic', role: 'chief_admin', expiresAt: Date.now()+60000,
    permissions: ['publication.maintenance'], registryIds: [REGISTRY], authMethod: 'oidc' });
  const approve = (name: string, checkId = proof.checkId, evidenceHash = proof.evidenceHash) => routePublicationMaintenance({pool, registryId: REGISTRY}, {
    method: 'POST', path: `/v2/admin/workflow/publication/archival-checks/${checkId}/approve`, body: { operationId: lease.operationId, evidenceHash }, idempotencyKey: randomUUID(),
  }, session(name));
  await assert.rejects(approve('carol', proof.checkId, '0'.repeat(64)), /EVIDENCE_BINDING_MISMATCH/);
  await approve('carol');
  await assert.rejects(approve('CAROL'), /APPROVER_NOT_INDEPENDENT/);
  await assert.rejects(stepReviewed(worker, lease), /PUBLICATION_MAINTENANCE_REQUIRED/);
  // SQL must reject a well-hashed forged FOREIGN_PROVEN record with no proof.
  const row = (await pool.query('SELECT * FROM wf_publication_archival_check WHERE check_id=$1', [proof.checkId])).rows[0];
  const detail = JSON.parse(row.detail_bytes.toString()); delete detail.attempts[0].proof;
  const bytes = Buffer.from(canonicalWorkflow(detail));
  const hash = createHash('sha256').update(ARCHIVAL_CHECK_DOMAIN+'\n').update(bytes).digest('hex');
  await assert.rejects(pool.query(`INSERT INTO wf_publication_archival_check(check_id,operation_id,archive_id,evidence_ref,outcome,detail_bytes,detail_hash,requested_by,reason,fence,worker)
    VALUES($1,$2,$3,$4,'FOREIGN_PROVEN',$5,$6,$7,$8,$9,$10)`, [randomUUID(),lease.operationId,row.archive_id,row.evidence_ref,bytes,hash,row.requested_by,row.reason,lease.fence,lease.worker]), /every attempt of ours proven not landed/);
  const newer = await worker.reconcileWithArchive(lease, source, request);
  assert.equal(newer.outcome, 'FOREIGN_PROVEN');
  if (newer.outcome !== 'FOREIGN_PROVEN') throw new Error('missing replacement proof');
  await assert.rejects(approve('dave'), /ARCHIVAL_CHECK_SUPERSEDED/);
  await approve('carol', newer.checkId, newer.evidenceHash);
  await approve('dave', newer.checkId, newer.evidenceHash);
  const done = await stepReviewed(worker, lease);
  assert.equal(done.status, 'ABANDONED');
  assert.equal((await opState(pool, lease.operationId)).state, 'ABANDONED');
  assert.equal(await count(pool, 'SELECT count(*) FROM wf_publication'), 2);
  assert.equal(await count(pool, "SELECT count(*) FROM wf_audit WHERE action='PUBLICATION_ABANDONED'"), 1);
  assert.equal(chain.sent.length, 1, 'no new publication is sent during investigation');
});
