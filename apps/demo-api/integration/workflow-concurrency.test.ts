import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { isolatedPostgres } from './support/postgres.ts';
import { routeWorkflow } from '../src/registry-workflow.ts';
import { PostgresSessionStore } from '../src/postgres-session.ts';
import { routeAdmin, type AdminContext } from '../src/admin.ts';
import type { AdminSession } from '../src/admin-session.ts';

// Defect 08 (recorded 2026-10-01): concurrent edits of one draft answered
// [200,404] instead of [200,409]. The `... JOIN wf_revision ... FOR UPDATE OF d`
// statement took its snapshot before the winner committed, so the join lost the
// new revision during lock recheck and the loser looked like a missing draft.
// These cases force that exact interleaving instead of relying on scheduler
// luck: the winner is held inside its write while the loser waits on the row
// lock, and the loser must still observe the committed revision.

const moduleSession = (username: string): AdminSession => ({
  username, sessionId: username, role: 'operator', csrfToken: 'synthetic',
  expiresAt: Date.now() + 60000,
  permissions: ['records.read', 'records.draft', 'records.approve'],
  registryIds: ['synthetic'],
  resourcePolicy: { version: 1, grants: [{ registryId: 'synthetic', recordIds: 'all', fieldPaths: 'all', actions: ['records.read', 'records.write'] }] },
});

type WorkflowDraft = { draftId: string; revision: number; payloadHash: string; baseVersion: number; state: string };

async function waitFor(pool: Pool, sql: string, pattern: string, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const { rows } = await pool.query(sql, [pattern]);
    if ((rows[0] as { n: number }).n > 0) return true;
    if (Date.now() >= deadline) return false;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
}
/** The backend running the statement is visible as active while a trigger sleeps. */
const activeQuery = (pool: Pool, pattern: string, timeoutMs: number) => waitFor(pool,
  "SELECT count(*)::int AS n FROM pg_stat_activity WHERE state='active' AND query LIKE $1", pattern, timeoutMs);
/** The backend running the statement is blocked on a transaction lock. */
const waitingForRowLock = (pool: Pool, pattern: string, timeoutMs: number) => waitFor(pool,
  "SELECT count(*)::int AS n FROM pg_locks l JOIN pg_stat_activity a USING (pid) WHERE l.locktype='transactionid' AND NOT l.granted AND a.query LIKE $1", pattern, timeoutMs);
async function evidenceCounts(pool: Pool) {
  const { rows } = await pool.query(`SELECT (SELECT count(*)::int FROM wf_revision) AS revisions,
    (SELECT count(*)::int FROM wf_audit) AS audits, (SELECT count(*)::int FROM wf_request) AS requests,
    (SELECT count(*)::int FROM wf_outbox) AS outbox, (SELECT count(*)::int FROM wf_version) AS versions`);
  return rows[0] as { revisions: number; audits: number; requests: number; outbox: number; versions: number };
}

test('concurrent edits serialize on the draft row: one revision wins, the stale edit is a domain 409 and writes nothing', { timeout: 60000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  const call = (who: string, suffix: string, body: Record<string, unknown>, key = randomUUID()) => routeWorkflow(
    { pool, registryId: 'synthetic' },
    { method: 'POST', path: '/v2/admin/workflow/drafts' + suffix, body, idempotencyKey: key },
    moduleSession(who));
  const created = await call('alice', '', { recordId: 'race', baseVersion: 0, operation: 'upsert', payload: { owner: 'initial' } });
  assert.equal(created.status, 201);
  const draft = created.body as WorkflowDraft;
  const binding = { expectedRevision: draft.revision, operation: 'upsert' };

  // Hold the first edit inside its revision insert so the second request
  // snapshots before the winner commits and then blocks on the draft row.
  await pool.query("CREATE FUNCTION synthetic_revision_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NEW; END $$");
  await pool.query('CREATE TRIGGER synthetic_revision_delay BEFORE INSERT ON wf_revision FOR EACH ROW EXECUTE FUNCTION synthetic_revision_delay()');
  const before = await evidenceCounts(pool);
  const first = call('alice', `/${draft.draftId}/edit`, { ...binding, payload: { owner: 'alice-edit' } });
  assert.equal(await activeQuery(pool, 'INSERT INTO wf_revision%', 5000), true, 'first edit never reached its revision insert');
  const second = call('carol', `/${draft.draftId}/edit`, { ...binding, payload: { owner: 'carol-edit' } });
  assert.equal(await waitingForRowLock(pool, 'SELECT%FROM wf_draft%', 4000), true, 'second edit never waited on the draft row lock');
  const [firstResult, secondResult] = await Promise.all([first, second]);
  assert.deepEqual([firstResult.status, secondResult.status].sort(), [200, 409]);
  const aliceWon = firstResult.status === 200;
  const winner = (aliceWon ? firstResult : secondResult).body as WorkflowDraft;
  assert.equal(((aliceWon ? secondResult : firstResult).body as { error: string }).error, 'REVISION_CONFLICT');
  assert.equal(winner.revision, draft.revision + 1);
  assert.equal(winner.state, 'DRAFT');
  await pool.query('DROP TRIGGER synthetic_revision_delay ON wf_revision');

  // Exactly one appended revision, audit entry and idempotency record; the
  // refused edit is not cached and left no evidence behind.
  const after = await evidenceCounts(pool);
  assert.deepEqual(after, { ...before, revisions: before.revisions + 1, audits: before.audits + 1, requests: before.requests + 1 });
  const revisions = (await pool.query('SELECT revision,payload,editor FROM wf_revision WHERE draft_id=$1 ORDER BY revision', [draft.draftId])).rows as { revision: number; payload: { owner: string }; editor: string }[];
  assert.deepEqual(revisions.map(row => [row.revision, row.payload, row.editor]), [
    [1, { owner: 'initial' }, 'alice'],
    [2, { owner: aliceWon ? 'alice-edit' : 'carol-edit' }, aliceWon ? 'alice' : 'carol'],
  ]);
  assert.deepEqual((await pool.query('SELECT revision,state,approver FROM wf_draft WHERE draft_id=$1', [draft.draftId])).rows[0], { revision: 2, state: 'DRAFT', approver: null });

  const staleKey = randomUUID();
  const stale = await call('carol', `/${draft.draftId}/edit`, { ...binding, payload: { owner: 'stale' } }, staleKey);
  assert.equal(stale.status, 409);
  assert.equal((stale.body as { error: string }).error, 'REVISION_CONFLICT');
  assert.deepEqual(await evidenceCounts(pool), after);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM wf_request WHERE idempotency_key=$1', [staleKey])).rows[0].n, 0);

  // A malformed (absent) revision is a request error, not a missing object or a crash.
  const noRevision = await call('alice', `/${draft.draftId}/edit`, { operation: 'upsert', payload: { owner: 'no-revision' } });
  assert.equal(noRevision.status, 400);
  assert.equal((noRevision.body as { error: string }).error, 'INVALID_VERSION');
  assert.deepEqual(await evidenceCounts(pool), after);

  // A genuinely absent draft stays 404 for every transition.
  const absent = randomUUID();
  for (const [suffix, body] of [
    [`/${absent}/edit`, { ...binding, payload: { owner: 'absent' } }],
    [`/${absent}/submit`, { expectedRevision: 1, payloadHash: draft.payloadHash, baseVersion: 0 }],
    [`/${absent}/approve`, { expectedRevision: 1, payloadHash: draft.payloadHash, baseVersion: 0 }],
    [`/${absent}/commit`, { expectedRevision: 1, payloadHash: draft.payloadHash, baseVersion: 0 }],
  ] as const) {
    const result = await call('alice', suffix, body as Record<string, unknown>);
    assert.equal(result.status, 404);
    assert.equal((result.body as { error: string }).error, 'DRAFT_NOT_FOUND');
  }

  const bound = { expectedRevision: winner.revision, payloadHash: winner.payloadHash, baseVersion: winner.baseVersion };
  assert.equal((await call('alice', `/${draft.draftId}/submit`, bound)).status, 200);
  const beforeRefusedApprove = await evidenceCounts(pool);
  const refusedApprove = await call('bob', `/${draft.draftId}/approve`, { ...bound, payloadHash: '0'.repeat(64) });
  assert.equal(refusedApprove.status, 409);
  assert.equal((refusedApprove.body as { error: string }).error, 'APPROVAL_BINDING_MISMATCH');
  assert.deepEqual(await evidenceCounts(pool), beforeRefusedApprove);
  assert.equal((await call('bob', `/${draft.draftId}/approve`, bound)).status, 200);

  // Editing an approved draft drops the approval and invalidates the old binding.
  const edited = await call('alice', `/${draft.draftId}/edit`, { expectedRevision: winner.revision, operation: 'upsert', payload: { owner: 'after-approval' } });
  assert.equal(edited.status, 200);
  assert.deepEqual((await pool.query('SELECT state,approver FROM wf_draft WHERE draft_id=$1', [draft.draftId])).rows[0], { state: 'DRAFT', approver: null });
  const beforeStaleCommit = await evidenceCounts(pool);
  const staleCommit = await call('alice', `/${draft.draftId}/commit`, bound);
  assert.equal(staleCommit.status, 409);
  assert.equal((staleCommit.body as { error: string }).error, 'REVISION_CONFLICT');
  assert.deepEqual(await evidenceCounts(pool), beforeStaleCommit);

  const revised = edited.body as WorkflowDraft;
  const revisedBound = { expectedRevision: revised.revision, payloadHash: revised.payloadHash, baseVersion: revised.baseVersion };
  assert.equal(((await call('alice', `/${draft.draftId}/commit`, revisedBound)).body as { error: string }).error, 'APPROVAL_REQUIRED');
  assert.equal((await call('alice', `/${draft.draftId}/submit`, revisedBound)).status, 200);
  assert.equal(((await call('alice', `/${draft.draftId}/commit`, revisedBound)).body as { error: string }).error, 'APPROVAL_REQUIRED');
  assert.equal((await call('bob', `/${draft.draftId}/approve`, revisedBound)).status, 200);
  const committed = await call('alice', `/${draft.draftId}/commit`, revisedBound);
  assert.equal(committed.status, 200);
  assert.deepEqual((committed.body as { committed: { version: number } }).committed, { recordId: 'race', version: 1, payloadHash: revised.payloadHash });
  const final = await evidenceCounts(pool);
  assert.equal(final.versions, 1);
  assert.equal(final.outbox, 1);
});

test('concurrent commits through the admin dispatcher keep one version and refuse the stale base version with a domain 409', { timeout: 60000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  const sessions = new PostgresSessionStore(pool, [], { oidcOnly: true });
  const provision = async (username: string, role: 'registry_worker' | 'registry_approver') => {
    await sessions.provisionOidcAccount({ username, issuer: 'https://synthetic.example', subject: username,
      access: { role, registryIds: ['synthetic'] },
      resourcePolicy: { version: 1, grants: [{ registryId: 'synthetic', recordIds: 'all', fieldPaths: 'all', actions: ['records.read', 'records.write'] }] } }, 'bootstrap');
    await sessions.enrollDevice(username, username, 'bootstrap');
    return (await sessions.loginOidc({ issuer: 'https://synthetic.example', subject: username, deviceId: username, expiresAt: Date.now() + 60000 }))!;
  };
  const author = await provision('author', 'registry_worker');
  const approver = await provision('approver', 'registry_approver');
  const context = { pool, sessions, registryId: 'synthetic' } as unknown as AdminContext;
  const call = (session: AdminSession, method: string, suffix: string, body: Record<string, unknown> | null = null, key = randomUUID()) => routeAdmin(context, {
    method, path: '/v2/admin/workflow/' + suffix, query: new URLSearchParams(), body,
    cookieHeader: `onelayer_admin_session=${session.sessionId}`, csrfHeader: session.csrfToken, idempotencyKey: key,
  });
  const prepare = async (payload: Record<string, unknown>, baseVersion: number) => {
    const created = await call(author, 'POST', 'drafts', { recordId: 'cas', baseVersion, operation: 'upsert', payload });
    assert.equal(created.status, 201);
    const draft = created.body as WorkflowDraft;
    const binding = { expectedRevision: draft.revision, payloadHash: draft.payloadHash, baseVersion: draft.baseVersion };
    assert.equal((await call(author, 'POST', `drafts/${draft.draftId}/submit`, binding)).status, 200);
    assert.equal((await call(approver, 'POST', `drafts/${draft.draftId}/approve`, binding)).status, 200);
    return { draft, binding, payload };
  };
  const seed = await prepare({ name: 'seed' }, 0);
  const seeded = await call(author, 'POST', `drafts/${seed.draft.draftId}/commit`, seed.binding);
  assert.equal(seeded.status, 200);
  const first = await prepare({ name: 'first' }, 1);
  const second = await prepare({ name: 'second' }, 1);

  // Hold the first commit inside its version insert so the second commit takes
  // its snapshot first and blocks on the record row, then must still see v2.
  await pool.query("CREATE FUNCTION synthetic_version_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NEW; END $$");
  await pool.query('CREATE TRIGGER synthetic_version_delay BEFORE INSERT ON wf_version FOR EACH ROW EXECUTE FUNCTION synthetic_version_delay()');
  const firstKey = randomUUID(), secondKey = randomUUID();
  const firstCommit = call(author, 'POST', `drafts/${first.draft.draftId}/commit`, first.binding, firstKey);
  assert.equal(await activeQuery(pool, 'INSERT INTO wf_version%', 5000), true, 'first commit never reached its version insert');
  const secondCommit = call(author, 'POST', `drafts/${second.draft.draftId}/commit`, second.binding, secondKey);
  assert.equal(await waitingForRowLock(pool, 'SELECT h.version%', 4000), true, 'second commit never waited on the record row lock');
  const [firstResult, secondResult] = await Promise.all([firstCommit, secondCommit]);
  assert.deepEqual([firstResult.status, secondResult.status].sort(), [200, 409]);
  const firstWon = firstResult.status === 200;
  const refused = (firstWon ? secondResult : firstResult).body as { error: string };
  assert.equal(refused.error, 'BASE_VERSION_CONFLICT');
  await pool.query('DROP TRIGGER synthetic_version_delay ON wf_version');
  const winner = firstWon ? first : second;
  const loser = firstWon ? second : first;

  // One committed version, one outbox event, no lost update and nothing from
  // the refused transaction, including its idempotency record.
  assert.deepEqual((await pool.query('SELECT version,payload FROM wf_version ORDER BY version')).rows, [
    { version: 1, payload: { name: 'seed' } },
    { version: 2, payload: winner.payload },
  ]);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM wf_outbox')).rows[0].n, 2);
  assert.deepEqual((await pool.query('SELECT version FROM wf_record WHERE registry_id=$1 AND record_id=$2', ['synthetic', 'cas'])).rows[0], { version: 2 });
  assert.deepEqual((await pool.query('SELECT state,committed_version FROM wf_draft WHERE draft_id=$1', [winner.draft.draftId])).rows[0], { state: 'COMMITTED', committed_version: 2 });
  assert.deepEqual((await pool.query('SELECT state,committed_version FROM wf_draft WHERE draft_id=$1', [loser.draft.draftId])).rows[0], { state: 'APPROVED', committed_version: null });
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM wf_audit WHERE action='COMMIT' AND details->>'draftId'=$1", [loser.draft.draftId])).rows[0].n, 0);
  assert.deepEqual((await pool.query('SELECT idempotency_key FROM wf_request WHERE idempotency_key = ANY($1::text[])', [[firstKey, secondKey]])).rows, [{ idempotency_key: firstWon ? firstKey : secondKey }]);

  // Retry stays a deterministic domain refusal: no 500, no missing-draft 404.
  const retry = await call(author, 'POST', `drafts/${loser.draft.draftId}/commit`, loser.binding);
  assert.equal(retry.status, 409);
  assert.equal((retry.body as { error: string }).error, 'BASE_VERSION_CONFLICT');
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM wf_version')).rows[0].n, 2);

  // Missing objects answer 404 through the same dispatcher, stale objects 409.
  const missingDraft = await call(author, 'GET', `drafts/${randomUUID()}`);
  assert.equal(missingDraft.status, 404);
  assert.equal((missingDraft.body as { error: string }).error, 'DRAFT_NOT_FOUND');
  const missingVersion = await call(author, 'GET', 'records/cas/versions/99');
  assert.equal(missingVersion.status, 404);
  assert.equal((missingVersion.body as { error: string }).error, 'RECORD_VERSION_NOT_FOUND');
  const missingRecord = await call(author, 'GET', 'records/absent/versions/latest');
  assert.equal(missingRecord.status, 404);
  assert.equal((missingRecord.body as { error: string }).error, 'RECORD_VERSION_NOT_FOUND');
  const missingEdit = await call(author, 'POST', `drafts/${randomUUID()}/edit`, { expectedRevision: 1, operation: 'upsert', payload: {} });
  assert.equal(missingEdit.status, 404);
  assert.equal((missingEdit.body as { error: string }).error, 'DRAFT_NOT_FOUND');
  const staleEdit = await call(author, 'POST', `drafts/${loser.draft.draftId}/edit`, { expectedRevision: 2, operation: 'upsert', payload: { name: 'late' } });
  assert.equal(staleEdit.status, 409);
  assert.equal((staleEdit.body as { error: string }).error, 'REVISION_CONFLICT');
  const committedEdit = await call(author, 'POST', `drafts/${winner.draft.draftId}/edit`, { expectedRevision: 1, operation: 'upsert', payload: { name: 'late' } });
  assert.equal(committedEdit.status, 409);
  assert.equal((committedEdit.body as { error: string }).error, 'ALREADY_COMMITTED');
});
