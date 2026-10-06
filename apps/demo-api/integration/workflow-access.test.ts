import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { isolatedPostgres } from './support/postgres.ts';
import { PostgresSessionStore } from '../src/postgres-session.ts';
import { routeAdmin, type AdminContext } from '../src/admin.ts';
import { routeWorkflow, workflowHash } from '../src/registry-workflow.ts';
import type { AdminSession } from '../src/admin-session.ts';

test('durable identities authorize workflow transitions and historical version reads through admin dispatcher', async t => {
  const { pool } = await isolatedPostgres(t);
  const sessions = new PostgresSessionStore(pool, [], { oidcOnly: true });
  const registryId = 'synthetic';
  const provision = async (username: string, role: 'registry_worker' | 'registry_approver', recordIds: string[] | 'all' = 'all', fieldPaths: string[] | 'all' = 'all') => {
    await sessions.provisionOidcAccount({ username, issuer: 'https://synthetic.example', subject: username,
      access: { role, registryIds: [registryId] }, resourcePolicy: { version: 1, grants: [{ registryId, recordIds, fieldPaths, actions: ['records.read', 'records.write'] }] } }, 'bootstrap');
    await sessions.enrollDevice(username, username, 'bootstrap');
    return (await sessions.loginOidc({ issuer: 'https://synthetic.example', subject: username, deviceId: username, expiresAt: Date.now() + 60000 }))!;
  };
  const author = await provision('author', 'registry_worker');
  const approver = await provision('approver', 'registry_approver');
  const restricted = await provision('restricted', 'registry_worker', ['allowed'], ['name']);
  const context = { pool, sessions, registryId } as unknown as AdminContext;
  const call = (session: AdminSession, method: string, suffix: string, body: Record<string, unknown> | null = null, csrf = session.csrfToken) => routeAdmin(context, {
    method, path: '/v2/admin/workflow/' + suffix, query: new URLSearchParams(), body,
    cookieHeader: `onelayer_admin_session=${session.sessionId}`, csrfHeader: csrf, idempotencyKey: randomUUID(),
  });
  const createBody = { recordId: 'allowed', baseVersion: 0, operation: 'upsert', payload: { name: 'first', secret: 'synthetic' } };
  assert.equal((await call(author, 'POST', 'drafts', createBody, 'wrong')).status, 403);
  const created = await call(author, 'POST', 'drafts', createBody);
  assert.equal(created.status, 201);
  const draft = created.body as {draftId: string; revision: number; payloadHash: string; baseVersion: number};
  const bound = { expectedRevision: draft.revision, payloadHash: draft.payloadHash, baseVersion: draft.baseVersion };
  const path = `drafts/${draft.draftId}/`;
  const hiddenDraft = await call(restricted, 'GET', `drafts/${draft.draftId}`);
  assert.equal(hiddenDraft.status, 404);
  assert.deepEqual(await call(restricted, 'GET', `drafts/${randomUUID()}`), hiddenDraft);
  assert.equal((await call(approver, 'POST', path + 'edit', {expectedRevision: 1, operation: 'upsert', payload: {}})).status, 403);
  assert.equal((await call(author, 'POST', path + 'submit', bound)).status, 200);
  assert.equal((await call(author, 'POST', path + 'approve', bound)).status, 403);
  assert.equal((await call(approver, 'POST', path + 'approve', bound)).status, 200);
  assert.equal((await call(author, 'POST', path + 'commit', bound)).status, 200);
  const latest = await call(author, 'GET', 'records/allowed/versions/latest');
  assert.deepEqual(latest.body, { recordId: 'allowed', version: 1, payload: createBody.payload,
    payloadHash: workflowHash({operation: 'upsert', payload: createBody.payload}), operation: 'upsert', state: 'COMMITTED' });
  assert.deepEqual(await call(author, 'GET', 'records/allowed/versions/1'), latest);
  const denied = await call(restricted, 'GET', 'records/allowed/versions/1');
  assert.equal(denied.status, 404);
  assert.deepEqual(await call(restricted, 'GET', 'records/absent/versions/1'), denied);
  assert.equal((await call(author, 'GET', 'records/allowed/versions/999999999999999999')).status, 400);
  assert.equal((await call(author, 'POST', 'records/allowed/versions/1')).status, 405);
  const second = await call(author, 'POST', 'drafts', {recordId: 'allowed', baseVersion: 1, operation: 'upsert', payload: {name: 'second'}});
  assert.equal(second.status, 201);
  const revision = second.body as typeof draft;
  const binding = {expectedRevision: revision.revision, payloadHash: revision.payloadHash, baseVersion: revision.baseVersion};
  for (const [who, action] of [[author, 'submit'], [approver, 'approve'], [author, 'commit']] as const) {
    assert.equal((await call(who, 'POST', `drafts/${revision.draftId}/${action}`, binding)).status, 200);
  }
  const current = await call(restricted, 'GET', 'records/allowed/versions/latest');
  assert.equal(current.status, 200);
  assert.deepEqual((current.body as {payload: unknown}).payload, {name: 'second'});
  assert.equal((await call(restricted, 'GET', 'records/allowed/versions/1')).status, 404);
  assert.deepEqual(await call(author, 'GET', 'records/allowed/versions/1'), latest);
  await sessions.revokeDevice('author', 'bootstrap');
  assert.equal((await call(author, 'GET', 'records/allowed/versions/1')).status, 401);
});

test('workflow snapshots caller JSON before waiting for the database', async t => {
  const { pool } = await isolatedPostgres(t);
  const session: AdminSession = { username: 'author', sessionId: 'test', csrfToken: 'test', role: 'registry_worker', expiresAt: Date.now()+60000,
    permissions: ['records.draft'], registryIds: ['synthetic'], resourcePolicy: {version: 1, grants: [{registryId: 'synthetic', recordIds: 'all', fieldPaths: 'all', actions: ['records.write']}]}};
  const body = {recordId: 'original', baseVersion: 0, operation: 'upsert', payload: {name: 'original'}};
  const pending = routeWorkflow({pool, registryId: 'synthetic'}, {method: 'POST', path: '/v2/admin/workflow/drafts', body, idempotencyKey: randomUUID()}, session);
  body.recordId = 'changed'; body.payload.name = 'changed';
  assert.equal((await pending).status, 201);
  const rows = (await pool.query('SELECT d.record_id,r.payload FROM wf_draft d JOIN wf_revision r USING(draft_id)')).rows;
  assert.deepEqual(rows, [{record_id: 'original', payload: {name: 'original'}}]);
});
