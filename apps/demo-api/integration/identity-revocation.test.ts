import test from 'node:test';
import assert from 'node:assert/strict';
import { Pool } from 'pg';
import { routeAdmin, type AdminContext, type AdminRequest } from '../src/admin.ts';
import { PostgresSessionStore } from '../src/postgres-session.ts';
import { isolatedPostgres } from './support/postgres.ts';

async function identityFixture(t: Parameters<typeof isolatedPostgres>[0]) {
  let replicaPool: Pool | undefined;
  t.after(async () => { await replicaPool?.end(); });
  const db = await isolatedPostgres(t);
  replicaPool = new Pool({ connectionString: db.connectionString });
  const store = new PostgresSessionStore(db.pool, [], { oidcOnly: true });
  const replica = new PostgresSessionStore(replicaPool, [], { oidcOnly: true });
  const login = (username: string, deviceId = `${username}-device`) => store.loginOidc({
    issuer: 'https://idp.example', subject: username, deviceId, expiresAt: Date.now() + 120000,
  });
  const provision = async (username: string, role: 'identity_admin' | 'registry_worker' | 'chief_admin', registryIds = ['gov.registry.land']) => {
    await store.provisionOidcAccount({ username, issuer: 'https://idp.example', subject: username,
      access: { role, registryIds }, resourcePolicy: { version: 1, grants: [] } }, 'bootstrap');
    await store.enrollDevice(username, `${username}-device`, 'bootstrap');
    return (await login(username))!;
  };
  return { ...db, store, replica, login, provision };
}

test('authenticated revocation hides foreign identities and rejects self, critical roles, stale revision and revoked actors', async t => {
  const { store, provision, replica } = await identityFixture(t);
  const admin = await provision('admin', 'identity_admin');
  const worker = await provision('worker', 'registry_worker');
  await provision('foreign', 'registry_worker', ['foreign.registry']);
  await provision('chief', 'chief_admin');
  const revoke = (username: string, revision = '1', deviceId?: string) => store.revokeAsSession(admin.sessionId, username, revision, deviceId);
  await assert.rejects(revoke('admin'), /SELF_ACCESS_CHANGE_FORBIDDEN/);
  for (const username of ['foreign', 'missing']) await assert.rejects(revoke(username), /ACCOUNT_NOT_FOUND/);
  // A critical-role target is indistinguishable from an absent/foreign one (no 403/404 oracle).
  await assert.rejects(revoke('chief'), /ACCOUNT_NOT_FOUND/);
  await assert.rejects(revoke('worker', '2'), /ACCESS_REVISION_CONFLICT/);
  await assert.rejects(revoke('worker', '1', 'foreign-device'), /DEVICE_NOT_FOUND/);
  await assert.rejects(revoke('worker', '2', 'worker-device'), /DEVICE_REVISION_CONFLICT/);
  await assert.rejects(revoke('worker', '01'), /expected revision required/);
  await assert.rejects(store.revokeAsSession(worker.sessionId, 'foreign', '1'), /PERMISSION_FORBIDDEN/);
  assert.ok(await replica.get(worker.sessionId));
  await store.revokeDevice('admin-device', 'bootstrap');
  await assert.rejects(revoke('worker'), /SESSION_REQUIRED/);
  assert.ok(await replica.get(worker.sessionId));
});

test('device revoke only closes that device; account revoke closes all devices and survives another API instance', async t => {
  const { pool, store, replica, provision, login } = await identityFixture(t);
  const admin = await provision('admin', 'identity_admin');
  const worker = await provision('worker', 'registry_worker');
  await store.enrollDevice('worker', 'second-device', 'bootstrap');
  const second = (await login('worker', 'second-device'))!;
  await store.revokeAsSession(admin.sessionId, 'worker', '1', 'worker-device');
  assert.equal(await replica.get(worker.sessionId), null);
  assert.equal(await login('worker'), null);
  assert.ok(await replica.get(second.sessionId));
  await assert.rejects(store.revokeAsSession(admin.sessionId, 'worker', '1', 'worker-device'), /DEVICE_REVISION_CONFLICT/);
  const event = (await pool.query("SELECT actor,access FROM demo_admin_access_event WHERE action='DEVICE_REVOKED'")).rows[0];
  assert.equal(event.actor, 'admin');
  assert.equal(event.access.deviceId, 'worker-device');
  assert.equal(event.access.deviceRevision, '2');
  await store.revokeAsSession(admin.sessionId, 'worker', '1');
  assert.equal(await replica.get(second.sessionId), null);
  assert.equal(await login('worker', 'second-device'), null);
  await assert.rejects(store.revokeAsSession(admin.sessionId, 'worker', '1'), /ACCESS_REVISION_CONFLICT/);
  assert.ok(await replica.get(admin.sessionId));
});

test('audit failure rolls back authenticated revocation and racing login cannot survive committed revoke', async t => {
  const { pool, store, replica, provision, login } = await identityFixture(t);
  const admin = await provision('admin', 'identity_admin');
  const worker = await provision('worker', 'registry_worker');
  await pool.query(`CREATE FUNCTION reject_revoke_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit failure'; END $$;
    CREATE TRIGGER reject_revoke_audit BEFORE INSERT ON demo_admin_access_event FOR EACH ROW EXECUTE FUNCTION reject_revoke_audit()`);
  for (const deviceId of [undefined, 'worker-device']) {
    await assert.rejects(store.revokeAsSession(admin.sessionId, 'worker', '1', deviceId), /IDENTITY_UNAVAILABLE/);
    assert.ok(await replica.get(worker.sessionId));
    assert.ok(await login('worker'));
  }
  await pool.query('DROP TRIGGER reject_revoke_audit ON demo_admin_access_event');
  const [racing] = await Promise.all([login('worker'), store.revokeAsSession(admin.sessionId, 'worker', '1')]);
  if (racing) assert.equal(await replica.get(racing.sessionId), null);
  assert.equal(await replica.get(worker.sessionId), null);
  assert.equal(await login('worker'), null);
  assert.equal((await pool.query("SELECT count(*) FROM demo_admin_access_event WHERE action='REVOKE'")).rows[0].count, '1');
});


test('revocation routes require session, CSRF, pinned origin and an exact request body', async t => {
  const { pool, store, replica, provision } = await identityFixture(t);
  const admin = await provision('admin', 'identity_admin');
  const worker = await provision('worker', 'registry_worker');
  const context = { pool, sessions: store, oidc: { browserOrigin: 'https://desktop.example' } } as unknown as AdminContext;
  const request: AdminRequest = { method: 'POST', path: '/v2/admin/accounts/worker/devices/worker-device/revoke',
    query: new URLSearchParams(), body: { expectedRevision: '1' }, cookieHeader: `onelayer_admin_session=${admin.sessionId}`,
    csrfHeader: admin.csrfToken, originHeader: 'https://desktop.example', idempotencyKey: undefined };
  for (const [change, status] of [
    [{ cookieHeader: undefined }, 401], [{ csrfHeader: undefined }, 403],
    [{ originHeader: 'https://hostile.example' }, 403], [{ body: { expectedRevision: 1 } }, 400],
    [{ body: { expectedRevision: '1', actor: 'chief_admin' } }, 400],
    [{ body: { expectedRevision: '2' } }, 409],
    [{ path: '/v2/admin/accounts/absent/devices/worker-device/revoke' }, 404],
    [{ path: '/v2/admin/accounts/%E0%A4%A/revoke' }, 400], [{ path: '/v2/admin/accounts/worker/devices/%ZZ/revoke' }, 400],
    [{ method: 'PATCH', path: '/v2/admin/accounts/%E0/access', body: { role: 'auditor', expectedRevision: '1' } }, 400],
  ] as const) assert.equal((await routeAdmin(context, { ...request, ...change })).status, status);
  assert.ok(await replica.get(worker.sessionId));
  assert.equal((await routeAdmin(context, request)).status, 204);
  assert.equal(await replica.get(worker.sessionId), null);
  assert.equal((await routeAdmin(context, { ...request, path: '/v2/admin/accounts/worker/revoke' })).status, 204);
  assert.equal((await pool.query("SELECT enabled FROM demo_admin_account WHERE username='worker'")).rows[0].enabled, false);
});
