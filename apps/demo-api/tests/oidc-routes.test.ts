import assert from 'node:assert/strict';
import test from 'node:test';
import { routeOidc, OIDC_BINDING_COOKIE, type OidcRoutes } from '../src/oidc-routes.ts';
import { OidcError } from '../src/oidc.ts';
import { SessionStore } from '../src/admin-session.ts';
import { routeAdmin, type AdminContext } from '../src/admin.ts';

const store = new SessionStore([{ username: 'worker', password: 'synthetic-password-123456', role: 'operator' }]);
const session = store.login('worker', 'synthetic-password-123456')!;
const request = { method: 'POST', path: '/v2/admin/oidc/start', query: new URLSearchParams(), cookieHeader: undefined as string | undefined, originHeader: 'https://desktop.example' };
const context: OidcRoutes = {
  browserOrigin: 'https://desktop.example', secureCookies: true,
  client: {
    start: () => ({ authorizationUrl: 'https://idp.example/auth?state=state', state: 'state', browserBinding: 'private-binding', expiresAt: 123 }),
    complete: async input => {
      if (input.browserBinding !== 'private-binding' || input.state !== 'state' || input.code !== 'code') throw new OidcError();
      return { issuer: 'https://idp.example', subject: 'worker', deviceId: 'device', expiresAt: Date.now() + 10000 };
    },
  },
  login: async () => session,
};

test('OIDC start requires exact trusted Origin and keeps binding HttpOnly', async () => {
  for (const originHeader of [undefined, 'null', 'https://attacker.example', 'https://desktop.example.evil']) {
    assert.equal((await routeOidc(context, { ...request, originHeader })).status, 403);
  }
  const result = await routeOidc(context, request);
  assert.equal(result.status, 200);
  assert.ok(result.setCookie?.includes('HttpOnly; SameSite=Lax'));
  assert.ok(result.setCookie?.endsWith('; Secure'));
  assert.ok(!JSON.stringify(result.body).includes('private-binding'));
});

test('callback requires browser binding and unique code/state, and does not leak identity claims', async () => {
  const callback = { ...request, method: 'GET', path: '/v2/admin/oidc/callback', query: new URLSearchParams('state=state&code=code'), cookieHeader: `${OIDC_BINDING_COOKIE}=private-binding` };
  assert.equal((await routeOidc(context, { ...callback, cookieHeader: undefined })).status, 401);
  for (const query of ['state=state&state=other&code=code', 'state=state&code=code&code=other', 'state=state&code=code&error=denied']) {
    assert.equal((await routeOidc(context, { ...callback, query: new URLSearchParams(query) })).status, 401);
  }
  const result = await routeOidc(context, callback);
  assert.equal(result.status, 200);
  assert.ok(result.setCookie?.includes('onelayer_admin_session='));
  assert.ok(result.setCookie?.endsWith('; Secure'));
  assert.ok(!JSON.stringify(result.body).includes('csrfToken'));
  assert.equal((await routeOidc({ ...context, login: async () => null }, callback)).status, 401);
});

test('OIDC mode disables password endpoint and narrowed identities cannot reach legacy aggregate SQL', async () => {
  let queries = 0;
  const narrowed = { ...session, authMethod: 'oidc' as const, resourcePolicy: { version: 1, grants: [] } };
  const ctx = { oidc: context, sessions: { login: () => { throw new Error('password must not be attempted'); }, get: () => narrowed },
    registryId: 'gov.registry.land', pool: { query: () => { queries++; throw new Error('must deny before SQL'); } } } as unknown as AdminContext;
  const req = { ...request, path: '/v1/admin/session', body: {}, csrfHeader: undefined, idempotencyKey: undefined };
  assert.equal((await routeAdmin(ctx, req)).status, 403);
  for (const path of ['/v1/admin/records', '/v1/admin/dashboard', '/v1/admin/certificates', '/v1/admin/timeline', '/v1/admin/backup-centers']) {
    assert.equal((await routeAdmin(ctx, { ...req, path, method: 'GET' })).status, 403);
  }
  assert.equal(queries, 0);
});

test('workflow routing requires session and CSRF before accessing the database', async () => {
  const ctx = { sessions: store, registryId: 'gov.registry.land', pool: { connect() { throw new Error('SQL must not be reached'); } } } as unknown as AdminContext;
  const req = { ...request, path: '/v2/admin/workflow/drafts', body: {}, csrfHeader: undefined, idempotencyKey: 'id' };
  assert.equal((await routeAdmin(ctx, req)).status, 401);
  assert.equal((await routeAdmin(ctx, { ...req, cookieHeader: `onelayer_admin_session=${session.sessionId}` })).status, 403);
});
