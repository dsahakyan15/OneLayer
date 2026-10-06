import test from 'node:test';
import assert from 'node:assert/strict';
import { OidcClient, OidcError, parseOidcConfig } from '../src/oidc.ts';
import { startTestIdp } from './support/test-idp.ts';

test('real HTTP test IdP code exchange binds PKCE, nonce, browser and single-use state', async () => {
  const idp = await startTestIdp();
  try {
    const client = new OidcClient(idp.config());
    const login = client.start();
    const callback = await idp.authorize(login.authorizationUrl);
    const input = { ...callback, browserBinding: login.browserBinding };
    const identity = await client.complete(input);
    assert.equal(identity.issuer, idp.issuer); assert.equal(identity.subject, 'test-user'); assert.equal(identity.deviceId, 'test-device');
    assert.ok(identity.expiresAt > Date.now());
    await assert.rejects(client.complete(input), OidcError);
    assert.equal(idp.tokenRequests, 1);
  } finally { await idp.close(); }
});

test('rejects forged claims, signatures, endpoint redirects and token-supplied key locations', async t => {
  const idp = await startTestIdp();
  try {
    const cases = [
      { name: 'issuer', claims: { iss: 'https://evil.example' } },
      { name: 'audience', claims: { aud: 'other-client' } },
      { name: 'expiry', claims: { exp: Math.floor(Date.now() / 1000) - 1 } },
      { name: 'future iat', claims: { iat: Math.floor(Date.now() / 1000) + 60 } },
      { name: 'nonce', claims: { nonce: 'other-nonce' } },
      { name: 'empty subject', claims: { sub: '' } },
      { name: 'missing device', claims: { device_id: null } },
      { name: 'multi audience missing azp', claims: { aud: ['test-client', 'other'] } },
      { name: 'wrong azp', claims: { azp: 'other' } },
      { name: 'forged signature', forgeSignature: true },
      { name: 'token redirect', redirectToken: true },
      { name: 'jwks redirect', redirectJwks: true },
      { name: 'oversized response', oversizedJwks: true },
      { name: 'token jku', maliciousHeader: true },
    ];
    for (const item of cases) await t.test(item.name, async () => {
      Object.assign(idp.controls, { claims: {}, forgeSignature: false, redirectToken: false, redirectJwks: false, oversizedJwks: false, maliciousHeader: false }, item);
      const client = new OidcClient(idp.config()); const login = client.start();
      const callback = await idp.authorize(login.authorizationUrl);
      await assert.rejects(client.complete({ ...callback, browserBinding: login.browserBinding }), OidcError);
    });
  } finally { await idp.close(); }
});

test('state, cookie and substituted code reject; failed callback also cannot replay', async () => {
  const idp = await startTestIdp();
  try {
    const client = new OidcClient(idp.config());
    for (const field of ['state', 'browserBinding', 'code'] as const) {
      const login = client.start(); const callback = await idp.authorize(login.authorizationUrl);
      const input = { ...callback, browserBinding: login.browserBinding };
      await assert.rejects(client.complete({ ...input, [field]: 'invalid' }), OidcError);
      if (field !== 'state') await assert.rejects(client.complete(input), OidcError);
    }
    assert.equal(idp.tokenRequests, 1);
  } finally { await idp.close(); }
});

test('strict static endpoint config excludes remote HTTP, alternate origins, URL credentials and open redirects', () => {
  const config = { issuer: 'https://idp.example', authorizationEndpoint: 'https://idp.example/auth', tokenEndpoint: 'https://idp.example/token', jwksUri: 'https://idp.example/jwks', redirectUri: 'https://app.example/callback', clientId: 'client' };
  assert.deepEqual(parseOidcConfig(config), config);
  for (const change of [{ jwksUri: 'https://evil.example/jwks' }, { tokenEndpoint: 'http://idp.example/token', allowInsecureLocalhostForTests: true },
    { redirectUri: 'https://app.example/callback?next=https://evil.example' }, { issuer: 'https://user:pass@idp.example' }, { allowInsecureLocalhostForTests: 'true' }]) {
    assert.throws(() => parseOidcConfig({ ...config, ...change }));
  }
});


test('valid signed ID tokens above 2 KiB retain the explicit 16 KiB JWT limit', async () => {
  const idp = await startTestIdp();
  try {
    idp.controls.claims = { synthetic_padding: 'x'.repeat(2500) };
    const client = new OidcClient(idp.config());
    const start = client.start();
    const identity = await client.complete({ ...await idp.authorize(start.authorizationUrl), browserBinding: start.browserBinding });
    assert.equal(identity.subject, 'test-user');
    idp.controls.claims = { synthetic_padding: 'x'.repeat(17000) };
    const oversized = client.start();
    await assert.rejects(client.complete({ ...await idp.authorize(oversized.authorizationUrl), browserBinding: oversized.browserBinding }), OidcError);
  } finally { await idp.close(); }
});
