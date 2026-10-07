import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT, type JWTPayload } from 'jose';
import type { OidcConfig } from '../../src/oidc.ts';

/** Synthetic issuer over a real loopback HTTP socket. Never a production identity source. */
export async function startTestIdp() {
  const keys = await generateKeyPair('RS256');
  const forged = await generateKeyPair('RS256');
  const jwk = { ...await exportJWK(keys.publicKey), kid: 'test-key', alg: 'RS256', use: 'sig' };
  const codes = new Map<string, { nonce: string; challenge: string; redirectUri: string }>();
  let issuer = '';
  let tokenRequests = 0;
  const controls: { claims: JWTPayload; forgeSignature: boolean; redirectToken: boolean; redirectJwks: boolean; oversizedJwks: boolean; maliciousHeader: boolean } = {
    claims: {}, forgeSignature: false, redirectToken: false, redirectJwks: false, oversizedJwks: false, maliciousHeader: false,
  };
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url!, issuer);
      if (url.pathname === '/authorize') {
        const query = url.searchParams;
        if (query.get('client_id') !== 'test-client' || query.get('response_type') !== 'code' || query.get('code_challenge_method') !== 'S256') throw new Error('request');
        const code = randomBytes(24).toString('hex');
        codes.set(code, { nonce: query.get('nonce')!, challenge: query.get('code_challenge')!, redirectUri: query.get('redirect_uri')! });
        const location = new URL(query.get('redirect_uri')!); location.searchParams.set('state', query.get('state')!); location.searchParams.set('code', code);
        res.writeHead(302, { location: location.href }); res.end(); return;
      }
      if (url.pathname === '/jwks') {
        if (controls.redirectJwks) { res.writeHead(302, { location: 'http://127.0.0.1:1/evil' }); res.end(); return; }
        res.setHeader('content-type', 'application/json');
        res.end(controls.oversizedJwks ? JSON.stringify({ padding: 'x'.repeat(70000) }) : JSON.stringify({ keys: [jwk] })); return;
      }
      if (url.pathname !== '/token' || req.method !== 'POST') { res.writeHead(404); res.end(); return; }
      tokenRequests++;
      if (controls.redirectToken) { res.writeHead(302, { location: 'http://127.0.0.1:1/evil' }); res.end(); return; }
      const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(chunk);
      const form = new URLSearchParams(Buffer.concat(chunks).toString());
      const pending = codes.get(form.get('code')!); codes.delete(form.get('code')!);
      if (!pending || form.get('grant_type') !== 'authorization_code' || form.get('client_id') !== 'test-client' || form.get('redirect_uri') !== pending.redirectUri ||
          createHash('sha256').update(form.get('code_verifier') ?? '').digest('base64url') !== pending.challenge) throw new Error('invalid_grant');
      const now = Math.floor(Date.now() / 1000);
      const idToken = await new SignJWT({ iss: issuer, sub: 'test-user', aud: 'test-client', iat: now, exp: now + 300,
        nonce: pending.nonce, device_id: 'test-device', ...controls.claims })
        .setProtectedHeader({ alg: 'RS256', kid: 'test-key', ...(controls.maliciousHeader ? { jku: 'http://127.0.0.1:1/evil' } : {}) })
        .sign(controls.forgeSignature ? forged.privateKey : keys.privateKey);
      res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ id_token: idToken, token_type: 'Bearer', access_token: 'synthetic-unused' }));
    } catch { res.writeHead(400, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: 'invalid_grant' })); }
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('listen');
  issuer = `http://127.0.0.1:${address.port}`;
  return { issuer, controls, get tokenRequests() { return tokenRequests; },
    config(redirectUri = `${issuer}/callback`): OidcConfig { return { issuer, authorizationEndpoint: `${issuer}/authorize`, tokenEndpoint: `${issuer}/token`, jwksUri: `${issuer}/jwks`, redirectUri, clientId: 'test-client', allowInsecureLocalhostForTests: true }; },
    async authorize(authorizationUrl: string) {
      const response = await fetch(authorizationUrl, { redirect: 'manual' });
      const callback = new URL(response.headers.get('location')!);
      return { state: callback.searchParams.get('state')!, code: callback.searchParams.get('code')! };
    },
    async close() { server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); },
  };
}
