import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose';

export type OidcConfig = {
  issuer: string; authorizationEndpoint: string; tokenEndpoint: string; jwksUri: string;
  redirectUri: string; clientId: string; clientSecret?: string; deviceClaim?: string;
  allowInsecureLocalhostForTests?: boolean;
};
export type OidcIdentity = { issuer: string; subject: string; deviceId: string; expiresAt: number };
export class OidcError extends Error {
  constructor() { super('OIDC authentication failed'); this.name = 'OidcError'; }
}
const validText = (value: unknown): value is string => typeof value === 'string' && value.length > 0 && value.length <= 2048 && !/[\x00-\x20\x7f]/.test(value);
export function parseOidcConfig(value: unknown): OidcConfig {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid OIDC configuration');
  const config = value as Record<string, unknown>;
  const required = ['issuer', 'authorizationEndpoint', 'tokenEndpoint', 'jwksUri', 'redirectUri', 'clientId'];
  const optional = ['clientSecret', 'deviceClaim', 'allowInsecureLocalhostForTests'];
  if (Object.keys(config).some(key => ![...required, ...optional].includes(key)) || required.some(key => !validText(config[key])) ||
      ['clientSecret', 'deviceClaim'].some(key => config[key] !== undefined && !validText(config[key])) ||
      (config.allowInsecureLocalhostForTests !== undefined && typeof config.allowInsecureLocalhostForTests !== 'boolean')) throw new Error('Invalid OIDC configuration');
  for (const key of required.slice(0, 5)) {
    const url = new URL(config[key] as string);
    const testHttp = config.allowInsecureLocalhostForTests === true && url.protocol === 'http:' && ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
    if ((url.protocol !== 'https:' && !testHttp) || url.username || url.password || url.hash || url.search) throw new Error('Invalid OIDC endpoint');
  }
  const issuerOrigin = new URL(config.issuer as string).origin;
  if (['authorizationEndpoint', 'tokenEndpoint', 'jwksUri'].some(key => new URL(config[key] as string).origin !== issuerOrigin)) throw new Error('OIDC endpoints must share the pinned issuer origin');
  return { ...config } as OidcConfig;
}
const random = () => randomBytes(32).toString('base64url');
const hash = (value: string) => createHash('sha256').update(value).digest();
type Pending = { nonce: string; verifier: string; bindingHash: Buffer; expiresAt: number };

/** Server-only code flow. All expiration timestamps are Unix milliseconds. */
export class OidcClient {
  readonly #config: OidcConfig;
  readonly #pending = new Map<string, Pending>();
  constructor(config: OidcConfig) { this.#config = parseOidcConfig(config); }
  start(): { authorizationUrl: string; state: string; browserBinding: string; expiresAt: number } {
    const now = Date.now();
    for (const [state, pending] of this.#pending) if (pending.expiresAt <= now) this.#pending.delete(state);
    if (this.#pending.size >= 1024) throw new OidcError();
    const state = random(), nonce = random(), verifier = random(), browserBinding = random();
    const expiresAt = now + 5 * 60_000;
    this.#pending.set(state, { nonce, verifier, bindingHash: hash(browserBinding), expiresAt });
    const url = new URL(this.#config.authorizationEndpoint);
    url.search = new URLSearchParams({ response_type: 'code', client_id: this.#config.clientId, redirect_uri: this.#config.redirectUri,
      scope: 'openid', state, nonce, code_challenge: hash(verifier).toString('base64url'), code_challenge_method: 'S256' }).toString();
    return { authorizationUrl: url.href, state, browserBinding, expiresAt };
  }
  async complete(input: { state: string; code: string; browserBinding: string }): Promise<OidcIdentity> {
    const pending = this.#pending.get(input.state);
    // Consume before any await: concurrent callback and retries cannot exchange twice.
    this.#pending.delete(input.state);
    try {
      if (!pending || pending.expiresAt <= Date.now() || !validText(input.code) || !validText(input.browserBinding) ||
          !timingSafeEqual(hash(input.browserBinding), pending.bindingHash)) throw new OidcError();
      const form = new URLSearchParams({ grant_type: 'authorization_code', code: input.code, client_id: this.#config.clientId,
        redirect_uri: this.#config.redirectUri, code_verifier: pending.verifier });
      const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
      if (this.#config.clientSecret) {
        const encode = (value: string) => new URLSearchParams({ v: value }).toString().slice(2);
        headers.authorization = `Basic ${Buffer.from(`${encode(this.#config.clientId)}:${encode(this.#config.clientSecret)}`).toString('base64')}`;
      }
      const tokens = await this.#json(this.#config.tokenEndpoint, { method: 'POST', headers, body: form.toString() });
      if (typeof tokens.id_token !== 'string' || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(tokens.id_token) || tokens.id_token.length > 16384) throw new OidcError();
      const jwks = await this.#json(this.#config.jwksUri);
      if (!Array.isArray(jwks.keys) || jwks.keys.length === 0 || jwks.keys.length > 32) throw new OidcError();
      const { payload, protectedHeader } = await jwtVerify(tokens.id_token, createLocalJWKSet(jwks as unknown as JSONWebKeySet), {
        issuer: this.#config.issuer, audience: this.#config.clientId, algorithms: ['RS256', 'ES256'],
        requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce'], maxTokenAge: '5 minutes', clockTolerance: 0,
      });
      if (protectedHeader.jku || protectedHeader.jwk || protectedHeader.x5u || payload.nonce !== pending.nonce ||
          !validText(payload.sub) || !validText(payload[this.#config.deviceClaim ?? 'device_id']) ||
          (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== this.#config.clientId) ||
          (payload.azp !== undefined && payload.azp !== this.#config.clientId)) throw new OidcError();
      return { issuer: payload.iss!, subject: payload.sub, deviceId: payload[this.#config.deviceClaim ?? 'device_id'] as string, expiresAt: payload.exp! * 1000 };
    } catch { throw new OidcError(); }
  }
  async #json(url: string, init: RequestInit = {}): Promise<Record<string, unknown>> {
    const response = await fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(5000) });
    if (!response.ok || !response.headers.get('content-type')?.toLowerCase().startsWith('application/json') || !response.body) {
      await response.body?.cancel(); throw new OidcError();
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = []; let length = 0;
    try {
      while (true) {
        const { value, done } = await reader.read(); if (done) break;
        length += value.byteLength;
        if (length > 64 * 1024) throw new OidcError();
        chunks.push(value);
      }
    } finally { await reader.cancel(); }
    const value: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new OidcError();
    return value as Record<string, unknown>;
  }
}
