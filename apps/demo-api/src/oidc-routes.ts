import { parseCookies, sessionCookie, type AdminSession } from './admin-session.ts';
import { OidcError, type OidcClient, type OidcIdentity } from './oidc.ts';

export interface OidcRoutes {
  client: Pick<OidcClient, 'start' | 'complete'>;
  login: (identity: OidcIdentity) => Promise<AdminSession | null>;
  browserOrigin: string;
  secureCookies: boolean;
  successRedirect?: string;
}
export const OIDC_BINDING_COOKIE = 'onelayer_oidc_binding';

/** The browser binding never enters the JSON response or renderer storage. */
export async function routeOidc(context: OidcRoutes, request: {
  method: string; path: string; query: URLSearchParams;
  cookieHeader: string | undefined; originHeader?: string;
}): Promise<{ status: number; body: unknown; setCookie?: string; location?: string }> {
  if (request.path === '/v2/admin/oidc/start' && request.method === 'POST') {
    if (request.originHeader !== context.browserOrigin) return { status: 403, body: { code: 'ORIGIN_FORBIDDEN' } };
    const started = context.client.start();
    return { status: 200, body: { authorizationUrl: started.authorizationUrl, expiresAt: started.expiresAt },
      setCookie: `${OIDC_BINDING_COOKIE}=${started.browserBinding}; HttpOnly; SameSite=Lax; Path=/v2/admin/oidc; Max-Age=300${context.secureCookies ? '; Secure' : ''}` };
  }
  if (request.path === '/v2/admin/oidc/callback' && request.method === 'GET') {
    try {
      if (request.query.has('error') || request.query.getAll('state').length !== 1 || request.query.getAll('code').length !== 1) throw new OidcError();
      const identity = await context.client.complete({ state: request.query.get('state')!, code: request.query.get('code')!,
        browserBinding: parseCookies(request.cookieHeader).get(OIDC_BINDING_COOKIE) ?? '' });
      const session = await context.login(identity);
      if (!session) throw new OidcError();
      return { status: context.successRedirect ? 303 : 200, ...(context.successRedirect ? { location: context.successRedirect } : {}), setCookie: sessionCookie(session) + (context.secureCookies ? '; Secure' : ''),
        body: { username: session.username, role: session.role, expiresAt: new Date(session.expiresAt).toISOString() } };
    } catch (error) {
      if (!(error instanceof OidcError)) throw error;
      return { status: 401, body: { code: 'OIDC_AUTHENTICATION_FAILED' } };
    }
  }
  return { status: 404, body: { code: 'NOT_FOUND' } };
}
