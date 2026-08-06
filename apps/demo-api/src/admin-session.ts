// Demo access separation (OL-C-31). Runtime-generated credentials live in
// tmpfs; the role is read from the server session only — never from a cookie
// payload, request body, query string or hidden UI element. This is not an IdP
// and does not replace production SSO/RBAC (Gate E).
import { randomBytes, timingSafeEqual } from "node:crypto";

export type AdminRole = "operator" | "auditor" | "chief_admin";

export const SESSION_COOKIE = "onelayer_admin_session";
export const CSRF_HEADER = "x-onelayer-csrf";
export const SESSION_TTL_MS = 30 * 60 * 1000;

export interface AdminSession {
  sessionId: string;
  username: string;
  role: AdminRole;
  csrfToken: string;
  expiresAt: number;
}

export interface Credential {
  username: string;
  password: string;
  role: AdminRole;
}

export function parseCredentials(raw: string): Credential[] {
  const parsed: unknown = JSON.parse(raw);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TypeError("admin credentials file must be a JSON object");
  }
  const credentials: Credential[] = [];
  for (const [username, password] of Object.entries(parsed as Record<string, unknown>)) {
    if (username !== "operator" && username !== "auditor" && username !== "chief_admin") {
      throw new TypeError(`unknown admin role ${username}`);
    }
    if (typeof password !== "string" || password.length < 16) {
      throw new TypeError(`admin password for ${username} is too short`);
    }
    credentials.push({ username, password, role: username });
  }
  const roles = new Set(credentials.map((credential) => credential.role));
  if (!roles.has("operator") || !roles.has("auditor")) {
    throw new TypeError("both operator and auditor credentials are required");
  }
  return credentials;
}

function constantTimeEquals(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function parseCookies(header: string | undefined): Map<string, string> {
  const cookies = new Map<string, string>();
  for (const part of (header ?? "").split(";")) {
    const index = part.indexOf("=");
    if (index <= 0) continue;
    cookies.set(part.slice(0, index).trim(), part.slice(index + 1).trim());
  }
  return cookies;
}

export class SessionStore {
  private readonly sessions = new Map<string, AdminSession>();
  private readonly credentials: Credential[];
  private readonly now: () => number;

  constructor(credentials: Credential[], now: () => number = Date.now) {
    this.credentials = credentials;
    this.now = now;
  }

  /** Returns a session, or null for unknown users and wrong passwords alike. */
  login(username: unknown, password: unknown): AdminSession | null {
    if (typeof username !== "string" || typeof password !== "string") return null;
    let matched: Credential | null = null;
    // Every credential is compared so the response time does not reveal which
    // usernames exist.
    for (const credential of this.credentials) {
      const same = constantTimeEquals(credential.username, username) &&
        constantTimeEquals(credential.password, password);
      if (same) matched = credential;
    }
    if (matched === null) return null;
    const session: AdminSession = {
      sessionId: randomBytes(32).toString("base64url"),
      username: matched.username,
      role: matched.role,
      csrfToken: randomBytes(32).toString("base64url"),
      expiresAt: this.now() + SESSION_TTL_MS,
    };
    this.sessions.set(session.sessionId, session);
    return session;
  }

  get(sessionId: string | undefined): AdminSession | null {
    if (sessionId === undefined) return null;
    const session = this.sessions.get(sessionId);
    if (session === undefined) return null;
    if (session.expiresAt <= this.now()) {
      this.sessions.delete(sessionId);
      return null;
    }
    return session;
  }

  destroy(sessionId: string | undefined): void {
    if (sessionId !== undefined) this.sessions.delete(sessionId);
  }

  get size(): number {
    return this.sessions.size;
  }
}

export function sessionCookie(session: AdminSession): string {
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  // No `Secure`: the demo is served over the exact loopback origin only. Any
  // other origin is rejected before a session is issued.
  return `${SESSION_COOKIE}=${session.sessionId}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

export function clearedCookie(): string {
  return `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`;
}

export class AuthorizationError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

export interface AuthorizedRequest {
  method: string;
  cookieHeader: string | undefined;
  csrfHeader: string | undefined;
}

/**
 * Resolves the session for a request and enforces CSRF on mutations. Role
 * checks are separate and always run on the server (`requireOperator`).
 */
export function authorize(store: SessionStore, request: AuthorizedRequest): AdminSession {
  const sessionId = parseCookies(request.cookieHeader).get(SESSION_COOKIE);
  const session = store.get(sessionId);
  if (session === null) throw new AuthorizationError(401, "SESSION_REQUIRED");
  if (request.method !== "GET" && request.method !== "HEAD") {
    if (request.csrfHeader === undefined || !constantTimeEquals(session.csrfToken, request.csrfHeader)) {
      throw new AuthorizationError(403, "CSRF_TOKEN_INVALID");
    }
  }
  return session;
}

export function requireOperator(session: AdminSession): AdminSession {
  if (session.role !== "operator") throw new AuthorizationError(403, "ROLE_FORBIDDEN");
  return session;
}

export function requireChiefAdmin(session: AdminSession): AdminSession {
  if (session.role !== "chief_admin") throw new AuthorizationError(403, "ROLE_FORBIDDEN");
  return session;
}
