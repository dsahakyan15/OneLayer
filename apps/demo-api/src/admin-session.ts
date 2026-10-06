// Demo access separation (OL-C-31). Runtime-generated credentials live in
// tmpfs; the role is read from the server session only — never from a cookie
// payload, request body, query string or hidden UI element. This is not an IdP
// and does not replace production SSO/RBAC (Gate E).
import { randomBytes, timingSafeEqual } from "node:crypto";
import { demoPermissions, type AdminPermission, type AdminRole } from "./admin-permissions.ts";

export type { AdminRole } from "./admin-permissions.ts";

export const SESSION_COOKIE = "onelayer_admin_session";
export const CSRF_HEADER = "x-onelayer-csrf";
export const SESSION_TTL_MS = 30 * 60 * 1000;

export interface AdminSession {
  sessionId: string;
  username: string;
  role: AdminRole;
  csrfToken: string;
  expiresAt: number;
  permissions: readonly AdminPermission[];
  registryIds: readonly string[];
  authMethod?: "password" | "oidc";
  deviceId?: string;
  resourcePolicy?: unknown;
}

export interface Credential {
  username: string;
  password: string;
  role: AdminRole;
  permissions?: readonly AdminPermission[];
  registryIds?: readonly string[];
}

export type AdminAccess = Pick<Credential, "role" | "permissions" | "registryIds">;

export interface SessionBackend {
  revokeAsSession?(sessionId: string | undefined, username: string, expectedRevision: string, deviceId?: string): Promise<void>;
  changeAccessAsSession?(sessionId: string | undefined, username: string, access: AdminAccess, expectedRevision: string): Promise<void>;
  loginOidc?(identity: import("./oidc.ts").OidcIdentity): Promise<AdminSession | null>;
  login(username: unknown, password: unknown): AdminSession | null | Promise<AdminSession | null>;
  get(sessionId: string | undefined): AdminSession | null | Promise<AdminSession | null>;
  destroy(sessionId: string | undefined): void | Promise<void>;
}

export class IdentityUnavailableError extends Error {
  constructor() { super("IDENTITY_UNAVAILABLE"); }
}

export function normalizeAccess(access: AdminAccess): Required<AdminAccess> {
  const ceiling = demoPermissions(access.role);
  const permissions = access.permissions === undefined ? ceiling : access.permissions;
  if (!Array.isArray(permissions) || permissions.some((permission) => !ceiling.includes(permission))) {
    throw new TypeError("permission exceeds demo role policy");
  }
  const registryIds = access.registryIds === undefined ? ["gov.registry.land"] : access.registryIds;
  if (!Array.isArray(registryIds) || registryIds.some((id) => typeof id !== "string" || id.trim() !== id || id.length === 0 || id === "*")) {
    throw new TypeError("explicit registry IDs required");
  }
  return { role: access.role, permissions: [...permissions], registryIds: [...registryIds] };
}

function copyCredential(credential: Credential): Credential {
  return { ...credential, ...normalizeAccess(credential) };
}

export function parseCredentials(raw: string): Credential[] {
  const parsed: unknown = JSON.parse(raw);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TypeError("admin credentials file must be a JSON object");
  }
  const credentials: Credential[] = [];
  for (const [username, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (username !== "operator" && username !== "auditor" && username !== "chief_admin") {
      throw new TypeError(`unknown admin role ${username}`);
    }
    // Existing flat demo credentials remain valid. Deployment-owned entries
    // may additionally narrow access; request bodies never use this parser.
    const entry = typeof value === "string" ? { password: value } : value;
    if (entry === null || typeof entry !== "object" || Array.isArray(entry) ||
        Object.keys(entry).some((key) => !["password", "permissions", "registryIds"].includes(key))) {
      throw new TypeError("invalid admin credential entry");
    }
    const { password, permissions, registryIds } = entry as Record<string, unknown>;
    if (typeof password !== "string" || password.length < 16) {
      throw new TypeError(`admin password for ${username} is too short`);
    }
    credentials.push(copyCredential({ username, password, role: username,
      permissions: permissions as readonly AdminPermission[] | undefined,
      registryIds: registryIds as readonly string[] | undefined,
    }));
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

export function matchCredential(credentials: readonly Credential[], username: unknown, password: unknown): Credential | null {
  if (typeof username !== "string" || typeof password !== "string") return null;
  let matched: Credential | null = null;
  for (const credential of credentials) {
    const sameUser = constantTimeEquals(credential.username, username);
    const samePassword = constantTimeEquals(credential.password, password);
    if (sameUser && samePassword) matched = credential;
  }
  return matched;
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
  private readonly revokedUsers = new Set<string>();

  constructor(credentials: Credential[], now: () => number = Date.now) {
    if (new Set(credentials.map((credential) => credential.username)).size !== credentials.length) {
      throw new TypeError("duplicate admin username");
    }
    this.credentials = credentials.map(copyCredential);
    this.now = now;
  }

  /** Returns a session, or null for unknown users and wrong passwords alike. */
  login(username: unknown, password: unknown): AdminSession | null {
    const matched = matchCredential(this.credentials, username, password);
    if (matched === null || this.revokedUsers.has(matched.username)) return null;
    const session: AdminSession = {
      sessionId: randomBytes(32).toString("base64url"),
      username: matched.username,
      role: matched.role,
      csrfToken: randomBytes(32).toString("base64url"),
      expiresAt: this.now() + SESSION_TTL_MS,
      permissions: Object.freeze([...matched.permissions!]),
      registryIds: Object.freeze([...matched.registryIds!]),
    };
    Object.freeze(session);
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

  /** Trusted provisioning API only; deliberately not exposed as an HTTP route. */
  revokeUser(username: string): void {
    this.revokedUsers.add(username);
    this.destroyUserSessions(username);
  }

  /** Reauthentication is required after every access change, including narrowing. */
  updateAccess(username: string, access: Pick<Credential, "role" | "permissions" | "registryIds">): void {
    const index = this.credentials.findIndex((credential) => credential.username === username);
    if (index < 0) throw new TypeError("unknown admin user");
    // Validate before changing either credentials or sessions. Revocation is sticky.
    const previous = this.credentials[index];
    const permissions = access.permissions ?? previous.permissions!.filter((permission) => demoPermissions(access.role).includes(permission));
    this.credentials[index] = copyCredential({ ...previous, ...access, permissions });
    this.destroyUserSessions(username);
  }

  private destroyUserSessions(username: string): void {
    for (const [id, session] of this.sessions) {
      if (session.username === username) this.sessions.delete(id);
    }
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
  return validateSessionRequest(session, request);
}

export async function authorizeRequest(store: SessionBackend, request: AuthorizedRequest): Promise<AdminSession> {
  const sessionId = parseCookies(request.cookieHeader).get(SESSION_COOKIE);
  return validateSessionRequest(await store.get(sessionId), request);
}

function validateSessionRequest(session: AdminSession | null, request: AuthorizedRequest): AdminSession {
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

export function requirePermission(session: AdminSession, registryId: string, permission: AdminPermission): AdminSession {
  if (!session.registryIds.includes(registryId) || !session.permissions.includes(permission)) {
    throw new AuthorizationError(403, "PERMISSION_FORBIDDEN");
  }
  return session;
}

export function requireChiefAdmin(session: AdminSession): AdminSession {
  if (session.role !== "chief_admin") throw new AuthorizationError(403, "ROLE_FORBIDDEN");
  return session;
}
