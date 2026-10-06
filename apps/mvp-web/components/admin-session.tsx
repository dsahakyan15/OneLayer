"use client";

import Link from "next/link";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { admin, ApiError } from "../lib/api";

export interface AdminSessionState {
  username: string;
  /** Server role ID; the client never sets or overrides it. */
  role: string;
  csrfToken: string;
  /** Server-sent permission metadata. A session without it grants nothing. */
  permissions: string[];
  registryIds: string[];
  deploymentRegistryId: string | null;
  /** True only when the server session carried the permission metadata. */
  metadataPresent: boolean;
}

/** English labels for the eight server role IDs. */
export const ROLE_LABELS: Record<string, string> = {
  operator: "Operator",
  auditor: "Auditor",
  chief_admin: "Chief admin",
  registry_worker: "Registry worker",
  registry_approver: "Registry approver",
  identity_admin: "Identity admin",
  key_holder: "Key holder",
  storage_custodian: "Storage custodian",
};

/** Own-property lookup: a role named `constructor` is not a labelled role. */
export function roleLabel(role: string): string | null {
  return Object.hasOwn(ROLE_LABELS, role) ? ROLE_LABELS[role] : null;
}

/**
 * A grant is only trusted when the server session carried permission metadata,
 * the permission is granted, and the deployment registry is inside the session
 * registry scope. This mirrors the server rule (exact registry IDs only; the
 * backend rejects a \`*\` wildcard), so a session scoped to a foreign registry
 * stays read-only and hidden. Absent or malformed metadata grants nothing.
 */
export function hasPermission(session: AdminSessionState | null, permission: string): boolean {
  if (session === null || !session.metadataPresent) return false;
  if (session.deploymentRegistryId === null) return false;
  if (!session.registryIds.includes(session.deploymentRegistryId)) return false;
  return session.permissions.includes(permission);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string" && entry.length > 0);
}

/**
 * Absent or malformed permission metadata is treated as no grants at all: every
 * entry must be a string, and the deployment registry ID must be a non-empty
 * string. Invalid entries are never filtered into a partially trusted session.
 */
function sessionMetadata(current: any): Pick<AdminSessionState, "permissions" | "registryIds" | "deploymentRegistryId" | "metadataPresent"> {
  const deploymentRegistryId = typeof current?.deploymentRegistryId === "string" && current.deploymentRegistryId.length > 0
    ? current.deploymentRegistryId
    : null;
  const metadataPresent = isStringArray(current?.permissions) && isStringArray(current?.registryIds) && deploymentRegistryId !== null;
  if (!metadataPresent) return { permissions: [], registryIds: [], deploymentRegistryId, metadataPresent: false };
  return { permissions: [...current.permissions], registryIds: [...current.registryIds], deploymentRegistryId, metadataPresent: true };
}

/**
 * The identity fields must be non-empty strings. A malformed session DTO fails
 * the whole session closed instead of producing a partially trusted shell.
 */
function sessionIdentity(current: any): { username: string; role: string; csrfToken: string } | null {
  if (typeof current?.username !== "string" || current.username.length === 0) return null;
  if (typeof current?.role !== "string" || current.role.length === 0) return null;
  if (typeof current?.csrfToken !== "string" || current.csrfToken.length === 0) return null;
  return { username: current.username, role: current.role, csrfToken: current.csrfToken };
}

/**
 * The corporate sign-in answer must carry an absolute URL without embedded
 * credentials. HTTPS is allowed for any configured provider; plain http only
 * for the loopback hosts the server's own OIDC policy accepts for tests
 * (127.0.0.1, [::1], localhost). Anything else opens nothing.
 */
function safeAuthorizationUrl(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.username !== "" || url.password !== "") return null;
  if (url.protocol === "https:") return url.toString();
  if (url.protocol !== "http:") return null;
  if (!["127.0.0.1", "[::1]", "localhost"].includes(url.hostname)) return null;
  return url.toString();
}

interface SessionContextValue {
  session: AdminSessionState | null;
  loading: boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

const SessionContext = createContext<SessionContextValue>({
  session: null,
  loading: true,
  refresh: async () => {},
  logout: async () => {},
});

export function useAdminSession(): SessionContextValue {
  return useContext(SessionContext);
}

/** The role always comes from the server session, never from local state. */
export function AdminShell({ children }: { children: ReactNode }): ReactNode {
  const [session, setSession] = useState<AdminSessionState | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const current = await admin("/session");
      const identity = sessionIdentity(current);
      if (identity === null) {
        setSession(null);
        return;
      }
      setSession({
        ...identity,
        ...sessionMetadata(current),
      });
    } catch {
      setSession(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    if (session !== null) {
      await admin("/session", { method: "DELETE", csrfToken: session.csrfToken }).catch(() => undefined);
    }
    setSession(null);
  }, [session]);

  useEffect(() => { void refresh(); }, [refresh]);

  return (
    <SessionContext.Provider value={{ session, loading, refresh, logout }}>
      <main className="ol-shell">
        <div className="ol-nav">
          <Link href="/admin">Dashboard</Link>
          <Link href="/admin/records">Records</Link>
          {hasPermission(session, "records.read") ? <Link href="/admin/workflow" data-testid="nav-workflow">Workflow</Link> : null}
          <Link href="/admin/publish">Prepare &amp; publish</Link>
          <Link href="/admin/certificates">Certificates</Link>
          <Link href="/admin/backups">Backup Centers</Link>
          <Link href="/admin/timeline">Timeline</Link>
          <Link href="/verify">Public panel</Link>
        </div>
        {loading ? <p role="status">Loading session…</p> : null}
        {!loading && session === null ? <LoginForm onSuccess={refresh} /> : null}
        {!loading && session !== null ? (
          <>
            <p data-testid="session-summary">
              Signed in as <strong data-testid="session-username">{session.username}</strong>{" "}
              with role <strong data-testid="session-role">{session.role}</strong>
              {roleLabel(session.role) === null ? null : <> (<span data-testid="session-role-label">{roleLabel(session.role)}</span>)</>}
              .{" "}
              <button type="button" onClick={() => void logout()} data-testid="logout">Sign out</button>
            </p>
            {children}
          </>
        ) : null}
      </main>
    </SessionContext.Provider>
  );
}

function LoginForm({ onSuccess }: { onSuccess: () => Promise<void> }): ReactNode {
  const [username, setUsername] = useState("operator");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [corporateLogin, setCorporateLogin] = useState(false);
  useEffect(() => {
    let active = true;
    fetch('/v2/admin/oidc/config', { cache: 'no-store' })
      .then(response => response.ok ? response.json() : null)
      .then(value => { if (active) setCorporateLogin(value?.enabled === true); })
      .catch(() => undefined);
    return () => { active = false; };
  }, []);

  const startCorporateSignIn = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch('/v2/admin/oidc/start', { method: 'POST', credentials: 'same-origin' });
      if (!response.ok) throw new Error('SIGN_IN_UNAVAILABLE');
      const result = await response.json().catch(() => null);
      const authorizationUrl = safeAuthorizationUrl(result?.authorizationUrl);
      if (authorizationUrl === null) {
        setError('Corporate sign-in answered without a usable authorization URL. Nothing was opened; try again or contact the administrator.');
        setBusy(false);
        return;
      }
      window.location.assign(authorizationUrl);
    } catch {
      setError('Corporate sign-in is unavailable. Try again.');
      setBusy(false);
    }
  };

  if (corporateLogin) return (
    <section className="ol-card">
      <h2>Corporate sign-in</h2>
      <p>Use your organization account and enrolled device.</p>
      <button type="button" data-testid="oidc-signin" disabled={busy} onClick={() => void startCorporateSignIn()}>
        {busy ? 'Opening sign-in…' : 'Sign in with organization account'}
      </button>
      {error ? <p className="ol-error" data-testid="login-error">{error}</p> : null}
    </section>
  );

  return (
    <section className="ol-card">
      <h2>Admin sign-in</h2>
      <p className="ol-muted">
        Configured demo credentials. Any account name the deployment configures works here; the role,
        permissions and registry scope always come from the server session and are never chosen by the
        browser. This is access separation for the demo, not an identity provider: production SSO and RBAC
        are Gate E.
      </p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          setBusy(true);
          setError(null);
          admin("/session", { method: "POST", body: { username, password } })
            .then(() => onSuccess())
            .catch((cause: unknown) => setError(cause instanceof ApiError ? cause.code : "SIGN_IN_FAILED"))
            .finally(() => setBusy(false));
        }}
      >
        <div className="ol-grid">
          <label className="ol-field">
            <span className="ol-label">User</span>
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              data-testid="login-username"
              autoComplete="username"
              list="admin-demo-users"
            />
            <datalist id="admin-demo-users">
              <option value="operator" />
              <option value="auditor" />
              <option value="chief_admin" />
              <option value="registry_worker" />
              <option value="registry_approver" />
            </datalist>
          </label>
          <label className="ol-field">
            <span className="ol-label">Password</span>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              data-testid="login-password"
              autoComplete="current-password"
            />
          </label>
        </div>
        <p>
          <button type="submit" data-variant="primary" disabled={busy} data-testid="login-submit">
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </p>
        {error !== null ? <p className="ol-error" data-testid="login-error">{error}</p> : null}
      </form>
    </section>
  );
}
