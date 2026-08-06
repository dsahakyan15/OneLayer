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
  role: "operator" | "auditor" | "chief_admin";
  csrfToken: string;
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
      setSession({ username: current.username, role: current.role, csrfToken: current.csrfToken });
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
              with role <strong data-testid="session-role">{session.role}</strong>.{" "}
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

  return (
    <section className="ol-card">
      <h2>Admin sign-in</h2>
      <p className="ol-muted">
        Runtime-generated demo credentials. This is access separation for the demo, not an identity
        provider: production SSO and RBAC are Gate E.
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
            <select value={username} onChange={(event) => setUsername(event.target.value)} data-testid="login-username">
              <option value="operator">operator</option>
              <option value="auditor">auditor</option>
              <option value="chief_admin">chief_admin</option>
            </select>
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
