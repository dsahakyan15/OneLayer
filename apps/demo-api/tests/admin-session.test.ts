import assert from "node:assert/strict";
import { test } from "node:test";
import {
  authorize,
  AuthorizationError,
  clearedCookie,
  parseCookies,
  parseCredentials,
  requireOperator,
  SESSION_COOKIE,
  sessionCookie,
  SessionStore,
  SESSION_TTL_MS,
  type AdminSession,
} from "../src/admin-session.ts";

const credentials = parseCredentials(
  JSON.stringify({ operator: "operator-password-0123456789", auditor: "auditor-password-0123456789" }),
);

function loggedIn(store: SessionStore, username: string): AdminSession {
  const session = store.login(username, `${username}-password-0123456789`);
  assert.notEqual(session, null);
  return session as AdminSession;
}

test("credentials must cover both roles with non-trivial passwords", () => {
  assert.throws(() => parseCredentials(JSON.stringify({ operator: "short" })), TypeError);
  assert.throws(() => parseCredentials(JSON.stringify({ root: "x".repeat(20) })), TypeError);
  assert.throws(() => parseCredentials(JSON.stringify({ operator: "x".repeat(20) })), TypeError);
  assert.equal(credentials.length, 2);
});

test("a wrong password yields no session", () => {
  const store = new SessionStore(credentials);
  assert.equal(store.login("operator", "wrong"), null);
  assert.equal(store.login("nobody", "operator-password-0123456789"), null);
  assert.equal(store.size, 0);
});

test("the cookie is HttpOnly, SameSite and path-scoped", () => {
  const store = new SessionStore(credentials);
  const cookie = sessionCookie(loggedIn(store, "operator"));
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Path=\//);
  assert.match(clearedCookie(), /Max-Age=0/);
});

test("mutations require the session CSRF token", () => {
  const store = new SessionStore(credentials);
  const session = loggedIn(store, "operator");
  const cookieHeader = `${SESSION_COOKIE}=${session.sessionId}`;
  assert.equal(
    authorize(store, { method: "GET", cookieHeader, csrfHeader: undefined }).role,
    "operator",
  );
  assert.throws(
    () => authorize(store, { method: "POST", cookieHeader, csrfHeader: undefined }),
    (error: AuthorizationError) => error.code === "CSRF_TOKEN_INVALID" && error.status === 403,
  );
  assert.throws(
    () => authorize(store, { method: "POST", cookieHeader, csrfHeader: "guessed" }),
    (error: AuthorizationError) => error.code === "CSRF_TOKEN_INVALID",
  );
  assert.equal(
    authorize(store, { method: "POST", cookieHeader, csrfHeader: session.csrfToken }).username,
    "operator",
  );
});

test("an auditor session is rejected by operator-only handlers", () => {
  const store = new SessionStore(credentials);
  const auditor = loggedIn(store, "auditor");
  assert.throws(
    () => requireOperator(auditor),
    (error: AuthorizationError) => error.code === "ROLE_FORBIDDEN",
  );
  assert.equal(requireOperator(loggedIn(store, "operator")).role, "operator");
});

test("expired and destroyed sessions stop authorizing", () => {
  let now = 1_000;
  const store = new SessionStore(credentials, () => now);
  const session = loggedIn(store, "operator");
  now += SESSION_TTL_MS + 1;
  assert.equal(store.get(session.sessionId), null);
  const second = loggedIn(store, "operator");
  store.destroy(second.sessionId);
  assert.throws(
    () => authorize(store, {
      method: "GET",
      cookieHeader: `${SESSION_COOKIE}=${second.sessionId}`,
      csrfHeader: undefined,
    }),
    (error: AuthorizationError) => error.code === "SESSION_REQUIRED" && error.status === 401,
  );
});

test("cookie parsing tolerates unrelated cookies", () => {
  const cookies = parseCookies(`theme=dark; ${SESSION_COOKIE}=abc; =broken`);
  assert.equal(cookies.get(SESSION_COOKIE), "abc");
  assert.equal(parseCookies(undefined).size, 0);
});
