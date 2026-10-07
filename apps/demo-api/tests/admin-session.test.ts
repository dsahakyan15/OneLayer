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
import { demoPermissions } from "../src/admin-permissions.ts";

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

test("revocation closes all user sessions and prevents reauthentication", () => {
  const store = new SessionStore(credentials);
  const first = loggedIn(store, "operator");
  const second = loggedIn(store, "operator");
  const auditor = loggedIn(store, "auditor");
  store.revokeUser("operator");
  assert.equal(store.get(first.sessionId), null);
  assert.equal(store.get(second.sessionId), null);
  assert.equal(store.login("operator", "operator-password-0123456789"), null);
  assert.notEqual(store.get(auditor.sessionId), null);
  store.updateAccess("operator", { role: "auditor" });
  assert.equal(store.login("operator", "operator-password-0123456789"), null);
});

test("role and scope changes invalidate sessions and apply on the next login", () => {
  const store = new SessionStore(credentials);
  const session = loggedIn(store, "operator");
  store.updateAccess("operator", { role: "auditor", permissions: ["records.read"], registryIds: ["other.registry"] });
  assert.equal(store.get(session.sessionId), null);
  const next = loggedIn(store, "operator");
  assert.equal(next.role, "auditor");
  assert.deepEqual(next.permissions, ["records.read"]);
  assert.deepEqual(next.registryIds, ["other.registry"]);
});

test("invalid grants cannot elevate a role or partially change existing access", () => {
  const store = new SessionStore(credentials);
  const session = loggedIn(store, "auditor");
  assert.throws(() => store.updateAccess("auditor", { role: "auditor", permissions: ["recovery.approve"] }), TypeError);
  assert.equal(store.get(session.sessionId), session);
  assert.throws(() => new SessionStore([{ ...credentials[0], registryIds: ["*"] }]), TypeError);
  assert.throws(() => new SessionStore([credentials[0], credentials[0]]), TypeError);
});

test("caller-owned credentials and session objects cannot mutate stored authorization", () => {
  const source = [{ ...credentials[1], permissions: ["records.read" as const], registryIds: ["gov.registry.land"] }];
  const store = new SessionStore(source);
  source[0].role = "operator";
  source[0].registryIds.push("other.registry");
  source[0].permissions.length = 0;
  const session = loggedIn(store, "auditor");
  assert.equal(session.role, "auditor");
  assert.deepEqual(session.permissions, ["records.read"]);
  assert.deepEqual(session.registryIds, ["gov.registry.land"]);
  assert.throws(() => { session.role = "operator"; }, TypeError);
  assert.throws(() => { (session.registryIds as string[]).push("other.registry"); }, TypeError);
});

test("deployment credentials can narrow access and reject malformed or elevated grants", () => {
  const config = {
    operator: { password: "operator-password-0123456789", permissions: ["records.read"], registryIds: [] },
    auditor: "auditor-password-0123456789",
  };
  const store = new SessionStore(parseCredentials(JSON.stringify(config)));
  const session = loggedIn(store, "operator");
  assert.deepEqual(session.permissions, ["records.read"]);
  assert.deepEqual(session.registryIds, []);
  store.updateAccess("operator", { role: "operator", registryIds: ["gov.registry.land"] });
  assert.deepEqual(loggedIn(store, "operator").permissions, ["records.read"]);
  for (const entry of [
    { password: "x".repeat(20), role: "chief_admin" },
    { password: "x".repeat(20), permissions: ["recovery.approve"] },
    { password: "x".repeat(20), permissions: "records.read" },
    { password: "x".repeat(20), registryIds: "gov.registry.land" },
    { password: "x".repeat(20), registryIds: null },
  ]) {
    assert.throws(() => parseCredentials(JSON.stringify({ ...config, operator: entry })), TypeError);
  }
});

test("audit.export exists and belongs only to the correctly scoped roles", () => {
  assert.ok(demoPermissions("auditor").includes("audit.export"));
  assert.ok(demoPermissions("chief_admin").includes("audit.export"));
  for (const role of ["operator", "registry_worker", "registry_approver", "identity_admin", "key_holder", "storage_custodian"] as const) {
    assert.equal(demoPermissions(role).includes("audit.export"), false, `${role} must not export audit evidence`);
    assert.equal(demoPermissions(role).includes("audit.read"), role === "operator", "audit.read alone never implies export");
  }
  // A deployment credential may carry the permission only inside its role ceiling.
  const config = {
    operator: { password: "operator-password-0123456789", permissions: ["audit.export"] },
    auditor: "auditor-password-0123456789",
  };
  assert.throws(() => parseCredentials(JSON.stringify(config)), TypeError, "operator may not be granted audit.export");
  const auditorScoped = parseCredentials(JSON.stringify({
    operator: "operator-password-0123456789",
    auditor: { password: "auditor-password-0123456789", permissions: ["audit.read", "audit.export"] },
  }));
  assert.deepEqual(auditorScoped.find(entry => entry.username === "auditor")?.permissions, ["audit.read", "audit.export"]);
  const chiefScoped = parseCredentials(JSON.stringify({
    operator: "operator-password-0123456789",
    auditor: "auditor-password-0123456789",
    chief_admin: { password: "chief-password-0123456789", permissions: ["audit.read", "audit.export"] },
  }));
  assert.deepEqual(chiefScoped.find(entry => entry.username === "chief_admin")?.permissions, ["audit.read", "audit.export"]);
});
