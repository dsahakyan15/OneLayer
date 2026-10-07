import assert from "node:assert/strict";
import test from "node:test";
import { Pool } from "pg";
import { parseCredentials, IdentityUnavailableError, type AdminSession } from "../src/admin-session.ts";
import { PostgresSessionStore } from "../src/postgres-session.ts";
import { isolatedPostgres } from "./support/postgres.ts";

const credentials = parseCredentials(JSON.stringify({ operator: "synthetic-operator-password", auditor: "synthetic-auditor-password" }));
const login = async (store: PostgresSessionStore, username = "operator"): Promise<AdminSession> => {
  const session = await store.login(username, `synthetic-${username}-password`);
  assert.ok(session);
  return session;
};

test("durable sessions, account revocation and access revisions survive new connections", { timeout: 60_000 }, async context => {
  let otherPool: Pool | undefined;
  context.after(async () => { await otherPool?.end(); });
  const { pool, connectionString } = await isolatedPostgres(context);
  otherPool = new Pool({ connectionString });
  const first = new PostgresSessionStore(pool, credentials);
  const second = new PostgresSessionStore(otherPool, credentials);
  await Promise.all([first.initialize(), second.initialize()]);
  assert.equal((await pool.query("SELECT count(*) FROM demo_admin_access_event WHERE action='BOOTSTRAP'")).rows[0].count, "2");
  assert.equal(await first.login("operator", "wrong"), null);
  assert.equal(await first.login("unknown", "synthetic-operator-password"), null);
  const original = await login(first);
  assert.deepEqual(await second.get(original.sessionId), original);
  const stored = (await pool.query("SELECT * FROM demo_admin_session")).rows[0];
  assert.equal(stored.token_hash.length, 32);
  assert.equal(JSON.stringify(stored).includes(original.sessionId), false, "raw bearer token must not be stored");
  assert.equal(JSON.stringify(stored).includes("synthetic-operator-password"), false);
  assert.equal(await second.get("bad-token"), null);

  await second.updateAccess("operator", { role: "auditor", permissions: ["records.read"] }, "test-provisioner");
  assert.equal(await first.get(original.sessionId), null);
  const narrowed = await login(first);
  assert.equal(narrowed.role, "auditor");
  assert.deepEqual(narrowed.permissions, ["records.read"]);
  // Reinitialization with the original broad file must not restore operator rights.
  const restarted = new PostgresSessionStore(otherPool, credentials);
  await restarted.initialize();
  assert.deepEqual(await restarted.get(narrowed.sessionId), narrowed);
  assert.equal((await login(restarted)).role, "auditor");
  await restarted.updateAccess("operator", { role: "operator", registryIds: ["other.registry"] }, "test-provisioner");
  const scoped = await login(first);
  assert.deepEqual(scoped.permissions, ["records.read"], "omitted grants must not elevate the new role");
  assert.deepEqual(scoped.registryIds, ["other.registry"]);
  await second.destroy(scoped.sessionId);
  assert.equal(await first.get(scoped.sessionId), null);

  const auditor = await login(first, "auditor");
  await first.revokeUser("operator", "test-provisioner");
  await restarted.initialize();
  assert.equal(await restarted.login("operator", "synthetic-operator-password"), null);
  assert.ok(await restarted.get(auditor.sessionId));
  await restarted.updateAccess("operator", { role: "operator" }, "test-provisioner");
  assert.equal(await first.login("operator", "synthetic-operator-password"), null, "access update must not reenable a revoked user");

  // Database time, not the API process clock, controls expiry.
  await pool.query("UPDATE demo_admin_session SET created_at=clock_timestamp()-interval '2 hours', expires_at=clock_timestamp()-interval '1 hour' WHERE username='auditor'");
  assert.equal(await restarted.get(auditor.sessionId), null);
  const fresh = await login(first, "auditor");
  // Even a stale retained session cannot cross an access revision boundary.
  await pool.query("UPDATE demo_admin_account SET access_revision=access_revision+1 WHERE username='auditor'");
  assert.equal(await second.get(fresh.sessionId), null);
  const events = (await pool.query("SELECT action, actor, access FROM demo_admin_access_event ORDER BY event_id")).rows;
  assert.ok(events.some(row => row.action === "REVOKE" && row.actor === "test-provisioner"));
  assert.equal(JSON.stringify(events).includes("synthetic-operator-password"), false);
  const valid = await login(first, "auditor");
  await pool.query("UPDATE demo_admin_account SET permissions=ARRAY['recovery.approve'] WHERE username='auditor'");
  await assert.rejects(second.get(valid.sessionId), IdentityUnavailableError);
  await assert.rejects(first.login("auditor", "synthetic-auditor-password"), IdentityUnavailableError);
});

test("login races, invalid grants and audit failure cannot bypass atomic revoke", { timeout: 60_000 }, async context => {
  const { pool } = await isolatedPostgres(context);
  const store = new PostgresSessionStore(pool, credentials);
  await store.initialize();
  const original = await login(store);
  await assert.rejects(store.updateAccess("operator", { role: "auditor", permissions: ["recovery.approve"] }, "test"), TypeError);
  assert.ok(await store.get(original.sessionId));
  await assert.rejects(store.revokeUser("missing", "test"), { code: "ACCOUNT_NOT_FOUND" });
  await assert.rejects(store.revokeUser("operator", ""), TypeError);

  // Force audit insertion to fail: the account, revision and sessions must roll back together.
  await pool.query(`CREATE FUNCTION reject_test_audit() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'synthetic audit outage'; END $$`);
  await pool.query("CREATE TRIGGER reject_test_audit BEFORE INSERT ON demo_admin_access_event FOR EACH ROW EXECUTE FUNCTION reject_test_audit()");
  await assert.rejects(store.revokeUser("operator", "test"), IdentityUnavailableError);
  assert.ok(await store.get(original.sessionId));
  await assert.rejects(store.updateAccess("operator", { role: "auditor" }, "test"), IdentityUnavailableError);
  assert.equal((await store.get(original.sessionId))?.role, "operator");
  await pool.query("DROP TRIGGER reject_test_audit ON demo_admin_access_event");

  // Hold the account lock while login and revoke queue behind it. Either order
  // is safe: login returns null or its session is revoked before both finish.
  const blocker = await pool.connect();
  await blocker.query("BEGIN");
  await blocker.query("SELECT * FROM demo_admin_account WHERE username='operator' FOR UPDATE");
  const concurrentLogin = store.login("operator", "synthetic-operator-password");
  const revoke = store.revokeUser("operator", "test");
  await blocker.query("COMMIT");
  blocker.release();
  const [session] = await Promise.all([concurrentLogin, revoke]);
  if (session) assert.equal(await store.get(session.sessionId), null);
  assert.equal(await store.login("operator", "synthetic-operator-password"), null);

  const active = await login(store, "auditor");
  const closedPool = new Pool({ connectionString: "postgresql://unused@127.0.0.1:1/unused", connectionTimeoutMillis: 200 });
  await closedPool.end();
  const unavailable = new PostgresSessionStore(closedPool, credentials);
  await assert.rejects(unavailable.get(active.sessionId), IdentityUnavailableError);
  await assert.rejects(unavailable.login("auditor", "synthetic-auditor-password"), IdentityUnavailableError);
  await assert.rejects(unavailable.destroy(active.sessionId), IdentityUnavailableError);
});

test("lab password sessions carry the deployment-owned device identity without touching the OIDC device binding", { timeout: 60_000 }, async context => {
  const { pool } = await isolatedPostgres(context);
  const previous = process.env.ONELAYER_ADMIN_ACCESS_LAB;
  process.env.ONELAYER_ADMIN_ACCESS_LAB = "1";
  let lab: ReturnType<typeof parseCredentials>;
  try {
    lab = parseCredentials(JSON.stringify({
      operator: { password: "lab-operator-password-0123456789", role: "operator", deviceId: "demo-device-operator-1" },
      auditor: { password: "lab-auditor-password-0123456789", role: "auditor", deviceId: "demo-device-auditor-1" },
    }));
  } finally {
    if (previous === undefined) delete process.env.ONELAYER_ADMIN_ACCESS_LAB;
    else process.env.ONELAYER_ADMIN_ACCESS_LAB = previous;
  }
  const store = new PostgresSessionStore(pool, lab);
  await store.initialize();
  // Regression: a lab credential's deviceId was written into the OIDC
  // managed-device binding column, violating `session_device_binding`, so every
  // password login surfaced as 503 IDENTITY_UNAVAILABLE.
  const session = await store.login("operator", "lab-operator-password-0123456789");
  assert.ok(session, "a lab password login must return a session, not IDENTITY_UNAVAILABLE");
  assert.equal(session?.deviceId, "demo-device-operator-1", "the deployment-owned device identity must ride the session");
  const stored = (await pool.query("SELECT auth_method, device_id, device_revision FROM demo_admin_session WHERE username='operator'")).rows[0];
  assert.equal(stored.auth_method, "password");
  assert.equal(stored.device_id, null, "demo_admin_session.device_id is the OIDC managed-device binding and must stay NULL for password sessions");
  assert.equal(stored.device_revision, null);
  const reread = await store.get(session?.sessionId);
  assert.equal(reread?.deviceId, "demo-device-operator-1", "get() must re-attach the deployment-owned device identity");
  const auditor = await store.login("auditor", "lab-auditor-password-0123456789");
  assert.equal(auditor?.deviceId, "demo-device-auditor-1");
  assert.equal(await store.login("auditor", "wrong-password-0000000000000"), null, "a wrong password stays indistinguishable from an unknown user");
  await store.destroy(session?.sessionId);
  assert.equal(await store.get(session?.sessionId), null);
});
