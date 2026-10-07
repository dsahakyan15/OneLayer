import test from "node:test";
import assert from "node:assert/strict";
import { Pool } from "pg";
import { IdentityUnavailableError } from "../src/admin-session.ts";
import { PostgresSessionStore } from "../src/postgres-session.ts";
import { SERVICE_CREDENTIAL_TTL_CEILING_DAYS, ServicePrincipalStore } from "../src/service-principal.ts";
import { isolatedPostgres } from "./support/postgres.ts";

const LAND = "gov.registry.land";
const bearer = (token: string) => `Bearer ${token}`;

async function fixture(t: Parameters<typeof isolatedPostgres>[0]) {
  let otherPool: Pool | undefined;
  t.after(async () => { await otherPool?.end(); });
  const db = await isolatedPostgres(t);
  otherPool = new Pool({ connectionString: db.connectionString });
  // Two stores on independent pools stand in for two API processes.
  return { ...db, store: new ServicePrincipalStore(db.pool), other: new ServicePrincipalStore(otherPool) };
}

/** Append-only events with consecutive duplicates collapsed (a minute boundary may split a denial window). */
async function reasons(pool: Pool, principalId: string): Promise<string[]> {
  const rows = (await pool.query(
    "SELECT coalesce(reason, event) AS r FROM service_principal_event WHERE principal_id=$1 ORDER BY event_id", [principalId],
  )).rows.map(row => row.r as string);
  return rows.filter((row, index) => index === 0 || row !== rows[index - 1]);
}

async function denials(pool: Pool, principalId: string): Promise<Record<string, number>> {
  const rows = (await pool.query(
    "SELECT reason, sum(denials)::int AS n FROM service_principal_denial_window WHERE principal_id=$1 GROUP BY reason", [principalId],
  )).rows;
  return Object.fromEntries(rows.map(row => [row.reason, row.n]));
}

test("service principals enforce action allowlist, registry scope and constant digest storage", async t => {
  const { pool, store } = await fixture(t);
  const token = await store.provision("svc.register", { actions: ["artifacts.register"], registryIds: [LAND] }, "host-maintainer");
  assert.match(token, /^olsp_[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/);

  const principal = await store.authorize(bearer(token), "artifacts.register", LAND);
  assert.equal(principal.principalId, "svc.register");
  assert.deepEqual(principal.actions, ["artifacts.register"]);
  await assert.rejects(store.authorize(bearer(token), "integrity.reconcile", LAND), /SERVICE_PERMISSION_FORBIDDEN/);
  for (const foreign of ["other.registry", "*", "", undefined, ["gov.registry.land"], `${LAND} `]) {
    await assert.rejects(store.authorize(bearer(token), "artifacts.register", foreign), /SERVICE_PERMISSION_FORBIDDEN/);
  }
  // Wrong secret for a real credential ID, unknown ID, malformed and non-Bearer schemes.
  const [prefix] = token.split(".");
  await assert.rejects(store.authorize(bearer(`${prefix}.${"A".repeat(43)}`), "artifacts.register", LAND), /SERVICE_CREDENTIAL_REQUIRED/);
  await assert.rejects(store.authorize(bearer(`olsp_${"B".repeat(22)}.${"A".repeat(43)}`), "artifacts.register", LAND), /SERVICE_CREDENTIAL_REQUIRED/);
  for (const header of [undefined, "", token, `Basic ${token}`, `Bearer  ${token}`, `bearer ${token}`, `Bearer ${token} `, `Bearer ${token}x`, `Bearer ${"a".repeat(43)}`]) {
    await assert.rejects(store.authorize(header, "artifacts.register", LAND), /SERVICE_CREDENTIAL_REQUIRED/);
  }

  // Repeated denials are counted, not appended: one event per credential/reason/action/minute.
  assert.deepEqual(await reasons(pool, "svc.register"), [
    "PROVISIONED", "REQUEST_AUTHORIZED", "ACTION_NOT_ALLOWED", "REGISTRY_OUT_OF_SCOPE", "SECRET_MISMATCH",
  ]);
  assert.deepEqual(await denials(pool, "svc.register"), { ACTION_NOT_ALLOWED: 1, REGISTRY_OUT_OF_SCOPE: 6, SECRET_MISMATCH: 1 });
  // Untrusted registry text is audited only when it is a well-formed registry ID.
  const audited = (await pool.query(
    "SELECT registry_id FROM service_principal_event WHERE principal_id='svc.register' AND reason='REGISTRY_OUT_OF_SCOPE'")).rows;
  assert.equal(audited[0].registry_id, "other.registry");
  const hostile = await store.provision("svc.hostile", { actions: ["artifacts.register"], registryIds: [LAND] }, "host");
  await assert.rejects(store.authorize(bearer(hostile), "artifacts.register", "x'); DROP TABLE t; --\n<script>"), /SERVICE_PERMISSION_FORBIDDEN/);
  assert.deepEqual((await pool.query("SELECT registry_id FROM service_principal_event WHERE principal_id='svc.hostile' AND reason IS NOT NULL")).rows, [{ registry_id: null }]);
  // Pre-body check (N2): full check against the deployment registry, no success audit.
  await store.authorize(bearer(hostile), "artifacts.register", LAND, { recordSuccess: false });
  const foreignOnly = await store.provision("svc.foreignonly", { actions: ["artifacts.register"], registryIds: ["other.registry"] }, "host");
  await assert.rejects(store.authorize(bearer(foreignOnly), "artifacts.register", LAND, { recordSuccess: false }), /SERVICE_PERMISSION_FORBIDDEN/);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM service_principal_event WHERE principal_id='svc.hostile' AND event='REQUEST_AUTHORIZED'")).rows[0].n, 0);
  // Only the digest is stored; the raw token and secret appear in no identity table.
  const dump = (await pool.query(
    "SELECT (SELECT json_agg(p)::text FROM service_principal p) || (SELECT json_agg(c)::text FROM service_principal_credential c) || (SELECT json_agg(e)::text FROM service_principal_event e) AS all",
  )).rows[0].all as string;
  assert.ok(!dump.includes(token.split(".")[1]!));
  const stored = (await pool.query("SELECT octet_length(secret_hash) AS n FROM service_principal_credential WHERE principal_id='svc.register'")).rows;
  assert.deepEqual(stored, [{ n: 32 }]);

  await assert.rejects(store.provision("svc.register", { actions: ["artifacts.register"], registryIds: [LAND] }, "host"), /SERVICE_PRINCIPAL_EXISTS/);
  for (const scope of [
    { actions: [], registryIds: [LAND] }, { actions: ["artifacts.register"], registryIds: [] },
    { actions: ["records.draft"], registryIds: [LAND] }, { actions: ["artifacts.register"], registryIds: ["*"] },
    { actions: ["artifacts.register", "artifacts.register"], registryIds: [LAND] },
    { actions: ["artifacts.register"], registryIds: [LAND], role: "chief_admin" }, null, [],
    { actions: ["artifacts.register"], registryIds: ["Gov.Registry"] }, { actions: ["artifacts.register"], registryIds: ["gov"] },
  ]) await assert.rejects(store.provision("svc.bad", scope, "host"), TypeError);
  for (const id of ["Svc", "a", "svc/other", "svc other", ""]) {
    await assert.rejects(store.provision(id, { actions: ["artifacts.register"], registryIds: [LAND] }, "host"), TypeError);
  }
  // Database constraints independently reject wildcard scope and unknown actions.
  await assert.rejects(pool.query("INSERT INTO service_principal (principal_id,actions,registry_ids) VALUES ('svc.sql','{artifacts.register}','{*}')"));
  await assert.rejects(pool.query("INSERT INTO service_principal (principal_id,actions,registry_ids) VALUES ('svc.sql','{access.manage}','{gov.registry.land}')"));
  await assert.rejects(pool.query("UPDATE service_principal_event SET actor='x'"), /append-only/);
  await assert.rejects(pool.query("DELETE FROM service_principal_event"), /append-only/);
  await assert.rejects(pool.query("TRUNCATE service_principal_event CASCADE"), /append-only/);
});

test("rotation and revoke apply to the next request on another API process and are sticky", async t => {
  const { pool, store, other } = await fixture(t);
  const first = await store.provision("svc.reconciler", { actions: ["integrity.reconcile"], registryIds: [LAND] }, "host");
  await other.authorize(bearer(first), "integrity.reconcile", LAND);
  const second = await other.rotate("svc.reconciler", "host");
  await assert.rejects(store.authorize(bearer(first), "integrity.reconcile", LAND), /SERVICE_CREDENTIAL_REQUIRED/);
  await store.authorize(bearer(second), "integrity.reconcile", LAND);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM service_principal_credential WHERE revoked_at IS NULL")).rows[0].n, 1);
  // 0016 makes expires_at mandatory: the row must satisfy the TTL CHECK so this
  // INSERT still exercises the one-live-credential unique index, not NOT NULL.
  await assert.rejects(pool.query(
    `INSERT INTO service_principal_credential (credential_id,principal_id,secret_hash,expires_at)
     VALUES ($1,'svc.reconciler',decode(repeat('00',32),'hex'),clock_timestamp() + interval '1 day')`, ["C".repeat(22)],
  ), /service_principal_one_live_credential/);

  await store.revoke("svc.reconciler", "host");
  await assert.rejects(other.authorize(bearer(second), "integrity.reconcile", LAND), /SERVICE_CREDENTIAL_REQUIRED/);
  await assert.rejects(other.rotate("svc.reconciler", "host"), /SERVICE_PRINCIPAL_NOT_FOUND/);
  // Revoking an already revoked principal is not a silent success and is not audited again.
  await assert.rejects(store.revoke("svc.reconciler", "host"), /SERVICE_PRINCIPAL_NOT_FOUND/);
  await assert.rejects(store.revoke("svc.missing", "host"), /SERVICE_PRINCIPAL_NOT_FOUND/);
  assert.deepEqual(await reasons(pool, "svc.reconciler"), [
    "PROVISIONED", "REQUEST_AUTHORIZED", "ROTATED", "CREDENTIAL_REVOKED", "REQUEST_AUTHORIZED", "REVOKED", "CREDENTIAL_REVOKED",
  ]);
  const revisions = (await pool.query("SELECT revision::text FROM service_principal WHERE principal_id='svc.reconciler'")).rows[0];
  assert.equal(revisions.revision, "3");
});

test("startup schema check requires every security-relevant 0012 object", async t => {
  const { pool, store } = await fixture(t);
  await store.initialize();
  for (const [breakIt, repair] of [
    ["ALTER TABLE service_principal_event DISABLE TRIGGER append_only_truncate", "ALTER TABLE service_principal_event ENABLE TRIGGER append_only_truncate"],
    ["DROP TRIGGER append_only ON service_principal_event", "CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON service_principal_event FOR EACH ROW EXECUTE FUNCTION service_principal_event_append_only()"],
    ["ALTER TABLE service_principal_denial_window RENAME TO renamed_window", "ALTER TABLE renamed_window RENAME TO service_principal_denial_window"],
    ["DROP INDEX service_principal_one_live_credential", "CREATE UNIQUE INDEX service_principal_one_live_credential ON service_principal_credential(principal_id) WHERE revoked_at IS NULL"],
  ] as const) {
    await pool.query(breakIt);
    await assert.rejects(store.initialize(), IdentityUnavailableError, breakIt);
    await pool.query(repair);
    await store.initialize();
  }
  const check = (await pool.query(`SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
    WHERE conrelid='service_principal_event'::regclass AND contype='c' AND pg_get_constraintdef(oid) LIKE '%registry_id ~%'`)).rows[0];
  await pool.query(`ALTER TABLE service_principal_event DROP CONSTRAINT "${check.conname}"`);
  await assert.rejects(store.initialize(), IdentityUnavailableError);
  await pool.query(`ALTER TABLE service_principal_event ADD CONSTRAINT "${check.conname}" ${check.def}`);
  await store.initialize();
});

test("service and human identities never substitute for one another", async t => {
  const { store, pool } = await fixture(t);
  const sessions = new PostgresSessionStore(pool, [], { oidcOnly: true });
  await sessions.provisionOidcAccount({ username: "svc.register", issuer: "https://idp.example", subject: "svc.register",
    access: { role: "registry_worker" }, resourcePolicy: { version: 1, grants: [] } }, "host");
  await sessions.enrollDevice("svc.register", "device-1", "host");
  const human = (await sessions.loginOidc({ issuer: "https://idp.example", subject: "svc.register", deviceId: "device-1", expiresAt: Date.now() + 60_000 }))!;
  const token = await store.provision("svc.register", { actions: ["artifacts.register"], registryIds: [LAND] }, "host");
  // Same name in both namespaces: neither credential authenticates the other identity type.
  await assert.rejects(store.authorize(bearer(human.sessionId), "artifacts.register", LAND), /SERVICE_CREDENTIAL_REQUIRED/);
  await assert.rejects(store.authorize(bearer(`olsp_${human.sessionId.slice(0, 22)}.${human.sessionId}`), "artifacts.register", LAND), /SERVICE_CREDENTIAL_REQUIRED/);
  assert.equal(await sessions.get(token), null);
  assert.equal(await sessions.get(token.split(".")[1]), null);
});

test("audit failure fails closed for requests and rolls back provisioning, rotation and revoke", async t => {
  const { pool, store } = await fixture(t);
  const token = await store.provision("svc.audit", { actions: ["integrity.reconcile"], registryIds: [LAND] }, "host");
  await pool.query("ALTER TABLE service_principal_event ADD CONSTRAINT test_audit_down CHECK (event = 'PROVISIONED') NOT VALID");
  await assert.rejects(store.authorize(bearer(token), "integrity.reconcile", LAND), IdentityUnavailableError);
  await assert.rejects(store.authorize(bearer(token), "integrity.reconcile", "other.registry"), IdentityUnavailableError);
  await assert.rejects(store.rotate("svc.audit", "host"), IdentityUnavailableError);
  await assert.rejects(store.revoke("svc.audit", "host"), IdentityUnavailableError);
  await pool.query("ALTER TABLE service_principal_event DROP CONSTRAINT test_audit_down");
  await pool.query("ALTER TABLE service_principal_event ADD CONSTRAINT test_audit_down CHECK (event <> 'PROVISIONED') NOT VALID");
  await assert.rejects(store.provision("svc.lost", { actions: ["integrity.reconcile"], registryIds: [LAND] }, "host"), IdentityUnavailableError);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM service_principal WHERE principal_id='svc.lost'")).rows[0].n, 0);
  await pool.query("ALTER TABLE service_principal_event DROP CONSTRAINT test_audit_down");
  // Failed rotation/revoke left the original credential live and unchanged.
  await store.authorize(bearer(token), "integrity.reconcile", LAND);
  assert.equal((await pool.query("SELECT revision::text FROM service_principal WHERE principal_id='svc.audit'")).rows[0].revision, "1");
});

test("rotation committed while authorization waits on the principal lock rejects the old secret (EvalPlanQual)", async t => {
  const { pool, store, other } = await fixture(t);
  const old = await store.provision("svc.rotating", { actions: ["integrity.reconcile"], registryIds: [LAND] }, "host");
  // Hold a rotation open at the point where it owns the principal row lock and
  // has revoked the old credential, then let authorization queue behind it.
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT 1 FROM service_principal WHERE principal_id='svc.rotating' FOR UPDATE");
    await client.query("UPDATE service_principal_credential SET revoked_at=clock_timestamp() WHERE principal_id='svc.rotating' AND revoked_at IS NULL");
    await client.query("UPDATE service_principal SET revision=revision+1 WHERE principal_id='svc.rotating'");
    const pending = other.authorize(bearer(old), "integrity.reconcile", LAND).then(() => "ALLOWED", (error: Error) => error.message);
    await new Promise(resolve => setTimeout(resolve, 300));
    await client.query("COMMIT");
    assert.equal(await pending, "SERVICE_CREDENTIAL_REQUIRED");
  } finally { client.release(); }
  assert.deepEqual(await denials(pool, "svc.rotating"), { CREDENTIAL_REVOKED: 1 });
});

test("register-style write transaction revalidates the principal and rolls back after a later rotation", async t => {
  const { pool, store, other } = await fixture(t);
  const token = await store.provision("svc.writer", { actions: ["artifacts.register"], registryIds: [LAND] }, "host");
  const principal = await store.authorize(bearer(token), "artifacts.register", LAND);
  const inTransaction = async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await store.revalidate(client, principal);
      await client.query("COMMIT");
    } catch (error) { await client.query("ROLLBACK"); throw error; }
    finally { client.release(); }
  };
  await inTransaction();
  await other.rotate("svc.writer", "host");
  await assert.rejects(inTransaction(), /SERVICE_CREDENTIAL_REQUIRED/);
  const again = await store.provision("svc.writer2", { actions: ["artifacts.register"], registryIds: [LAND] }, "host");
  const second = await store.authorize(bearer(again), "artifacts.register", LAND);
  await other.revoke("svc.writer2", "host");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await assert.rejects(store.revalidate(client, second), /SERVICE_CREDENTIAL_REQUIRED/);
    await client.query("ROLLBACK");
  } finally { client.release(); }
});

test("authorizations racing a revoke: none succeeds after the revoke commits", async t => {
  const { store, other } = await fixture(t);
  const token = await store.provision("svc.race", { actions: ["integrity.reconcile"], registryIds: [LAND] }, "host");
  const attempts = Array.from({ length: 20 }, () => other.authorize(bearer(token), "integrity.reconcile", LAND).then(() => true, () => false));
  await Promise.all([store.revoke("svc.race", "host"), ...attempts]);
  await assert.rejects(other.authorize(bearer(token), "integrity.reconcile", LAND), /SERVICE_CREDENTIAL_REQUIRED/);
  await assert.rejects(store.authorize(bearer(token), "integrity.reconcile", LAND), /SERVICE_CREDENTIAL_REQUIRED/);
});

test("expired credentials are refused everywhere, audited as CREDENTIAL_EXPIRED and replaced only by rotation", async t => {
  const { pool, store, other } = await fixture(t);
  const token = await store.provision("svc.expiring", { actions: ["artifacts.register"], registryIds: [LAND] }, "host", 30);
  const principal = await store.authorize(bearer(token), "artifacts.register", LAND);
  // Expiry is a durable timestamp: move the live credential into the past. The
  // 0016 CHECK still admits any expiry in (created_at, created_at + 366 days].
  await pool.query(
    `UPDATE service_principal_credential
        SET created_at = clock_timestamp() - interval '2 days', expires_at = clock_timestamp() - interval '1 day'
      WHERE credential_id = $1`, [principal.credentialId]);

  // Every instance refuses it, and the refusal is attributed to expiry, not to a wrong secret.
  for (const instance of [store, other]) {
    await assert.rejects(instance.authorize(bearer(token), "artifacts.register", LAND), /SERVICE_CREDENTIAL_REQUIRED/);
  }
  assert.deepEqual(await denials(pool, "svc.expiring"), { CREDENTIAL_EXPIRED: 2 });
  assert.deepEqual(await reasons(pool, "svc.expiring"), ["PROVISIONED", "REQUEST_AUTHORIZED", "CREDENTIAL_EXPIRED"]);

  // The register write path re-checks the credential and must refuse the expired one too.
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await assert.rejects(store.revalidate(client, principal), /SERVICE_CREDENTIAL_REQUIRED/);
    await client.query("ROLLBACK");
  } finally { client.release(); }

  // Rotation is the only replacement: the old bearer stays refused, the new one works, one live credential remains.
  const rotated = await store.rotate("svc.expiring", "host");
  await assert.rejects(store.authorize(bearer(token), "artifacts.register", LAND), /SERVICE_CREDENTIAL_REQUIRED/);
  await store.authorize(bearer(rotated), "artifacts.register", LAND);
  assert.deepEqual((await pool.query(
    `SELECT count(*)::int AS live, count(*) FILTER (WHERE expires_at > clock_timestamp())::int AS valid
       FROM service_principal_credential WHERE principal_id='svc.expiring' AND revoked_at IS NULL`)).rows[0],
  { live: 1, valid: 1 });
});

test("credential TTL boundaries are enforced by the store and by the 0016 database constraints", async t => {
  const { pool } = await fixture(t);
  const scope = { actions: ["artifacts.register"], registryIds: [LAND] };
  const boundaryStore = new ServicePrincipalStore(pool, { maxTtlDays: SERVICE_CREDENTIAL_TTL_CEILING_DAYS });

  // 1 day and the 366-day ceiling are accepted; 0, negatives, non-integers and 367 days fail before any DB write.
  const oneDay = await boundaryStore.provision("svc.ttl.one", scope, "host", 1);
  const ceiling = await boundaryStore.provision("svc.ttl.ceiling", scope, "host", SERVICE_CREDENTIAL_TTL_CEILING_DAYS);
  await boundaryStore.authorize(bearer(oneDay), "artifacts.register", LAND);
  await boundaryStore.authorize(bearer(ceiling), "artifacts.register", LAND);
  for (const bad of [0, -1, 1.5, SERVICE_CREDENTIAL_TTL_CEILING_DAYS + 1]) {
    await assert.rejects(boundaryStore.provision("svc.ttl.bad", scope, "host", bad), TypeError, String(bad));
    await assert.rejects(boundaryStore.rotate("svc.ttl.one", "host", bad), TypeError, String(bad));
  }
  // The default maximum is 90 days: an explicit 90 is accepted and 91 fails without an override.
  const defaultStore = new ServicePrincipalStore(pool);
  await defaultStore.provision("svc.ttl.default", scope, "host", 90);
  await assert.rejects(defaultStore.provision("svc.ttl.bad", scope, "host", 91), TypeError);
  assert.deepEqual((await pool.query(
    `SELECT principal_id, round(extract(epoch FROM expires_at - created_at) / 86400)::int AS days
       FROM service_principal_credential
      WHERE principal_id IN ('svc.ttl.one','svc.ttl.ceiling','svc.ttl.default') ORDER BY principal_id`)).rows,
  [{ principal_id: "svc.ttl.ceiling", days: 366 }, { principal_id: "svc.ttl.default", days: 90 }, { principal_id: "svc.ttl.one", days: 1 }]);

  // The database CHECK is the backstop: a hand-written row at or above the ceiling is refused.
  await pool.query("INSERT INTO service_principal (principal_id,actions,registry_ids) VALUES ('svc.ttl.boundary','{artifacts.register}','{gov.registry.land}')");
  const handWritten = (credentialId: string, offset: string) => pool.query(
    `WITH t AS (SELECT clock_timestamp() AS at)
     INSERT INTO service_principal_credential (credential_id, principal_id, secret_hash, created_at, expires_at)
     SELECT $1, 'svc.ttl.boundary', decode(repeat('11',32),'hex'), t.at, t.at + ${offset} FROM t`, [credentialId]);
  await assert.rejects(handWritten("D".repeat(22), "interval '367 days'"), /service_credential_ttl/);
  await assert.rejects(handWritten("E".repeat(22), "interval '0 seconds'"), /service_credential_ttl/);

  // Authorization after writing the current timestamp rejects an already-expired credential.
  // This does not distinguish exact-clock equality; moving the same credential into
  // the future restores access, so the refusal was expiry, not revocation.
  const ceilingId = (await pool.query("SELECT credential_id FROM service_principal_credential WHERE principal_id='svc.ttl.ceiling'")).rows[0].credential_id as string;
  await pool.query(
    "UPDATE service_principal_credential SET created_at = clock_timestamp() - interval '1 second', expires_at = clock_timestamp() WHERE credential_id = $1",
    [ceilingId]);
  await assert.rejects(boundaryStore.authorize(bearer(ceiling), "artifacts.register", LAND), /SERVICE_CREDENTIAL_REQUIRED/);
  await pool.query("UPDATE service_principal_credential SET expires_at = clock_timestamp() + interval '1 hour' WHERE credential_id = $1", [ceilingId]);
  await boundaryStore.authorize(bearer(ceiling), "artifacts.register", LAND);
});
