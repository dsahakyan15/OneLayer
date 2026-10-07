import assert from "node:assert/strict";
import test from "node:test";
import { SessionStore, type Credential } from "../src/admin-session.ts";
import { routeAdmin, type AdminContext } from "../src/admin.ts";

function context(sessions: SessionStore): AdminContext {
  return {
    sessions, registryId: "gov.registry.land", publicWebBaseUrl: "http://127.0.0.1:8091",
    pool: { async query() { throw new Error("session metadata must not query record data"); } } as unknown as AdminContext["pool"],
    rpc: {} as AdminContext["rpc"],
    programId: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo" as AdminContext["programId"],
    configPda: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo" as AdminContext["configPda"],
    issuerSecretKey: Buffer.alloc(32, 0x29), now: () => new Date(),
  };
}

const requestDefaults = { cookieHeader: undefined, csrfHeader: undefined, idempotencyKey: undefined };

const credentials: Credential[] = [{
  username: "restricted-worker", role: "registry_worker", password: "synthetic-worker-password-012345",
  permissions: [], registryIds: ["other.registry"],
}];

test("session view returns actual empty permissions and registry scope without role-derived grants", async () => {
  const sessions = new SessionStore(credentials);
  const ctx = context(sessions);
  const login = await routeAdmin(ctx, { ...requestDefaults, method: "POST", path: "/v1/admin/session",
    query: new URLSearchParams(), body: { username: credentials[0].username, password: credentials[0].password } });
  assert.equal(login.status, 201);
  const cookie = login.setCookie!.split(";")[0];
  for (const result of [login, await routeAdmin(ctx, { ...requestDefaults,
    method: "GET", path: "/v1/admin/session", query: new URLSearchParams(), body: null, cookieHeader: cookie,
  })]) {
    assert.equal(result.status === 200 || result.status === 201, true);
    const body = result.body as Record<string, unknown>;
    assert.equal(body.role, "registry_worker");
    assert.deepEqual(body.permissions, []);
    assert.deepEqual(body.registryIds, ["other.registry"]);
    assert.equal(body.deploymentRegistryId, "gov.registry.land");
    assert.equal(body.resourcePolicy, undefined);
    assert.equal(body.issuerSecretKey, undefined);
    assert.ok(!JSON.stringify(body).includes(credentials[0].password));
  }
  // Returned JSON metadata cannot mutate the server's authority.
  (login.body as { permissions: string[] }).permissions.push("records.draft");
  const again = await routeAdmin(ctx, { ...requestDefaults, method: "GET", path: "/v1/admin/session",
    query: new URLSearchParams(), body: null, cookieHeader: cookie });
  assert.deepEqual((again.body as { permissions: string[] }).permissions, []);
});

test("changed access invalidates old session metadata instead of keeping stale controls", async () => {
  const sessions = new SessionStore(credentials);
  const ctx = context(sessions);
  const session = sessions.login(credentials[0].username, credentials[0].password);
  assert.ok(session);
  const request = { ...requestDefaults, method: "GET", path: "/v1/admin/session", query: new URLSearchParams(), body: null,
    cookieHeader: `onelayer_admin_session=${session.sessionId}` };
  assert.equal((await routeAdmin(ctx, request)).status, 200);
  sessions.updateAccess(credentials[0].username, { role: "registry_worker", permissions: ["records.read"], registryIds: ["gov.registry.land"] });
  const invalidated = await routeAdmin(ctx, request);
  assert.equal(invalidated.status, 401);
  assert.equal((invalidated.body as Record<string, unknown>).permissions, undefined);
});
