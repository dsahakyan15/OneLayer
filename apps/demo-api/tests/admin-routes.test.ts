import assert from "node:assert/strict";
import { test } from "node:test";
import type { Address } from "@solana/kit";
import { parseCredentials, SESSION_COOKIE, SessionStore } from "../src/admin-session.ts";
import { routeAdmin, type AdminContext, type AdminRequest } from "../src/admin.ts";

const credentials = parseCredentials(
  JSON.stringify({
    operator: "operator-password-0123456789",
    auditor: "auditor-password-0123456789",
    chief_admin: "chief_admin-password-0123456789",
  }),
);

/**
 * Minimal query stub: the role and CSRF checks under test run before any SQL,
 * and the fixture marker is the only statement a rejected request could reach.
 */
function stubPool(): any {
  return {
    async query(sql: string) {
      if (sql.includes("demo_fixture_marker")) {
        return { rows: [{ marker: "ONELAYER_SYNTHETIC_DEVNET_DEMO_V1" }] };
      }
      return { rows: [] };
    },
  };
}

function context(sessions: SessionStore): AdminContext {
  return {
    pool: stubPool(),
    sessions,
    rpc: {} as AdminContext["rpc"],
    registryId: "gov.registry.land",
    programId: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo" as Address,
    configPda: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo" as Address,
    issuerSecretKey: new Uint8Array(32).fill(9),
    publicWebBaseUrl: "http://127.0.0.1:8091",
    now: () => new Date("2026-08-01T00:00:00Z"),
  };
}

function request(overrides: Partial<AdminRequest>): AdminRequest {
  return {
    method: "GET",
    path: "/v1/admin/session",
    query: new URLSearchParams(),
    body: null,
    cookieHeader: undefined,
    csrfHeader: undefined,
    idempotencyKey: undefined,
    ...overrides,
  };
}

async function login(sessions: SessionStore, role: "operator" | "auditor" | "chief_admin") {
  const response = await routeAdmin(context(sessions), request({
    method: "POST",
    path: "/v1/admin/session",
    body: { username: role, password: `${role}-password-0123456789` },
  }));
  assert.equal(response.status, 201);
  const cookie = /onelayer_admin_session=([^;]+)/.exec(response.setCookie ?? "");
  assert.notEqual(cookie, null);
  return {
    cookieHeader: `${SESSION_COOKIE}=${cookie?.[1]}`,
    csrfToken: (response.body as any).csrfToken as string,
  };
}

test("wrong credentials do not create a session", async () => {
  const sessions = new SessionStore(credentials);
  const response = await routeAdmin(context(sessions), request({
    method: "POST",
    path: "/v1/admin/session",
    body: { username: "operator", password: "wrong" },
  }));
  assert.equal(response.status, 401);
  assert.equal((response.body as any).code, "INVALID_CREDENTIALS");
});

test("admin routes require a session", async () => {
  const response = await routeAdmin(context(new SessionStore(credentials)), request({
    path: "/v1/admin/records",
  }));
  assert.equal(response.status, 401);
  assert.equal((response.body as any).code, "SESSION_REQUIRED");
});

test("an auditor is refused at the API, not only in the UI", async () => {
  const sessions = new SessionStore(credentials);
  const auditor = await login(sessions, "auditor");
  const create = await routeAdmin(context(sessions), request({
    method: "POST",
    path: "/v1/admin/records",
    body: { internalRecordId: "SYNTHETIC-3", status: "ACTIVE" },
    cookieHeader: auditor.cookieHeader,
    csrfHeader: auditor.csrfToken,
  }));
  assert.equal(create.status, 403);
  assert.equal((create.body as any).code, "ROLE_FORBIDDEN");

  const publish = await routeAdmin(context(sessions), request({
    method: "POST",
    path: "/v1/admin/publish-intents",
    body: { operator: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo", cluster: "solana:devnet" },
    cookieHeader: auditor.cookieHeader,
    csrfHeader: auditor.csrfToken,
    idempotencyKey: "abcdefghijklmnop",
  }));
  assert.equal(publish.status, 403);

  const read = await routeAdmin(context(sessions), request({
    path: "/v1/admin/records",
    cookieHeader: auditor.cookieHeader,
  }));
  assert.equal(read.status, 200);
});

test("backup mutations are operator-only and backup deletion is forbidden", async () => {
  const sessions = new SessionStore(credentials);
  const auditor = await login(sessions, "auditor");
  const headers = { cookieHeader: auditor.cookieHeader, csrfHeader: auditor.csrfToken };

  const createCenter = await routeAdmin(context(sessions), request({
    method: "POST",
    path: "/v1/admin/backup-centers",
    body: { name: "Unauthorized center" },
    ...headers,
  }));
  assert.equal(createCenter.status, 403);
  assert.equal((createCenter.body as any).code, "ROLE_FORBIDDEN");

  const refresh = await routeAdmin(context(sessions), request({
    method: "POST",
    path: "/v1/admin/snapshots/refresh",
    body: {},
    idempotencyKey: "backup-auditor-key",
    ...headers,
  }));
  assert.equal(refresh.status, 403);
  assert.equal((refresh.body as any).code, "ROLE_FORBIDDEN");

  const deletion = await routeAdmin(context(sessions), request({
    method: "DELETE",
    path: "/v1/admin/snapshots",
    ...headers,
  }));
  assert.equal(deletion.status, 403);
  assert.equal((deletion.body as any).code, "BACKUP_DELETE_FORBIDDEN");
});

test("only chief_admin can reach the Restore Approval signer route", async () => {
  const sessions = new SessionStore(credentials);
  const operationId = "00000000-0000-0000-0000-000000000001";
  for (const role of ["operator", "auditor"] as const) {
    const actor = await login(sessions, role);
    const response = await routeAdmin(context(sessions), request({
      method: "POST",
      path: `/v1/admin/recovery/operations/${operationId}/approve`,
      body: { snapshotId: operationId, merkleRoot: "00".repeat(32), target: "local-demo-target" },
      cookieHeader: actor.cookieHeader,
      csrfHeader: actor.csrfToken,
    }));
    assert.equal(response.status, 403);
    assert.equal((response.body as any).code, "ROLE_FORBIDDEN");
  }
});

test("mutations without the CSRF token are refused for operators too", async () => {
  const sessions = new SessionStore(credentials);
  const operator = await login(sessions, "operator");
  const response = await routeAdmin(context(sessions), request({
    method: "POST",
    path: "/v1/admin/records",
    body: { internalRecordId: "SYNTHETIC-3", status: "ACTIVE" },
    cookieHeader: operator.cookieHeader,
  }));
  assert.equal(response.status, 403);
  assert.equal((response.body as any).code, "CSRF_TOKEN_INVALID");
});

test("a publish intent requires an idempotency key and a devnet cluster", async () => {
  const sessions = new SessionStore(credentials);
  const operator = await login(sessions, "operator");
  const missingKey = await routeAdmin(context(sessions), request({
    method: "POST",
    path: "/v1/admin/publish-intents",
    body: { operator: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo", cluster: "solana:devnet" },
    cookieHeader: operator.cookieHeader,
    csrfHeader: operator.csrfToken,
  }));
  assert.equal(missingKey.status, 400);
  assert.equal((missingKey.body as any).code, "IDEMPOTENCYKEY_INVALID");

  const mainnet = await routeAdmin(context(sessions), request({
    method: "POST",
    path: "/v1/admin/publish-intents",
    body: { operator: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo", cluster: "solana:mainnet" },
    cookieHeader: operator.cookieHeader,
    csrfHeader: operator.csrfToken,
    idempotencyKey: "abcdefghijklmnop",
  }));
  assert.equal(mainnet.status, 400);
  assert.equal((mainnet.body as any).code, "CLUSTER_INVALID");
});

test("a dry-run import validates without writing and reports every rejection", async () => {
  const sessions = new SessionStore(credentials);
  const operator = await login(sessions, "operator");
  const response = await routeAdmin(context(sessions), request({
    method: "POST",
    path: "/v1/admin/records/import",
    body: {
      format: "csv",
      dryRun: true,
      content: [
        "internalRecordId,status,cadastralNumber",
        "SYNTHETIC-51,ACTIVE,01-004-0123-051",
        "SYNTHETIC-52,ACTIVE,",
      ].join("\n"),
    },
    cookieHeader: operator.cookieHeader,
    csrfHeader: operator.csrfToken,
  }));
  // The stub pool has no `connect`, so a write would have thrown: reaching 200
  // is itself the proof that a dry run touches nothing.
  assert.equal(response.status, 200);
  const body = response.body as any;
  assert.equal(body.dryRun, true);
  assert.equal(body.accepted.length, 1);
  assert.deepEqual(body.rejected, [{ row: 3, code: "FIELD_REQUIRED_MISSING", path: "cadastralNumber" }]);
  assert.equal(body.applied.length, 0);
});

test("the import route is closed to the auditor role", async () => {
  const sessions = new SessionStore(credentials);
  const auditor = await login(sessions, "auditor");
  const response = await routeAdmin(context(sessions), request({
    method: "POST",
    path: "/v1/admin/records/import",
    body: { format: "json", dryRun: true, records: [] },
    cookieHeader: auditor.cookieHeader,
    csrfHeader: auditor.csrfToken,
  }));
  assert.equal(response.status, 403);
  assert.equal((response.body as any).code, "ROLE_FORBIDDEN");
});

test("the record schema is served to any authenticated role", async () => {
  const sessions = new SessionStore(credentials);
  const auditor = await login(sessions, "auditor");
  const response = await routeAdmin(context(sessions), request({
    path: "/v1/admin/schema",
    cookieHeader: auditor.cookieHeader,
  }));
  assert.equal(response.status, 200);
  const body = response.body as any;
  assert.equal(body.schemaId, "land-registry-v1");
  assert.ok(body.fields.some((field: any) => field.path === "cadastralNumber" && field.required));
});

test("unknown admin paths are 404 for an authenticated session", async () => {
  const sessions = new SessionStore(credentials);
  const operator = await login(sessions, "operator");
  const response = await routeAdmin(context(sessions), request({
    path: "/v1/admin/unknown",
    cookieHeader: operator.cookieHeader,
  }));
  assert.equal(response.status, 404);
});
