// M7 (launcher review r1): the legacy certificate issuance path applies the same
// record + field resource scope as the durable path, so `certificates.issue`
// alone never yields a FULL_RECORD certificate for a scoped session. The
// whole-registry OIDC guard and the password-demo behavior stay unchanged.
import assert from "node:assert/strict";
import test from "node:test";
import { routeAdmin, type AdminContext, type AdminRequest } from "../src/admin.ts";
import { SESSION_COOKIE, type AdminSession } from "../src/admin-session.ts";
import type { ResourcePolicy } from "../src/resource-access.ts";

const REGISTRY = "gov.registry.land";
const INTENT = "00000000-0000-0000-0000-000000000001";
const RECORD = "SYNTHETIC-7";

function session(overrides: Partial<AdminSession>): AdminSession {
  return {
    sessionId: "synthetic-session", username: "operator", role: "operator",
    csrfToken: "synthetic-csrf", expiresAt: Date.now() + 60_000,
    permissions: ["certificates.issue", "records.read", "certificates.read"],
    registryIds: [REGISTRY],
    ...overrides,
  };
}

function resourcePolicy(recordIds: string[] | "all", fieldPaths: string[] | "all", actions: ResourcePolicy["grants"][number]["actions"]): ResourcePolicy {
  return { version: 1, grants: [{ registryId: REGISTRY, recordIds, fieldPaths, actions }] };
}

interface Harness { context: AdminContext; sql: () => number }
function harness(actor: AdminSession): Harness {
  let statements = 0;
  const context = {
    pool: {
      async query() { statements += 1; return { rows: [] }; },
    },
    sessions: { get: (id: string | undefined) => (id === actor.sessionId ? actor : null), destroy() {}, login: () => null },
    rpc: { getRegistryConfig: async () => ({ paused: false }) },
    registryId: REGISTRY,
    programId: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo",
    configPda: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo",
    issuerSecretKey: new Uint8Array(32).fill(9),
    publicWebBaseUrl: "http://127.0.0.1:8091",
    now: () => new Date("2026-10-07T00:00:00Z"),
  } as unknown as AdminContext;
  return { context, sql: () => statements };
}

async function issue(actor: AdminSession, body: Record<string, unknown>) {
  const { context, sql } = harness(actor);
  const request: AdminRequest = {
    method: "POST", path: `/v1/admin/publish-intents/${INTENT}/certificate`, query: new URLSearchParams(),
    body, cookieHeader: `${SESSION_COOKIE}=${actor.sessionId}`, csrfHeader: actor.csrfToken, idempotencyKey: undefined,
  };
  return { response: await routeAdmin(context, request), statements: sql() };
}

test("a scoped session cannot issue through the legacy path even with certificates.issue", async () => {
  const policy = resourcePolicy([RECORD], ["status"], ["records.read", "certificates.read"]);
  const scoped = session({ resourcePolicy: policy });

  // Omitted disclosure is FULL_RECORD: unrestricted records.read + certificates.read required.
  const full = await issue(scoped, { internalRecordId: RECORD });
  assert.equal(full.response.status, 403);
  assert.deepEqual(full.response.body, { code: "RESOURCE_FORBIDDEN" });
  assert.equal(full.statements, 0, "denied before any intent SQL");

  // Explicit selective fields must cover the record and every path on both actions.
  assert.equal((await issue(scoped, { internalRecordId: "SYNTHETIC-8", disclosedPaths: ["status"] })).response.status, 403);
  assert.equal((await issue(scoped, { internalRecordId: RECORD, disclosedPaths: ["other"] })).response.status, 403);

  // records.read alone is not enough: issuance also reads the certificate resource.
  const readOnly = session({ resourcePolicy: resourcePolicy([RECORD], ["status"], ["records.read"]) });
  const readOnlyResponse = await issue(readOnly, { internalRecordId: RECORD, disclosedPaths: ["status"] });
  assert.equal(readOnlyResponse.response.status, 403);
  assert.equal(readOnlyResponse.statements, 0);

  // Only a policy covering both actions for the record and path reaches the intent.
  const covered = await issue(scoped, { internalRecordId: RECORD, disclosedPaths: ["status"] });
  assert.equal(covered.response.status, 404);
  assert.deepEqual(covered.response.body, { code: "INTENT_NOT_FOUND" });
  assert.ok(covered.statements > 0);
});

test("the whole-registry OIDC guard is preserved for scoped identities", async () => {
  const oidc = session({ authMethod: "oidc", resourcePolicy: resourcePolicy([RECORD], ["status"], ["records.read", "certificates.read"]) });
  const { response, statements } = await issue(oidc, { internalRecordId: RECORD, disclosedPaths: ["status"] });
  assert.equal(response.status, 403);
  assert.equal(statements, 0, "the aggregate guard still denies before any SQL");
});

test("password demo sessions without a resource policy keep their existing behavior", async () => {
  const password = session({});
  const { response, statements } = await issue(password, { internalRecordId: RECORD });
  // No policy: the legacy role/permission/registry triple applies, so the
  // request reaches the intent lookup as before (404 here, not 403).
  assert.equal(response.status, 404);
  assert.deepEqual(response.body, { code: "INTENT_NOT_FOUND" });
  assert.ok(statements > 0);
});
