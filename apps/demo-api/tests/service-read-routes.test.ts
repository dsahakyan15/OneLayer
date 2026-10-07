// Pins the scoped verifier read surface (ticket 07 slice): the exact method and
// pathname allowlist, and the rule that a live credential/action/scope decision
// always precedes the route's own registry selector and any resource lookup.
import test from "node:test";
import assert from "node:assert/strict";
import { AuthorizationError } from "../src/admin-session.ts";
import { SERVICE_ACTIONS, type ServiceAction, type ServicePrincipal } from "../src/service-principal.ts";
import { authorizeServiceRead, matchServiceRead, SERVICE_READ_ROUTES } from "../src/service-read-routes.ts";

const REGISTRY = "gov.registry.land";
const CERTIFICATE = "ab".repeat(16);
const HEADER = `Bearer olsp_${"A".repeat(22)}.${"b".repeat(43)}`;

function recorder(outcome: ServicePrincipal | Error = principal(["anchors.read", "incidents.read", "certificates.read"])) {
  const calls: Array<{ action: ServiceAction; registry: unknown; recordSuccess: unknown }> = [];
  return {
    calls,
    store: {
      authorize: async (_header: string | undefined, action: ServiceAction, registry: unknown, options?: { recordSuccess?: boolean }) => {
        calls.push({ action, registry, recordSuccess: options?.recordSuccess });
        if (outcome instanceof Error) throw outcome;
        return outcome;
      },
    },
  };
}

function principal(actions: ServiceAction[]): ServicePrincipal {
  return { principalId: "svc.test", credentialId: "credential", revision: "1", actions, registryIds: [REGISTRY] };
}

test("the verifier read surface is an exact method and pathname allowlist", () => {
  const allowed: Array<[string, ServiceAction, "deployment" | "query"]> = [
    ["/v1/anchors/0", "anchors.read", "deployment"],
    ["/v1/anchors/1", "anchors.read", "deployment"],
    // The digit bound is the allowlist's job; the u64 and BIGINT boundaries
    // (400 / 404) belong to the handler, so these stay whitelisted.
    ["/v1/anchors/18446744073709551615", "anchors.read", "deployment"],
    ["/v1/anchors/99999999999999999999", "anchors.read", "deployment"],
    ["/v1/incidents", "incidents.read", "query"],
    [`/v1/certificates/${CERTIFICATE}/status`, "certificates.read", "deployment"],
    [`/v1/certificates/${CERTIFICATE}/lifecycle`, "certificates.read", "query"],
  ];
  for (const [path, action, registry] of allowed) {
    const route = matchServiceRead("GET", path);
    assert.ok(route !== null, path);
    assert.equal(route.action, action, path);
    assert.equal(route.registry, registry, path);
  }
  // Prefixes, non-canonical numbers and every surface that returns field values,
  // packages, QR material or HTML stay outside the allowlist. HEAD is not GET.
  const refused = [
    "/v1/anchors", "/v1/anchors/", "/v1/anchors/01", "/v1/anchors/1/", "/v1/anchors/1/extra", "/v1/anchors/-1", "/v1/anchors/1.5",
    `/v1/anchors/${"9".repeat(21)}`, `/v1/anchors/${"1"}${"0".repeat(30)}`,
    "/v1/incidents/", "/v1/incidents/1",
    `/v1/certificates/${CERTIFICATE}/package`, `/v1/certificates/${CERTIFICATE}/metadata`,
    `/v1/certificates/${CERTIFICATE}/lifecycle/extra`, `/v1/certificates/${CERTIFICATE.slice(1)}/status`,
    `/v1/certificates/${CERTIFICATE.toUpperCase()}/status`,
    `/v1/qr/${CERTIFICATE}.svg`, `/v1/qr/${CERTIFICATE}.png`, `/c/${CERTIFICATE}`,
    "/v1/health", "/v1/admin/session", "/internal/register", "/internal/reconcile",
  ];
  for (const path of refused) assert.equal(matchServiceRead("GET", path), null, path);
  for (const [path] of allowed) {
    for (const method of ["HEAD", "POST", "PUT", "PATCH", "DELETE", undefined]) {
      assert.equal(matchServiceRead(method, path), null, `${method} ${path}`);
    }
  }
  // Every action is a declared service action; no read route carries an
  // aggregate/export action, and duplicate path coverage would let one route
  // shadow another.
  for (const route of SERVICE_READ_ROUTES) assert.ok(SERVICE_ACTIONS.includes(route.action), route.action);
  assert.deepEqual(SERVICE_READ_ROUTES.map(route => route.action).sort(), ["anchors.read", "certificates.read", "certificates.read", "incidents.read"]);
  assert.equal(new Set(SERVICE_READ_ROUTES.map(route => route.pattern.source)).size, SERVICE_READ_ROUTES.length);
});

test("a deployment-registry read makes one audited authorization check", async () => {
  const { store, calls } = recorder();
  const route = matchServiceRead("GET", "/v1/anchors/1");
  assert.ok(route !== null);
  await authorizeServiceRead(store, HEADER, route, new URL("http://127.0.0.1/v1/anchors/1"), REGISTRY);
  assert.deepEqual(calls, [{ action: "anchors.read", registry: REGISTRY, recordSuccess: undefined }]);
});

test("a registry-selector read audits success only for one deployment-registry selector", async () => {
  const route = matchServiceRead("GET", "/v1/incidents");
  assert.ok(route !== null);
  const accepted = recorder();
  await authorizeServiceRead(accepted.store, HEADER, route, new URL(`http://127.0.0.1/v1/incidents?registryId=${REGISTRY}&batchSequence=7`), REGISTRY);
  assert.deepEqual(accepted.calls, [
    { action: "incidents.read", registry: REGISTRY, recordSuccess: false },
    { action: "incidents.read", registry: REGISTRY, recordSuccess: undefined },
  ]);
  // Absent, foreign, malformed, differently cased and repeated selectors are
  // all refused: the handlers resolve `registryId` by first value, so a
  // duplicate must never be accepted here.
  for (const query of ["", "?registryId=other.registry", "?registryId=", "?registryId=gov.registry.land.extra", "?registryId=GOV.REGISTRY.LAND",
    `?registryId=${REGISTRY}&registryId=${REGISTRY}`, `?registryId=${REGISTRY}&registryId=other.registry`, `?registryId=other.registry&registryId=${REGISTRY}`]) {
    const refused = recorder();
    await assert.rejects(
      authorizeServiceRead(refused.store, HEADER, route, new URL(`http://127.0.0.1/v1/incidents${query}`), REGISTRY),
      (error: unknown) => error instanceof AuthorizationError && error.status === 403 && error.code === "SERVICE_PERMISSION_FORBIDDEN",
      query);
    // Only the pre-check ran: a selector outside the deployment registry never
    // records REQUEST_AUTHORIZED and never reaches a resource query.
    assert.deepEqual(refused.calls, [{ action: "incidents.read", registry: REGISTRY, recordSuccess: false }], query);
  }
});

test("credential and scope decisions stop before the registry selector", async () => {
  const route = matchServiceRead("GET", `/v1/certificates/${CERTIFICATE}/lifecycle`);
  assert.ok(route !== null);
  for (const failure of [new AuthorizationError(401, "SERVICE_CREDENTIAL_REQUIRED"), new AuthorizationError(403, "SERVICE_PERMISSION_FORBIDDEN")]) {
    for (const query of [`?registryId=${REGISTRY}`, "?registryId=other.registry"]) {
      const { store, calls } = recorder(failure);
      await assert.rejects(
        authorizeServiceRead(store, HEADER, route, new URL(`http://127.0.0.1/v1/certificates/${CERTIFICATE}/lifecycle${query}`), REGISTRY),
        (error: unknown) => error === failure, query);
      assert.equal(calls.length, 1, query);
      assert.equal(calls[0]!.recordSuccess, false, query);
    }
  }
});
