// Whitelisted service-principal reads for the verifier (ticket 07 slice).
//
// The verifier sends `Authorization: Bearer olsp_…` on the SAME public GET
// paths it already uses; nothing here renames an endpoint or reshapes a DTO.
// The allowlist is exact on method and whole pathname, so any other path or
// method keeps the pre-existing `SERVICE_PRINCIPAL_NOT_ALLOWED` refusal and
// `certificates.read` never reaches the package, metadata, QR or /c surfaces
// (those return record field values or export material).
import { AuthorizationError } from "./admin-session.ts";
import { SERVICE_PERMISSION_FORBIDDEN, type ServiceAction, type ServicePrincipalStore } from "./service-principal.ts";

export interface ServiceReadRoute {
  /** Action the live principal must hold for this path. */
  readonly action: ServiceAction;
  /**
   * `deployment` reads the single registry this deployment serves. `query`
   * additionally requires the route's own `registryId` query parameter to name
   * that same deployment registry before any resource lookup.
   */
  readonly registry: "deployment" | "query";
  /** Whole-pathname match; there is no prefix matching. */
  readonly pattern: RegExp;
}

/**
 * The exact allowlist. The anchors pattern is the canonical unsigned form with
 * at most 20 digits, the widest u64, so a whitelisted path can never make the
 * handler parse an unbounded number; the handler itself decides the u64 and the
 * BIGINT boundary (400 / 404) before it touches the anchor store.
 */
export const SERVICE_READ_ROUTES: readonly ServiceReadRoute[] = [
  { action: "anchors.read", registry: "deployment", pattern: /^\/v1\/anchors\/(?:0|[1-9][0-9]{0,19})$/ },
  { action: "incidents.read", registry: "query", pattern: /^\/v1\/incidents$/ },
  { action: "certificates.read", registry: "deployment", pattern: /^\/v1\/certificates\/[0-9a-f]{32}\/status$/ },
  { action: "certificates.read", registry: "query", pattern: /^\/v1\/certificates\/[0-9a-f]{32}\/lifecycle$/ },
];

/** The whitelisted route for an exact method+pathname pair, or null. */
export function matchServiceRead(method: string | undefined, pathname: string): ServiceReadRoute | null {
  if (method !== "GET") return null;
  return SERVICE_READ_ROUTES.find(route => route.pattern.test(pathname)) ?? null;
}

/**
 * Authorizes one whitelisted service read against the live principal store.
 * Credential, action and deployment scope are always evaluated before anything
 * else, so an absent, unknown, expired, revoked, disabled, wrong-action or
 * foreign-registry credential fails with the same error as on the internal
 * routes, before the route's registry selector and before any resource lookup.
 *
 * A route whose contract carries an explicit `registryId` selector is checked
 * twice: the pre-check (no success audit) proves the credential may read this
 * deployment at all, so a principal scoped only to foreign registries is
 * refused here like the pre-body check of /internal/register; then the request
 * must carry exactly one `registryId` selector naming the deployment registry
 * itself, and only the final check records REQUEST_AUTHORIZED. A selector that
 * names another registry, is absent or is repeated is a deployment-scope
 * refusal: no resource is read and no success is audited for it.
 */
export async function authorizeServiceRead(
  store: Pick<ServicePrincipalStore, "authorize">,
  authorizationHeader: string | undefined,
  route: ServiceReadRoute,
  url: URL,
  deploymentRegistryId: string,
): Promise<void> {
  if (route.registry === "deployment") {
    await store.authorize(authorizationHeader, route.action, deploymentRegistryId);
    return;
  }
  await store.authorize(authorizationHeader, route.action, deploymentRegistryId, { recordSuccess: false });
  // Strict selector: exactly one `registryId` parameter naming this
  // deployment's registry. The handlers read the first value, so a repeated
  // parameter must not be resolved here.
  const selectors = url.searchParams.getAll("registryId");
  if (selectors.length !== 1 || selectors[0] !== deploymentRegistryId) {
    throw new AuthorizationError(403, SERVICE_PERMISSION_FORBIDDEN);
  }
  await store.authorize(authorizationHeader, route.action, deploymentRegistryId);
}
