import { AuthorizationError } from "./admin-session.ts";

export const RESOURCE_ACTIONS = ["records.read", "records.write", "certificates.read", "certificates.export"] as const;
export type ResourceAction = typeof RESOURCE_ACTIONS[number];
export interface ResourceGrant {
  readonly registryId: string;
  readonly recordIds: readonly string[] | "all";
  readonly fieldPaths: readonly string[] | "all";
  readonly actions: readonly ResourceAction[];
}
export interface ResourcePolicy {
  readonly version: 1;
  readonly grants: readonly ResourceGrant[];
}
export interface ResourceRequest {
  readonly registryId: string;
  readonly recordId: string;
  readonly fieldPaths: readonly string[];
  readonly action: ResourceAction;
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function identifier(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 1024 &&
    value.trim() === value && value.normalize("NFC") === value && !/[\u0000-\u001f\u007f*]/u.test(value);
}
function identifiers(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(identifier) && new Set(value).size === value.length;
}
function scope(value: unknown): value is "all" | string[] {
  return value === "all" || identifiers(value);
}
function exactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).sort().join("\0") === keys.sort().join("\0");
}

/** Parse deployment-owned DB policy only. Invalid/unknown versions never broaden access. */
export function normalizeResourcePolicy(value: unknown): ResourcePolicy {
  if (!object(value) || !exactKeys(value, ["version", "grants"]) || value.version !== 1 || !Array.isArray(value.grants)) {
    throw new TypeError("invalid resource policy");
  }
  const grants = value.grants.map((grant: unknown): ResourceGrant => {
    if (!object(grant) || !exactKeys(grant, ["registryId", "recordIds", "fieldPaths", "actions"]) ||
        !identifier(grant.registryId) || !scope(grant.recordIds) || !scope(grant.fieldPaths) ||
        !Array.isArray(grant.actions) || !grant.actions.every(action => RESOURCE_ACTIONS.includes(action)) ||
        new Set(grant.actions).size !== grant.actions.length) throw new TypeError("invalid resource grant");
    return Object.freeze({ registryId: grant.registryId,
      recordIds: grant.recordIds === "all" ? "all" : Object.freeze([...grant.recordIds]),
      fieldPaths: grant.fieldPaths === "all" ? "all" : Object.freeze([...grant.fieldPaths]),
      actions: Object.freeze([...grant.actions]) });
  });
  return Object.freeze({ version: 1, grants: Object.freeze(grants) });
}
function forbidden(): never { throw new AuthorizationError(403, "RESOURCE_FORBIDDEN"); }
function policyOrDeny(value: unknown): ResourcePolicy {
  try { return normalizeResourcePolicy(value); } catch { return forbidden(); }
}

/** One grant must cover the complete response; unrelated grants cannot be spliced. */
export function requireResourceAccess(policy: unknown, request: ResourceRequest): void {
  const normalized = policyOrDeny(policy);
  if (!identifier(request.registryId) || !identifier(request.recordId) ||
      !identifiers(request.fieldPaths) || !RESOURCE_ACTIONS.includes(request.action)) forbidden();
  if (!normalized.grants.some(grant => grant.registryId === request.registryId && grant.actions.includes(request.action) &&
      (grant.recordIds === "all" || grant.recordIds.includes(request.recordId)) &&
      (grant.fieldPaths === "all" || request.fieldPaths.every(path => grant.fieldPaths.includes(path))))) forbidden();
}

/** Aggregate routes must deny narrowed policies until scoped SQL/projections exist. */
export function requireUnrestrictedResourceAccess(policy: unknown, registryId: string, action: ResourceAction): void {
  const normalized = policyOrDeny(policy);
  if (!identifier(registryId) || !RESOURCE_ACTIONS.includes(action) ||
      !normalized.grants.some(grant => grant.registryId === registryId && grant.actions.includes(action) &&
        grant.recordIds === "all" && grant.fieldPaths === "all")) forbidden();
}
