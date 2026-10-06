import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeResourcePolicy, requireResourceAccess, requireUnrestrictedResourceAccess, type ResourcePolicy } from "../src/resource-access.ts";

const policy: ResourcePolicy = { version: 1, grants: [{ registryId: "land", recordIds: ["r1"], fieldPaths: ["status"], actions: ["records.read", "certificates.read"] }] };
const request = { registryId: "land", recordId: "r1", fieldPaths: ["status"], action: "records.read" as const };
function denied(fn: () => void): void {
  assert.throws(fn, { status: 403, code: "RESOURCE_FORBIDDEN" });
}
test("exact object, field and action grant is allowed; substitution fails uniformly", () => {
  requireResourceAccess(policy, request);
  for (const changed of [{ recordId: "r2" }, { registryId: "other" }, { fieldPaths: ["status", "ownerName"] },
    { action: "records.write" as const }, { action: "certificates.export" as const }, { recordId: "*" }]) {
    denied(() => requireResourceAccess(policy, { ...request, ...changed }));
  }
});
test("signed certificate disclosure is indivisible, even across separate field grants", () => {
  const separate = { version: 1, grants: [policy.grants[0], { ...policy.grants[0], fieldPaths: ["ownerName"] }] };
  denied(() => requireResourceAccess(separate, { ...request, action: "certificates.read", fieldPaths: ["status", "ownerName"] }));
  requireResourceAccess(separate, { ...request, action: "certificates.read", fieldPaths: ["ownerName"] });
});
test("aggregate lookup and counters require explicit unrestricted object and field scope", () => {
  denied(() => requireUnrestrictedResourceAccess(policy, "land", "records.read"));
  const unrestricted = { version: 1, grants: [{ ...policy.grants[0], recordIds: "all", fieldPaths: "all" }] };
  requireUnrestrictedResourceAccess(unrestricted, "land", "records.read");
  denied(() => requireUnrestrictedResourceAccess(unrestricted, "other", "records.read"));
  denied(() => requireUnrestrictedResourceAccess(unrestricted, "land", "records.write"));
});
test("missing, corrupt and future policies fail closed", () => {
  for (const invalid of [undefined, null, {}, { ...policy, version: 2 }, { ...policy, role: "operator" },
    { version: 1, grants: [{ ...policy.grants[0], actions: ["admin"] }] },
    { version: 1, grants: [{ ...policy.grants[0], recordIds: ["*"] }] },
    { version: 1, grants: [{ ...policy.grants[0], fieldPaths: ["status", "status"] }] },
    { version: 1, grants: [{ ...policy.grants[0], fieldPaths: ["owner.*"] }] }]) {
    assert.throws(() => normalizeResourcePolicy(invalid), TypeError);
    denied(() => requireResourceAccess(invalid, request));
  }
  denied(() => requireResourceAccess({ version: 1, grants: [] }, request));
});
test("normalized policy cannot be widened by mutating the source or returned policy", () => {
  const source = { version: 1, grants: [{ registryId: "land", recordIds: ["r1"], fieldPaths: ["status"], actions: ["records.read"] }] };
  const normalized = normalizeResourcePolicy(source);
  source.grants[0].recordIds.push("r2");
  denied(() => requireResourceAccess(normalized, { ...request, recordId: "r2" }));
  assert.ok(Object.isFrozen(normalized.grants[0].recordIds));
  assert.ok(Object.isFrozen(normalized.grants[0].actions));
});
