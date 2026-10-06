// Compatibility policy for the synthetic demo, not the production role matrix.
export type AdminRole = "operator" | "auditor" | "chief_admin" | "registry_worker" | "registry_approver" | "identity_admin" | "key_holder" | "storage_custodian";

export const ADMIN_PERMISSIONS = [
  "records.read", "records.draft", "records.approve", "certificates.verify", "certificates.export", "incidents.read", "access.manage", "publication.read", "publication.prepare",
  "publication.submit", "certificates.read", "certificates.issue", "backups.read",
  "backups.create", "recovery.read", "recovery.initiate", "recovery.approve",
  "recovery.cutover", "audit.read",
  // ADR-0009: approve a version exclusion or an archival publication cancellation.
  "publication.maintenance",
] as const;
export type AdminPermission = typeof ADMIN_PERMISSIONS[number];

const reads: readonly AdminPermission[] = [
  "records.read", "publication.read", "certificates.read", "backups.read",
  "recovery.read", "audit.read",
];
const policy: Record<AdminRole, readonly AdminPermission[]> = {
  operator: [...reads, "records.draft", "publication.prepare", "publication.submit",
    "certificates.issue", "backups.create", "recovery.initiate", "recovery.cutover"],
  registry_worker: ["records.read", "records.draft", "certificates.read", "certificates.verify", "certificates.export"],
  registry_approver: ["records.read", "records.approve", "publication.maintenance"],
  identity_admin: ["access.manage"],
  key_holder: ["recovery.read"],
  storage_custodian: ["backups.read"],
  auditor: reads,
  chief_admin: [...reads, "recovery.approve"],
};

export function demoPermissions(role: AdminRole): readonly AdminPermission[] {
  if (!Object.hasOwn(policy, role)) throw new TypeError("unknown admin role");
  return [...policy[role]];
}
