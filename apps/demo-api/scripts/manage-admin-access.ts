// Trusted host-side maintenance command. No HTTP endpoint or user-supplied
// session is allowed to invoke this provisioning interface.
import { open, readFile, rm } from "node:fs/promises";
import { Pool } from "pg";
import { AuthorizationError, IdentityUnavailableError, type AdminAccess } from "../src/admin-session.ts";
import { PostgresSessionStore } from "../src/postgres-session.ts";
import { parseMaxTtlDays, ServicePrincipalStore } from "../src/service-principal.ts";

async function databasePool(): Promise<Pool> {
  const path = process.env.ONELAYER_DATABASE_URL_FILE;
  if (!path) throw new TypeError("ONELAYER_DATABASE_URL_FILE is required");
  return new Pool({ connectionString: (await readFile(path, "utf8")).trim(), max: 1, connectionTimeoutMillis: 5_000 });
}

class OutcomeUnknown extends Error {}

/**
 * Service principals: the raw bearer is written once to a new 0600 file that
 * must not already exist, never to stdout. The file is created before the DB
 * transaction, so an unwritable path fails before anything is committed. After
 * a commit, the token is written and fsynced; if that fails, or the DB outcome
 * itself is unknown, the command reports "outcome unknown" instead of "failed".
 */
async function manageService(args: string[]): Promise<void> {
  const [action, principalId, actor, ...rest] = args;
  const shapes: Record<string, number> = { "service-provision": 3, "service-rotate": 2, "service-revoke": 0 };
  if (!principalId || !actor || rest.length !== shapes[action!]) {
    throw new TypeError("usage: service-provision ID ACTOR SCOPE_FILE TOKEN_OUT TTL_DAYS | service-rotate ID ACTOR TOKEN_OUT TTL_DAYS | service-revoke ID ACTOR");
  }
  // TTL is explicit and bounded by ONELAYER_SERVICE_CREDENTIAL_MAX_TTL_DAYS (default 90, ceiling 366).
  const maxTtlDays = parseMaxTtlDays(process.env.ONELAYER_SERVICE_CREDENTIAL_MAX_TTL_DAYS);
  const ttlText = action === "service-provision" ? rest[2] : action === "service-rotate" ? rest[1] : undefined;
  if (ttlText !== undefined && !/^[1-9][0-9]{0,2}$/.test(ttlText)) throw new TypeError("TTL_DAYS must be a positive integer");
  const ttlDays = ttlText === undefined ? undefined : Number(ttlText);
  if (ttlDays !== undefined && ttlDays > maxTtlDays) throw new TypeError(`TTL_DAYS exceeds the configured maximum of ${maxTtlDays}`);
  const scope: unknown = action === "service-provision" ? JSON.parse(await readFile(rest[0]!, "utf8")) : undefined;
  const tokenPath = action === "service-provision" ? rest[1] : action === "service-rotate" ? rest[0] : undefined;
  // Pool config first (N5): a missing/unreadable DB URL file fails before any token file exists.
  const pool = await databasePool();
  let output: Awaited<ReturnType<typeof open>> | undefined;
  let committed = false, persisted = false;
  try {
    output = tokenPath === undefined ? undefined : await open(tokenPath, "wx", 0o600);
    const store = new ServicePrincipalStore(pool, { maxTtlDays });
    let token: string | undefined;
    try {
      if (action === "service-revoke") await store.revoke(principalId, actor);
      else token = action === "service-provision" ? await store.provision(principalId, scope, actor, ttlDays) : await store.rotate(principalId, actor, ttlDays);
      committed = true;
    } catch (error) {
      // A lost COMMIT acknowledgement is not proof of rollback.
      if (error instanceof IdentityUnavailableError) throw new OutcomeUnknown();
      throw error;
    }
    if (output && token !== undefined) {
      try {
        await output.writeFile(`${token}\n`);
        await output.sync();
        persisted = true;
      } catch { throw new OutcomeUnknown(); }
    }
    process.stdout.write("Service principal change committed.\n");
  } finally {
    await output?.close().catch(() => undefined);
    // Never leave an empty, partial or unusable secret file behind. Only a file
    // this run created (opened with wx) is ever removed.
    if (output && !persisted) await rm(tokenPath!, { force: true });
    await pool.end();
    if (committed && output && !persisted) process.stderr.write("change committed but the new token was not persisted; rotate the principal\n");
  }
}

async function main(): Promise<void> {
  if (process.argv[2]?.startsWith("service-")) return manageService(process.argv.slice(2));
  const [action, username, actor, accessFile, ...extra] = process.argv.slice(2);
  const fileActions = ['access', 'oidc-provision', 'resource-policy'];
  const knownActions = [...fileActions, 'revoke', 'device-enroll', 'device-revoke'];
  if (!username || !actor || extra.length ||
      !knownActions.includes(action!) ||
      (fileActions.includes(action!) || action === 'device-enroll' ? !accessFile : accessFile !== undefined)) {
    throw new TypeError("usage: manage-admin-access.ts revoke USER ACTOR | access USER ACTOR FILE | oidc-provision USER ACTOR FILE | resource-policy USER ACTOR FILE | device-enroll USER ACTOR DEVICE_ID | device-revoke DEVICE_ID ACTOR");
  }
  const input: unknown = fileActions.includes(action!) && action !== 'access'
    ? JSON.parse(await readFile(accessFile!, 'utf8')) : undefined;
  let access: AdminAccess | undefined;
  if (action === "access") {
    const parsed: unknown = JSON.parse(await readFile(accessFile!, "utf8"));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) ||
        Object.keys(parsed).some(key => !["role", "permissions", "registryIds"].includes(key)) || !Object.hasOwn(parsed, "role")) {
      throw new TypeError("access JSON must contain role and optional permissions/registryIds only");
    }
    access = parsed as AdminAccess;
  }
  const pool = await databasePool();
  try {
    const store = new PostgresSessionStore(pool, []);
    if (action === "revoke") await store.revokeUser(username, actor);
    else if (action === 'access') await store.updateAccess(username, access!, actor);
    else if (action === 'device-enroll') await store.enrollDevice(username, accessFile!, actor);
    else if (action === 'device-revoke') await store.revokeDevice(username, actor);
    else if (action === 'resource-policy') await store.updateResourcePolicy(username, input, actor);
    else {
      if (!input || typeof input !== 'object' || Array.isArray(input) ||
          Object.keys(input).sort().join(',') !== 'access,issuer,resourcePolicy,subject') throw new TypeError('invalid OIDC provisioning input');
      const value = input as { issuer: string; subject: string; access: AdminAccess; resourcePolicy: unknown };
      await store.provisionOidcAccount({ ...value, username }, actor);
    }
    process.stdout.write("Admin access change committed.\n");
  } finally { await pool.end(); }
}

main().catch((error: unknown) => {
  // Never print SQL, connection strings, input JSON or credentials on errors.
  const message = error instanceof OutcomeUnknown
    ? "OUTCOME_UNKNOWN: the change may have committed; verify service_principal_event and rotate or revoke the principal"
    : error instanceof TypeError || error instanceof AuthorizationError ? error.message : "ADMIN_ACCESS_CHANGE_FAILED";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
