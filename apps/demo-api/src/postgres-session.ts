import { createHash, randomBytes } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type { OidcIdentity } from "./oidc.ts";
import { normalizeResourcePolicy } from "./resource-access.ts";
import { demoPermissions } from "./admin-permissions.ts";
import {
  AuthorizationError, IdentityUnavailableError, matchCredential, normalizeAccess, SESSION_TTL_MS,
  type AdminAccess, type AdminSession, type Credential, type SessionBackend,
} from "./admin-session.ts";

function tokenHash(token: string): Buffer {
  return createHash("sha256").update(token).digest();
}

function accessFromRow(row: any): Required<AdminAccess> {
  try {
    return normalizeAccess({ role: row.role, permissions: row.permissions, registryIds: row.registry_ids });
  } catch { throw new IdentityUnavailableError(); }
}

/** Deployment-owned demo credentials authenticate; PostgreSQL alone owns grants. */
export class PostgresSessionStore implements SessionBackend {
  private readonly credentials: readonly Credential[];

  constructor(private readonly pool: Pool, credentials: readonly Credential[], private readonly options: { oidcOnly?: boolean } = {}) {
    if (new Set(credentials.map(entry => entry.username)).size !== credentials.length) {
      throw new TypeError("duplicate admin username");
    }
    this.credentials = credentials.map(entry => ({ ...entry, ...normalizeAccess(entry) })).sort((a, b) => a.username.localeCompare(b.username));
  }

  private async transaction<T>(run: (client: PoolClient) => Promise<T>): Promise<T> {
    let client: PoolClient | undefined;
    try {
      client = await this.pool.connect();
      await client.query("BEGIN");
      await client.query("SET LOCAL statement_timeout = '5s'");
      await client.query("SET LOCAL lock_timeout = '3s'");
      const result = await run(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      // A failed connection is discarded if rollback also fails.
      if (client) {
        try { await client.query("ROLLBACK"); }
        catch { client.release(true); client = undefined; }
      }
      if (error instanceof AuthorizationError || error instanceof TypeError) throw error;
      throw new IdentityUnavailableError();
    } finally { client?.release(); }
  }

  /** Insert once. Existing grants and disabled accounts are NEVER reset at boot. */
  async initialize(): Promise<void> {
    await this.transaction(async client => {
      for (const credential of this.credentials) {
        const access = normalizeAccess(credential);
        const inserted = await client.query(
          `INSERT INTO demo_admin_account (username, role, permissions, registry_ids)
           VALUES ($1,$2,$3,$4) ON CONFLICT (username) DO NOTHING RETURNING username`,
          [credential.username, access.role, access.permissions, access.registryIds],
        );
        if (inserted.rowCount) {
          await this.audit(client, credential.username, "deployment-bootstrap", "BOOTSTRAP", "1", access);
        }
      }
    });
  }

  async login(username: unknown, password: unknown): Promise<AdminSession | null> {
    if (this.options.oidcOnly) return null;
    const credential = matchCredential(this.credentials, username, password);
    if (!credential) return null;
    return this.transaction(async client => {
      // Login and revoke/access change serialize on the same account row.
      const result = await client.query("SELECT * FROM demo_admin_account WHERE username=$1 FOR UPDATE", [credential.username]);
      const row = result.rows[0];
      if (!row || !row.enabled || row.auth_source !== "password") return null;
      const access = accessFromRow(row);
      const sessionId = randomBytes(32).toString("base64url");
      const csrfToken = randomBytes(32).toString("base64url");
      await client.query("DELETE FROM demo_admin_session WHERE username=$1 AND expires_at <= clock_timestamp()", [credential.username]);
      const inserted = await client.query(
        `INSERT INTO demo_admin_session (token_hash, username, access_revision, csrf_token, expires_at)
         VALUES ($1,$2,$3,$4,clock_timestamp() + $5 * interval '1 millisecond') RETURNING expires_at`,
        [tokenHash(sessionId), credential.username, row.access_revision, csrfToken, SESSION_TTL_MS],
      );
      return Object.freeze({ sessionId, username: credential.username, ...access,
        permissions: Object.freeze(access.permissions), registryIds: Object.freeze(access.registryIds),
        csrfToken, expiresAt: inserted.rows[0].expires_at.getTime(),
      });
    });
  }

  /** Only consume identities returned by the pinned OIDC adapter, never HTTP claims. */
  async loginOidc(identity: OidcIdentity): Promise<AdminSession | null> {
    if (!this.options.oidcOnly || !Number.isFinite(identity.expiresAt) || identity.expiresAt <= Date.now()) return null;
    return this.transaction(async client => {
      const result = await client.query(`SELECT * FROM demo_admin_account
        WHERE auth_source='oidc' AND oidc_issuer=$1 AND oidc_subject=$2 FOR UPDATE`, [identity.issuer, identity.subject]);
      const row = result.rows[0];
      if (!row || !row.enabled) return null;
      const devices = await client.query(`SELECT * FROM demo_managed_device WHERE device_id=$1 AND username=$2 FOR UPDATE`, [identity.deviceId, row.username]);
      const device = devices.rows[0];
      if (!device?.enabled) return null;
      const access = accessFromRow(row);
      const resourcePolicy = normalizeResourcePolicy(row.resource_policy);
      const sessionId = randomBytes(32).toString("base64url"), csrfToken = randomBytes(32).toString("base64url");
      const inserted = await client.query(`INSERT INTO demo_admin_session
        (token_hash,username,access_revision,csrf_token,expires_at,auth_method,device_id,device_revision)
        SELECT $1,$2,$3,$4,LEAST(clock_timestamp()+$5*interval '1 millisecond',to_timestamp($6 / 1000.0)),'oidc',$7,$8
        WHERE to_timestamp($6 / 1000.0)>clock_timestamp() RETURNING expires_at`,
        [tokenHash(sessionId),row.username,row.access_revision,csrfToken,SESSION_TTL_MS,identity.expiresAt,device.device_id,device.revision]);
      if (!inserted.rowCount) return null;
      return Object.freeze({ sessionId, username: row.username, ...access, permissions: Object.freeze(access.permissions),
        registryIds: Object.freeze(access.registryIds), csrfToken, expiresAt: inserted.rows[0].expires_at.getTime(),
        authMethod: "oidc" as const, deviceId: device.device_id, resourcePolicy });
    });
  }

  async provisionOidcAccount(input: { username: string; issuer: string; subject: string; access: AdminAccess; resourcePolicy: unknown }, actor: string): Promise<void> {
    this.validateActor(actor);
    for (const value of [input.username,input.issuer,input.subject]) this.validateIdentifier(value);
    const access = normalizeAccess(input.access), policy = normalizeResourcePolicy(input.resourcePolicy);
    await this.transaction(async client => {
      const inserted = await client.query(`INSERT INTO demo_admin_account
        (username,role,permissions,registry_ids,auth_source,oidc_issuer,oidc_subject,resource_policy)
        VALUES ($1,$2,$3,$4,'oidc',$5,$6,$7) ON CONFLICT DO NOTHING RETURNING access_revision`,
        [input.username,access.role,access.permissions,access.registryIds,input.issuer,input.subject,JSON.stringify(policy)]);
      if (!inserted.rowCount) throw new AuthorizationError(409,"ACCOUNT_ALREADY_EXISTS");
      await this.audit(client,input.username,actor,"ACCOUNT_PROVISIONED",inserted.rows[0].access_revision,{ ...access, resourcePolicy: policy });
    });
  }

  async enrollDevice(username: string, deviceId: string, actor: string): Promise<void> {
    this.validateActor(actor); this.validateIdentifier(deviceId);
    await this.transaction(async client => {
      const result = await client.query("SELECT * FROM demo_admin_account WHERE username=$1 FOR UPDATE",[username]);
      const row = result.rows[0];
      if (!row || !row.enabled || row.auth_source !== "oidc") throw new AuthorizationError(404,"ACCOUNT_NOT_FOUND");
      const inserted = await client.query("INSERT INTO demo_managed_device(device_id,username) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING device_id",[deviceId,username]);
      if (!inserted.rowCount) throw new AuthorizationError(409,"DEVICE_ALREADY_EXISTS");
      await this.audit(client,username,actor,"DEVICE_ENROLLED",row.access_revision,accessFromRow(row));
    });
  }

  async revokeDevice(deviceId: string, actor: string): Promise<void> {
    this.validateActor(actor);
    await this.transaction(async client => {
      const device = (await client.query("UPDATE demo_managed_device SET enabled=false,revision=revision+1 WHERE device_id=$1 RETURNING username,revision::text",[deviceId])).rows[0];
      if (!device) throw new AuthorizationError(404,"DEVICE_NOT_FOUND");
      await client.query("DELETE FROM demo_admin_session WHERE device_id=$1",[deviceId]);
      const row = (await client.query("SELECT * FROM demo_admin_account WHERE username=$1",[device.username])).rows[0];
      await this.audit(client,row.username,actor,"DEVICE_REVOKED",row.access_revision,{ ...accessFromRow(row), deviceId, deviceRevision: device.revision });
    });
  }

  async updateResourcePolicy(username: string, policy: unknown, actor: string): Promise<void> {
    this.validateActor(actor); const normalized = normalizeResourcePolicy(policy);
    await this.transaction(async client => {
      const row = (await client.query(`UPDATE demo_admin_account SET resource_policy=$2,access_revision=access_revision+1,
        updated_at=clock_timestamp() WHERE username=$1 RETURNING *`,[username,JSON.stringify(normalized)])).rows[0];
      if (!row) throw new AuthorizationError(404,"ACCOUNT_NOT_FOUND");
      await client.query("DELETE FROM demo_admin_session WHERE username=$1",[username]);
      await this.audit(client,username,actor,"RESOURCE_POLICY_CHANGED",row.access_revision,{ ...accessFromRow(row), resourcePolicy: normalized });
    });
  }

  private validateIdentifier(value: string): void {
    if (typeof value !== "string" || value.length === 0 || value.length > 2048 || /[\x00-\x20\x7f]/.test(value)) throw new TypeError("invalid identity identifier");
  }

  async get(sessionId: string | undefined): Promise<AdminSession | null> {
    if (sessionId === undefined || !/^[A-Za-z0-9_-]{43}$/.test(sessionId)) return null;
    try {
      const result = await this.transaction(client => client.query(
        `SELECT a.username, a.role, a.permissions, a.registry_ids, a.resource_policy, a.auth_source, s.auth_method, s.device_id, s.csrf_token, s.expires_at
          FROM demo_admin_session s JOIN demo_admin_account a ON a.username=s.username
          LEFT JOIN demo_managed_device d ON d.device_id=s.device_id AND d.username=a.username
          WHERE s.token_hash=$1 AND a.enabled AND s.access_revision=a.access_revision
            AND s.expires_at > clock_timestamp()
            AND (s.auth_method='password' OR (d.enabled AND d.revision=s.device_revision))`,
        [tokenHash(sessionId)],
      ));
      const row = result.rows[0];
      if (!row || row.auth_source !== row.auth_method) return null;
      if (this.options.oidcOnly ? row.auth_method !== "oidc" : row.auth_method !== "password" || !this.credentials.some(entry => entry.username === row.username)) return null;
      const access = accessFromRow(row);
      return Object.freeze({ sessionId, username: row.username, ...access,
        permissions: Object.freeze(access.permissions), registryIds: Object.freeze(access.registryIds),
        csrfToken: row.csrf_token, expiresAt: row.expires_at.getTime(),
        ...(row.auth_method === "oidc" ? { authMethod: "oidc" as const, deviceId: row.device_id, resourcePolicy: normalizeResourcePolicy(row.resource_policy) } : {}),
      });
    } catch { throw new IdentityUnavailableError(); }
  }

  async destroy(sessionId: string | undefined): Promise<void> {
    if (sessionId === undefined || !/^[A-Za-z0-9_-]{43}$/.test(sessionId)) return;
    await this.transaction(async client => {
      await client.query("DELETE FROM demo_admin_session WHERE token_hash=$1", [tokenHash(sessionId)]);
    });
  }

  /** Trusted local provisioning only; never accepts an actor supplied by HTTP. */
  async revokeUser(username: string, actor: string): Promise<void> {
    this.validateActor(actor);
    await this.transaction(async client => {
      const result = await client.query(
        `UPDATE demo_admin_account SET enabled=false, access_revision=access_revision+1, updated_at=clock_timestamp()
         WHERE username=$1 RETURNING *`, [username],
      );
      const row = result.rows[0];
      if (!row) throw new AuthorizationError(404, "ACCOUNT_NOT_FOUND");
      await client.query("DELETE FROM demo_admin_session WHERE username=$1", [username]);
      await this.audit(client, username, actor, "REVOKE", row.access_revision, accessFromRow(row));
    });
  }

  async updateAccess(username: string, access: AdminAccess, actor: string, expectedRevision?: string): Promise<void> {
    this.validateActor(actor);
    await this.transaction(async client => {
      const result = await client.query("SELECT * FROM demo_admin_account WHERE username=$1 FOR UPDATE", [username]);
      const row = result.rows[0];
      if (!row) throw new AuthorizationError(404, "ACCOUNT_NOT_FOUND");
      if (expectedRevision !== undefined && row.access_revision !== expectedRevision) throw new AuthorizationError(409, "ACCESS_REVISION_CONFLICT");
      const previous = accessFromRow(row);
      const normalized = normalizeAccess({
        role: access.role,
        permissions: access.permissions === undefined
          ? previous.permissions.filter(permission => demoPermissions(access.role).includes(permission)) : access.permissions,
        registryIds: access.registryIds === undefined ? previous.registryIds : access.registryIds,
      });
      const updated = await client.query(
        `UPDATE demo_admin_account SET role=$2, permissions=$3, registry_ids=$4,
           access_revision=access_revision+1, updated_at=clock_timestamp()
         WHERE username=$1 RETURNING access_revision`,
        [username, normalized.role, normalized.permissions, normalized.registryIds],
      );
      await client.query("DELETE FROM demo_admin_session WHERE username=$1", [username]);
      await this.audit(client, username, actor, "ACCESS_CHANGED", updated.rows[0].access_revision, normalized);
    });
  }

  /** Authenticated delegation. Critical roles remain trusted-provisioning only. */
  async changeAccessAsSession(sessionId: string | undefined, username: string, access: AdminAccess, expectedRevision: string): Promise<void> {
    if (!this.options.oidcOnly || !sessionId || !/^[A-Za-z0-9_-]{43}$/.test(sessionId)) throw new AuthorizationError(401, "SESSION_REQUIRED");
    this.validateIdentifier(username);
    if (typeof expectedRevision !== "string" || !/^[1-9][0-9]{0,18}$/.test(expectedRevision)) throw new TypeError("expected access revision required");
    await this.transaction(async client => {
      const { actor, target, actorAccess } = await this.managedAccount(client, sessionId, username);
      if (!["registry_worker", "registry_approver", "auditor"].includes(access.role)) throw new AuthorizationError(403, "ROLE_ASSIGNMENT_FORBIDDEN");
      const previous = accessFromRow(target);
      const normalized = normalizeAccess({ role: access.role,
        permissions: access.permissions ?? previous.permissions.filter(permission => demoPermissions(access.role).includes(permission)),
        registryIds: access.registryIds ?? previous.registryIds });
      if (!normalized.registryIds.every(id => actorAccess.registryIds.includes(id))) throw new AuthorizationError(403, "PERMISSION_FORBIDDEN");
      if (target.access_revision !== expectedRevision) throw new AuthorizationError(409, "ACCESS_REVISION_CONFLICT");
      const updated = await client.query(`UPDATE demo_admin_account SET role=$2,permissions=$3,registry_ids=$4,
        access_revision=access_revision+1,updated_at=clock_timestamp() WHERE username=$1 RETURNING access_revision`,
        [username, normalized.role, normalized.permissions, normalized.registryIds]);
      await client.query("DELETE FROM demo_admin_session WHERE username=$1", [username]);
      await this.audit(client, username, actor.username, "ACCESS_CHANGED", updated.rows[0].access_revision, normalized);
    });
  }

  /** Revision is the account revision for account revoke, or device revision for device revoke. */
  async revokeAsSession(sessionId: string | undefined, username: string, expectedRevision: string, deviceId?: string): Promise<void> {
    if (!this.options.oidcOnly || !sessionId || !/^[A-Za-z0-9_-]{43}$/.test(sessionId)) throw new AuthorizationError(401, "SESSION_REQUIRED");
    this.validateIdentifier(username);
    if (deviceId !== undefined) this.validateIdentifier(deviceId);
    if (typeof expectedRevision !== "string" || !/^[1-9][0-9]{0,18}$/.test(expectedRevision)) throw new TypeError("expected revision required");
    await this.transaction(async client => {
      const { actor, target } = await this.managedAccount(client, sessionId, username);
      if (deviceId !== undefined) {
        const device = (await client.query("SELECT * FROM demo_managed_device WHERE device_id=$1 AND username=$2 FOR UPDATE", [deviceId, username])).rows[0];
        if (!device) throw new AuthorizationError(404, "DEVICE_NOT_FOUND");
        if (device.revision !== expectedRevision) throw new AuthorizationError(409, "DEVICE_REVISION_CONFLICT");
        const revoked = (await client.query("UPDATE demo_managed_device SET enabled=false,revision=revision+1 WHERE device_id=$1 RETURNING revision::text", [deviceId])).rows[0];
        await client.query("DELETE FROM demo_admin_session WHERE device_id=$1", [deviceId]);
        await this.audit(client, username, actor.username, "DEVICE_REVOKED", target.access_revision, { ...accessFromRow(target), deviceId, deviceRevision: revoked.revision });
      } else {
        if (target.access_revision !== expectedRevision) throw new AuthorizationError(409, "ACCESS_REVISION_CONFLICT");
        const updated = (await client.query(`UPDATE demo_admin_account SET enabled=false,access_revision=access_revision+1,
          updated_at=clock_timestamp() WHERE username=$1 RETURNING access_revision`, [username])).rows[0];
        await client.query("DELETE FROM demo_admin_session WHERE username=$1", [username]);
        await this.audit(client, username, actor.username, "REVOKE", updated.access_revision, accessFromRow(target));
      }
    });
  }

  private async managedAccount(client: PoolClient, sessionId: string, username: string) {
    const candidate = (await client.query("SELECT username FROM demo_admin_session WHERE token_hash=$1", [tokenHash(sessionId)])).rows[0];
    if (!candidate) throw new AuthorizationError(401, "SESSION_REQUIRED");
    // Stable lock ordering serializes cross-account changes and actor revocation.
    const accounts = (await client.query("SELECT * FROM demo_admin_account WHERE username=ANY($1::text[]) ORDER BY username FOR UPDATE", [[candidate.username, username]])).rows;
    const actor = accounts.find(row => row.username === candidate.username);
    const session = (await client.query(`SELECT * FROM demo_admin_session WHERE token_hash=$1
      AND expires_at>clock_timestamp()`, [tokenHash(sessionId)])).rows[0];
    if (!actor?.enabled || actor.auth_source !== "oidc" || !session || session.auth_method !== "oidc" || session.access_revision !== actor.access_revision) throw new AuthorizationError(401, "SESSION_REQUIRED");
    const device = (await client.query("SELECT * FROM demo_managed_device WHERE device_id=$1 AND username=$2 FOR SHARE", [session.device_id, actor.username])).rows[0];
    if (!device?.enabled || device.revision !== session.device_revision) throw new AuthorizationError(401, "SESSION_REQUIRED");
    const live = (await client.query("SELECT token_hash FROM demo_admin_session WHERE token_hash=$1 AND expires_at>clock_timestamp() FOR SHARE", [tokenHash(sessionId)])).rowCount;
    if (!live) throw new AuthorizationError(401, "SESSION_REQUIRED");
    const actorAccess = accessFromRow(actor);
    if (actorAccess.role !== "identity_admin" || !actorAccess.permissions.includes("access.manage")) throw new AuthorizationError(403, "PERMISSION_FORBIDDEN");
    if (username === actor.username) throw new AuthorizationError(403, "SELF_ACCESS_CHANGE_FORBIDDEN");
    const target = accounts.find(row => row.username === username);
    // Every target the actor may not manage — absent, foreign, password-based or
    // holding a critical role — is indistinguishable (m8): no 403-vs-404 oracle.
    if (!target || target.auth_source !== "oidc" || !target.registry_ids.every((id: string) => actorAccess.registryIds.includes(id)) ||
        !["registry_worker", "registry_approver", "auditor"].includes(target.role)) throw new AuthorizationError(404, "ACCOUNT_NOT_FOUND");
    return { actor, target, actorAccess };
  }

  private validateActor(actor: string): void {
    if (typeof actor !== "string" || actor.trim().length === 0 || actor.length > 200) throw new TypeError("provisioning actor required");
  }

  private async audit(client: PoolClient, username: string, actor: string, action: string, revision: string, access: Required<AdminAccess> & { resourcePolicy?: unknown; deviceId?: string; deviceRevision?: string }): Promise<void> {
    await client.query(
      "INSERT INTO demo_admin_access_event (username, actor, action, access_revision, access) VALUES ($1,$2,$3,$4,$5)",
      [username, actor, action, revision, JSON.stringify(access)],
    );
  }
}
