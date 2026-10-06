// Durable, scoped service principals for trusted internal callers (ticket 07).
// A service principal is a separate identity type: it never becomes an
// AdminSession, is never accepted on human admin routes, and a human session
// cookie is never accepted on internal routes. PostgreSQL is the only source of
// truth; every request re-reads enabled/credential/scope, so revoke and rotation
// apply to the next authorization read on any API process sharing the primary DB.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { AuthorizationError, IdentityUnavailableError, parseCookies, SESSION_COOKIE } from "./admin-session.ts";

export const SERVICE_ACTIONS = [
  "artifacts.register", "integrity.reconcile",
  // Read-only verifier lookups (no record field values are returned by these routes).
  "certificates.read", "incidents.read", "anchors.read",
] as const;
export type ServiceAction = typeof SERVICE_ACTIONS[number];

export interface ServiceScope {
  actions: readonly ServiceAction[];
  registryIds: readonly string[];
}

export interface ServicePrincipal extends ServiceScope {
  principalId: string;
  credentialId: string;
  revision: string;
}

/** Hard ceiling, also enforced by a DB CHECK (migration 0016). */
export const SERVICE_CREDENTIAL_TTL_CEILING_DAYS = 366;
export const DEFAULT_SERVICE_CREDENTIAL_MAX_TTL_DAYS = 90;

export function parseMaxTtlDays(raw: string | undefined): number {
  const value = raw === undefined ? DEFAULT_SERVICE_CREDENTIAL_MAX_TTL_DAYS : Number(raw);
  if (!Number.isSafeInteger(value) || value < 1 || value > SERVICE_CREDENTIAL_TTL_CEILING_DAYS) {
    throw new TypeError(`ONELAYER_SERVICE_CREDENTIAL_MAX_TTL_DAYS must be 1-${SERVICE_CREDENTIAL_TTL_CEILING_DAYS}`);
  }
  return value;
}

const TOKEN_PREFIX = "olsp_";
const TOKEN_PATTERN = /^olsp_([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/;
const PRINCIPAL_PATTERN = /^[a-z][a-z0-9._-]{2,63}$/;
// Compared when the credential ID is unknown so the digest comparison still runs.
const DUMMY_DIGEST = createHash("sha256").update("onelayer-service-principal-dummy").digest();

// Only format-valid registry IDs from an untrusted body are written to audit (m4).
const REGISTRY_ID_PATTERN = /^[a-z][a-z0-9-]{0,62}(?:\.[a-z][a-z0-9-]{0,62}){1,7}$/;
export function auditableRegistryId(value: unknown): string | null {
  return typeof value === "string" && value.length <= 128 && REGISTRY_ID_PATTERN.test(value) ? value : null;
}

export const SERVICE_CREDENTIAL_REQUIRED = "SERVICE_CREDENTIAL_REQUIRED";
export const SERVICE_PERMISSION_FORBIDDEN = "SERVICE_PERMISSION_FORBIDDEN";

function digest(secret: string): Buffer {
  return createHash("sha256").update(secret).digest();
}

/** Syntactic parse only; it never proves identity. */
export function parseServiceBearer(header: string | undefined): { credentialId: string; secret: string } | null {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return null;
  const match = TOKEN_PATTERN.exec(header.slice("Bearer ".length));
  return match ? { credentialId: match[1]!, secret: match[2]! } : null;
}

/** True for any Authorization header that carries a service-principal bearer. */
export function carriesServiceBearer(header: string | undefined): boolean {
  return typeof header === "string" && /^Bearer\s+olsp_/i.test(header.trim());
}

/** A human admin session cookie must never reach internal routes. */
export function carriesHumanSession(cookieHeader: string | undefined): boolean {
  return parseCookies(cookieHeader).has(SESSION_COOKIE);
}

export function normalizeServiceScope(input: unknown): ServiceScope {
  if (input === null || typeof input !== "object" || Array.isArray(input) ||
      Object.keys(input).sort().join(",") !== "actions,registryIds") {
    throw new TypeError("service scope must contain exactly actions and registryIds");
  }
  const { actions, registryIds } = input as Record<string, unknown>;
  if (!Array.isArray(actions) || actions.length === 0 || new Set(actions).size !== actions.length ||
      actions.some(action => !(SERVICE_ACTIONS as readonly unknown[]).includes(action))) {
    throw new TypeError("service actions must be a non-empty unique allowlist");
  }
  if (!Array.isArray(registryIds) || registryIds.length === 0 || new Set(registryIds).size !== registryIds.length ||
      registryIds.some(id => auditableRegistryId(id) === null)) {
    throw new TypeError("explicit service registry IDs required");
  }
  return { actions: [...actions].sort() as ServiceAction[], registryIds: [...registryIds].sort() as string[] };
}

function validatePrincipalId(principalId: string): void {
  if (typeof principalId !== "string" || !PRINCIPAL_PATTERN.test(principalId)) throw new TypeError("invalid service principal ID");
}

function validateActor(actor: string): void {
  if (typeof actor !== "string" || actor.trim().length === 0 || actor.length > 200) throw new TypeError("provisioning actor required");
}

function newCredential(): { credentialId: string; secret: string; token: string } {
  const credentialId = randomBytes(16).toString("base64url");
  const secret = randomBytes(32).toString("base64url");
  return { credentialId, secret, token: `${TOKEN_PREFIX}${credentialId}.${secret}` };
}

export interface GateLimits {
  /** Internal requests in flight per process, including the operation itself. */
  maxConcurrent: number;
  /** Token bucket per credential ID (or "legacy"). */
  keyBurst: number; keyPerSecond: number;
  /** Token bucket shared by all internal requests of the process. */
  globalBurst: number; globalPerSecond: number;
  /** Bound on remembered keys; least recently used keys are evicted. */
  maxKeys: number;
}

export const DEFAULT_GATE_LIMITS: GateLimits = {
  maxConcurrent: 2, keyBurst: 20, keyPerSecond: 5, globalBurst: 60, globalPerSecond: 20, maxKeys: 4096,
};

/**
 * In-process admission for internal routes, applied before any database work
 * (M1). Excess load is refused with 429 instead of queueing on the pool, so a
 * hostile caller cannot hold the identity/API pool that human sessions use.
 * Limits are per API process; N processes allow N times the rate.
 */
export class ServiceRequestGate {
  private active = 0;
  private readonly buckets = new Map<string, { tokens: number; at: number }>();
  private global: { tokens: number; at: number };

  constructor(private readonly limits: GateLimits = DEFAULT_GATE_LIMITS, private readonly now: () => number = Date.now) {
    this.global = { tokens: limits.globalBurst, at: now() };
  }

  private take(bucket: { tokens: number; at: number }, burst: number, perSecond: number): boolean {
    const now = this.now();
    bucket.tokens = Math.min(burst, bucket.tokens + Math.max(0, now - bucket.at) * perSecond / 1000);
    bucket.at = now;
    if (bucket.tokens < 1) return false;
    bucket.tokens -= 1;
    return true;
  }

  /** Returns a release function, or the refusal reason. Never touches the DB. */
  enter(key: string): (() => void) | "BUSY" | "RATE_LIMITED" {
    if (this.active >= this.limits.maxConcurrent) return "BUSY";
    let bucket = this.buckets.get(key);
    if (bucket) this.buckets.delete(key);
    else {
      bucket = { tokens: this.limits.keyBurst, at: this.now() };
      while (this.buckets.size >= this.limits.maxKeys) this.buckets.delete(this.buckets.keys().next().value!);
    }
    this.buckets.set(key, bucket);
    if (!this.take(bucket, this.limits.keyBurst, this.limits.keyPerSecond)) return "RATE_LIMITED";
    if (!this.take(this.global, this.limits.globalBurst, this.limits.globalPerSecond)) return "RATE_LIMITED";
    this.active += 1;
    let released = false;
    return () => { if (!released) { released = true; this.active -= 1; } };
  }

  get inFlight(): number { return this.active; }
}

type Decision =
  | { allowed: true; principal: ServicePrincipal }
  | { allowed: false; status: 401 | 403; code: string };

export class ServicePrincipalStore {
  private readonly maxTtlDays: number;

  constructor(private readonly pool: Pool, options: { maxTtlDays?: number } = {}) {
    this.maxTtlDays = options.maxTtlDays ?? DEFAULT_SERVICE_CREDENTIAL_MAX_TTL_DAYS;
    parseMaxTtlDays(String(this.maxTtlDays));
  }

  private ttl(ttlDays: number | undefined): number {
    const days = ttlDays ?? this.maxTtlDays;
    if (!Number.isSafeInteger(days) || days < 1 || days > this.maxTtlDays) {
      throw new TypeError(`credential TTL must be 1-${this.maxTtlDays} days`);
    }
    return days;
  }

  private async insertCredential(client: PoolClient, credentialId: string, principalId: string, secret: string, ttlDays: number): Promise<void> {
    // created_at and expires_at come from one clock read so the DB TTL CHECK is exact.
    await client.query(
      `WITH t AS (SELECT clock_timestamp() AS at)
       INSERT INTO service_principal_credential (credential_id, principal_id, secret_hash, created_at, expires_at)
       SELECT $1, $2, $3, t.at, t.at + $4 * interval '1 day' FROM t`,
      [credentialId, principalId, digest(secret), ttlDays]);
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
      if (client) {
        try { await client.query("ROLLBACK"); }
        catch { client.release(true); client = undefined; }
      }
      if (error instanceof AuthorizationError || error instanceof TypeError) throw error;
      throw new IdentityUnavailableError();
    } finally { client?.release(); }
  }

  /**
   * Fails startup unless every object of migration 0012 that the security
   * properties depend on is present and enabled: the four tables, the one-live-
   * credential index, the append-only row and TRUNCATE triggers and the audit
   * registry_id CHECK. It does not prove the migration file's exact bytes.
   */
  async initialize(): Promise<void> {
    await this.transaction(async client => {
      const row = (await client.query(
        `SELECT
           (SELECT count(*)::int FROM unnest(ARRAY['service_principal','service_principal_credential',
              'service_principal_event','service_principal_denial_window']) AS t(name) WHERE to_regclass(t.name) IS NOT NULL) AS tables,
           (SELECT count(*)::int FROM pg_index WHERE indexrelid = to_regclass('service_principal_one_live_credential') AND indisunique) AS live_index,
           (SELECT count(*)::int FROM pg_trigger WHERE tgrelid = to_regclass('service_principal_event')
              AND tgname IN ('append_only','append_only_truncate') AND tgenabled IN ('O','A')) AS triggers,
           (SELECT count(*)::int FROM pg_constraint WHERE conrelid = to_regclass('service_principal_event') AND contype = 'c'
              AND convalidated AND pg_get_constraintdef(oid) LIKE '%registry_id ~%') AS registry_check,
           (SELECT count(*)::int FROM pg_attribute WHERE attrelid = to_regclass('service_principal_credential')
              AND attname = 'expires_at' AND attnotnull AND NOT attisdropped) AS expiry_column,
           (SELECT count(*)::int FROM pg_constraint WHERE conrelid = to_regclass('service_principal_credential')
              AND conname = 'service_credential_ttl' AND convalidated) AS ttl_check`,
      )).rows[0];
      if (row.tables !== 4 || row.live_index !== 1 || row.triggers !== 2 || row.registry_check !== 1 ||
          row.expiry_column !== 1 || row.ttl_check !== 1) {
        throw new Error("service principal schema 0012/0016 is incomplete");
      }
    });
  }

  /**
   * Authenticates the bearer and authorizes one action on one registry.
   * `recordSuccess: false` is the pre-body check of /internal/register: it runs
   * the full check against the deployment registry (so a principal scoped only
   * to foreign registries is refused before any body is read) but does not
   * record REQUEST_AUTHORIZED; the later call with the body's registryId does.
   * Denials for a known credential are aggregated per credential/reason/action/
   * minute and committed before the error is thrown; an audit failure is never
   * converted into success.
   */
  async authorize(authorizationHeader: string | undefined, action: ServiceAction, registryId: unknown,
    options: { recordSuccess?: boolean } = {}): Promise<ServicePrincipal> {
    const parsed = parseServiceBearer(authorizationHeader);
    if (!parsed) throw new AuthorizationError(401, SERVICE_CREDENTIAL_REQUIRED);
    if (!(SERVICE_ACTIONS as readonly string[]).includes(action)) throw new TypeError("unknown service action");
    const decision = await this.transaction<Decision>(async client => {
      // Lock order everywhere: principal, then credential. Each statement takes a
      // fresh READ COMMITTED snapshot, so the credential re-read after the
      // principal lock observes a rotation/revoke that committed while we waited
      // (a single join with FOR SHARE OF p would EvalPlanQual-recheck only p).
      const located = (await client.query(
        "SELECT principal_id FROM service_principal_credential WHERE credential_id=$1", [parsed.credentialId],
      )).rows[0];
      const principal = located ? (await client.query(
        "SELECT principal_id, actions, registry_ids, enabled, revision FROM service_principal WHERE principal_id=$1 FOR SHARE",
        [located.principal_id],
      )).rows[0] : undefined;
      const credential = principal ? (await client.query(
        `SELECT credential_id, secret_hash, revoked_at, expires_at <= clock_timestamp() AS expired
           FROM service_principal_credential WHERE credential_id=$1 AND principal_id=$2 FOR SHARE`,
        [parsed.credentialId, principal.principal_id],
      )).rows[0] : undefined;
      const supplied = digest(parsed.secret);
      const stored: Buffer = credential ? credential.secret_hash : DUMMY_DIGEST;
      const secretMatches = stored.length === supplied.length && timingSafeEqual(stored, supplied);
      if (!principal || !credential) return { allowed: false, status: 401, code: SERVICE_CREDENTIAL_REQUIRED };
      const scoped = auditableRegistryId(registryId);
      const deny = async (status: 401 | 403, code: string, reason: string): Promise<Decision> => {
        await this.denial(client, principal.principal_id, credential.credential_id, principal.revision, action, scoped, reason);
        return { allowed: false, status, code };
      };
      if (!secretMatches) return deny(401, SERVICE_CREDENTIAL_REQUIRED, "SECRET_MISMATCH");
      if (credential.revoked_at !== null) return deny(401, SERVICE_CREDENTIAL_REQUIRED, "CREDENTIAL_REVOKED");
      if (credential.expired) return deny(401, SERVICE_CREDENTIAL_REQUIRED, "CREDENTIAL_EXPIRED");
      if (!principal.enabled) return deny(401, SERVICE_CREDENTIAL_REQUIRED, "PRINCIPAL_DISABLED");
      if (!principal.actions.includes(action)) return deny(403, SERVICE_PERMISSION_FORBIDDEN, "ACTION_NOT_ALLOWED");
      if (scoped === null || !principal.registry_ids.includes(scoped)) return deny(403, SERVICE_PERMISSION_FORBIDDEN, "REGISTRY_OUT_OF_SCOPE");
      if (options.recordSuccess !== false) {
        await this.event(client, principal.principal_id, credential.credential_id, "service-request", "REQUEST_AUTHORIZED", principal.revision, action, scoped, null);
      }
      return { allowed: true, principal: Object.freeze({
        principalId: principal.principal_id, credentialId: credential.credential_id, revision: principal.revision,
        actions: Object.freeze([...principal.actions]), registryIds: Object.freeze([...principal.registry_ids]),
      }) };
    });
    if (!decision.allowed) throw new AuthorizationError(decision.status, decision.code);
    return decision.principal;
  }

  /**
   * Re-checks, inside the caller's write transaction, that the principal and
   * credential authorized earlier are still live at the same revision. Used by
   * /internal/register so a revoke/rotation committed during the RPC window
   * rolls the write back.
   */
  async revalidate(client: PoolClient, principal: ServicePrincipal): Promise<void> {
    const live = (await client.query(
      "SELECT 1 FROM service_principal WHERE principal_id=$1 AND enabled AND revision=$2 FOR SHARE", [principal.principalId, principal.revision],
    )).rowCount;
    const credential = live ? (await client.query(
      "SELECT 1 FROM service_principal_credential WHERE credential_id=$1 AND principal_id=$2 AND revoked_at IS NULL AND expires_at > clock_timestamp() FOR SHARE",
      [principal.credentialId, principal.principalId],
    )).rowCount : 0;
    if (!credential) throw new AuthorizationError(401, SERVICE_CREDENTIAL_REQUIRED);
  }

  /** Trusted host provisioning only. Returns the raw bearer exactly once. */
  async provision(principalId: string, scope: unknown, actor: string, ttlDays?: number): Promise<string> {
    validatePrincipalId(principalId); validateActor(actor);
    const days = this.ttl(ttlDays);
    const normalized = normalizeServiceScope(scope);
    const credential = newCredential();
    await this.transaction(async client => {
      const inserted = await client.query(
        `INSERT INTO service_principal (principal_id, actions, registry_ids) VALUES ($1,$2,$3)
         ON CONFLICT DO NOTHING RETURNING revision`, [principalId, normalized.actions, normalized.registryIds]);
      if (!inserted.rowCount) throw new AuthorizationError(409, "SERVICE_PRINCIPAL_EXISTS");
      await this.insertCredential(client, credential.credentialId, principalId, credential.secret, days);
      await this.event(client, principalId, credential.credentialId, actor, "PROVISIONED", inserted.rows[0].revision, null, null, null);
    });
    return credential.token;
  }

  /** Replaces the live secret; the previous one fails on the next request. */
  async rotate(principalId: string, actor: string, ttlDays?: number): Promise<string> {
    validatePrincipalId(principalId); validateActor(actor);
    const days = this.ttl(ttlDays);
    const credential = newCredential();
    await this.transaction(async client => {
      const row = (await client.query("SELECT * FROM service_principal WHERE principal_id=$1 FOR UPDATE", [principalId])).rows[0];
      if (!row || !row.enabled) throw new AuthorizationError(404, "SERVICE_PRINCIPAL_NOT_FOUND");
      await client.query("UPDATE service_principal_credential SET revoked_at=clock_timestamp() WHERE principal_id=$1 AND revoked_at IS NULL", [principalId]);
      const updated = await client.query("UPDATE service_principal SET revision=revision+1, updated_at=clock_timestamp() WHERE principal_id=$1 RETURNING revision", [principalId]);
      await this.insertCredential(client, credential.credentialId, principalId, credential.secret, days);
      await this.event(client, principalId, credential.credentialId, actor, "ROTATED", updated.rows[0].revision, null, null, null);
    });
    return credential.token;
  }

  /** Sticky: there is no reenable path. Provision a new principal instead. */
  async revoke(principalId: string, actor: string): Promise<void> {
    validatePrincipalId(principalId); validateActor(actor);
    await this.transaction(async client => {
      const updated = await client.query(
        `UPDATE service_principal SET enabled=false, revision=revision+1, updated_at=clock_timestamp()
          WHERE principal_id=$1 AND enabled RETURNING revision`, [principalId]);
      if (!updated.rowCount) throw new AuthorizationError(404, "SERVICE_PRINCIPAL_NOT_FOUND");
      await client.query("UPDATE service_principal_credential SET revoked_at=clock_timestamp() WHERE principal_id=$1 AND revoked_at IS NULL", [principalId]);
      await this.event(client, principalId, null, actor, "REVOKED", updated.rows[0].revision, null, null, null);
    });
  }

  /**
   * Denials are counted per credential/reason/action/minute. Only the first one
   * in a window becomes an append-only event; later ones only bump the counter,
   * so a hostile client with a known or revoked credential ID cannot grow the
   * append-only log without bound.
   */
  private async denial(client: PoolClient, principalId: string, credentialId: string, revision: string,
    action: ServiceAction, registryId: string | null, reason: string): Promise<void> {
    const window = await client.query(
      `INSERT INTO service_principal_denial_window (credential_id, principal_id, reason, service_action, window_start)
       VALUES ($1,$2,$3,$4,date_bin('1 minute', clock_timestamp(), TIMESTAMPTZ '2000-01-01'))
       ON CONFLICT (credential_id, reason, service_action, window_start)
       DO UPDATE SET denials = service_principal_denial_window.denials + 1, last_seen = clock_timestamp()
       RETURNING denials`, [credentialId, principalId, reason, action]);
    if (Number(window.rows[0].denials) === 1) {
      await this.event(client, principalId, credentialId, "service-request", "REQUEST_DENIED", revision, action, registryId, reason);
    }
  }

  private async event(client: PoolClient, principalId: string, credentialId: string | null, actor: string, event: string,
    revision: string, action: ServiceAction | null, registryId: string | null, reason: string | null): Promise<void> {
    await client.query(
      `INSERT INTO service_principal_event (principal_id, credential_id, actor, event, revision, service_action, registry_id, reason)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [principalId, credentialId, actor, event, revision, action, registryId, reason]);
  }
}
