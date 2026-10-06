import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { workflowHash, workflowTransaction } from './registry-workflow.ts';

export class PublicationError extends Error {
  /** `detail` names the offending object (event, record, version) when useful to an operator. */
  constructor(public code: string, public detail?: Record<string, unknown>) { super(code); }
}
export interface PublicationLease {
  operationId: string;
  registryId: string;
  worker: string;
  /** Decimal string: fencing remains exact beyond JavaScript's integer range. */
  fence: string;
  leaseUntil: string;
}
export interface PublicationItem {
  eventId: string;
  recordId: string;
  version: number;
  operation: 'upsert' | 'tombstone';
  payload: Record<string, unknown>;
  payloadHash: string;
}
const leaseOf = (r: any): PublicationLease => ({operationId:r.operation_id,registryId:r.registry_id,worker:r.owner,fence:r.fence,leaseUntil:r.lease_until.toISOString()});
function validateDuration(ms: number) {
  if (!Number.isSafeInteger(ms) || ms < 100 || ms > 300000) throw new PublicationError('INVALID_LEASE_DURATION');
}
export async function journal(c: PoolClient, lease: PublicationLease, action: string) {
  await c.query('INSERT INTO wf_publication_attempt(operation_id,fence,worker,action) VALUES($1,$2,$3,$4)',[lease.operationId,lease.fence,lease.worker,action]);
}
/** Internal worker interface, never a user-controlled HTTP completion endpoint.
 * One unresolved operation blocks later registry work. A crash reclaims the same
 * immutable membership, never a fresh logical publication. No method here may
 * mark FINALIZED or issue a Certificate Package: finalization belongs solely to
 * the trusted chain path in `publication-worker.ts`.
 */
export class WorkflowPublicationStore {
  constructor(private pool: Pool) {}
  async claim(registryId: string, worker: string, leaseMs = 30000, limit = 100): Promise<PublicationLease | null> {
    validateDuration(leaseMs);
    if (!registryId || !worker || worker.length > 128 || !Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new PublicationError('INVALID_CLAIM');
    return workflowTransaction(this.pool, async c => {
      // A stable transaction lock also serializes first creation, where no row exists.
      await lockRegistryPublication(c, registryId);
      const existing = await c.query("SELECT * FROM wf_publication WHERE registry_id=$1 AND state='OPEN' FOR UPDATE",[registryId]);
      if (existing.rowCount) {
        const active = await c.query("SELECT lease_until > clock_timestamp() AS active FROM wf_publication WHERE registry_id=$1 AND state='OPEN'",[registryId]);
        if (active.rows[0].active) return null;
        const updated = await c.query("UPDATE wf_publication SET owner=$2,fence=fence+1,lease_until=clock_timestamp()+$3*interval '1 millisecond' WHERE registry_id=$1 AND state='OPEN' RETURNING *",[registryId,worker,leaseMs]);
        const lease = leaseOf(updated.rows[0]);
        await journal(c,lease,'RECLAIM');
        return lease;
      }
      // The per-record version lock in workflow commits makes predecessors
      // visible before successors. Sort record IDs and versions explicitly so
      // wall-clock changes cannot reverse version order. Not a global cursor.
      // Events of live or finalized operations are never selected again; only
      // an ABANDONED operation releases its membership (to its explicit successor).
      // Versions excluded by an effective two-person decision (ADR-0009, 0017)
      // are skipped; the order of the remaining events is unchanged.
      const events = await c.query(`SELECT o.event_id FROM wf_outbox o WHERE o.registry_id=$1
        AND NOT EXISTS (SELECT 1 FROM wf_publication_item i JOIN wf_publication p USING(operation_id)
                        WHERE i.event_id=o.event_id AND p.state<>'ABANDONED')
        AND NOT EXISTS (SELECT 1 FROM wf_version_excluded x WHERE x.event_id=o.event_id)
        ORDER BY o.record_id COLLATE "C",o.version,o.event_id LIMIT $2`,[registryId,limit]);
      if (!events.rowCount) return null;
      const operationId = randomUUID();
      const inserted = await c.query("INSERT INTO wf_publication(operation_id,registry_id,owner,lease_until) VALUES($1,$2,$3,clock_timestamp()+$4*interval '1 millisecond') RETURNING *",[operationId,registryId,worker,leaseMs]);
      for (const [ordinal,event] of events.rows.entries()) await c.query('INSERT INTO wf_publication_item VALUES($1,$2,$3)',[operationId,ordinal,event.event_id]);
      const lease = leaseOf(inserted.rows[0]);
      await journal(c,lease,'CLAIM');
      return lease;
    });
  }
  /** The caller's own current, unexpired lease on an OPEN operation, if any.
   * Read-only: it neither creates membership nor reclaims another worker's
   * lease. Used by the runtime so an operator resumes the same durable step. */
  async leaseFor(registryId: string, worker: string): Promise<PublicationLease | null> {
    if (!registryId || !worker || worker.length > 128) throw new PublicationError('INVALID_CLAIM');
    return workflowTransaction(this.pool, async c => {
      const r = await c.query("SELECT * FROM wf_publication WHERE registry_id=$1 AND state='OPEN' AND owner=$2 AND lease_until>clock_timestamp() ORDER BY lease_until DESC LIMIT 1",[registryId,worker]);
      return r.rowCount ? leaseOf(r.rows[0]) : null;
    });
  }
  async items(lease: PublicationLease): Promise<PublicationItem[]> {
    lease = {...lease};
    return workflowTransaction(this.pool, async c => {
      await this.check(c,lease);
      const result = await c.query(`SELECT o.event_id,o.record_id,o.version,o.payload_hash AS outbox_hash,v.payload_hash,v.payload,v.operation
        FROM wf_publication_item i JOIN wf_outbox o USING(event_id)
        JOIN wf_version v USING(registry_id,record_id,version)
        WHERE i.operation_id=$1 ORDER BY i.ordinal`,[lease.operationId]);
      return result.rows.map(r => {
        if (r.outbox_hash !== r.payload_hash || workflowHash({operation:r.operation,payload:r.payload}) !== r.payload_hash) throw new PublicationError('PUBLICATION_PAYLOAD_MISMATCH');
        return {eventId:r.event_id,recordId:r.record_id,version:r.version,operation:r.operation,payload:r.payload,payloadHash:r.payload_hash};
      });
    });
  }
  async renew(lease: PublicationLease, leaseMs = 30000): Promise<PublicationLease> {
    lease = {...lease};
    validateDuration(leaseMs);
    return workflowTransaction(this.pool,async c => {
      await this.check(c,lease);
      const r = await c.query("UPDATE wf_publication SET lease_until=clock_timestamp()+$2*interval '1 millisecond' WHERE operation_id=$1 RETURNING *",[lease.operationId,leaseMs]);
      const renewed = leaseOf(r.rows[0]); await journal(c,renewed,'RENEW'); return renewed;
    });
  }
  async release(lease: PublicationLease): Promise<void> {
    lease = {...lease};
    await workflowTransaction(this.pool,async c => {
      await this.check(c,lease);
      await c.query('UPDATE wf_publication SET lease_until=clock_timestamp() WHERE operation_id=$1',[lease.operationId]);
      await journal(c,lease,'RELEASE');
    });
  }
  private check(c: PoolClient, lease: PublicationLease): Promise<void> { return assertPublicationLease(c, lease); }
}

/** Serializes operation creation/abandonment for one registry. */
export async function lockRegistryPublication(c: PoolClient, registryId: string): Promise<void> {
  await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['publication:'+registryId]);
}

/** Locks the operation row and requires the caller's current, unexpired fence
 * on an OPEN operation. Every durable publication write calls this inside its
 * own transaction, so a stale worker cannot append intent/attempt evidence. */
export async function assertPublicationLease(c: PoolClient, lease: PublicationLease): Promise<void> {
  // Lock first: a WHERE clock check before a lock wait can become stale.
  await c.query('SELECT operation_id FROM wf_publication WHERE operation_id=$1 FOR UPDATE',[lease.operationId]);
  const r = await c.query("SELECT operation_id FROM wf_publication WHERE operation_id=$1 AND registry_id=$2 AND owner=$3 AND fence=$4 AND state='OPEN' AND lease_until>clock_timestamp()",[lease.operationId,lease.registryId,lease.worker,lease.fence]);
  if (!r.rowCount) throw new PublicationError('PUBLICATION_LEASE_LOST');
}
