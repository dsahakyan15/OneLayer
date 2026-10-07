import type { Pool, PoolClient } from "pg";
import type { IncidentStore, IndexedNotice, IndexState } from "./incident-index.ts";

function unsigned(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(value)) throw new TypeError(`${label} is invalid`);
  return BigInt(value);
}

export class PostgresIncidentStore implements IncidentStore {
  private readonly pool: Pool;
  private readonly executor: Pool | PoolClient;
  private readonly transactionClient?: PoolClient;
  private readonly registryConfig: string;

  constructor(pool: Pool, registryConfig: string, transactionClient?: PoolClient) {
    this.pool = pool;
    this.executor = transactionClient ?? pool;
    this.transactionClient = transactionClient;
    this.registryConfig = registryConfig;
  }

  async transaction<T>(registryId: string, action: (store: IncidentStore) => Promise<T>): Promise<T> {
    if (this.transactionClient !== undefined) throw new Error("nested incident transactions are unsupported");
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SET LOCAL lock_timeout = '15s'");
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`incident-index:${registryId}`]);
      const result = await action(new PostgresIncidentStore(this.pool, this.registryConfig, client));
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async loadState(registryId: string): Promise<IndexState> {
    // The bound config address is part of the identity of the index: a redeploy
    // under a different registry PDA must not inherit an old watermark.
    const result = await this.executor.query(
      `INSERT INTO incident_index_state (registry_id, registry_config)
       VALUES ($1, $2)
       ON CONFLICT (registry_id) DO UPDATE SET registry_id = EXCLUDED.registry_id
       RETURNING registry_config, indexed_through_slot::text, last_signature`,
      [registryId, this.registryConfig],
    );
    const row = result.rows[0];
    if (row.registry_config !== this.registryConfig) {
      throw new Error("incident index is bound to a different registry config account");
    }
    return {
      indexedThroughSlot: unsigned(row.indexed_through_slot, "indexedThroughSlot"),
      lastSignature: row.last_signature,
    };
  }

  async applyOpened(registryId: string, notice: IndexedNotice): Promise<void> {
    await this.executor.query(
      `INSERT INTO incident_index_notice (
         registry_id, incident_sequence, first_suspect_batch, last_suspect_batch,
         incident_type, status, opened_slot, resolved_slot
       ) VALUES ($1,$2,$3,$4,$5,'OPEN',$6,NULL)
       ON CONFLICT (registry_id, incident_sequence) DO UPDATE SET
         first_suspect_batch = EXCLUDED.first_suspect_batch,
         last_suspect_batch = EXCLUDED.last_suspect_batch,
         incident_type = EXCLUDED.incident_type,
         status = 'OPEN',
         opened_slot = EXCLUDED.opened_slot,
         resolved_slot = NULL`,
      [
        registryId,
        notice.incidentSequence.toString(),
        notice.firstSuspectBatch.toString(),
        notice.lastSuspectBatch.toString(),
        notice.incidentType,
        notice.openedSlot.toString(),
      ],
    );
  }

  async applyResolved(registryId: string, incidentSequence: bigint, slot: bigint, status: Exclude<IndexedNotice["status"], "OPEN">): Promise<void> {
    const result = await this.executor.query(
      `UPDATE incident_index_notice
         SET status = $4, resolved_slot = $3
       WHERE registry_id = $1 AND incident_sequence = $2`,
      [registryId, incidentSequence.toString(), slot.toString(), status],
    );
    if (result.rowCount !== 1) throw new Error("incident resolution has no indexed opening event");
  }

  async saveState(registryId: string, state: IndexState): Promise<void> {
    await this.executor.query(
      `UPDATE incident_index_state
         SET indexed_through_slot = $2, last_signature = $3, updated_at = now()
       WHERE registry_id = $1`,
      [registryId, state.indexedThroughSlot.toString(), state.lastSignature],
    );
  }

  async listNotices(registryId: string, batchSequence?: bigint): Promise<IndexedNotice[]> {
    const result = await this.executor.query(
      `SELECT incident_sequence::text, first_suspect_batch::text, last_suspect_batch::text,
              incident_type, status, opened_slot::text, resolved_slot::text
         FROM incident_index_notice
        WHERE registry_id = $1 AND ($2::numeric IS NULL OR (first_suspect_batch <= $2::numeric AND last_suspect_batch >= $2::numeric))
        ORDER BY incident_sequence`,
      [registryId, batchSequence?.toString() ?? null],
    );
    return result.rows.map((row) => ({
      incidentSequence: unsigned(row.incident_sequence, "incidentSequence"),
      firstSuspectBatch: unsigned(row.first_suspect_batch, "firstSuspectBatch"),
      lastSuspectBatch: unsigned(row.last_suspect_batch, "lastSuspectBatch"),
      incidentType: row.incident_type,
      status: row.status,
      openedSlot: unsigned(row.opened_slot, "openedSlot"),
      resolvedSlot: row.resolved_slot === null ? null : unsigned(row.resolved_slot, "resolvedSlot"),
    }));
  }
}
