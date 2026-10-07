// `GET /v1/incidents` (incident wire API V1), kept out of main.ts so the exact
// status mapping is testable. u64 values are always decimal strings.
import type { IncidentStore, IndexedNotice } from "./incident-index.ts";

export interface LocalIncidentRow {
  incident_id: string;
  incident_sequence: string | null;
  first_suspect_batch: string | null;
  last_suspect_batch: string | null;
  status: string;
}

export interface IncidentRouteDeps {
  registryId: string;
  refresh(): Promise<void>;
  store: Pick<IncidentStore, "loadState" | "listNotices">;
  /** Runs {@link LOCAL_INCIDENT_SQL} with `[registryId, batchSequence]`. */
  queryLocal(sql: string, values: string[]): Promise<{ rows: LocalIncidentRow[] }>;
}

/**
 * Local monitor findings covering a batch; the batch is compared as numeric
 * (u64). A finding without a complete range (either bound NULL) covers every
 * batch: it must never be dropped, or the verifier would see a clean batch.
 */
export const LOCAL_INCIDENT_SQL =
  "SELECT incident_id::text, incident_sequence::text, first_suspect_batch::text, last_suspect_batch::text, status FROM integrity_incident WHERE registry_id=$1 AND (first_suspect_batch IS NULL OR last_suspect_batch IS NULL OR (first_suspect_batch <= $2::numeric AND last_suspect_batch >= $2::numeric))";

const U64_MAX = 0xffff_ffff_ffff_ffffn;

function batchParam(value: string | null): bigint {
  if (value === null || !/^(?:0|[1-9][0-9]{0,19})$/.test(value) || BigInt(value) > U64_MAX) {
    throw new TypeError("batchSequence is invalid");
  }
  return BigInt(value);
}

/**
 * ADR-0008: OPEN, CONFIRMED and RESOLVED keep the suspect range blocked; only
 * FALSE_POSITIVE lifts this incident's block. The V1 field `status` means
 * "blocking" (`OPEN`) or "not blocking" (`RESOLVED`) to existing clients, so
 * RESOLVED is sent as `OPEN`: old verifiers stay fail-safe without an upgrade.
 * The exact disposition is `resolutionStatus`, the decision is `blocking`.
 */
export function incidentBlocks(status: IndexedNotice["status"]): boolean {
  return status !== "FALSE_POSITIVE";
}

export function wireStatus(status: IndexedNotice["status"]): "OPEN" | "RESOLVED" {
  return incidentBlocks(status) ? "OPEN" : "RESOLVED";
}

export async function incidentsRoute(deps: IncidentRouteDeps, url: URL): Promise<Record<string, unknown>> {
  if (url.searchParams.get("registryId") !== deps.registryId) throw new TypeError("registryId is invalid");
  const batchSequence = batchParam(url.searchParams.get("batchSequence"));
  await deps.refresh();
  const [state, onchain, local] = await Promise.all([
    deps.store.loadState(deps.registryId),
    deps.store.listNotices(deps.registryId, batchSequence),
    // Local monitor findings (direct-DB tampering) are not on-chain events and
    // are reported as a separate source; they never set the watermark.
    deps.queryLocal(LOCAL_INCIDENT_SQL, [deps.registryId, batchSequence.toString()]),
  ]);
  const incidents = [
    ...onchain.map((notice) => ({
      source: "ONCHAIN" as const,
      incidentSequence: notice.incidentSequence.toString(),
      firstBatchSequence: notice.firstSuspectBatch.toString(),
      lastBatchSequence: notice.lastSuspectBatch.toString(),
      status: wireStatus(notice.status),
      resolutionStatus: notice.status,
      blocking: incidentBlocks(notice.status),
      openedSlot: notice.openedSlot.toString(),
      ...(notice.resolvedSlot === null ? {} : { resolvedSlot: notice.resolvedSlot.toString() }),
    })),
    ...local.rows.map((row) => {
      // Unscoped finding: reported as the whole u64 range so the V1 verifier
      // (OPEN && first <= batch <= last -> DISPUTED) blocks every batch.
      // Local findings have no FALSE_POSITIVE state: per ADR-0008 a RESOLVED
      // finding stays blocking, so both states are sent as blocking `OPEN`.
      const unscoped = row.first_suspect_batch === null || row.last_suspect_batch === null;
      return {
        source: "LOCAL_MONITOR" as const,
        incidentId: row.incident_id,
        ...(row.incident_sequence === null ? {} : { incidentSequence: row.incident_sequence }),
        firstBatchSequence: unscoped ? "0" : row.first_suspect_batch!,
        lastBatchSequence: unscoped ? U64_MAX.toString() : row.last_suspect_batch!,
        ...(unscoped ? { unscopedRange: true } : {}),
        status: "OPEN" as const,
        resolutionStatus: row.status === "OPEN" ? "OPEN" as const : "RESOLVED" as const,
        blocking: true,
      };
    }),
  ];
  const body: Record<string, unknown> = { registryId: deps.registryId, incidents };
  // No watermark means "never indexed", which the verifier must read as
  // UNAVAILABLE rather than as a complete empty answer.
  if (state.indexedThroughSlot > 0n) body.indexedThroughSlot = state.indexedThroughSlot.toString();
  return body;
}
