// Pins the `GET /v1/incidents` mapping decided in ADR-0008 (D2): OPEN,
// CONFIRMED and RESOLVED block; only FALSE_POSITIVE lifts the block.
import assert from "node:assert/strict";
import { test } from "node:test";
import { incidentsRoute, LOCAL_INCIDENT_SQL, wireStatus } from "../src/incident-route.ts";
import type { IndexedNotice, IndexState } from "../src/incident-index.ts";

const U64_MAX = 0xffff_ffff_ffff_ffffn;

function deps(notices: IndexedNotice[], state: IndexState = { indexedThroughSlot: 900n, lastSignature: "s" }) {
  const calls: unknown[] = [];
  return {
    calls,
    deps: {
      registryId: "gov.registry.land",
      refresh: async () => { calls.push("refresh"); },
      store: {
        loadState: async () => state,
        listNotices: async (_registry: string, batch?: bigint) => { calls.push(["listNotices", batch]); return notices; },
      },
      queryLocal: async (sql: string, values: string[]) => {
        calls.push(["local", sql, values]);
        return { rows: [{ incident_id: "0b7e0f7e-0000-4000-8000-000000000001", incident_sequence: null, first_suspect_batch: "3", last_suspect_batch: "3", status: "OPEN" }] };
      },
    },
  };
}

const notice = (sequence: bigint, status: IndexedNotice["status"]): IndexedNotice => ({
  incidentSequence: sequence, firstSuspectBatch: 0n, lastSuspectBatch: U64_MAX, incidentType: 1, status,
  openedSlot: 10n + sequence, resolvedSlot: status === "OPEN" ? null : 20n + sequence,
});

test("incident route maps all four on-chain statuses and u64 values as strings", async () => {
  const { deps: d, calls } = deps([notice(0n, "OPEN"), notice(1n, "CONFIRMED"), notice(2n, "FALSE_POSITIVE"), notice(U64_MAX, "RESOLVED")]);
  const body = await incidentsRoute(d, new URL(`http://x/v1/incidents?registryId=gov.registry.land&batchSequence=${U64_MAX}`));
  assert.deepEqual(body, {
    registryId: "gov.registry.land",
    indexedThroughSlot: "900",
    incidents: [
      { source: "ONCHAIN", incidentSequence: "0", firstBatchSequence: "0", lastBatchSequence: U64_MAX.toString(), status: "OPEN", resolutionStatus: "OPEN", blocking: true, openedSlot: "10" },
      { source: "ONCHAIN", incidentSequence: "1", firstBatchSequence: "0", lastBatchSequence: U64_MAX.toString(), status: "OPEN", resolutionStatus: "CONFIRMED", blocking: true, openedSlot: "11", resolvedSlot: "21" },
      { source: "ONCHAIN", incidentSequence: "2", firstBatchSequence: "0", lastBatchSequence: U64_MAX.toString(), status: "RESOLVED", resolutionStatus: "FALSE_POSITIVE", blocking: false, openedSlot: "12", resolvedSlot: "22" },
      // ADR-0008 (D2): RESOLVED keeps blocking; V1 `status` is OPEN for old clients.
      { source: "ONCHAIN", incidentSequence: U64_MAX.toString(), firstBatchSequence: "0", lastBatchSequence: U64_MAX.toString(), status: "OPEN", resolutionStatus: "RESOLVED", blocking: true, openedSlot: (10n + U64_MAX).toString(), resolvedSlot: (20n + U64_MAX).toString() },
      { source: "LOCAL_MONITOR", incidentId: "0b7e0f7e-0000-4000-8000-000000000001", firstBatchSequence: "3", lastBatchSequence: "3", status: "OPEN", resolutionStatus: "OPEN", blocking: true },
    ],
  });
  // Refresh happens before reading; batch is passed exactly, compared as numeric.
  assert.deepEqual(calls, ["refresh", ["listNotices", U64_MAX], ["local", LOCAL_INCIDENT_SQL, ["gov.registry.land", U64_MAX.toString()]]]);
  assert.match(LOCAL_INCIDENT_SQL, /\$2::numeric.*\$2::numeric/);
  assert.deepEqual((["OPEN", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"] as const).map(wireStatus), ["OPEN", "OPEN", "RESOLVED", "OPEN"]);
});

test("incident route never reports a watermark for a never-indexed registry and rejects bad input", async () => {
  const { deps: d } = deps([], { indexedThroughSlot: 0n, lastSignature: null });
  const body = await incidentsRoute(d, new URL("http://x/v1/incidents?registryId=gov.registry.land&batchSequence=5"));
  assert.equal("indexedThroughSlot" in body, false);
  for (const query of ["registryId=other&batchSequence=5", "registryId=gov.registry.land&batchSequence=-1",
    "registryId=gov.registry.land&batchSequence=01", "registryId=gov.registry.land", `registryId=gov.registry.land&batchSequence=${U64_MAX + 1n}`]) {
    await assert.rejects(incidentsRoute(d, new URL(`http://x/v1/incidents?${query}`)), TypeError, query);
  }
});

test("an unscoped local finding (NULL bound) is reported as covering every batch, so the verifier cannot say VERIFIED", async () => {
  const U64 = U64_MAX.toString();
  for (const [first, last] of [[null, null], [null, "7"], ["7", null]] as const) {
    const body = await incidentsRoute({
      registryId: "gov.registry.land",
      refresh: async () => undefined,
      store: { loadState: async () => ({ indexedThroughSlot: 900n, lastSignature: "s" }), listNotices: async () => [] },
      queryLocal: async (sql: string) => {
        assert.match(sql, /first_suspect_batch IS NULL OR last_suspect_batch IS NULL/);
        return { rows: [{ incident_id: "0b7e0f7e-0000-4000-8000-000000000002", incident_sequence: null, first_suspect_batch: first, last_suspect_batch: last, status: "OPEN" }] };
      },
    }, new URL(`http://x/v1/incidents?registryId=gov.registry.land&batchSequence=${U64}`));
    const [incident] = body.incidents as any[];
    assert.deepEqual(incident, {
      source: "LOCAL_MONITOR", incidentId: "0b7e0f7e-0000-4000-8000-000000000002",
      firstBatchSequence: "0", lastBatchSequence: U64, unscopedRange: true, status: "OPEN", resolutionStatus: "OPEN", blocking: true,
    });
    // Same predicate as apps/verifier/src/verify.ts: OPEN && first <= batch <= last -> DISPUTED.
    for (const batch of [0n, 1n, U64_MAX]) {
      assert.ok(BigInt(incident.firstBatchSequence) <= batch && BigInt(incident.lastBatchSequence) >= batch);
    }
  }
});

test("a RESOLVED local finding stays blocking (ADR-0008; local findings have no FALSE_POSITIVE state)", async () => {
  const body = await incidentsRoute({
    registryId: "gov.registry.land",
    refresh: async () => undefined,
    store: { loadState: async () => ({ indexedThroughSlot: 900n, lastSignature: "s" }), listNotices: async () => [] },
    queryLocal: async () => ({ rows: [{ incident_id: "0b7e0f7e-0000-4000-8000-000000000003", incident_sequence: "1", first_suspect_batch: "4", last_suspect_batch: "4", status: "RESOLVED" }] }),
  }, new URL("http://x/v1/incidents?registryId=gov.registry.land&batchSequence=4"));
  assert.deepEqual(body.incidents, [{ source: "LOCAL_MONITOR", incidentId: "0b7e0f7e-0000-4000-8000-000000000003", incidentSequence: "1",
    firstBatchSequence: "4", lastBatchSequence: "4", status: "OPEN", resolutionStatus: "RESOLVED", blocking: true }]);
});
