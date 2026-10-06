import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decodeIncidentEvent,
  eventDiscriminator,
  incidentEventsFromLogs,
} from "../src/incident-events.ts";
import {
  refreshIncidentIndex,
  type IncidentRpc,
  type IncidentStore,
  type IndexedNotice,
  type IndexState,
  type RegistryBinding,
} from "../src/incident-index.ts";

const PROGRAM = "TrustedProgram1111111111111111111111111111111";
const CONFIG = new Uint8Array(32).fill(7);
const OTHER_CONFIG = new Uint8Array(32).fill(8);

function openedPayload(sequence: bigint, first: bigint, last: bigint, registry = CONFIG): string {
  const data = new Uint8Array(98);
  data.set(eventDiscriminator("IncidentOpened"), 0);
  data.set(registry, 8);
  const view = new DataView(data.buffer);
  view.setBigUint64(40, sequence, true);
  view.setBigUint64(48, first, true);
  view.setBigUint64(56, last, true);
  view.setUint16(64, 3, true);
  data.fill(0xcd, 66);
  return Buffer.from(data).toString("base64");
}

function resolvedPayload(sequence: bigint, registry = CONFIG): string {
  const data = new Uint8Array(81);
  data.set(eventDiscriminator("IncidentResolved"), 0);
  data.set(registry, 8);
  new DataView(data.buffer).setBigUint64(40, sequence, true);
  data[48] = 4;
  return Buffer.from(data).toString("base64");
}

class MemoryStore implements IncidentStore {
  state: IndexState = { indexedThroughSlot: 0n, lastSignature: null };
  notices = new Map<string, IndexedNotice>();

  async transaction<T>(_registryId: string, action: (store: IncidentStore) => Promise<T>): Promise<T> {
    const state = { ...this.state };
    const notices = new Map(this.notices);
    try { return await action(this); }
    catch (error) { this.state = state; this.notices = notices; throw error; }
  }

  async loadState(): Promise<IndexState> {
    return this.state;
  }

  async applyOpened(_registryId: string, notice: IndexedNotice): Promise<void> {
    this.notices.set(notice.incidentSequence.toString(), notice);
  }

  async applyResolved(_registryId: string, incidentSequence: bigint, slot: bigint, status: Exclude<IndexedNotice["status"], "OPEN">): Promise<void> {
    const existing = this.notices.get(incidentSequence.toString());
    if (existing === undefined) throw new Error("missing incident opening");
    this.notices.set(incidentSequence.toString(), { ...existing, status, resolvedSlot: slot });
  }

  async saveState(_registryId: string, state: IndexState): Promise<void> {
    this.state = state;
  }

  async listNotices(_registryId: string, batchSequence?: bigint): Promise<IndexedNotice[]> {
    return [...this.notices.values()].filter(
      (notice) => batchSequence === undefined || (notice.firstSuspectBatch <= batchSequence && notice.lastSuspectBatch >= batchSequence),
    );
  }
}

const registry: RegistryBinding = {
  registryId: "gov.registry.land",
  configAddress: "ConfigPda1111111111111111111111111111111111",
  configBytes: CONFIG,
  programId: PROGRAM,
};

function rpcFrom(
  head: bigint,
  transactions: Array<{ signature: string; slot: bigint; logs: string[]; failed?: boolean }>,
): IncidentRpc {
  return {
    async getIncidentSnapshot() {
      const notices = new Map<string, IndexedNotice>();
      for (const tx of transactions) {
        if (tx.failed) continue;
        for (const line of tx.logs) {
          const payload = /^Program data: (.+)$/.exec(line)?.[1];
          if (!payload) continue;
          const event = decodeIncidentEvent(Buffer.from(payload, "base64"));
          if (!event || !Buffer.from(event.registry).equals(Buffer.from(CONFIG))) continue;
          const key = event.incidentSequence.toString();
          if (event.kind === "OPENED") notices.set(key, { ...event, status: "OPEN", openedSlot: tx.slot, resolvedSlot: null });
          else {
            const notice = notices.get(key);
            if (notice) notice.status = ({2: "CONFIRMED", 3: "FALSE_POSITIVE", 4: "RESOLVED"} as const)[event.status as 2 | 3 | 4];
          }
        }
      }
      return { incidentCount: BigInt(notices.size), notices: [...notices.values()] };
    },
    async getFinalizedHeadSlot() {
      return head;
    },
    async getSignaturesForAddress(_address, until) {
      const stop = transactions.findIndex((entry) => entry.signature === until);
      const fresh = stop === -1 ? transactions : transactions.slice(stop + 1);
      return [...fresh].reverse().map((entry) => ({ signature: entry.signature, slot: entry.slot }));
    },
    async getTransactionLogs(signature) {
      const found = transactions.find((entry) => entry.signature === signature);
      return found === undefined
        ? null
        : { slot: found.slot, logs: found.logs.length ? [`Program ${PROGRAM} invoke [1]`, ...found.logs, `Program ${PROGRAM} success`] : [], failed: found.failed ?? false };
    },
  };
}

test("an opened incident becomes an OPEN notice covering its batch range", async () => {
  const store = new MemoryStore();
  const rpc = rpcFrom(900n, [
    { signature: "sigA", slot: 800n, logs: [`Program data: ${openedPayload(0n, 5n, 9n)}`] },
  ]);
  const result = await refreshIncidentIndex(registry, rpc, store);
  assert.equal(result.appliedEvents, 1);
  assert.equal(result.indexedThroughSlot, 900n);
  assert.deepEqual(
    (await store.listNotices(registry.registryId, 7n)).map((notice) => notice.status),
    ["OPEN"],
  );
  assert.deepEqual(await store.listNotices(registry.registryId, 4n), []);
});

test("a resolve event clears the current status without inventing history", async () => {
  const store = new MemoryStore();
  const rpc = rpcFrom(1_000n, [
    { signature: "sigA", slot: 800n, logs: [`Program data: ${openedPayload(0n, 5n, 9n)}`] },
    { signature: "sigB", slot: 950n, logs: [`Program data: ${resolvedPayload(0n)}`] },
  ]);
  await refreshIncidentIndex(registry, rpc, store);
  const notices = await store.listNotices(registry.registryId, 7n);
  assert.equal(notices[0].status, "RESOLVED");
  assert.equal(notices[0].openedSlot, 800n);
  assert.equal(notices[0].resolvedSlot, 950n);
});

test("events of another registry config are ignored", async () => {
  const store = new MemoryStore();
  const rpc = rpcFrom(900n, [
    { signature: "sigA", slot: 800n, logs: [`Program data: ${openedPayload(1n, 1n, 9n, OTHER_CONFIG)}`] },
  ]);
  const result = await refreshIncidentIndex(registry, rpc, store);
  assert.equal(result.appliedEvents, 0);
  assert.deepEqual(await store.listNotices(registry.registryId, 5n), []);
});

test("failed transactions emit no notices", async () => {
  const store = new MemoryStore();
  const rpc = rpcFrom(900n, [
    { signature: "sigA", slot: 800n, failed: true, logs: [`Program data: ${openedPayload(0n, 1n, 9n)}`] },
  ]);
  assert.equal((await refreshIncidentIndex(registry, rpc, store)).appliedEvents, 0);
});

test("an interrupted scan keeps the old watermark", async () => {
  const store = new MemoryStore();
  store.state = { indexedThroughSlot: 100n, lastSignature: null };
  const rpc = rpcFrom(900n, [{ signature: "sigA", slot: 800n, logs: [] }]);
  const broken: IncidentRpc = { ...rpc, async getTransactionLogs() { return null; } };
  await assert.rejects(() => refreshIncidentIndex(registry, broken, store), /unavailable/);
  assert.equal(store.state.indexedThroughSlot, 100n);
});

test("the watermark never moves backwards", async () => {
  const store = new MemoryStore();
  store.state = { indexedThroughSlot: 5_000n, lastSignature: null };
  const result = await refreshIncidentIndex(registry, rpcFrom(900n, []), store);
  assert.equal(result.indexedThroughSlot, 5_000n);
});

test("only well-formed program data lines decode", () => {
  assert.equal(decodeIncidentEvent(new Uint8Array(8)), null);
  assert.deepEqual(incidentEventsFromLogs(["Program log: hello", "Program data: !!!"], CONFIG, PROGRAM), []);
  const truncated = Buffer.from(openedPayload(0n, 1n, 2n), "base64").subarray(0, 90);
  assert.equal(decodeIncidentEvent(new Uint8Array(truncated)), null);
  assert.throws(() => incidentEventsFromLogs([], new Uint8Array(31), PROGRAM), RangeError);
});


test("foreign program and nested CPI payloads cannot impersonate the registry program", () => {
  const data = `Program data: ${openedPayload(0n, 1n, 9n)}`;
  assert.deepEqual(incidentEventsFromLogs([
    "Program Foreign invoke [1]", data, "Program Foreign success",
    `Program ${PROGRAM} invoke [1]`, "Program Foreign invoke [2]", data,
    "Program Foreign success", `Program ${PROGRAM} success`,
  ], CONFIG, PROGRAM), []);
  assert.equal(incidentEventsFromLogs([
    "Program Foreign invoke [1]", `Program ${PROGRAM} invoke [2]`, data,
    `Program ${PROGRAM} success`, "Program Foreign success",
  ], CONFIG, PROGRAM).length, 1);
});

test("truncated and incomplete invocation logs cannot certify complete history", () => {
  assert.throws(() => incidentEventsFromLogs([`Program ${PROGRAM} invoke [1]`, "Log truncated"], CONFIG, PROGRAM), /truncated/);
  assert.throws(() => incidentEventsFromLogs([`Program ${PROGRAM} invoke [1]`], CONFIG, PROGRAM), /incomplete/);
});

test("partial application leaves both cursor and watermark unchanged and restart replays", async () => {
  const store = new MemoryStore();
  const rpc = rpcFrom(1000n, [
    { signature: "a", slot: 800n, logs: [`Program data: ${openedPayload(0n, 1n, 9n)}`] },
    { signature: "b", slot: 900n, logs: [`Program data: ${resolvedPayload(0n)}`] },
  ]);
  await assert.rejects(() => refreshIncidentIndex(registry, {
    ...rpc, async getTransactionLogs(signature) { return signature === "b" ? null : rpc.getTransactionLogs(signature); },
  }, store), /unavailable/);
  assert.deepEqual(store.state, { indexedThroughSlot: 0n, lastSignature: null });
  assert.equal(store.notices.size, 0);
  await refreshIncidentIndex(registry, rpc, store);
  assert.equal(store.notices.get("0")?.status, "RESOLVED");
  assert.equal(store.state.lastSignature, "b");
});

test("resolution statuses retain their on-chain meaning", async () => {
  for (const [code, expected] of [[2, "CONFIRMED"], [3, "FALSE_POSITIVE"], [4, "RESOLVED"]] as const) {
    const payload = Buffer.from(resolvedPayload(0n), "base64");
    payload[48] = code;
    const store = new MemoryStore();
    await refreshIncidentIndex(registry, rpcFrom(1000n, [
      { signature: "a", slot: 800n, logs: [`Program data: ${openedPayload(0n, 1n, 9n)}`] },
      { signature: "b", slot: 900n, logs: [`Program data: ${payload.toString("base64")}`] },
    ]), store);
    assert.equal(store.notices.get("0")?.status, expected);
  }
});

test("bootstrap with pruned opening events cannot declare an empty index complete", async () => {
  const store = new MemoryStore();
  const rpc = {
    ...rpcFrom(1000n, []),
    async getIncidentSnapshot() {
      return { incidentCount: 1n, notices: [{ incidentSequence: 0n, firstSuspectBatch: 1n, lastSuspectBatch: 9n, incidentType: 3, status: "OPEN" as const }] };
    },
  };
  await assert.rejects(refreshIncidentIndex(registry, rpc, store), /incident.*(count|incomplete|match)/);
  assert.equal(store.state.indexedThroughSlot, 0n);
});

test("account status disagreement rolls back events and progress", async () => {
  const store = new MemoryStore();
  const rpc = rpcFrom(1000n, [{ signature: "a", slot: 800n, logs: [`Program data: ${openedPayload(0n, 1n, 9n)}`] }]);
  await assert.rejects(refreshIncidentIndex(registry, {
    ...rpc,
    async getIncidentSnapshot(binding, slot) {
      const snapshot = await rpc.getIncidentSnapshot(binding, slot);
      snapshot.notices[0].status = "RESOLVED";
      return snapshot;
    },
  }, store), /does not match/);
  assert.equal(store.notices.size, 0);
  assert.deepEqual(store.state, { indexedThroughSlot: 0n, lastSignature: null });
});

test("u64 boundary suspect ranges decode and index exactly (D1)", async () => {
  const U64_MAX = 0xffff_ffff_ffff_ffffn;
  const I64_MAX = 0x7fff_ffff_ffff_ffffn;
  const cases: Array<[bigint, bigint]> = [[0n, 0n], [0n, U64_MAX], [U64_MAX, U64_MAX], [I64_MAX + 1n, U64_MAX - 1n]];
  for (const [first, last] of cases) {
    const event = decodeIncidentEvent(new Uint8Array(Buffer.from(openedPayload(U64_MAX, first, last), "base64")));
    assert.equal(event?.kind, "OPENED");
    assert.deepEqual(event?.kind === "OPENED" && [event.incidentSequence, event.firstSuspectBatch, event.lastSuspectBatch], [U64_MAX, first, last]);
  }
  const store = new MemoryStore();
  const rpc = rpcFrom(900n, cases.map(([first, last], index) => ({
    signature: `sig${index}`, slot: 800n + BigInt(index), logs: [`Program data: ${openedPayload(BigInt(index), first, last)}`],
  })));
  assert.equal((await refreshIncidentIndex(registry, rpc, store)).appliedEvents, cases.length);
  assert.deepEqual((await store.listNotices(registry.registryId)).map(n => [n.firstSuspectBatch, n.lastSuspectBatch]), cases);
  assert.deepEqual((await store.listNotices(registry.registryId, 0n)).map(n => n.incidentSequence), [0n, 1n]);
  assert.deepEqual((await store.listNotices(registry.registryId, U64_MAX)).map(n => n.incidentSequence), [1n, 2n]);
});
