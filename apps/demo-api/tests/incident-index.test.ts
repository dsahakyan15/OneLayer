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
  data[48] = 2;
  return Buffer.from(data).toString("base64");
}

class MemoryStore implements IncidentStore {
  state: IndexState = { indexedThroughSlot: 0n, lastSignature: null };
  notices = new Map<string, IndexedNotice>();

  async loadState(): Promise<IndexState> {
    return this.state;
  }

  async applyOpened(_registryId: string, notice: IndexedNotice): Promise<void> {
    this.notices.set(notice.incidentSequence.toString(), notice);
  }

  async applyResolved(_registryId: string, incidentSequence: bigint, slot: bigint): Promise<void> {
    const existing = this.notices.get(incidentSequence.toString());
    if (existing === undefined) return;
    this.notices.set(incidentSequence.toString(), { ...existing, status: "RESOLVED", resolvedSlot: slot });
  }

  async saveState(_registryId: string, state: IndexState): Promise<void> {
    this.state = state;
  }

  async listNotices(_registryId: string, batchSequence: bigint): Promise<IndexedNotice[]> {
    return [...this.notices.values()].filter(
      (notice) => notice.firstSuspectBatch <= batchSequence && notice.lastSuspectBatch >= batchSequence,
    );
  }
}

const registry: RegistryBinding = {
  registryId: "gov.registry.land",
  configAddress: "ConfigPda1111111111111111111111111111111111",
  configBytes: CONFIG,
};

function rpcFrom(
  head: bigint,
  transactions: Array<{ signature: string; slot: bigint; logs: string[]; failed?: boolean }>,
): IncidentRpc {
  return {
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
        : { slot: found.slot, logs: found.logs, failed: found.failed ?? false };
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
  assert.deepEqual(incidentEventsFromLogs(["Program log: hello", "Program data: !!!"], CONFIG), []);
  const truncated = Buffer.from(openedPayload(0n, 1n, 2n), "base64").subarray(0, 90);
  assert.equal(decodeIncidentEvent(new Uint8Array(truncated)), null);
  assert.throws(() => incidentEventsFromLogs([], new Uint8Array(31)), RangeError);
});
