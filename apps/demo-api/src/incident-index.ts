// Event-backed incident index (OL-C-14, §2.3).
//
// The watermark is the finalized head observed *before* a scan starts and is
// only advanced when every finalized signature newer than the previous
// watermark has been read. A failed or partial scan leaves the old watermark in
// place, so the verifier sees `STALE` rather than a self-certified `CHECKED`.
import { incidentEventsFromLogs, type IncidentEvent } from "./incident-events.ts";

export interface SignatureRecord {
  signature: string;
  slot: bigint;
}

export interface TransactionLogs {
  slot: bigint;
  logs: readonly string[];
  failed: boolean;
}

export interface IncidentRpc {
  getFinalizedHeadSlot(): Promise<bigint>;
  /** Newest-first finalized signatures for the account, stopping at `until`. */
  getSignaturesForAddress(address: string, until: string | null): Promise<SignatureRecord[]>;
  getTransactionLogs(signature: string): Promise<TransactionLogs | null>;
}

export interface IndexedNotice {
  incidentSequence: bigint;
  firstSuspectBatch: bigint;
  lastSuspectBatch: bigint;
  incidentType: number;
  status: "OPEN" | "RESOLVED";
  openedSlot: bigint;
  resolvedSlot: bigint | null;
}

export interface IndexState {
  indexedThroughSlot: bigint;
  lastSignature: string | null;
}

export interface IncidentStore {
  loadState(registryId: string): Promise<IndexState>;
  applyOpened(registryId: string, notice: IndexedNotice): Promise<void>;
  applyResolved(registryId: string, incidentSequence: bigint, slot: bigint): Promise<void>;
  saveState(registryId: string, state: IndexState): Promise<void>;
  listNotices(registryId: string, batchSequence: bigint): Promise<IndexedNotice[]>;
}

export interface RefreshResult {
  indexedThroughSlot: bigint;
  scannedSignatures: number;
  appliedEvents: number;
}

export interface RegistryBinding {
  registryId: string;
  /** Registry config PDA, base58 for RPC and raw bytes for event matching. */
  configAddress: string;
  configBytes: Uint8Array;
}

async function applyEvent(
  store: IncidentStore,
  registry: RegistryBinding,
  event: IncidentEvent,
  slot: bigint,
): Promise<void> {
  if (event.kind === "OPENED") {
    await store.applyOpened(registry.registryId, {
      incidentSequence: event.incidentSequence,
      firstSuspectBatch: event.firstSuspectBatch,
      lastSuspectBatch: event.lastSuspectBatch,
      incidentType: event.incidentType,
      status: "OPEN",
      openedSlot: slot,
      resolvedSlot: null,
    });
    return;
  }
  await store.applyResolved(registry.registryId, event.incidentSequence, slot);
}

export async function refreshIncidentIndex(
  registry: RegistryBinding,
  rpc: IncidentRpc,
  store: IncidentStore,
): Promise<RefreshResult> {
  const state = await store.loadState(registry.registryId);
  const head = await rpc.getFinalizedHeadSlot();
  const signatures = await rpc.getSignaturesForAddress(registry.configAddress, state.lastSignature);
  // Oldest first, so a failure part-way through never records a newer
  // `lastSignature` than the events actually applied.
  const ordered = [...signatures].reverse();
  let applied = 0;
  let newest = state.lastSignature;
  for (const record of ordered) {
    const transaction = await rpc.getTransactionLogs(record.signature);
    if (transaction === null) throw new Error(`finalized transaction ${record.signature} is unavailable`);
    if (!transaction.failed) {
      for (const event of incidentEventsFromLogs(transaction.logs, registry.configBytes)) {
        await applyEvent(store, registry, event, transaction.slot);
        applied += 1;
      }
    }
    newest = record.signature;
    await store.saveState(registry.registryId, {
      indexedThroughSlot: state.indexedThroughSlot,
      lastSignature: newest,
    });
  }
  const indexedThroughSlot = head > state.indexedThroughSlot ? head : state.indexedThroughSlot;
  await store.saveState(registry.registryId, { indexedThroughSlot, lastSignature: newest });
  return { indexedThroughSlot, scannedSignatures: ordered.length, appliedEvents: applied };
}
