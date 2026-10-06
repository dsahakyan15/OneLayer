import {
  getDailyAnchorLedgerSegmentDecoder,
  getRegistryConfigDecoder,
  getIncidentNoticeDecoder,
  findIncidentNoticePda,
  REGISTRY_CONFIG_DISCRIMINATOR,
  INCIDENT_NOTICE_DISCRIMINATOR,
  type DailyAnchorLedgerSegment,
  type RegistryConfig,
} from "../../../packages/onchain-client/src/index.ts";
import { address } from "@solana/kit";
import { registryIdHash } from "../../../packages/canonical-ts/src/index.ts";
import type { IncidentRpc, IncidentSnapshot, RegistryBinding, SignatureRecord, TransactionLogs } from "./incident-index.ts";

interface JsonRpcResponse {
  result?: unknown;
  error?: { message?: unknown };
}

const SIGNATURE_PAGE = 100;

export class SolanaIncidentRpc implements IncidentRpc {
  private readonly rpcUrl: string;
  private readonly request: typeof fetch;
  private id = 0;

  constructor(rpcUrl: string, request: typeof fetch = fetch) {
    this.rpcUrl = rpcUrl;
    this.request = request;
  }

  protected async rpc(method: string, params: unknown[]): Promise<unknown> {
    const response = await this.request(this.rpcUrl, {
      method: "POST",
      signal: AbortSignal.timeout(15_000),
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++this.id, method, params }),
    });
    if (!response.ok) throw new Error(`${method} failed with HTTP ${response.status}`);
    const payload = await response.json() as JsonRpcResponse;
    if (payload.error !== undefined) throw new Error(`${method} failed: ${String(payload.error.message ?? "unknown")}`);
    if (payload.result === undefined) throw new TypeError(`${method} returned no result`);
    return payload.result;
  }

  async getFinalizedHeadSlot(): Promise<bigint> {
    const result = await this.rpc("getSlot", [{ commitment: "finalized" }]);
    if (typeof result !== "number" || !Number.isSafeInteger(result) || result < 0) {
      throw new TypeError("finalized head slot is invalid");
    }
    return BigInt(result);
  }

  async getIncidentSnapshot(registry: RegistryBinding, minContextSlot: bigint): Promise<IncidentSnapshot> {
    const contextSlot = (response: any, minimum: bigint): bigint => {
      const value = response?.context?.slot;
      if (!Number.isSafeInteger(value) || value < 0 || BigInt(value) < minimum) throw new Error("incident account context is stale or invalid");
      return BigInt(value);
    };
    const accountBytes = (account: any, discriminator: ArrayLike<number>, size: number): Uint8Array => {
      if (account?.owner !== registry.programId || !Array.isArray(account.data) || account.data[1] !== "base64" || typeof account.data[0] !== "string") throw new Error("invalid incident account owner or encoding");
      const bytes = Buffer.from(account.data[0], "base64");
      if (bytes.length !== size || !Buffer.from(discriminator).equals(bytes.subarray(0, 8))) throw new Error("invalid incident account discriminator or size");
      return bytes;
    };
    if (minContextSlot < 0n || minContextSlot > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("invalid incident context slot");
    const configResponse = await this.rpc("getAccountInfo", [registry.configAddress, { commitment: "finalized", encoding: "base64", minContextSlot: Number(minContextSlot) }]) as any;
    const slot = contextSlot(configResponse, minContextSlot);
    const config = getRegistryConfigDecoder().decode(accountBytes(configResponse?.value, REGISTRY_CONFIG_DISCRIMINATOR, 277));
    if (config.version !== 1 || !Buffer.from(config.registryIdHash).equals(Buffer.from(registryIdHash(registry.registryId)))) throw new Error("incident registry binding mismatch");
    const notices: IncidentSnapshot["notices"] = [];
    for (let offset = 0n; offset < config.incidentCount; offset += 100n) {
      const count = Number(config.incidentCount - offset < 100n ? config.incidentCount - offset : 100n);
      const pdas = await Promise.all(Array.from({ length: count }, (_, index) => findIncidentNoticePda({ config: address(registry.configAddress), incidentSequence: offset + BigInt(index) }, { programAddress: address(registry.programId) })));
      const response = await this.rpc("getMultipleAccounts", [pdas.map(([pda]) => pda), { commitment: "finalized", encoding: "base64", minContextSlot: Number(slot) }]) as any;
      contextSlot(response, slot);
      if (!Array.isArray(response.value) || response.value.length !== count) throw new Error("incident account set is incomplete");
      for (let index = 0; index < count; index += 1) {
        const notice = getIncidentNoticeDecoder().decode(accountBytes(response.value[index], INCIDENT_NOTICE_DISCRIMINATOR, 181));
        const status = ({ 1: "OPEN", 2: "CONFIRMED", 3: "FALSE_POSITIVE", 4: "RESOLVED" } as const)[notice.status as 1 | 2 | 3 | 4];
        if (notice.version !== 1 || notice.registry !== registry.configAddress || notice.incidentSequence !== offset + BigInt(index) || notice.bump !== pdas[index][1] || !status || notice.lastSuspectBatch < notice.firstSuspectBatch) throw new Error("incident account binding mismatch");
        notices.push({ incidentSequence: notice.incidentSequence, firstSuspectBatch: notice.firstSuspectBatch, lastSuspectBatch: notice.lastSuspectBatch, incidentType: notice.incidentType, status });
      }
    }
    return { incidentCount: config.incidentCount, notices };
  }

  async getSignaturesForAddress(address: string, until: string | null): Promise<SignatureRecord[]> {
    const collected: SignatureRecord[] = [];
    const seen = new Set<string>();
    let before: string | undefined;
    for (;;) {
      const options = { commitment: "finalized", limit: SIGNATURE_PAGE, ...(before ? { before } : {}) };
      const result = await this.rpc("getSignaturesForAddress", [address, options]);
      if (!Array.isArray(result)) throw new TypeError("signature list is invalid");
      if (result.length === 0) {
        if (until !== null) throw new Error("incident history cursor is unavailable; history may be pruned");
        return collected;
      }
      for (const entry of result) {
        if (typeof entry?.signature !== "string" || !entry.signature ||
            !Number.isSafeInteger(entry?.slot) || entry.slot < 0) {
          throw new TypeError("signature entry is invalid");
        }
        if (entry.signature === until) return collected;
        if (seen.has(entry.signature)) throw new Error("incident signature pagination did not advance");
        const slot = BigInt(entry.slot);
        if (collected.length && slot > collected[collected.length - 1].slot) {
          throw new Error("incident signatures are not newest-first");
        }
        seen.add(entry.signature);
        collected.push({ signature: entry.signature, slot });
      }
      before = collected[collected.length - 1].signature;
    }
  }

  async getTransactionLogs(signature: string): Promise<TransactionLogs | null> {
    const result = await this.rpc("getTransaction", [
      signature,
      { commitment: "finalized", maxSupportedTransactionVersion: 0 },
    ]) as any;
    if (result === null) return null;
    if (!Number.isSafeInteger(result.slot) || result.slot < 0) throw new TypeError("transaction slot is invalid");
    if (result.meta == null || !("err" in result.meta)) throw new TypeError("transaction metadata is unavailable");
    const logs: unknown = result.meta.logMessages;
    if (!Array.isArray(logs) || logs.some((line) => typeof line !== "string")) {
      throw new TypeError("transaction logs are invalid");
    }
    return {
      slot: BigInt(result.slot),
      logs: logs as string[],
      failed: result.meta?.err !== null && result.meta?.err !== undefined,
    };
  }
}

export interface LatestBlockhash {
  blockhash: string;
  lastValidBlockHeight: bigint;
}

export interface SimulationResult {
  ok: boolean;
  error: string | null;
  logs: string[];
  unitsConsumed: number | null;
}

export interface FinalizedTransaction {
  slot: bigint;
  failed: boolean;
}

/**
 * Read and write access used by the browser publish flow. Account data is
 * decoded with the generated codecs after owner and discriminator checks — RPC
 * responses are never trusted by shape alone (§5.4).
 */
export class SolanaPublisherRpc extends SolanaIncidentRpc {
  private readonly programId: string;

  constructor(rpcUrl: string, programId: string, request: typeof fetch = fetch) {
    super(rpcUrl, request);
    this.programId = programId;
  }

  private async accountData(address: string): Promise<Uint8Array | null> {
    const result = await this.rpc("getAccountInfo", [
      address,
      { commitment: "finalized", encoding: "base64" },
    ]) as any;
    if (result?.value === null || result?.value === undefined) return null;
    if (result.value.owner !== this.programId) throw new TypeError("RPC_RESPONSE_INVALID: unexpected account owner");
    const encoded: unknown = result.value.data;
    if (!Array.isArray(encoded) || encoded[1] !== "base64" || typeof encoded[0] !== "string") {
      throw new TypeError("RPC_RESPONSE_INVALID: unexpected account encoding");
    }
    return new Uint8Array(Buffer.from(encoded[0], "base64"));
  }

  async getRegistryConfig(address: string): Promise<RegistryConfig | null> {
    const data = await this.accountData(address);
    return data === null ? null : getRegistryConfigDecoder().decode(data);
  }

  async getLedgerSegment(address: string): Promise<DailyAnchorLedgerSegment | null> {
    const data = await this.accountData(address);
    return data === null ? null : getDailyAnchorLedgerSegmentDecoder().decode(data);
  }

  async getLatestBlockhash(): Promise<LatestBlockhash> {
    const result = await this.rpc("getLatestBlockhash", [{ commitment: "finalized" }]) as any;
    if (typeof result?.value?.blockhash !== "string" || typeof result?.value?.lastValidBlockHeight !== "number") {
      throw new TypeError("RPC_RESPONSE_INVALID: latest blockhash");
    }
    return {
      blockhash: result.value.blockhash,
      lastValidBlockHeight: BigInt(result.value.lastValidBlockHeight),
    };
  }

  async getBlockHeight(): Promise<bigint> {
    const result = await this.rpc("getBlockHeight", [{ commitment: "finalized" }]);
    if (typeof result !== "number") throw new TypeError("RPC_RESPONSE_INVALID: block height");
    return BigInt(result);
  }

  async simulate(transactionBase64: string): Promise<SimulationResult> {
    const result = await this.rpc("simulateTransaction", [
      transactionBase64,
      { commitment: "finalized", encoding: "base64", sigVerify: false, replaceRecentBlockhash: false },
    ]) as any;
    const logs: unknown = result?.value?.logs ?? [];
    return {
      ok: result?.value?.err === null || result?.value?.err === undefined,
      error: result?.value?.err == null ? null : JSON.stringify(result.value.err),
      logs: Array.isArray(logs) ? logs.filter((line): line is string => typeof line === "string") : [],
      unitsConsumed: typeof result?.value?.unitsConsumed === "number" ? result.value.unitsConsumed : null,
    };
  }

  async send(transactionBase64: string): Promise<string> {
    const result = await this.rpc("sendTransaction", [
      transactionBase64,
      { encoding: "base64", preflightCommitment: "finalized", maxRetries: 3 },
    ]);
    if (typeof result !== "string") throw new TypeError("RPC_RESPONSE_INVALID: send transaction");
    return result;
  }

  async getFinalizedTransaction(signature: string): Promise<FinalizedTransaction | null> {
    const logs = await this.getTransactionLogs(signature);
    return logs === null ? null : { slot: logs.slot, failed: logs.failed };
  }
}
