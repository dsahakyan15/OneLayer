import {
  getDailyAnchorLedgerSegmentDecoder,
  getRegistryConfigDecoder,
  type DailyAnchorLedgerSegment,
  type RegistryConfig,
} from "../../../packages/onchain-client/src/index.ts";
import type { IncidentRpc, SignatureRecord, TransactionLogs } from "./incident-index.ts";

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

  async getSignaturesForAddress(address: string, until: string | null): Promise<SignatureRecord[]> {
    const options: Record<string, unknown> = { commitment: "finalized", limit: SIGNATURE_PAGE };
    if (until !== null) options.until = until;
    const result = await this.rpc("getSignaturesForAddress", [address, options]);
    if (!Array.isArray(result)) throw new TypeError("signature list is invalid");
    return result.map((entry: any) => {
      if (typeof entry?.signature !== "string" || typeof entry?.slot !== "number") {
        throw new TypeError("signature entry is invalid");
      }
      return { signature: entry.signature, slot: BigInt(entry.slot) };
    });
  }

  async getTransactionLogs(signature: string): Promise<TransactionLogs | null> {
    const result = await this.rpc("getTransaction", [
      signature,
      { commitment: "finalized", maxSupportedTransactionVersion: 0 },
    ]) as any;
    if (result === null) return null;
    if (typeof result.slot !== "number") throw new TypeError("transaction slot is invalid");
    const logs: unknown = result.meta?.logMessages ?? [];
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
