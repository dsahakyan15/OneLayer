// Chain adapter for the workflow publisher (ticket 09).
//
// Every read that feeds a publication decision is finalized and carries a
// context slot. Reads take `minContextSlot`, so a lagging or load-balanced RPC
// node fails the read instead of answering from an older state; responses
// whose context slot is below the requested minimum are rejected as well.
import {
  DAILY_ANCHOR_LEDGER_SEGMENT_DISCRIMINATOR,
  getDailyAnchorLedgerSegmentDecoder,
  getDailyAnchorLedgerSegmentSize,
  getRegistryConfigDecoder,
  getRegistryConfigSize,
  REGISTRY_CONFIG_DISCRIMINATOR,
  type DailyAnchorLedgerSegment,
  type RegistryConfig,
} from "../../../packages/onchain-client/src/index.ts";
import { SolanaPublisherRpc, type LatestBlockhash, type SimulationResult } from "./solana-rpc.ts";

export class ChainReadError extends Error {
  constructor(public code: string) { super(code); }
}

export interface ChainRead<T> { value: T; contextSlot: bigint }
export interface SignatureStatus { slot: bigint; finalized: boolean; failed: boolean }
export interface FinalizedBlock { slot: bigint; blockHeight: bigint; blockTime: bigint }

/** What the publisher needs from the chain; tests inject a fake. */
export interface PublicationChain {
  /** Genesis hash of the connected node. The publisher compares it with the
   * pinned expected identity before reserving or signing anything (M4); a
   * failure or mismatch fails closed. */
  genesisHash(): Promise<string>;
  /** Finalized slot of a node that has reached at least `minContextSlot`. */
  finalizedSlot(minContextSlot: bigint): Promise<bigint>;
  /** Height and block time of the finalized block at exactly `slot`. */
  finalizedBlock(slot: bigint): Promise<FinalizedBlock>;
  registryConfig(address: string, minContextSlot: bigint): Promise<ChainRead<RegistryConfig | null>>;
  ledgerSegment(address: string, minContextSlot: bigint): Promise<ChainRead<DailyAnchorLedgerSegment | null>>;
  latestBlockhash(minContextSlot: bigint): Promise<LatestBlockhash>;
  /** Quoted fee (lamports) for an unsigned compiled message. A quote is
   * mandatory before reserving an attempt: the publisher fails closed when the
   * chain cannot provide one. */
  feeForMessage(messageBase64: string): Promise<bigint>;
  /** Statuses with `searchTransactionHistory: true`; context slot of the answer. */
  signatureStatuses(signatures: readonly string[]): Promise<ChainRead<Array<SignatureStatus | null>>>;
  simulate(transactionBase64: string): Promise<SimulationResult>;
  send(transactionBase64: string): Promise<string>;
}

const safeSlot = (slot: bigint) => {
  if (slot < 0n || slot > BigInt(Number.MAX_SAFE_INTEGER)) throw new ChainReadError("RPC_RESPONSE_INVALID");
  return Number(slot);
};

export class PublicationRpc extends SolanaPublisherRpc implements PublicationChain {
  private readonly owner: string;
  constructor(rpcUrl: string, programId: string, request: typeof fetch = fetch) {
    super(rpcUrl, programId, request);
    this.owner = programId;
  }

  private contextOf(response: any, minimum: bigint): bigint {
    const slot = response?.context?.slot;
    if (!Number.isSafeInteger(slot) || slot < 0) throw new ChainReadError("RPC_RESPONSE_INVALID");
    if (BigInt(slot) < minimum) throw new ChainReadError("RPC_CONTEXT_STALE");
    return BigInt(slot);
  }

  /** `getGenesisHash` of the configured RPC. The caller compares it with the
   * out-of-band expected identity; this adapter never trusts its own URL. */
  async genesisHash(): Promise<string> {
    const value = await this.rpc("getGenesisHash", []);
    if (typeof value !== "string" || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)) throw new ChainReadError("RPC_RESPONSE_INVALID");
    return value;
  }

  private async account(address: string, minContextSlot: bigint, discriminator: ArrayLike<number>, size: number): Promise<ChainRead<Uint8Array | null>> {
    const response = await this.rpc("getAccountInfo", [address, { commitment: "finalized", encoding: "base64", minContextSlot: safeSlot(minContextSlot) }]) as any;
    const contextSlot = this.contextOf(response, minContextSlot);
    const value = response?.value;
    if (value === null || value === undefined) return { value: null, contextSlot };
    if (value.owner !== this.owner || !Array.isArray(value.data) || value.data[1] !== "base64" || typeof value.data[0] !== "string") {
      throw new ChainReadError("RPC_RESPONSE_INVALID");
    }
    const bytes = new Uint8Array(Buffer.from(value.data[0], "base64"));
    if (bytes.length !== size || !Buffer.from(discriminator).equals(Buffer.from(bytes.subarray(0, 8)))) throw new ChainReadError("RPC_RESPONSE_INVALID");
    return { value: bytes, contextSlot };
  }

  async finalizedSlot(minContextSlot: bigint): Promise<bigint> {
    const slot = await this.rpc("getSlot", [{ commitment: "finalized", minContextSlot: safeSlot(minContextSlot) }]);
    if (typeof slot !== "number" || !Number.isSafeInteger(slot) || BigInt(slot) < minContextSlot) throw new ChainReadError("RPC_CONTEXT_STALE");
    return BigInt(slot);
  }

  async finalizedBlock(slot: bigint): Promise<FinalizedBlock> {
    const block = await this.rpc("getBlock", [safeSlot(slot), { commitment: "finalized", transactionDetails: "none", rewards: false, maxSupportedTransactionVersion: 0 }]) as any;
    if (!Number.isSafeInteger(block?.blockHeight) || !Number.isSafeInteger(block?.blockTime)) throw new ChainReadError("RPC_RESPONSE_INVALID");
    return { slot, blockHeight: BigInt(block.blockHeight), blockTime: BigInt(block.blockTime) };
  }

  async registryConfig(address: string, minContextSlot: bigint): Promise<ChainRead<RegistryConfig | null>> {
    const read = await this.account(address, minContextSlot, REGISTRY_CONFIG_DISCRIMINATOR, getRegistryConfigSize());
    return { value: read.value && getRegistryConfigDecoder().decode(read.value), contextSlot: read.contextSlot };
  }

  async ledgerSegment(address: string, minContextSlot: bigint): Promise<ChainRead<DailyAnchorLedgerSegment | null>> {
    const read = await this.account(address, minContextSlot, DAILY_ANCHOR_LEDGER_SEGMENT_DISCRIMINATOR, getDailyAnchorLedgerSegmentSize());
    return { value: read.value && getDailyAnchorLedgerSegmentDecoder().decode(read.value), contextSlot: read.contextSlot };
  }

  async latestBlockhash(minContextSlot: bigint): Promise<LatestBlockhash> {
    const response = await this.rpc("getLatestBlockhash", [{ commitment: "finalized", minContextSlot: safeSlot(minContextSlot) }]) as any;
    this.contextOf(response, minContextSlot);
    if (typeof response?.value?.blockhash !== "string" || !Number.isSafeInteger(response?.value?.lastValidBlockHeight)) throw new ChainReadError("RPC_RESPONSE_INVALID");
    return { blockhash: response.value.blockhash, lastValidBlockHeight: BigInt(response.value.lastValidBlockHeight) };
  }

  /** `getFeeForMessage` on the reserved unsigned message. A null result (e.g. an
   * unknown blockhash) or an invalid shape is unavailability, not a fee of 0:
   * the publisher must fail closed rather than reserve an unbounded attempt. */
  async feeForMessage(messageBase64: string): Promise<bigint> {
    const response = await this.rpc("getFeeForMessage", [messageBase64, { commitment: "finalized" }]) as any;
    const value = response?.value;
    if (value === null || value === undefined) throw new ChainReadError("FEE_QUOTE_UNAVAILABLE");
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new ChainReadError("RPC_RESPONSE_INVALID");
    return BigInt(value);
  }

  async signatureStatuses(signatures: readonly string[]): Promise<ChainRead<Array<SignatureStatus | null>>> {
    if (signatures.length === 0 || signatures.length > 256) throw new ChainReadError("RPC_REQUEST_INVALID");
    const response = await this.rpc("getSignatureStatuses", [signatures, { searchTransactionHistory: true }]) as any;
    const contextSlot = this.contextOf(response, 0n);
    if (!Array.isArray(response?.value) || response.value.length !== signatures.length) throw new ChainReadError("RPC_RESPONSE_INVALID");
    return {
      contextSlot,
      value: response.value.map((status: any) => {
        if (status === null) return null;
        if (!Number.isSafeInteger(status?.slot)) throw new ChainReadError("RPC_RESPONSE_INVALID");
        return { slot: BigInt(status.slot), finalized: status.confirmationStatus === "finalized", failed: status.err !== null && status.err !== undefined };
      }),
    };
  }
}

/** Full-history source for ADR-0009 reconciliation: an archival RPC, never the
 * primary publisher RPC with its recent status cache. `transaction() === null`
 * is evidence of absence only inside [historyFromSlot, finalizedSlot] of this
 * archive; the publisher also requires the attempt's blockhash to have expired
 * by finalized height at a slot the archive has reached. */
export interface ArchivalChain {
  /** Stable reference to the archive used, recorded with the evidence. */
  readonly archiveId: string;
  /** Lowest slot covered by a trusted complete-history contract; null when
   * completeness cannot be established. A first available block is insufficient. */
  historyFromSlot(): Promise<bigint | null>;
  /** Highest finalized slot the archive has ingested. */
  finalizedSlot(): Promise<bigint>;
  /** Finalized transaction by signature over full history; null when absent. */
  transaction(signature: string): Promise<{ slot: bigint; failed: boolean } | null>;
}

/** Historical lookups over JSON-RPC. Positive finalized results are usable;
 * null results remain inconclusive without a separate completeness contract. */
export class ArchivalRpc extends SolanaPublisherRpc implements ArchivalChain {
  constructor(rpcUrl: string, programId: string, readonly archiveId: string, request: typeof fetch = fetch) {
    super(rpcUrl, programId, request);
  }
  async historyFromSlot(): Promise<null> {
    // Standard JSON-RPC exposes no guarantee of gap-free transaction history.
    // Even a low getFirstAvailableBlock plus a current finalized tip cannot
    // prove that a missing signature never landed. A provider-specific trusted
    // ArchivalChain adapter must supply that stronger contract for cancellation.
    return null;
  }
  async finalizedSlot(): Promise<bigint> {
    const slot = await this.rpc("getSlot", [{ commitment: "finalized" }]);
    if (typeof slot !== "number" || !Number.isSafeInteger(slot) || slot < 0) throw new ChainReadError("RPC_RESPONSE_INVALID");
    return BigInt(slot);
  }
  async transaction(signature: string): Promise<{ slot: bigint; failed: boolean } | null> {
    const result = await this.rpc("getTransaction", [signature, { commitment: "finalized", maxSupportedTransactionVersion: 0, encoding: "base64" }]) as any;
    if (result === null) return null;
    if (!Number.isSafeInteger(result?.slot) || result.meta == null) throw new ChainReadError("RPC_RESPONSE_INVALID");
    return { slot: BigInt(result.slot), failed: result.meta.err !== null && result.meta.err !== undefined };
  }
}

/** Separate historical endpoint configuration. URL and ID do not attest
 * complete history: missing signatures still cannot authorize cancellation.
 * `ONELAYER_ARCHIVAL_RPC_URL` and `ONELAYER_ARCHIVAL_RPC_ID` (the
 * stable reference recorded in evidence). */
export function archivalRpcFromEnv(env: Record<string, string | undefined>, primaryRpcUrl: string, programId: string, request: typeof fetch = fetch): ArchivalRpc {
  const url = env.ONELAYER_ARCHIVAL_RPC_URL?.trim();
  const id = env.ONELAYER_ARCHIVAL_RPC_ID?.trim();
  if (!url || !id) throw new ChainReadError("ARCHIVAL_RPC_NOT_CONFIGURED");
  let parsed: URL, primary: URL | null = null;
  try { parsed = new URL(url); } catch { throw new ChainReadError("ARCHIVAL_RPC_NOT_CONFIGURED"); }
  try { primary = new URL(primaryRpcUrl); } catch { primary = null; }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new ChainReadError("ARCHIVAL_RPC_NOT_CONFIGURED");
  if (primary && parsed.origin === primary.origin && parsed.pathname === primary.pathname) throw new ChainReadError("ARCHIVAL_RPC_SAME_AS_PRIMARY");
  if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(id)) throw new ChainReadError("ARCHIVAL_RPC_NOT_CONFIGURED");
  return new ArchivalRpc(url, programId, id, request);
}
