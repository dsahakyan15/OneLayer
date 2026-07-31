import { decodeLedgerSegment, findAnchorEntry } from "../../verifier/src/solana-account.ts";
import type { Hash } from "../../../packages/merkle-ts/src/index.ts";

export interface AnchoredManifestReference {
  programId: string;
  segmentPda: string;
  batchSequence: bigint;
  transactionSignature?: string;
  anchorSlot?: bigint;
}

export interface DirectAnchorObservation {
  registryVersion: bigint;
  merkleRoot: Hash;
  manifestHash: Hash;
  observedThroughSlot: bigint;
}

type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export class SolanaAnchorSource {
  private readonly rpcUrl: string;
  private readonly request: Fetch;
  private requestId = 0;

  constructor(rpcUrl: string, request: Fetch = fetch) {
    this.rpcUrl = rpcUrl;
    this.request = request;
  }

  private async rpc(method: string, params: unknown[]): Promise<any> {
    const response = await this.request(this.rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++this.requestId, method, params }),
    });
    if (!response.ok) throw new TypeError(`Solana RPC HTTP ${response.status}`);
    const body: any = await response.json();
    if (body.error !== undefined || body.result === undefined) throw new TypeError("Solana RPC response is invalid");
    return body.result;
  }

  async getAnchor(reference: AnchoredManifestReference): Promise<DirectAnchorObservation> {
    const account = await this.rpc("getAccountInfo", [reference.segmentPda, { commitment: "finalized", encoding: "base64" }]);
    if (account.value === null || account.value.owner !== reference.programId || !Array.isArray(account.value.data) || account.value.data[1] !== "base64") {
      throw new TypeError("finalized ledger account is invalid");
    }
    const segment = decodeLedgerSegment(Buffer.from(account.value.data[0], "base64"));
    const entry = findAnchorEntry(segment, reference.batchSequence);
    if ((reference.transactionSignature === undefined) !== (reference.anchorSlot === undefined)) {
      throw new TypeError("transaction signature and anchor slot must be provided together");
    }
    if (reference.transactionSignature !== undefined && reference.anchorSlot !== undefined) {
      const transaction = await this.rpc("getTransaction", [reference.transactionSignature, { commitment: "finalized", maxSupportedTransactionVersion: 0 }]);
      if (transaction === null || BigInt(transaction.slot) !== reference.anchorSlot || transaction.meta?.err !== null) {
        throw new TypeError("finalized anchor transaction is invalid");
      }
    }
    return {
      registryVersion: entry.registryVersion,
      merkleRoot: entry.merkleRoot,
      manifestHash: entry.manifestHash,
      observedThroughSlot: BigInt(account.context.slot),
    };
  }
}
