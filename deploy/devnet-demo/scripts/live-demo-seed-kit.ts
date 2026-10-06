// Shared runtime plumbing for the live-demo seed (B4).
//
// This directory deliberately carries no package manifest: `@solana/kit` is
// resolved through the demo-api package that declares it (7.0.0, pinned), so
// the seed scripts stay deploy-side while every dependency keeps exactly one
// installed copy. Types come from the same package via erased type-only
// imports; key material is only ever touched through the accepted A1 loader.
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { randomBytes, sign as ed25519Sign } from "node:crypto";
import type * as Kit from "@solana/kit";
import {
  defaultKeyFile,
  KeyStoreError,
  loadSigningKey,
  type KeyStoreOptions,
} from "../../../apps/demo-api/scripts/live-demo-key-store.ts";

export const kit = createRequire(
  fileURLToPath(new URL("../../../apps/demo-api/package.json", import.meta.url)),
)("@solana/kit") as typeof Kit;

export type Address = Kit.Address;
export const toAddress = kit.address;

export class SeedRefusal extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

export interface SeedSigner {
  /** Public address only; key bytes never leave the A1 loader. */
  address: string;
  sign(messageBytes: Uint8Array): Uint8Array;
}

export async function loadSeedSigner(
  keyFile?: string,
  options?: KeyStoreOptions,
): Promise<SeedSigner> {
  try {
    const loaded = await loadSigningKey(keyFile ?? defaultKeyFile(options), options);
    return {
      address: String(loaded.address),
      sign: (messageBytes: Uint8Array): Uint8Array =>
        new Uint8Array(ed25519Sign(null, Buffer.from(messageBytes), loaded.privateKey)),
    };
  } catch (error) {
    if (error instanceof KeyStoreError) throw new SeedRefusal(error.code);
    throw error;
  }
}

export interface SeedAccount {
  owner: string;
  data: Uint8Array;
}

export interface SeedChainReader {
  getGenesisHash(): Promise<string>;
  getHealth(): Promise<string>;
  getAccountInfo(account: string): Promise<SeedAccount | null>;
  getBalanceLamports(account: string): Promise<bigint>;
  getMinimumBalanceForRentExemption(dataLength: number): Promise<bigint>;
}

export interface SeedChain extends SeedChainReader {
  getLatestBlockhash(): Promise<{ blockhash: string; lastValidBlockHeight: bigint }>;
  sendTransaction(transactionBase64: string): Promise<string>;
  getSignatureStatuses(
    signatures: string[],
  ): Promise<Array<{ confirmationStatus?: string; err?: unknown } | null>>;
  requestAirdrop(address: string, lamports: bigint): Promise<string>;
}

export const MAX_HTTP_BODY_BYTES = 262_144;
export const RPC_TIMEOUT_MS = 15_000;

async function readBodyBounded(response: Response): Promise<string> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const size = Number(declared);
    if (Number.isFinite(size) && size > MAX_HTTP_BODY_BYTES) throw new SeedRefusal("HTTP_BODY_TOO_LARGE");
  }
  const body = response.body;
  if (body === null) return "";
  const reader = body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.byteLength;
      if (total > MAX_HTTP_BODY_BYTES) throw new SeedRefusal("HTTP_BODY_TOO_LARGE");
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    if (error instanceof SeedRefusal) throw error;
    throw new SeedRefusal("RPC_UNREACHABLE");
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** Loopback-only service URL policy (ADR-0006); the chain RPC may leave the host. */
export function requireServiceUrl(value: string, label: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new SeedRefusal("REQUEST_INVALID");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new SeedRefusal("REQUEST_INVALID");
  if (parsed.username !== "" || parsed.password !== "" || parsed.hash !== "") throw new SeedRefusal("REQUEST_INVALID");
  if (label !== "rpcUrl" && parsed.hostname !== "127.0.0.1" && parsed.hostname !== "localhost") {
    throw new SeedRefusal("LINK_REFUSED");
  }
  return parsed;
}

type JsonRpcResponse = { result?: unknown; error?: unknown };

/**
 * Bounded JSON-RPC reader/writer for the seed. Every mutation goes through
 * `sendTransaction`/`requestAirdrop` only after the executor's rechecks, and
 * every response body is size-capped like the A2 probe's.
 */
export class JsonRpcSeedChain implements SeedChain {
  private readonly rpcUrl: string;
  private readonly request: typeof fetch;
  private id = 0;

  constructor(rpcUrl: string, request: typeof fetch = fetch) {
    this.rpcUrl = requireServiceUrl(rpcUrl, "rpcUrl").toString();
    this.request = request;
  }

  private async rpc(method: string, params: unknown[]): Promise<unknown> {
    let response: Response;
    try {
      response = await this.request(this.rpcUrl, {
        method: "POST",
        signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: ++this.id, method, params }),
      });
    } catch {
      throw new SeedRefusal("RPC_UNREACHABLE");
    }
    if (!response.ok) throw new SeedRefusal("RPC_UNREACHABLE");
    const text = await readBodyBounded(response);
    let payload: JsonRpcResponse;
    try {
      payload = JSON.parse(text) as JsonRpcResponse;
    } catch {
      throw new SeedRefusal("RPC_UNREACHABLE");
    }
    if (payload.error !== undefined) throw new SeedRefusal("RPC_UNREACHABLE");
    if (payload.result === undefined) throw new TypeError(`${method} returned no result`);
    return payload.result;
  }

  async getHealth(): Promise<string> {
    const result = await this.rpc("getHealth", []);
    if (typeof result !== "string") throw new TypeError("health is invalid");
    return result;
  }

  async getGenesisHash(): Promise<string> {
    const result = await this.rpc("getGenesisHash", []);
    if (typeof result !== "string" || result.length === 0) throw new TypeError("genesis hash is invalid");
    return result;
  }

  async getAccountInfo(account: string): Promise<SeedAccount | null> {
    const result = (await this.rpc("getAccountInfo", [account, { encoding: "base64", commitment: "finalized" }])) as {
      value?: { owner?: unknown; data?: unknown } | null;
    };
    const value = result?.value;
    if (value === null || value === undefined) return null;
    const [encoded, encoding] = Array.isArray(value.data) ? value.data : [];
    if (typeof value.owner !== "string" || typeof encoded !== "string" || encoding !== "base64") {
      throw new TypeError("account info is invalid");
    }
    return { owner: value.owner, data: new Uint8Array(Buffer.from(encoded, "base64")) };
  }

  async getBalanceLamports(account: string): Promise<bigint> {
    const result = (await this.rpc("getBalance", [account, { commitment: "finalized" }])) as { value?: unknown };
    if (typeof result?.value !== "number" || !Number.isSafeInteger(result.value) || result.value < 0) {
      throw new TypeError("balance is invalid");
    }
    return BigInt(result.value);
  }

  async getMinimumBalanceForRentExemption(dataLength: number): Promise<bigint> {
    const result = await this.rpc("getMinimumBalanceForRentExemption", [dataLength]);
    if (typeof result !== "number" || !Number.isSafeInteger(result) || result < 0) {
      throw new TypeError("rent exemption is invalid");
    }
    return BigInt(result);
  }

  async getLatestBlockhash(): Promise<{ blockhash: string; lastValidBlockHeight: bigint }> {
    const result = (await this.rpc("getLatestBlockhash", [{ commitment: "confirmed" }])) as {
      value?: { blockhash?: unknown; lastValidBlockHeight?: unknown };
    };
    const value = result?.value;
    if (
      typeof value?.blockhash !== "string" ||
      value.blockhash.length === 0 ||
      typeof value.lastValidBlockHeight !== "number" ||
      !Number.isSafeInteger(value.lastValidBlockHeight)
    ) {
      throw new TypeError("blockhash is invalid");
    }
    return { blockhash: value.blockhash, lastValidBlockHeight: BigInt(value.lastValidBlockHeight) };
  }

  async sendTransaction(transactionBase64: string): Promise<string> {
    const result = await this.rpc("sendTransaction", [
      transactionBase64,
      { encoding: "base64", skipPreflight: false, preflightCommitment: "confirmed" },
    ]);
    if (typeof result !== "string" || result.length === 0) throw new TypeError("signature is invalid");
    return result;
  }

  async getSignatureStatuses(
    signatures: string[],
  ): Promise<Array<{ confirmationStatus?: string; err?: unknown } | null>> {
    const result = (await this.rpc("getSignatureStatuses", [signatures, { searchTransactionHistory: false }])) as {
      value?: unknown;
    };
    if (!Array.isArray(result?.value)) throw new TypeError("signature statuses are invalid");
    return result.value as Array<{ confirmationStatus?: string; err?: unknown } | null>;
  }

  async requestAirdrop(address: string, lamports: bigint): Promise<string> {
    if (lamports <= 0n || lamports > 0xffff_ffff_ffff_ffffn) throw new SeedRefusal("REQUEST_INVALID");
    const result = await this.rpc("requestAirdrop", [address, Number(lamports)]);
    if (typeof result !== "string" || result.length === 0) throw new SeedRefusal("FUNDING_UNAVAILABLE");
    return result;
  }
}

export const CONFIRMATION_POLL_MS = 250;
export const CONFIRMATION_ATTEMPTS = 120;

export async function waitFinalized(
  chain: SeedChain,
  signature: string,
  attempts: number = CONFIRMATION_ATTEMPTS,
  pollMs: number = CONFIRMATION_POLL_MS,
): Promise<void> {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const statuses = await chain.getSignatureStatuses([signature]);
    const status = statuses[0] ?? null;
    if (status !== null) {
      if (status.err !== null && status.err !== undefined) throw new SeedRefusal("TRANSACTION_FAILED");
      if (status.confirmationStatus === "finalized") return;
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  throw new SeedRefusal("TRANSACTION_TIMEOUT");
}

export function randomIdempotencyKey(): string {
  return randomBytes(18).toString("base64url");
}

export function assertRecordId(value: string): string {
  if (!/^SYNTHETIC-[1-9][0-9]*$/.test(value)) throw new SeedRefusal("REQUEST_INVALID");
  return value;
}

export function assertCertificateId(value: string): string {
  if (!/^[0-9a-f]{32}$/.test(value)) throw new SeedRefusal("REQUEST_INVALID");
  return value;
}

export function assertHex64(value: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new SeedRefusal("REQUEST_INVALID");
  return new Uint8Array(Buffer.from(value, "hex"));
}

export function isBase58Address(value: string): boolean {
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value);
}
