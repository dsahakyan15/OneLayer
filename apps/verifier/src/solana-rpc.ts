import {
  createSolanaRpc,
  getAddressDecoder,
  getAddressEncoder,
  getBase58Decoder,
  getProgramDerivedAddress,
  signature,
} from "@solana/kit";
import { registryIdHash } from "../../../packages/canonical-ts/src/index.ts";
import {
  findRegistryConfigPda,
  getRegistryConfigDecoder,
} from "../../../packages/onchain-client/src/index.ts";
import type { CertificateBody } from "../../../packages/canonical-ts/src/index.ts";
import { decodeLedgerSegment, findAnchorEntry } from "./solana-account.ts";
import type { ChainReader, ObservedAnchor, ObservedRegistry } from "./verify.ts";

function u32be(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function u16le(value: number): Uint8Array {
  const bytes = new Uint8Array(2);
  new DataView(bytes.buffer).setUint16(0, value, true);
  return bytes;
}

function accountData(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value) && typeof value[0] === "string" && value[1] === "base64") {
    return Buffer.from(value[0], "base64");
  }
  throw new TypeError("unsupported Solana account encoding");
}

function transactionAddresses(transaction: any): string[] {
  const staticKeys = transaction?.transaction?.message?.accountKeys ?? [];
  const loaded = transaction?.meta?.loadedAddresses;
  return [
    ...staticKeys.map((key: any) => typeof key === "string" ? key : key.pubkey),
    ...(loaded?.writable ?? []),
    ...(loaded?.readonly ?? []),
  ];
}

export class SolanaRpcChainReader implements ChainReader {
  private readonly rpc;
  private readonly addressDecoder = getAddressDecoder();
  private readonly addressEncoder = getAddressEncoder();
  private readonly base58Decoder = getBase58Decoder();

  constructor(rpcUrl: string) {
    this.rpc = createSolanaRpc(rpcUrl);
  }

  async getRegistryConfig(body: CertificateBody): Promise<ObservedRegistry> {
    const registryHash = registryIdHash(body.registryId);
    const programAddress = this.addressDecoder.decode(body.anchor.solanaProgramId);
    const [configAddress] = await findRegistryConfigPda(registryHash, { programAddress });
    const accountResponse = await this.rpc.getAccountInfo(configAddress, {
      commitment: "finalized",
      encoding: "base64",
    }).send();
    const account = accountResponse.value;
    if (account === null) throw new TypeError("registry config account not found");
    if (account.owner !== programAddress) throw new TypeError("registry config owner mismatch");
    const config = getRegistryConfigDecoder().decode(accountData(account.data));
    if (config.version !== 1 || !equalBytes(new Uint8Array(config.registryIdHash), registryHash)) {
      throw new TypeError("registry config is invalid");
    }
    return {
      registryIdHash: new Uint8Array(config.registryIdHash),
      paused: config.paused,
    };
  }

  async getAnchor(body: CertificateBody): Promise<ObservedAnchor> {
    const segmentAddress = this.addressDecoder.decode(body.anchor.segmentPda);
    const programAddress = this.addressDecoder.decode(body.anchor.solanaProgramId);
    const accountResponse = await this.rpc.getAccountInfo(segmentAddress, {
      commitment: "finalized",
      encoding: "base64",
    }).send();
    const account = accountResponse.value;
    if (account === null) throw new TypeError("ledger segment account not found");
    if (account.owner !== programAddress) throw new TypeError("ledger segment owner mismatch");

    const segment = decodeLedgerSegment(accountData(account.data));
    if (segment.segmentIndex !== body.anchor.segmentIndex) throw new TypeError("segment index mismatch");
    const [derivedAddress] = await getProgramDerivedAddress({
      programAddress,
      seeds: [new TextEncoder().encode("ledger"), segment.registry, u32be(segment.dayUtc), u16le(segment.segmentIndex)],
    });
    const entry = findAnchorEntry(segment, body.anchor.batchSequence);
    const transactionSignature = signature(this.base58Decoder.decode(body.anchor.transactionSignature));
    const [statusResponse, transaction] = await Promise.all([
      this.rpc.getSignatureStatuses([transactionSignature], { searchTransactionHistory: true }).send(),
      this.rpc.getTransaction(transactionSignature, {
        commitment: "finalized",
        encoding: "json",
        maxSupportedTransactionVersion: 0,
      }).send(),
    ]);
    const status = statusResponse.value[0];
    if (status === null || status.err !== null || status.confirmationStatus !== "finalized") {
      throw new TypeError("anchor transaction is not finalized");
    }
    if (transaction === null) throw new TypeError("anchor transaction not found");
    const addresses = transactionAddresses(transaction);
    if (!addresses.includes(segmentAddress) || !addresses.includes(programAddress)) {
      throw new TypeError("anchor transaction does not reference program and segment");
    }
    if (BigInt(transaction.slot) !== body.anchor.anchorSlot || BigInt(status.slot) !== body.anchor.anchorSlot) {
      throw new TypeError("anchor transaction slot mismatch");
    }

    return {
      programId: new Uint8Array(this.addressEncoder.encode(programAddress)),
      segmentPda: new Uint8Array(this.addressEncoder.encode(segmentAddress)),
      derivedSegmentPda: new Uint8Array(this.addressEncoder.encode(derivedAddress)),
      batchSequence: entry.batchSequence,
      registryVersion: entry.registryVersion,
      merkleRoot: entry.merkleRoot,
      manifestHash: entry.manifestHash,
      transactionSignature: body.anchor.transactionSignature,
      slot: BigInt(transaction.slot),
      commitment: "finalized",
    };
  }

  async getFinalizedHeadSlot(): Promise<bigint> {
    return BigInt(await this.rpc.getSlot({ commitment: "finalized" }).send());
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
