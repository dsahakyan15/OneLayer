import { timingSafeEqual } from "node:crypto";
import {
  AnchorDisputedError,
  type ChainReader,
  type ObservedAnchor,
} from "./verify.ts";
import type { CertificateBody } from "../../../packages/canonical-ts/src/index.ts";

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

function anchorsEqual(left: ObservedAnchor, right: ObservedAnchor): boolean {
  return bytesEqual(left.programId, right.programId)
    && bytesEqual(left.segmentPda, right.segmentPda)
    && bytesEqual(left.derivedSegmentPda, right.derivedSegmentPda)
    && left.batchSequence === right.batchSequence
    && left.registryVersion === right.registryVersion
    && bytesEqual(left.merkleRoot, right.merkleRoot)
    && bytesEqual(left.manifestHash, right.manifestHash)
    && bytesEqual(left.transactionSignature, right.transactionSignature)
    && left.slot === right.slot
    && left.commitment === right.commitment;
}

export class DualRpcChainReader implements ChainReader {
  private readonly primary: ChainReader;
  private readonly secondary: ChainReader;

  constructor(primary: ChainReader, secondary: ChainReader) {
    this.primary = primary;
    this.secondary = secondary;
  }

  async getAnchor(body: CertificateBody): Promise<ObservedAnchor> {
    const [primary, secondary] = await Promise.all([
      this.primary.getAnchor(body),
      this.secondary.getAnchor(body),
    ]);
    if (!anchorsEqual(primary, secondary)) throw new AnchorDisputedError("finalized RPC anchor data differs");
    return primary;
  }

  async getFinalizedHeadSlot(): Promise<bigint> {
    const heads = await this.getFinalizedHeadSlots();
    return heads[0] > heads[1] ? heads[0] : heads[1];
  }

  getFinalizedHeadSlots(): Promise<readonly bigint[]> {
    return Promise.all([
      this.primary.getFinalizedHeadSlot(),
      this.secondary.getFinalizedHeadSlot(),
    ]);
  }
}
