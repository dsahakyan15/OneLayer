import assert from "node:assert/strict";
import { test } from "node:test";
import { DualRpcChainReader } from "../src/dual-rpc.ts";
import { AnchorDisputedError, type ChainReader, type ObservedAnchor } from "../src/verify.ts";
import type { CertificateBody } from "../../../packages/canonical-ts/src/index.ts";

const anchor: ObservedAnchor = {
  programId: new Uint8Array(32).fill(1),
  segmentPda: new Uint8Array(32).fill(2),
  derivedSegmentPda: new Uint8Array(32).fill(2),
  batchSequence: 1n,
  registryVersion: 1n,
  merkleRoot: new Uint8Array(32).fill(3),
  manifestHash: new Uint8Array(32).fill(4),
  transactionSignature: new Uint8Array(64).fill(5),
  slot: 100n,
  commitment: "finalized",
};

function reader(observed: ObservedAnchor, head: bigint): ChainReader {
  return { async getAnchor() { return observed; }, async getFinalizedHeadSlot() { return head; } };
}

test("dual reader returns both heads and rejects differing finalized anchor data", async () => {
  const consistent = new DualRpcChainReader(reader(anchor, 110n), reader(anchor, 120n));
  assert.deepEqual(await consistent.getFinalizedHeadSlots(), [110n, 120n]);
  assert.equal(await consistent.getFinalizedHeadSlot(), 120n);

  const changed = { ...anchor, merkleRoot: new Uint8Array(32).fill(9) };
  const disputed = new DualRpcChainReader(reader(anchor, 110n), reader(changed, 110n));
  await assert.rejects(disputed.getAnchor({} as CertificateBody), AnchorDisputedError);
});
