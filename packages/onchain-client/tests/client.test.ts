import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  findIncidentNoticePda,
  findLedgerSegmentPda,
  findRegistryConfigPda,
  findRolePda,
  getPublishAnchorInstructionDataEncoder,
  ONELAYER_REGISTRY_PROGRAM_ADDRESS,
  PUBLISH_ANCHOR_DISCRIMINATOR,
} from "../src/index.ts";
import type { Address } from "@solana/kit";

const registryIdHash = new Uint8Array(createHash("sha256").update("gov.registry.land").digest());

test("publish_anchor instruction data matches the frozen ABI layout", () => {
  const encoded = getPublishAnchorInstructionDataEncoder().encode({
    batchSequence: 1n,
    registryVersion: 2n,
    sourceCursorStart: 3n,
    sourceCursorEnd: 4n,
    merkleRoot: new Uint8Array(32).fill(0xaa),
    manifestHash: new Uint8Array(32).fill(0xbb),
    snapshotHash: new Uint8Array(32),
    previousAnchorHash: new Uint8Array(32).fill(0xcc),
    leafCount: 2,
    schemaVersion: 1,
    flags: 0,
    hashAlgorithm: 1,
    treeAlgorithm: 1,
  });
  // 8 discriminator + 4×u64 + 4×32 bytes + u32 + 2×u16 + 2×u8
  assert.equal(encoded.length, 8 + 32 + 128 + 4 + 4 + 2);
  assert.deepEqual(Array.from(encoded.slice(0, 8)), Array.from(PUBLISH_ANCHOR_DISCRIMINATOR));
  const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);
  assert.equal(view.getBigUint64(8, true), 1n);
  assert.equal(view.getBigUint64(16, true), 2n);
});

test("registry, ledger and incident PDAs are derived from the program seeds", async () => {
  const [config] = await findRegistryConfigPda(registryIdHash);
  const [segment] = await findLedgerSegmentPda({ config, dayUtc: 20_300, segmentIndex: 0 });
  const [incident] = await findIncidentNoticePda({ config, incidentSequence: 0n });
  const [role] = await findRolePda({ config, operator: config });
  for (const address of [config, segment, incident, role]) {
    assert.match(address, /^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
  }
  assert.notEqual(config, segment);
  const [otherSegment] = await findLedgerSegmentPda({ config, dayUtc: 20_300, segmentIndex: 1 });
  assert.notEqual(segment, otherSegment);
});

test("PDA seed ranges are enforced", async () => {
  const [config] = await findRegistryConfigPda(registryIdHash);
  await assert.rejects(() => findRegistryConfigPda(new Uint8Array(31)), RangeError);
  await assert.rejects(() => findLedgerSegmentPda({ config, dayUtc: -1, segmentIndex: 0 }), RangeError);
  await assert.rejects(() => findLedgerSegmentPda({ config, dayUtc: 1, segmentIndex: 70_000 }), RangeError);
  await assert.rejects(() => findIncidentNoticePda({ config, incidentSequence: -1n }), RangeError);
});

test("the program address is the deployed devnet program", () => {
  assert.equal(
    ONELAYER_REGISTRY_PROGRAM_ADDRESS as Address,
    "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo",
  );
});
