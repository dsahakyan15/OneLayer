import assert from "node:assert/strict";
import test from "node:test";
import {
  ANCHOR_ENTRY_SIZE,
  decodeLedgerSegment,
  findAnchorEntry,
  ledgerDiscriminator,
  SEGMENT_ACCOUNT_SIZE,
  SEGMENT_HEADER_SIZE,
} from "../src/solana-account.ts";

function segmentBytes(): Uint8Array {
  const data = new Uint8Array(SEGMENT_ACCOUNT_SIZE);
  data.set(ledgerDiscriminator(), 0);
  const view = new DataView(data.buffer);
  const header = 8;
  view.setUint8(header, 1);
  data.fill(0x11, header + 4, header + 36);
  view.setUint32(header + 36, 20260731, true);
  view.setUint16(header + 40, 2, true);
  view.setUint16(header + 42, 1, true);
  view.setUint16(header + 44, 46, true);
  const entry = header + SEGMENT_HEADER_SIZE;
  view.setBigUint64(entry, 9n, true);
  view.setBigUint64(entry + 8, 12n, true);
  data.fill(0x22, entry + 32, entry + 64);
  data.fill(0x33, entry + 64, entry + 96);
  assert.equal(entry + ANCHOR_ENTRY_SIZE, 320);
  return data;
}

test("decodes the frozen zero-copy ledger layout", () => {
  const segment = decodeLedgerSegment(segmentBytes());
  assert.equal(segment.dayUtc, 20260731);
  assert.equal(segment.segmentIndex, 2);
  assert.equal(segment.entryCount, 1);
  assert.deepEqual(segment.registry, new Uint8Array(32).fill(0x11));
  const anchor = findAnchorEntry(segment, 9n);
  assert.equal(anchor.registryVersion, 12n);
  assert.deepEqual(anchor.merkleRoot, new Uint8Array(32).fill(0x22));
  assert.deepEqual(anchor.manifestHash, new Uint8Array(32).fill(0x33));
});

test("rejects wrong discriminator and impossible entry count", () => {
  const wrongDiscriminator = segmentBytes();
  wrongDiscriminator[0] ^= 1;
  assert.throws(() => decodeLedgerSegment(wrongDiscriminator), /discriminator/);

  const wrongCount = segmentBytes();
  new DataView(wrongCount.buffer).setUint16(8 + 42, 47, true);
  assert.throws(() => decodeLedgerSegment(wrongCount), /header/);
});
