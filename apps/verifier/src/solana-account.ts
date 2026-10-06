import { createHash, timingSafeEqual } from "node:crypto";
import type { Hash } from "../../../packages/merkle-ts/src/index.ts";

export const LEDGER_CAPACITY = 46;
export const ANCHOR_ENTRY_SIZE = 216;
export const SEGMENT_HEADER_SIZE = 96;
export const SEGMENT_ACCOUNT_SIZE = 8 + SEGMENT_HEADER_SIZE + LEDGER_CAPACITY * ANCHOR_ENTRY_SIZE;

export interface DecodedAnchorEntry {
  batchSequence: bigint;
  registryVersion: bigint;
  merkleRoot: Hash;
  manifestHash: Hash;
}

export interface DecodedLedgerSegment {
  registry: Uint8Array;
  dayUtc: number;
  segmentIndex: number;
  entryCount: number;
  entries: DecodedAnchorEntry[];
}

function discriminator(name: string): Uint8Array {
  return createHash("sha256").update(`account:${name}`).digest().subarray(0, 8);
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

export function ledgerDiscriminator(): Uint8Array {
  return discriminator("DailyAnchorLedgerSegment");
}

export function decodeLedgerSegment(data: Uint8Array): DecodedLedgerSegment {
  if (data.length !== SEGMENT_ACCOUNT_SIZE) {
    throw new RangeError(`ledger segment must be ${SEGMENT_ACCOUNT_SIZE} bytes`);
  }
  if (!equal(data.subarray(0, 8), ledgerDiscriminator())) throw new TypeError("ledger discriminator mismatch");
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const header = 8;
  if (view.getUint8(header) !== 1) throw new TypeError("unsupported ledger account version");
  const capacity = view.getUint16(header + 44, true);
  const entryCount = view.getUint16(header + 42, true);
  if (capacity !== LEDGER_CAPACITY || entryCount > capacity) throw new TypeError("ledger header is invalid");

  const entries: DecodedAnchorEntry[] = [];
  for (let index = 0; index < entryCount; index += 1) {
    const offset = header + SEGMENT_HEADER_SIZE + index * ANCHOR_ENTRY_SIZE;
    entries.push({
      batchSequence: view.getBigUint64(offset, true),
      registryVersion: view.getBigUint64(offset + 8, true),
      merkleRoot: data.slice(offset + 32, offset + 64),
      manifestHash: data.slice(offset + 64, offset + 96),
    });
  }
  return {
    registry: data.slice(header + 4, header + 36),
    dayUtc: view.getUint32(header + 36, true),
    segmentIndex: view.getUint16(header + 40, true),
    entryCount,
    entries,
  };
}

export function findAnchorEntry(segment: DecodedLedgerSegment, batchSequence: bigint): DecodedAnchorEntry {
  const entry = segment.entries.find((candidate) => candidate.batchSequence === batchSequence);
  if (entry === undefined) throw new TypeError("anchor entry not found in ledger segment");
  return entry;
}
