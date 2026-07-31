import {
  batchLeafHash,
  buildFieldTree,
  recordCommitment,
  recordIdCommitment,
  registryIdHash,
} from "../../../packages/canonical-ts/src/index.ts";
import { root } from "../../../packages/merkle-ts/src/index.ts";

export interface SyntheticFixtureRow {
  internalRecordId: string;
  recordVersion: string;
  status: string;
  recordFieldKeyHex: string;
}

export function fixtureRoot(rows: readonly SyntheticFixtureRow[], registryId = "gov.registry.land"): string {
  if (rows.length === 0) throw new RangeError("synthetic fixture is empty");
  const idKey = new Uint8Array(32).fill(9);
  const registryHash = registryIdHash(registryId);
  const leaves = rows.map((row) => {
    if (!/^SYNTHETIC-[1-9][0-9]*$/.test(row.internalRecordId)) throw new TypeError("non-synthetic record rejected");
    if (!/^[0-9a-f]{64}$/.test(row.recordFieldKeyHex)) throw new TypeError("record field key is invalid");
    if (!/^[1-9][0-9]*$/.test(row.recordVersion)) throw new TypeError("record version is invalid");
    const recordId = recordIdCommitment(idKey, registryId, row.internalRecordId);
    const fieldRoot = buildFieldTree(Buffer.from(row.recordFieldKeyHex, "hex"), [
      { path: "status", value: { type: "text", value: row.status } },
    ]).root;
    const recordVersion = BigInt(row.recordVersion);
    return {
      recordId,
      recordVersion,
      leaf: batchLeafHash(recordCommitment(registryHash, recordId, recordVersion, fieldRoot)),
    };
  }).sort((left, right) =>
    Buffer.compare(left.recordId, right.recordId) ||
    (left.recordVersion < right.recordVersion ? -1 : left.recordVersion > right.recordVersion ? 1 : 0)
  );
  return Buffer.from(root(leaves.map((entry) => entry.leaf))).toString("hex");
}
