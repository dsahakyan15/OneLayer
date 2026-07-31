import {
  batchLeafHash,
  buildFieldTree,
  recordCommitment,
  recordIdCommitment,
  registryIdHash,
} from "../../../packages/canonical-ts/src/index.ts";
import { root } from "../../../packages/merkle-ts/src/index.ts";

interface RestoredRow {
  internalRecordId: string;
  recordVersion: string;
  status: string;
  recordFieldKeyHex: string;
}

const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
const rows: RestoredRow[] = JSON.parse(Buffer.concat(chunks).toString("utf8"));
if (!Array.isArray(rows) || rows.length === 0) throw new TypeError("restored record set is empty");
const registryId = "gov.registry.land";
const idKey = new Uint8Array(32).fill(9);
const registryHash = registryIdHash(registryId);
const leaves = rows.map((row) => {
  if (!/^[0-9a-f]{64}$/.test(row.recordFieldKeyHex)) throw new TypeError("record field key is invalid");
  const recordId = recordIdCommitment(idKey, registryId, row.internalRecordId);
  const fieldRoot = buildFieldTree(Buffer.from(row.recordFieldKeyHex, "hex"), [
    { path: "status", value: { type: "text", value: row.status } },
  ]).root;
  const version = BigInt(row.recordVersion);
  return { recordId, version, leaf: batchLeafHash(recordCommitment(registryHash, recordId, version, fieldRoot)) };
}).sort((left, right) => Buffer.compare(left.recordId, right.recordId) || (left.version < right.version ? -1 : left.version > right.version ? 1 : 0));
process.stdout.write(`${Buffer.from(root(leaves.map((entry) => entry.leaf))).toString("hex")}\n`);
