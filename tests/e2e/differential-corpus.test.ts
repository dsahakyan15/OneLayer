import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  batchLeafHash,
  buildFieldTree,
  recordCommitment,
  recordIdCommitment,
  registryIdHash,
} from "../../packages/canonical-ts/src/index.ts";

interface CorpusCase {
  internalRecordId: string;
  recordVersion: number;
  recordFieldKeyHex: string;
  status: string;
  area: string;
  recordIdCommitmentHex: string;
  fieldRootHex: string;
  recordCommitmentHex: string;
  batchLeafHashHex: string;
}

test("Rust and TypeScript agree on the 1000-record PR differential corpus", () => {
  const output = execFileSync(
    "cargo",
    ["run", "--quiet", "-p", "onelayer-pilot-pipeline", "--bin", "differential_corpus"],
    { cwd: new URL("../..", import.meta.url), encoding: "utf8", maxBuffer: 4 * 1024 * 1024 },
  );
  const corpus: CorpusCase[] = JSON.parse(output);
  assert.equal(corpus.length, 1_000);
  const registryId = "gov.registry.land";
  const registryHash = registryIdHash(registryId);
  const idKey = new Uint8Array(32).fill(9);
  for (const entry of corpus) {
    const expectedKey = createHash("sha256")
      .update("ONELAYER:DIFF:V1")
      .update(Buffer.from(BigInt(entry.internalRecordId.slice(5)).toString(16).padStart(16, "0"), "hex"))
      .digest("hex");
    assert.equal(entry.recordFieldKeyHex, expectedKey);
    const recordId = recordIdCommitment(idKey, registryId, entry.internalRecordId);
    const tree = buildFieldTree(Buffer.from(entry.recordFieldKeyHex, "hex"), [
      { path: "status", value: { type: "text", value: entry.status } },
      { path: "area", value: { type: "text", value: entry.area } },
    ]);
    const commitment = recordCommitment(registryHash, recordId, BigInt(entry.recordVersion), tree.root);
    assert.equal(Buffer.from(recordId).toString("hex"), entry.recordIdCommitmentHex);
    assert.equal(Buffer.from(tree.root).toString("hex"), entry.fieldRootHex);
    assert.equal(Buffer.from(commitment).toString("hex"), entry.recordCommitmentHex);
    assert.equal(Buffer.from(batchLeafHash(commitment)).toString("hex"), entry.batchLeafHashHex);
  }
});
