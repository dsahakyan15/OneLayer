import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fromHex, proof, root, toHex, verify, type ProofStep } from "../src/index.ts";

interface MerkleVector {
  id: string;
  leaf_hashes: string[];
  proofs: Array<{
    leaf_index: number;
    path: Array<{ sibling: string; side: "LEFT" | "RIGHT" }>;
  }>;
  expected: { root: string };
}

const vectorUrl = new URL("../../../spec/vectors/merkle.json", import.meta.url);
const document = JSON.parse(await readFile(vectorUrl, "utf8")) as { vectors: MerkleVector[] };

test("RFC 6962 roots and proofs match shared vectors", () => {
  for (const vector of document.vectors) {
    const leaves = vector.leaf_hashes.map(fromHex);
    const expectedRoot = fromHex(vector.expected.root);
    assert.equal(toHex(root(leaves)), vector.expected.root, vector.id);

    for (const expectedProof of vector.proofs) {
      const generated = proof(leaves, expectedProof.leaf_index);
      assert.deepEqual(
        generated.map((step) => ({ sibling: toHex(step.sibling), side: step.side })),
        expectedProof.path,
        `${vector.id}: proof ${expectedProof.leaf_index}`,
      );
      const parsed: ProofStep[] = expectedProof.path.map((step) => ({
        sibling: fromHex(step.sibling),
        side: step.side,
      }));
      assert.equal(verify(leaves[expectedProof.leaf_index], parsed, expectedRoot), true);
    }
  }
});

test("empty trees and invalid indexes fail closed", () => {
  assert.throws(() => root([]), /MERKLE_EMPTY/);
  assert.throws(() => proof([new Uint8Array(32)], 1), /MERKLE_INDEX_OUT_OF_RANGE/);
});
