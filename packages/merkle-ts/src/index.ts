import { createHash, timingSafeEqual } from "node:crypto";

export type Hash = Uint8Array;
export type Side = "LEFT" | "RIGHT";

export interface ProofStep {
  sibling: Hash;
  side: Side;
}

function requireHash(value: Uint8Array): void {
  if (value.length !== 32) {
    throw new RangeError(`hash must be 32 bytes, got ${value.length}`);
  }
}

function sha256(...parts: Uint8Array[]): Hash {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
}

export function leafHash(commitment: Hash): Hash {
  requireHash(commitment);
  return sha256(Uint8Array.of(0), commitment);
}

export function nodeHash(left: Hash, right: Hash): Hash {
  requireHash(left);
  requireHash(right);
  return sha256(Uint8Array.of(1), left, right);
}

function foldLevel(level: Hash[]): Hash[] {
  const next: Hash[] = [];
  let index = 0;
  while (index + 1 < level.length) {
    next.push(nodeHash(level[index], level[index + 1]));
    index += 2;
  }
  if (index < level.length) next.push(level[index]);
  return next;
}

export function root(leaves: Hash[]): Hash {
  if (leaves.length === 0) throw new RangeError("MERKLE_EMPTY");
  let level = leaves.map((leaf) => {
    requireHash(leaf);
    return leaf;
  });
  while (level.length > 1) level = foldLevel(level);
  return level[0];
}

export function proof(leaves: Hash[], leafIndex: number): ProofStep[] {
  if (leaves.length === 0) throw new RangeError("MERKLE_EMPTY");
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= leaves.length) {
    throw new RangeError(`MERKLE_INDEX_OUT_OF_RANGE: index=${leafIndex}, leaves=${leaves.length}`);
  }

  const steps: ProofStep[] = [];
  let level = leaves.slice();
  let position = leafIndex;
  while (level.length > 1) {
    const unpaired = position === level.length - 1 && level.length % 2 === 1;
    if (!unpaired) {
      const right = position % 2 === 0;
      steps.push({
        sibling: level[right ? position + 1 : position - 1],
        side: right ? "RIGHT" : "LEFT",
      });
    }
    position = Math.floor(position / 2);
    level = foldLevel(level);
  }
  return steps;
}

export function rootFromProof(leaf: Hash, steps: ProofStep[]): Hash {
  requireHash(leaf);
  return steps.reduce(
    (current, step) =>
      step.side === "RIGHT"
        ? nodeHash(current, step.sibling)
        : nodeHash(step.sibling, current),
    leaf,
  );
}

export function verify(leaf: Hash, steps: ProofStep[], expectedRoot: Hash): boolean {
  requireHash(expectedRoot);
  return timingSafeEqual(rootFromProof(leaf, steps), expectedRoot);
}

export function fromHex(value: string): Hash {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new TypeError("hash must be 64 lowercase hex characters");
  return Buffer.from(value, "hex");
}

export function toHex(value: Hash): string {
  requireHash(value);
  return Buffer.from(value).toString("hex");
}
