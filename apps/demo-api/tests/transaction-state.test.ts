import assert from "node:assert/strict";
import { test } from "node:test";
import {
  assertTransition,
  canTransition,
  intentHash,
  isSettled,
  isTerminal,
  TRANSACTION_STATES,
  TransitionError,
  type PublishIntent,
} from "../src/transaction-state.ts";

const intent: PublishIntent = {
  registryId: "gov.registry.land",
  batchSequence: 1n,
  registryVersion: 1n,
  cursorStart: 1n,
  cursorEnd: 2n,
  leafCount: 2,
  merkleRootHex: "aa".repeat(32),
  manifestHashHex: "bb".repeat(32),
  previousAnchorHashHex: "cc".repeat(32),
  programId: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo",
  configPda: "ConfigPda",
  rolePda: "RolePda",
  segmentPda: "SegmentPda",
  segmentIndex: 0,
  dayUtc: 20_665,
  feePayer: "FeePayer",
  recentBlockhash: "11111111111111111111111111111111",
  lastValidBlockHeight: 1_000n,
  messageBase64: "AQID",
};

test("the happy path walks DRAFT to ISSUED", () => {
  const path = ["DRAFT", "PREPARED", "SIMULATED", "SIGNED", "SUBMITTED", "FINALIZED", "ISSUED"] as const;
  for (let index = 1; index < path.length; index += 1) {
    assert.ok(canTransition(path[index - 1], path[index]), `${path[index - 1]} → ${path[index]}`);
  }
});

test("ISSUED is unreachable before FINALIZED", () => {
  for (const state of TRANSACTION_STATES) {
    if (state === "FINALIZED") continue;
    assert.equal(canTransition(state, "ISSUED"), false, state);
  }
  assert.throws(() => assertTransition("SUBMITTED", "ISSUED"), TransitionError);
  assert.throws(() => assertTransition("SIMULATED", "SUBMITTED"), TransitionError);
});

test("UNKNOWN only resolves forward and never re-signs", () => {
  assert.ok(canTransition("SUBMITTED", "UNKNOWN"));
  assert.ok(canTransition("UNKNOWN", "FINALIZED"));
  assert.equal(canTransition("UNKNOWN", "SIGNED"), false);
  assert.equal(canTransition("UNKNOWN", "PREPARED"), false);
});

test("recoverable branches return to preparation, terminal ones do not", () => {
  for (const state of ["SIMULATION_FAILED", "SIGNING_REJECTED", "EXPIRED"] as const) {
    assert.ok(canTransition(state, "PREPARED"), state);
    assert.equal(isTerminal(state), false);
  }
  assert.ok(isTerminal("ISSUED"));
  assert.ok(isTerminal("FAILED"));
  assert.ok(isSettled("FINALIZED") && isSettled("ISSUED"));
  assert.equal(isSettled("SUBMITTED"), false);
});

test("the intent hash covers every reviewed field", () => {
  const base = intentHash(intent);
  const mutations: Array<Partial<PublishIntent>> = [
    { batchSequence: 2n },
    { merkleRootHex: "ab".repeat(32) },
    { manifestHashHex: "ba".repeat(32) },
    { previousAnchorHashHex: "cd".repeat(32) },
    { segmentPda: "OtherSegment" },
    { feePayer: "OtherPayer" },
    { messageBase64: "BAUG" },
    { recentBlockhash: "22222222222222222222222222222222" },
    { leafCount: 3 },
  ];
  for (const mutation of mutations) {
    assert.notDeepEqual(intentHash({ ...intent, ...mutation }), base, Object.keys(mutation).join(","));
  }
  assert.deepEqual(intentHash({ ...intent }), base);
});
