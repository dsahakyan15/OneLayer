// Ticket 09 review residual R1: a new signature is only ever produced under the
// exact reviewed intent hash. Reconciliation / re-send of an already journaled
// signed attempt needs no fresh approval; a fresh attempt after EXPIRED or a
// terminal CANCELLED/FAILED attempt does.
import assert from "node:assert/strict";
import test from "node:test";
import { WorkflowPublicationRuntime, WorkflowRuntimeError } from "../src/workflow-runtime.ts";
import { isolatedPostgres } from "./support/postgres.ts";
import {
  append, approvalService, APPROVAL_ACTOR, APPROVAL_DEVICE, CONFIG_PDA, FakeChain, KEYS, PROGRAM_ID, REGISTRY, TEST_CLUSTER, TEST_GENESIS, TestSigner, count, states,
} from "./support/publication-fake-chain.ts";

const runtimeFor = (pool: Parameters<typeof append>[0], chain: FakeChain, signer: TestSigner) =>
  new WorkflowPublicationRuntime(pool, chain, signer, {
    registryId: REGISTRY, programId: PROGRAM_ID, configPda: CONFIG_PDA,
    operatorKeyId: "synthetic-operator", keys: KEYS, cluster: TEST_CLUSTER, genesisHash: TEST_GENESIS,
  }, approvalService());

const approved = (attemptPlanHash: string) => ({ attemptPlanHash, actor: APPROVAL_ACTOR, device: APPROVAL_DEVICE });

const approvalRequired = (error: unknown) =>
  error instanceof WorkflowRuntimeError && error.status === 409 && error.code === "PUBLICATION_INTENT_APPROVAL_REQUIRED";

test("no unseen re-sign after an expired attempt; the reviewed hash re-arms exactly one new attempt", { timeout: 60_000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  await append(pool, "record", { value: 1 });
  const chain = new FakeChain();
  const signer = new TestSigner();
  const runtime = runtimeFor(pool, chain, signer);

  const reviewed = await runtime.review(REGISTRY, "worker-a");
  assert.equal(reviewed.review.hasLiveSignedAttempt, false);
  assert.equal(reviewed.review.hasSignedAttempt, false);

  // Approval publishes the first attempt; the still-valid one waits.
  chain.mode = "drop";
  const first = await runtime.run(REGISTRY, "worker-a", approved(reviewed.review.attemptPlanHash!));
  assert.equal(first.status, "SUBMITTED");
  assert.equal(chain.sent.length, 1);
  const waiting = await runtime.run(REGISTRY, "worker-a");
  assert.equal(waiting.status, "PENDING", "a live signed attempt is reconciled without a fresh approval");
  assert.equal(chain.sent.length, 1, "no re-send while the blockhash is valid");

  // The blockhash expires. Without the reviewed hash the publisher must not mint
  // a replacement signature, even though the operation membership is immutable.
  chain.advance(151n);
  await assert.rejects(runtime.run(REGISTRY, "worker-a"), approvalRequired);
  assert.equal(chain.sent.length, 1, "no unseen re-signing after expiry");
  assert.equal(await count(pool, "SELECT count(*) FROM wf_publication_tx"), 1);

  // Presenting the reviewed hash re-arms: attempt 2, a new signature, then final.
  const reviewedAgain = await runtime.review(REGISTRY, "worker-a");
  assert.equal(reviewedAgain.review.hasLiveSignedAttempt, false, "the expired attempt is no longer live");
  assert.equal(reviewedAgain.review.hasSignedAttempt, true);
  chain.mode = "land";
  const second = await runtime.run(REGISTRY, "worker-a", approved(reviewedAgain.review.attemptPlanHash!));
  assert.equal(second.status, "SUBMITTED");
  assert.equal(second.status === "SUBMITTED" && second.attemptNo, 2);
  assert.equal(chain.sent.length, 2);
  const done = await runtime.run(REGISTRY, "worker-a");
  assert.equal(done.status, "FINALIZED");
  assert.equal(chain.sent.length, 2);
  assert.deepEqual(await states(pool), ["1:PREPARED", "1:SIGNED", "1:SUBMITTED", "1:EXPIRED", "2:PREPARED", "2:SIGNED", "2:SUBMITTED", "2:FINALIZED"]);
});

test("an already journaled signed attempt completes without a fresh approval", { timeout: 60_000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  await append(pool, "record", { value: 1 });
  const chain = new FakeChain();
  const signer = new TestSigner();
  const runtime = runtimeFor(pool, chain, signer);

  const reviewed = await runtime.review(REGISTRY, "worker-a");
  // The send lands but the response is lost: the attempt is journaled SIGNED,
  // then UNKNOWN. Its signature may still be on chain.
  chain.mode = "land-then-throw";
  const unknown = await runtime.run(REGISTRY, "worker-a", approved(reviewed.review.attemptPlanHash!));
  assert.equal(unknown.status, "UNKNOWN");
  assert.equal(chain.sent.length, 1);
  assert.equal(unknown.status === "UNKNOWN" && unknown.attemptNo, 1);

  // No approval hash is presented: reconciliation of the stored bytes is allowed
  // and completes the operation without signing anything new.
  const done = await runtime.run(REGISTRY, "worker-a");
  assert.equal(done.status, "FINALIZED");
  assert.equal(chain.sent.length, 1, "no new attempt, re-send, or signature after reconciliation");
  assert.equal(await count(pool, "SELECT count(*) FROM wf_publication_tx"), 1);
});

test("a terminal cancelled attempt requires the reviewed hash again before any new signature", { timeout: 60_000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  await append(pool, "record", { value: 1 });
  const chain = new FakeChain();
  const signer = new TestSigner();
  const runtime = runtimeFor(pool, chain, signer);

  const reviewed = await runtime.review(REGISTRY, "worker-a");
  signer.reject = true;
  const rejected = await runtime.run(REGISTRY, "worker-a", approved(reviewed.review.attemptPlanHash!));
  assert.deepEqual(rejected, { status: "ERROR", operationId: reviewed.operationId, code: "SIGNING_REJECTED" });
  assert.equal(chain.sent.length, 0);

  // The only attempt is terminal and unsigned. A fresh review reserves exactly
  // one new (unsigned) attempt; without presenting that plan no signature is
  // produced and no further attempt is reserved.
  const afterRejection = await runtime.review(REGISTRY, "worker-a");
  assert.equal(afterRejection.review.hasSignedAttempt, false);
  assert.equal(afterRejection.review.hasLiveSignedAttempt, false);
  assert.match(String(afterRejection.review.attemptPlanHash), /^[0-9a-f]{64}$/);
  await assert.rejects(runtime.run(REGISTRY, "worker-a"), approvalRequired);
  assert.equal(signer.requests.length, 1);
  assert.equal(await count(pool, "SELECT count(*) FROM wf_publication_tx"), 2);
  assert.deepEqual(await states(pool), ["1:PREPARED", "1:CANCELLED", "2:PREPARED"]);

  // A fresh reviewed plan is required, and it produces exactly one new attempt.
  signer.reject = false;
  chain.mode = "land";
  const approvedAgain = await runtime.run(REGISTRY, "worker-a", approved(afterRejection.review.attemptPlanHash!));
  assert.equal(approvedAgain.status, "SUBMITTED");
  assert.equal(approvedAgain.status === "SUBMITTED" && approvedAgain.attemptNo, 2);
  assert.equal(signer.requests.length, 2);
  assert.equal((await runtime.run(REGISTRY, "worker-a")).status, "FINALIZED");
});
