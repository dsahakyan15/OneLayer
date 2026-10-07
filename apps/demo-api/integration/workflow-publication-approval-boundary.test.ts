// H4/H5/M4 adversarial boundary coverage (ported from the round-3 probes).
//
// H4: the publisher layer itself must not mint a signature without an exact
// reserved-plan approval; `step()` defaults, `{allowNewWork:true}`, and any
// direct/internal path are refused, and no unsafe maintenance/test method
// exists. H5: the signature requires an independently issued receipt verified
// against a pinned key; self-minted/mismatched/expired/identity-swapped
// receipts and consumed receipts are refused. M4: the connected chain's genesis
// hash is checked before any reservation/signing, and the runtime only mints
// approvals through the service with a session actor/device.
import assert from "node:assert/strict";
import test from "node:test";
import { WorkflowPublisher } from "../src/publication-worker.ts";
import { WorkflowPublicationRuntime } from "../src/workflow-runtime.ts";
import { PublicationApprovalIssuer, publicationApprovalReceiptHash } from "../src/publication-approval.ts";
import { WorkflowPublicationStore } from "../src/workflow-publication.ts";
import { isolatedPostgres } from "./support/postgres.ts";
import {
  append, approvalService, approve, APPROVAL_ACTOR, APPROVAL_DEVICE, CONFIG_PDA, count, FakeChain, KEYS, PROGRAM_ID, REGISTRY,
  publisher, TEST_APPROVAL_HOME, TEST_APPROVAL_KEY_FILE, TEST_CLUSTER, TEST_GENESIS, TestSigner,
} from "./support/publication-fake-chain.ts";

const code = (value: string) => (error: unknown) => (error as { code?: string }).code === value;
const runtimeError = (status: number, value: string) => (error: unknown) => (error as { status?: number; code?: string }).status === status && (error as { code?: string }).code === value;

test("H4: no unguarded step can reserve, sign or send; only an exact reserved-plan receipt signs", { timeout: 60_000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  await append(pool, "R-1", { value: 1 });
  const chain = new FakeChain(); const signer = new TestSigner(); const worker = publisher(pool, chain, signer);
  const store = new WorkflowPublicationStore(pool);
  const lease = (await store.claim(REGISTRY, "worker-a"))!;

  // No options, and the removed `allowNewWork` flag alone, are never approval.
  await assert.rejects(worker.step(lease), code("PUBLICATION_INTENT_APPROVAL_REQUIRED"));
  await assert.rejects(worker.step(lease, { allowNewWork: true } as unknown as { approval?: never }), code("PUBLICATION_INTENT_APPROVAL_REQUIRED"));
  assert.equal(signer.requests.length, 0);
  assert.equal(chain.sent.length, 0);
  assert.equal(await count(pool, "SELECT count(*) FROM wf_publication_tx"), 0, "no reservation without review");
  // No separate unsafe maintenance/test signing method is exposed.
  assert.equal((worker as unknown as Record<string, unknown>).newAttempt, undefined);
  assert.equal((worker as unknown as Record<string, unknown>).stepInternalUnguarded, undefined);

  // A reviewed but unapproved reservation is never signed...
  const review = await worker.review(lease);
  assert.match(String(review.attemptPlanHash), /^[0-9a-f]{64}$/);
  await assert.rejects(worker.step(lease), code("PUBLICATION_INTENT_APPROVAL_REQUIRED"));
  assert.equal(signer.requests.length, 0);
  // ...and the exact reviewed receipt signs precisely the reserved bytes.
  const result = await worker.step(lease, { approval: approve(lease.operationId, review.intentHash, review.attemptPlanHash!) });
  assert.equal(result.status, "SUBMITTED");
  assert.equal(signer.requests.length, 1);
  assert.equal(signer.requests[0]!.messageBase64, review.messageBase64);
  assert.equal(signer.requests[0]!.approvalReceipt.claims.attemptPlanHash, review.attemptPlanHash);
  assert.equal(signer.requests[0]!.approvalReceipt.claims.actor, APPROVAL_ACTOR);
});

test("H4/M4: a publisher without an explicit identity refuses; without a verifier it cannot sign", { timeout: 60_000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  const chain = new FakeChain(); const signer = new TestSigner();
  assert.throws(() => publisher(pool, chain, signer, { cluster: undefined }), code("PUBLICATION_IDENTITY_UNCONFIGURED"));
  // No default solana:local: an unknown/local label needs an explicit genesis.
  assert.throws(() => publisher(pool, chain, signer, { cluster: "solana:local", genesisHash: undefined }), code("PUBLICATION_CHAIN_IDENTITY_UNCONFIGURED"));

  await append(pool, "R-1", { value: 1 });
  const noVerifier = new WorkflowPublisher(pool, chain, signer, {
    registryId: REGISTRY, programId: PROGRAM_ID, configPda: CONFIG_PDA, operatorKeyId: "x", keys: KEYS,
    cluster: TEST_CLUSTER, genesisHash: TEST_GENESIS,
  });
  const store = new WorkflowPublicationStore(pool);
  const lease = (await store.claim(REGISTRY, "worker-a"))!;
  const review = await noVerifier.review(lease);
  await assert.rejects(
    noVerifier.step(lease, { approval: approve(lease.operationId, review.intentHash, review.attemptPlanHash!) }),
    code("PUBLICATION_APPROVAL_UNCONFIGURED"),
  );
  assert.equal(signer.requests.length, 0);
});

test("H5: self-minted, mismatched, identity-swapped, expired and consumed receipts are refused", { timeout: 60_000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  await append(pool, "R-1", { value: 1 });
  const chain = new FakeChain(); const signer = new TestSigner(); const worker = publisher(pool, chain, signer);
  const store = new WorkflowPublicationStore(pool);
  const lease = (await store.claim(REGISTRY, "worker-a"))!;
  const review = await worker.review(lease);
  const binding = { operationId: lease.operationId, intentHash: review.intentHash, attemptPlanHash: review.attemptPlanHash! };

  // Binding swaps cannot authorize this reserved plan.
  await assert.rejects(worker.step(lease, { approval: approve("33333333-3333-3333-3333-333333333333", binding.intentHash, binding.attemptPlanHash) }), code("PUBLICATION_APPROVAL_MISMATCH"));
  await assert.rejects(worker.step(lease, { approval: approve(binding.operationId, "ee".repeat(32), binding.attemptPlanHash) }), code("PUBLICATION_APPROVAL_MISMATCH"));
  // A tampered signature (a self-minted receipt) is refused.
  await assert.rejects(worker.step(lease, { approval: { ...approve(binding.operationId, binding.intentHash, binding.attemptPlanHash), signature: Buffer.alloc(64, 7).toString("base64") } }), code("PUBLICATION_APPROVAL_SIGNATURE"));
  // Identity swap: same approval key, a receipt issued for another genesis.
  const wrongGenesis = await PublicationApprovalIssuer.create(TEST_APPROVAL_KEY_FILE, { cluster: TEST_CLUSTER, genesisHash: "2".repeat(32) }, { home: TEST_APPROVAL_HOME });
  await assert.rejects(worker.step(lease, { approval: wrongGenesis.issue(binding, APPROVAL_ACTOR, APPROVAL_DEVICE) }), code("PUBLICATION_APPROVAL_IDENTITY"));
  // Expired receipt (issued 20 minutes ago, 10-minute TTL).
  const expired = await PublicationApprovalIssuer.create(TEST_APPROVAL_KEY_FILE, { cluster: TEST_CLUSTER, genesisHash: TEST_GENESIS, now: () => new Date(Date.now() - 20 * 60_000) }, { home: TEST_APPROVAL_HOME });
  await assert.rejects(worker.step(lease, { approval: expired.issue(binding, APPROVAL_ACTOR, APPROVAL_DEVICE) }), code("PUBLICATION_APPROVAL_EXPIRED"));
  assert.equal(signer.requests.length, 0);
  assert.equal(chain.sent.length, 0);

  // Sign attempt 1 for real, then expire it.
  chain.mode = "drop";
  const receipt1 = approve(binding.operationId, binding.intentHash, binding.attemptPlanHash);
  assert.equal((await worker.step(lease, { approval: receipt1 })).status, "SUBMITTED");
  chain.advance(151n);
  await assert.rejects(worker.step(lease), code("PUBLICATION_INTENT_APPROVAL_REQUIRED"));
  // A fresh reservation needs a fresh receipt...
  const review2 = await worker.review(lease);
  assert.notEqual(review2.attemptPlanHash, binding.attemptPlanHash);
  const receipt2 = approve(lease.operationId, review2.intentHash, review2.attemptPlanHash!);
  // ...and a receipt already recorded on a signed attempt is consumed: forge the
  // journal to prove the durable consumed-approval guard refuses a replay.
  await pool.query("ALTER TABLE wf_publication_tx_event DISABLE TRIGGER immutable");
  await pool.query(
    "UPDATE wf_publication_tx_event SET detail = jsonb_set(detail, '{approvalReceiptHash}', to_jsonb($1::text)) WHERE attempt_id=(SELECT attempt_id FROM wf_publication_tx WHERE attempt_no=1) AND state='SIGNED'",
    [publicationApprovalReceiptHash(receipt2)],
  );
  await pool.query("ALTER TABLE wf_publication_tx_event ENABLE TRIGGER immutable");
  await assert.rejects(worker.step(lease, { approval: receipt2 }), code("PUBLICATION_APPROVAL_CONSUMED"));
  assert.equal(signer.requests.length, 1, "the consumed receipt produced no second signature");
});

test("M4: wrong or unavailable genesis fails closed before any reservation or signature", { timeout: 60_000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  await append(pool, "R-1", { value: 1 });
  const chain = new FakeChain(); const signer = new TestSigner(); const worker = publisher(pool, chain, signer);
  const store = new WorkflowPublicationStore(pool);
  const lease = (await store.claim(REGISTRY, "worker-a"))!;

  chain.genesis = "2".repeat(32);
  await assert.rejects(worker.review(lease), code("PUBLICATION_CHAIN_IDENTITY_MISMATCH"));
  await assert.rejects(worker.step(lease), code("PUBLICATION_CHAIN_IDENTITY_MISMATCH"));
  chain.genesisUnavailable = true;
  await assert.rejects(worker.review(lease), code("PUBLICATION_CHAIN_IDENTITY_UNAVAILABLE"));
  assert.equal(await count(pool, "SELECT count(*) FROM wf_publication_tx"), 0, "nothing reserved on a wrong/unavailable chain");
  assert.equal(signer.requests.length, 0);
  assert.equal(chain.sent.length, 0);
});

test("runtime mints only through the approval service and requires session actor/device", { timeout: 60_000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  await append(pool, "R-1", { value: 1 });
  const chain = new FakeChain(); const signer = new TestSigner();
  const config = { registryId: REGISTRY, programId: PROGRAM_ID, configPda: CONFIG_PDA, operatorKeyId: "synthetic-operator", keys: KEYS, cluster: TEST_CLUSTER, genesisHash: TEST_GENESIS };
  const withoutService = new WorkflowPublicationRuntime(pool, chain, signer, config);
  const reviewed = await withoutService.review(REGISTRY, "worker-a");
  await assert.rejects(
    withoutService.run(REGISTRY, "worker-a", { attemptPlanHash: reviewed.review.attemptPlanHash!, actor: APPROVAL_ACTOR, device: APPROVAL_DEVICE }),
    runtimeError(503, "PUBLICATION_APPROVAL_UNAVAILABLE"),
  );
  const withService = new WorkflowPublicationRuntime(pool, chain, signer, config, approvalService());
  await assert.rejects(
    withService.run(REGISTRY, "worker-a", { attemptPlanHash: reviewed.review.attemptPlanHash! }),
    runtimeError(409, "PUBLICATION_APPROVAL_ACTOR_REQUIRED"),
  );
  const submitted = await withService.run(REGISTRY, "worker-a", { attemptPlanHash: reviewed.review.attemptPlanHash!, actor: APPROVAL_ACTOR, device: APPROVAL_DEVICE });
  assert.equal(submitted.status, "SUBMITTED");
});
