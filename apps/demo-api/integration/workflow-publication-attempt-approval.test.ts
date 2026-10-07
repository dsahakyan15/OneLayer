// Ticket 09 review residual H3: the per-attempt approval commitment.
//
// Proves, with the REAL LocalKeyPublicationSigner on a disposable PostgreSQL and
// the finalized fake chain, that `review` reserves the exact unsigned attempt
// and returns an attemptPlanHash over the reserved message bytes + lifetime +
// fee + attempt/day/segment/cluster; that `run` signs exactly those bytes
// (no second blockhash fetch); that an old plan hash cannot re-arm a new
// lifetime even when the semantic intent hash is unchanged; that a mutated plan
// is refused; that fee quoting fails closed; and that concurrent review/run and
// crash/restart behave. It also asserts reconciliation of a live signed attempt
// needs no approval and mints no signature.
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { WorkflowPublicationRuntime, WorkflowRuntimeError } from "../src/workflow-runtime.ts";
import { LocalKeyPublicationSigner } from "../src/publication-signer.ts";
import { WorkflowPublicationStore } from "../src/workflow-publication.ts";
import { defaultKeyFile, ensureKeyPair } from "../scripts/live-demo-key-store.ts";
import { isolatedPostgres } from "./support/postgres.ts";
import {
  append, approvalService, approve, APPROVAL_ACTOR, APPROVAL_DEVICE, CONFIG_PDA, FakeChain, KEYS, PROGRAM_ID, REGISTRY,
  TEST_APPROVAL_PUBLIC_KEY, TEST_CLUSTER, TEST_GENESIS,
} from "./support/publication-fake-chain.ts";

const runtimeFor = (pool: Parameters<typeof append>[0], chain: FakeChain, signer: LocalKeyPublicationSigner, extra: Record<string, unknown> = {}) =>
  new WorkflowPublicationRuntime(pool, chain, signer, {
    registryId: REGISTRY, programId: PROGRAM_ID, configPda: CONFIG_PDA,
    operatorKeyId: "synthetic-operator", keys: KEYS, cluster: TEST_CLUSTER, genesisHash: TEST_GENESIS, ...extra,
  }, approvalService());

const approved = (attemptPlanHash: string) => ({ attemptPlanHash, actor: APPROVAL_ACTOR, device: APPROVAL_DEVICE });

async function setup(t: Parameters<typeof isolatedPostgres>[0]): Promise<{ pool: any; chain: FakeChain; signer: LocalKeyPublicationSigner; runtime: WorkflowPublicationRuntime; home: string }> {
  const { pool } = await isolatedPostgres(t);
  const home = await mkdtemp(join(tmpdir(), "onelayer-attempt-approval-"));
  t.after(() => rm(home, { recursive: true, force: true }));
  await ensureKeyPair({ home });
  const chain = new FakeChain();
  const signer = await LocalKeyPublicationSigner.create(defaultKeyFile({ home }), {
    registryId: REGISTRY, programId: PROGRAM_ID, configPda: String(CONFIG_PDA),
    cluster: TEST_CLUSTER, genesisHash: TEST_GENESIS, approvalPublicKey: TEST_APPROVAL_PUBLIC_KEY,
  }, { home });
  return { pool, chain, signer, runtime: runtimeFor(pool, chain, signer), home };
}

const planMismatch = (error: unknown) =>
  error instanceof WorkflowRuntimeError && error.status === 409 && error.code === "PUBLICATION_ATTEMPT_PLAN_MISMATCH";
const approvalRequired = (error: unknown) =>
  error instanceof WorkflowRuntimeError && error.status === 409 && error.code === "PUBLICATION_INTENT_APPROVAL_REQUIRED";
const code = (value: string) => (error: unknown) => (error as { code?: string }).code === value;

test("review reserves exact bytes; run signs them; an old plan hash cannot re-arm after expiry", { timeout: 60_000 }, async t => {
  const { pool, chain, runtime } = await setup(t);
  await append(pool, "R-1", { name: "Ada", amount: 42 });

  const reviewed = await runtime.review(REGISTRY, "worker-a");
  assert.match(reviewed.review.intentHash, /^[0-9a-f]{64}$/);
  assert.match(String(reviewed.review.attemptPlanHash), /^[0-9a-f]{64}$/);
  assert.equal(reviewed.review.attemptNo, 1);
  assert.equal(reviewed.review.feeLamports, "5000");
  assert.equal(reviewed.review.feeLimitLamports, "100000");
  assert.match(String(reviewed.review.messageBase64), /^[A-Za-z0-9+/]+=*$/);
  assert.equal(chain.sent.length, 0, "review signs and sends nothing");
  // Re-review is idempotent: the same valid reservation and the same plan hash.
  const rere = await runtime.review(REGISTRY, "worker-a");
  assert.equal(rere.review.attemptPlanHash, reviewed.review.attemptPlanHash);
  assert.equal(Number((await pool.query("SELECT count(*) AS n FROM wf_publication_tx")).rows[0].n), 1);

  chain.mode = "drop";
  const first = await runtime.run(REGISTRY, "worker-a", approved(reviewed.review.attemptPlanHash!));
  assert.equal(first.status, "SUBMITTED");
  assert.equal(chain.sent.length, 1);

  // The signed message/blockhash/height/fee/plan are EXACTLY what was reviewed.
  const row = (await pool.query(
    `SELECT t.message_bytes, t.recent_blockhash, t.last_valid_block_height::text AS lvbh, t.fee_lamports::text AS fee,
            t.fee_limit_lamports::text AS feelimit, t.plan_hash, t.cluster, s.signed_bytes
       FROM wf_publication_tx t JOIN wf_publication_tx_signed s USING(attempt_id)`,
  )).rows[0];
  assert.equal(row.message_bytes.toString("base64"), reviewed.review.messageBase64, "signed message == reviewed reserved message");
  assert.equal(row.recent_blockhash, reviewed.review.blockhash, "signed blockhash == reviewed reserved blockhash");
  assert.equal(row.lvbh, reviewed.review.lastValidBlockHeight);
  assert.equal(row.fee, reviewed.review.feeLamports);
  assert.equal(row.feelimit, reviewed.review.feeLimitLamports);
  assert.equal(row.cluster, reviewed.review.cluster);
  assert.equal(row.plan_hash, reviewed.review.attemptPlanHash);

  // Expire the attempt. Without an approval the publisher must not mint a new
  // signature; it may only transition the live attempt to EXPIRED.
  chain.advance(151n);
  await assert.rejects(runtime.run(REGISTRY, "worker-a"), approvalRequired);
  assert.equal(chain.sent.length, 1);

  // Semantic intent is unchanged, but the lifetime is not: a fresh review yields
  // a new plan hash and a new blockhash.
  const again = await runtime.review(REGISTRY, "worker-a");
  assert.equal(again.review.intentHash, reviewed.review.intentHash, "semantic content hash is stable");
  assert.notEqual(again.review.attemptPlanHash, reviewed.review.attemptPlanHash);
  assert.notEqual(again.review.blockhash, reviewed.review.blockhash);
  assert.equal(again.review.attemptNo, 2);

  // The OLD plan hash cannot re-arm the new lifetime.
  await assert.rejects(runtime.run(REGISTRY, "worker-a", approved(reviewed.review.attemptPlanHash!)), planMismatch);
  assert.equal(chain.sent.length, 1, "a stale plan hash produces no signature");

  chain.mode = "land";
  const second = await runtime.run(REGISTRY, "worker-a", approved(again.review.attemptPlanHash!));
  assert.equal(second.status, "SUBMITTED");
  assert.equal(second.status === "SUBMITTED" && second.attemptNo, 2);
  assert.equal(chain.sent.length, 2);
  assert.equal((await runtime.run(REGISTRY, "worker-a")).status, "FINALIZED");
  assert.equal(chain.sent.length, 2);
});

test("the REAL signer never signs without an exact reserved-plan receipt (H4)", { timeout: 60_000 }, async t => {
  const { pool, chain, signer, runtime } = await setup(t);
  await append(pool, "R-1", { value: 1 });
  const store = new WorkflowPublicationStore(pool);
  const lease = (await store.claim(REGISTRY, "worker-a"))!;
  // Default step, and the removed allowNewWork flag alone, must not reserve/sign/send.
  await assert.rejects(runtime.publisher.step(lease), code("PUBLICATION_INTENT_APPROVAL_REQUIRED"));
  await assert.rejects(runtime.publisher.step(lease, { allowNewWork: true } as unknown as { approval?: never }), code("PUBLICATION_INTENT_APPROVAL_REQUIRED"));
  assert.equal(chain.sent.length, 0);
  assert.equal(Number((await pool.query("SELECT count(*) AS n FROM wf_publication_tx_signed")).rows[0].n), 0);
  // Review reserves but signs nothing; only the receipt for that exact plan signs.
  const review = await runtime.publisher.review(lease);
  await assert.rejects(runtime.publisher.step(lease), code("PUBLICATION_INTENT_APPROVAL_REQUIRED"));
  chain.mode = "drop";
  const submitted = await runtime.publisher.step(lease, { approval: approve(lease.operationId, review.intentHash, review.attemptPlanHash!) });
  assert.equal(submitted.status, "SUBMITTED");
  assert.equal(chain.sent.length, 1);
  const row = (await pool.query("SELECT message_bytes FROM wf_publication_tx WHERE attempt_no=1")).rows[0];
  assert.equal(row.message_bytes.toString("base64"), review.messageBase64, "signed exactly the reserved bytes");
});

test("a live signed attempt reconciles without approval and without a new signature (timeout recovery)", { timeout: 60_000 }, async t => {
  const { pool, chain, runtime } = await setup(t);
  await append(pool, "R-1", { value: 1 });
  const reviewed = await runtime.review(REGISTRY, "worker-a");
  chain.mode = "land-then-throw";
  const unknown = await runtime.run(REGISTRY, "worker-a", approved(reviewed.review.attemptPlanHash!));
  assert.equal(unknown.status, "UNKNOWN");
  assert.equal(chain.sent.length, 1);
  // No approval presented; reconciliation completes the stored signed attempt.
  const done = await runtime.run(REGISTRY, "worker-a");
  assert.equal(done.status, "FINALIZED");
  assert.equal(chain.sent.length, 1, "no re-send, no new attempt, no new signature");
});

test("fee quoting fails closed: unavailable or over the bound reserves nothing", { timeout: 60_000 }, async t => {
  const { pool, chain, signer, runtime } = await setup(t);
  await append(pool, "R-1", { value: 1 });

  chain.feeQuote = null;
  await assert.rejects(runtime.review(REGISTRY, "worker-a"), code("PUBLICATION_FEE_QUOTE_UNAVAILABLE"));
  assert.equal(Number((await pool.query("SELECT count(*) AS n FROM wf_publication_tx")).rows[0].n), 0);

  chain.feeQuote = 5_000n;
  const tight = runtimeFor(pool, chain, signer, { maxFeeLamports: 1_000n });
  await assert.rejects(tight.review(REGISTRY, "worker-a"), code("PUBLICATION_FEE_EXCEEDS_LIMIT"));
  assert.equal(Number((await pool.query("SELECT count(*) AS n FROM wf_publication_tx")).rows[0].n), 0, "no reservation without a bounded fee quote");
  assert.equal(chain.sent.length, 0);
});

test("crash/restart between review and run signs the reserved plan; concurrent review/run reserves once", { timeout: 60_000 }, async t => {
  const { pool, chain, signer, runtime } = await setup(t);
  await append(pool, "R-1", { value: 1 });
  const reviewed = await runtime.review(REGISTRY, "worker-a");

  // A fresh runtime instance (simulated restart) with the same worker reuses the
  // durable reservation and signs exactly it.
  const restarted = runtimeFor(pool, chain, signer);
  chain.mode = "land";
  const submitted = await restarted.run(REGISTRY, "worker-a", approved(reviewed.review.attemptPlanHash!));
  assert.equal(submitted.status, "SUBMITTED");
  assert.equal(chain.sent.length, 1);
  assert.equal((await restarted.run(REGISTRY, "worker-a")).status, "FINALIZED");

  // Concurrent review/run on a second operation: at most one reservation and no
  // duplicate signature.
  await append(pool, "R-2", { value: 2 });
  const reviewed2 = await runtime.review(REGISTRY, "worker-b");
  const results = await Promise.allSettled([
    runtime.review(REGISTRY, "worker-b"),
    runtime.run(REGISTRY, "worker-b", approved(reviewed2.review.attemptPlanHash!)),
  ]);
  const op2 = reviewed2.operationId;
  assert.equal(Number((await pool.query("SELECT count(*) AS n FROM wf_publication_tx WHERE operation_id=$1", [op2])).rows[0].n), 1, "exactly one reservation");
  assert.equal(chain.sent.length <= 2, true, "no ambiguous duplicate send");
  assert.equal(results.length, 2);
});
