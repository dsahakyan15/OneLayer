// Ticket 09 review r1: the new HTTP surface itself is exercised (R2), with real
// cookie/CSRF authentication, resource scope, the exact-intent approval gate and
// certificate replay on a disposable PostgreSQL + fake chain — but with the REAL
// LocalKeyPublicationSigner, never the TestSigner. Covers H1 (`payload.*`
// disclosure over HTTP) and H2 (normalized full/reordered/omitted idempotency,
// coded unknown paths, no raw pg codes).
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { address } from "@solana/kit";
import { decodeCertificatePackageBase64url } from "../../verifier/src/certificate-codec.ts";
import { validateSignedTransaction } from "../src/admin-transaction.ts";
import { CSRF_HEADER, SESSION_COOKIE, type AdminSession } from "../src/admin-session.ts";
import { routeAdmin, type AdminContext, type AdminRequest } from "../src/admin.ts";
import { PostgresSessionStore } from "../src/postgres-session.ts";
import { LocalKeyPublicationSigner } from "../src/publication-signer.ts";
import { WorkflowPublicationRuntime } from "../src/workflow-runtime.ts";
import { issueWorkflowCertificate } from "../src/workflow-certificate.ts";
import { defaultKeyFile, ensureKeyPair } from "../scripts/live-demo-key-store.ts";
import { isolatedPostgres } from "./support/postgres.ts";
import {
  append, approvalService, APPROVAL_ACTOR, APPROVAL_DEVICE, CONFIG_PDA, FakeChain, KEYS, PROGRAM_ID, REGISTRY,
  TEST_APPROVAL_PUBLIC_KEY, TEST_CLUSTER, TEST_GENESIS, TestSigner,
} from "./support/publication-fake-chain.ts";

const ISSUER_SEED = new Uint8Array(32).fill(9);
const UNRESTRICTED = { version: 1, grants: [{ registryId: REGISTRY, recordIds: "all", fieldPaths: "all", actions: ["records.read", "certificates.read", "records.write", "certificates.export"] }] };

function header(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

/** Minimal real HTTP surface over the actual dispatcher: cookies, CSRF headers,
 * status codes and JSON bodies exactly as `main.ts` serves them. */
async function serve(context: AdminContext): Promise<{ url: string; close: () => Promise<void> }> {
  const server = createServer(async (request, response) => {
    try {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk as Uint8Array));
      const raw = Buffer.concat(chunks).toString("utf8");
      const body = raw.length === 0 ? null : JSON.parse(raw) as Record<string, unknown>;
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      const adminRequest: AdminRequest = {
        method: request.method ?? "GET", path: url.pathname, query: url.searchParams, body,
        cookieHeader: request.headers.cookie, csrfHeader: header(request.headers[CSRF_HEADER]),
        idempotencyKey: undefined, originHeader: header(request.headers.origin),
      };
      const result = await routeAdmin(context, adminRequest);
      response.writeHead(result.status, { "content-type": "application/json" });
      response.end(JSON.stringify(result.body));
    } catch (error) {
      response.writeHead(500, { "content-type": "application/json" });
      response.end(JSON.stringify({ code: "TEST_SERVER_ERROR", message: (error as Error).message }));
    }
  });
  server.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.once("listening", resolve); });
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}`, close: () => new Promise((resolve) => server.close(() => resolve())) };
}

test("HTTP review/run/certificate: real signer, exact approval, normalized replay and scope", { timeout: 120_000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  const home = await mkdtemp(join(tmpdir(), "onelayer-http-signer-"));
  t.after(() => rm(home, { recursive: true, force: true }));
  const created = await ensureKeyPair({ home });
  const chain = new FakeChain();
  const signer = await LocalKeyPublicationSigner.create(defaultKeyFile({ home }), {
    registryId: REGISTRY, programId: PROGRAM_ID, configPda: String(CONFIG_PDA),
    cluster: TEST_CLUSTER, genesisHash: TEST_GENESIS, approvalPublicKey: TEST_APPROVAL_PUBLIC_KEY,
  }, { home });
  const runtime = new WorkflowPublicationRuntime(pool, chain, signer, {
    registryId: REGISTRY, programId: PROGRAM_ID, configPda: CONFIG_PDA, operatorKeyId: "synthetic-operator", keys: KEYS,
    cluster: TEST_CLUSTER, genesisHash: TEST_GENESIS,
  }, approvalService());
  const sessions = new PostgresSessionStore(pool, [], { oidcOnly: true });
  const provision = async (username: string, role: "operator" | "auditor", resourcePolicy: unknown): Promise<AdminSession> => {
    await sessions.provisionOidcAccount({ username, issuer: "https://synthetic.example", subject: username,
      access: { role, registryIds: [REGISTRY] }, resourcePolicy }, "bootstrap");
    await sessions.enrollDevice(username, username, "bootstrap");
    return (await sessions.loginOidc({ issuer: "https://synthetic.example", subject: username, deviceId: username, expiresAt: Date.now() + 600_000 }))!;
  };
  const operator = await provision("operator-1", "operator", UNRESTRICTED);
  const auditor = await provision("auditor-1", "auditor", UNRESTRICTED);
  const scoped = await provision("scoped-1", "operator", { version: 1, grants: [{ registryId: REGISTRY, recordIds: ["R-1"], fieldPaths: ["payload.name"], actions: ["records.read", "certificates.read"] }] });

  const context = {
    pool, sessions, rpc: {} as AdminContext["rpc"], registryId: REGISTRY,
    programId: PROGRAM_ID, configPda: CONFIG_PDA, issuerSecretKey: ISSUER_SEED,
    publicWebBaseUrl: "http://127.0.0.1:8091", now: () => new Date(),
    publication: { runtime, keys: KEYS, operatorKeyId: "synthetic-operator" },
  } as unknown as AdminContext;
  const { url, close } = await serve(context);
  t.after(close);
  const call = (path: string, options: { method?: string; session?: AdminSession; body?: Record<string, unknown>; csrf?: boolean } = {}) =>
    fetch(url + path, {
      method: options.method ?? (options.body === undefined ? "GET" : "POST"),
      headers: {
        ...(options.session === undefined ? {} : { cookie: `${SESSION_COOKIE}=${options.session.sessionId}` }),
        ...(options.csrf === false || options.body === undefined || options.session === undefined ? {} : { [CSRF_HEADER]: options.session.csrfToken }),
        ...(options.body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
    });
  const json = async (response: Response): Promise<any> => response.json();

  await append(pool, "R-1", { name: "Ada", amount: 42 });

  // Authentication is real: no cookie, no CSRF, and role permissions are enforced.
  assert.equal((await call("/v2/admin/workflow/publications")).status, 401);
  assert.equal((await call("/v2/admin/workflow/publications/review", { session: operator, body: {}, csrf: false })).status, 403);
  assert.equal((await call("/v2/admin/workflow/publications/review", { session: auditor, body: {} })).status, 403);
  // Forbidden role cannot trigger the approval boundary either, with or without CSRF.
  assert.equal((await call("/v2/admin/workflow/publications/run", { session: auditor, body: {} })).status, 403);
  assert.equal((await call("/v2/admin/workflow/publications/run", { session: operator, body: {}, csrf: false })).status, 403);
  assert.equal((await call("/v2/admin/workflow/publications", { session: auditor })).status, 200);

  // Review reserves the exact unsigned attempt to approve and sends nothing.
  const reviewed = await call("/v2/admin/workflow/publications/review", { session: operator, body: {} });
  assert.equal(reviewed.status, 200);
  const reviewBody = await json(reviewed) as { operationId: string; review: any };
  assert.match(reviewBody.review.intentHash, /^[0-9a-f]{64}$/);
  assert.match(String(reviewBody.review.attemptPlanHash), /^[0-9a-f]{64}$/);
  assert.equal(reviewBody.review.operator, String(created.address));
  assert.equal(reviewBody.review.operator, String(signer.address));
  assert.equal(reviewBody.review.simulation?.ok, true);
  assert.match(String(reviewBody.review.blockhash), /^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
  assert.equal(reviewBody.review.hasLiveSignedAttempt, false);
  assert.equal(reviewBody.review.feeLamports, "5000");
  assert.equal(chain.sent.length, 0, "review must not sign or send");
  // Review reserved exactly one unsigned attempt for the operator to approve.
  assert.equal(Number((await pool.query("SELECT count(*) AS n FROM wf_publication_tx WHERE operation_id=$1", [reviewBody.operationId])).rows[0].n), 1);
  assert.equal(Number((await pool.query("SELECT count(*) AS n FROM wf_publication_tx_signed")).rows[0].n), 0);

  const list = await json(await call("/v2/admin/workflow/publications", { session: operator })) as { operations: any[] };
  assert.deepEqual(list.operations.map((op) => [op.operationId, op.state, op.recordCount]), [[reviewBody.operationId, "OPEN", 1]]);

  // The approval gate: no approval, wrong intent hash, wrong plan hash, then the
  // exact reviewed attempt plan.
  const required = await call("/v2/admin/workflow/publications/run", { session: operator, body: { operationId: reviewBody.operationId } });
  assert.equal(required.status, 409);
  assert.deepEqual(await json(required), { code: "PUBLICATION_INTENT_APPROVAL_REQUIRED" });
  assert.equal(chain.sent.length, 0);
  const mismatch = await call("/v2/admin/workflow/publications/run", { session: operator, body: { operationId: reviewBody.operationId, approvedIntentHash: "00".repeat(32) } });
  assert.equal(mismatch.status, 409);
  assert.deepEqual(await json(mismatch), { code: "PUBLICATION_INTENT_APPROVAL_MISMATCH" });
  assert.equal(chain.sent.length, 0);
  const stalePlan = await call("/v2/admin/workflow/publications/run", { session: operator, body: { operationId: reviewBody.operationId, approvedAttemptPlanHash: "00".repeat(32) } });
  assert.equal(stalePlan.status, 409);
  assert.deepEqual(await json(stalePlan), { code: "PUBLICATION_ATTEMPT_PLAN_MISMATCH" });
  assert.equal(chain.sent.length, 0);

  const run = await call("/v2/admin/workflow/publications/run", { session: operator, body: { operationId: reviewBody.operationId, approvedAttemptPlanHash: reviewBody.review.attemptPlanHash } });
  assert.equal(run.status, 200);
  const submitted = await json(run) as { status: string; attemptNo: number; signature: string };
  assert.deepEqual([submitted.status, submitted.attemptNo], ["SUBMITTED", 1]);
  assert.equal(chain.sent.length, 1);
  // The stored signature is a real ed25519 signature over the reserved message,
  // and the signed message is exactly the one review committed to.
  const stored = (await pool.query(
    `SELECT t.message_bytes, t.recent_blockhash, t.last_valid_block_height::text AS lvbh, t.plan_hash, s.signed_bytes
       FROM wf_publication_tx t JOIN wf_publication_tx_signed s USING(attempt_id) WHERE t.operation_id=$1`,
    [reviewBody.operationId],
  )).rows[0];
  assert.equal(validateSignedTransaction(stored.signed_bytes.toString("base64"), stored.message_bytes.toString("base64"), address(String(created.address))), submitted.signature);
  assert.equal(stored.message_bytes.toString("base64"), reviewBody.review.messageBase64, "the signed message is exactly the reviewed, reserved one");
  assert.equal(stored.recent_blockhash, reviewBody.review.blockhash, "the signed blockhash is exactly the reviewed, reserved one");
  assert.equal(stored.lvbh, reviewBody.review.lastValidBlockHeight);
  assert.equal(stored.plan_hash, reviewBody.review.attemptPlanHash);

  // Reconciliation without a fresh approval finalizes the same signed attempt.
  const finalized = await json(await call("/v2/admin/workflow/publications/run", { session: operator, body: { operationId: reviewBody.operationId } })) as { status: string };
  assert.equal(finalized.status, "FINALIZED");
  assert.equal(chain.sent.length, 1);

  const certificate = (body: Record<string, unknown>, session: AdminSession = operator) =>
    call(`/v2/admin/workflow/publications/${reviewBody.operationId}/certificate`, { session, body });

  // H2: an explicit list covering every field, omitted disclosure and a
  // reordered list all normalize to one FULL_RECORD certificate.
  const explicit = await certificate({ recordId: "R-1", version: 1, disclosedPaths: ["operation", "payload.name", "payload.amount"] });
  assert.equal(explicit.status, 201);
  const explicitBody = await json(explicit) as { certificateId: string; disclosureMode: string; replayed: boolean; recordVersion: string };
  assert.equal(explicitBody.disclosureMode, "FULL_RECORD");
  assert.equal(explicitBody.replayed, false);
  assert.equal(explicitBody.recordVersion, "1");
  const omitted = await certificate({ recordId: "R-1", version: 1 });
  assert.equal(omitted.status, 200);
  const omittedBody = await json(omitted) as { certificateId: string; disclosureMode: string; replayed: boolean };
  assert.deepEqual([omittedBody.certificateId, omittedBody.disclosureMode, omittedBody.replayed], [explicitBody.certificateId, "FULL_RECORD", true]);
  const reordered = await certificate({ recordId: "R-1", version: 1, disclosedPaths: ["payload.amount", "operation", "payload.name"] });
  assert.equal(reordered.status, 200);
  assert.equal((await json(reordered) as { certificateId: string }).certificateId, explicitBody.certificateId);

  // The text-typed field reaches the package (the committed H1 text branch).
  const packageRow = (await pool.query("SELECT package_base64url FROM demo_certificate WHERE certificate_id=$1", [explicitBody.certificateId])).rows[0];
  const decoded = decodeCertificatePackageBase64url(packageRow.package_base64url);
  assert.deepEqual(decoded.body.disclosedFields["payload.name"], { type: "text", value: "Ada" });
  assert.deepEqual(decoded.body.disclosedFields.operation, { type: "text", value: "upsert" });

  // H1: real `payload.*` grammar over HTTP, and its selective replay.
  const selective = await certificate({ recordId: "R-1", version: 1, disclosedPaths: ["payload.name"] });
  assert.equal(selective.status, 201);
  const selectiveBody = await json(selective) as { certificateId: string; disclosureMode: string; disclosedPaths: string[] };
  assert.equal(selectiveBody.disclosureMode, "SELECTIVE_FIELDS");
  assert.deepEqual(selectiveBody.disclosedPaths, ["payload.name"]);
  const selectiveReplay = await certificate({ recordId: "R-1", version: 1, disclosedPaths: ["payload.name"] });
  assert.equal(selectiveReplay.status, 200);
  assert.equal((await json(selectiveReplay) as { certificateId: string }).certificateId, selectiveBody.certificateId);

  // Coded refusals, never a raw database code.
  const unknownField = await certificate({ recordId: "R-1", version: 1, disclosedPaths: ["payload.absent"] });
  assert.equal(unknownField.status, 400);
  assert.deepEqual(await json(unknownField), { code: "PUBLICATION_DISCLOSURE_PATH_UNKNOWN" });
  assert.deepEqual(await json(await certificate({ recordId: "R-1", version: 1, disclosedPaths: [] })), { code: "DISCLOSED_PATHS_INVALID" });
  assert.deepEqual(await json(await certificate({ recordId: "R-1", version: 1, disclosedPaths: ["payload.a.b"] })), { code: "DISCLOSEDPATH_INVALID" });
  assert.deepEqual(await json(await certificate({ recordId: "R-1", version: 2 })), { code: "PUBLICATION_VERSION_NOT_IN_OPERATION" });
  const malformed = await call(`/v2/admin/workflow/publications/not-a-uuid/certificate`, { session: operator, body: { recordId: "R-1", version: 1 } });
  assert.equal(malformed.status, 400);
  assert.deepEqual(await json(malformed), { code: "OPERATION_ID_INVALID" });
  assert.equal((await certificate({ recordId: "R-1", version: 1 }, auditor)).status, 403);

  // Scope is enforced on both axes even though the scoped session holds
  // certificates.issue: out-of-scope record, out-of-scope field, and FULL all fail.
  const scopedFull = await certificate({ recordId: "R-1", version: 1 }, scoped);
  assert.equal(scopedFull.status, 403);
  assert.deepEqual(await json(scopedFull), { code: "RESOURCE_FORBIDDEN" });
  const scopedField = await certificate({ recordId: "R-1", version: 1, disclosedPaths: ["payload.name", "payload.amount"] }, scoped);
  assert.equal(scopedField.status, 403);
  // The scoped session can issue exactly what its policy allows.
  const scopedAllowed = await certificate({ recordId: "R-1", version: 1, disclosedPaths: ["payload.name"] }, scoped);
  assert.equal(scopedAllowed.status, 200);
  const scopedReplay = await json(scopedAllowed) as { certificateId: string; disclosureMode: string };
  assert.deepEqual([scopedReplay.certificateId, scopedReplay.disclosureMode], [selectiveBody.certificateId, "SELECTIVE_FIELDS"], "same normalized selective disclosure, no second row");
});

test("a concurrent issuance collision recovers to the stored certificate, never a raw 23505", { timeout: 60_000 }, async t => {
  const { pool } = await isolatedPostgres(t);
  const chain = new FakeChain();
  const signer = new TestSigner();
  const runtime = new WorkflowPublicationRuntime(pool, chain, signer, {
    registryId: REGISTRY, programId: PROGRAM_ID, configPda: CONFIG_PDA, operatorKeyId: "synthetic-operator", keys: KEYS,
    cluster: TEST_CLUSTER, genesisHash: TEST_GENESIS,
  }, approvalService());
  await append(pool, "R-1", { name: "Ada", amount: 42 });
  const reviewed = await runtime.review(REGISTRY, "worker-a");
  await runtime.run(REGISTRY, "worker-a", { attemptPlanHash: reviewed.review.attemptPlanHash!, actor: APPROVAL_ACTOR, device: APPROVAL_DEVICE });
  await runtime.run(REGISTRY, "worker-a");
  const deps = {
    pool, registryId: REGISTRY, programId: PROGRAM_ID, keys: KEYS,
    issuerSecretKey: ISSUER_SEED, issuerKeyId: "synthetic-demo-issuer-1",
    publicBaseUrl: "http://127.0.0.1:8090", now: () => new Date("2026-10-07T00:00:00Z"),
  };
  const request = { operationId: reviewed.operationId, recordId: "R-1", version: 1, disclosedPaths: ["payload.amount"] };
  const winner = await issueWorkflowCertificate(deps, request);
  assert.equal(winner.replayed, false);

  // Simulate the true race on one connection: the loser's pre-check must not see
  // the winner, its insert must hit the unique index, and the recovery query must
  // find the winner. Without the coded 23505 recovery this would throw / 500.
  let preCheckHidden = false;
  const racingPool = {
    query: async (sql: string, params?: unknown[]) => {
      if (!preCheckHidden && sql.includes("FROM demo_certificate") && sql.includes("anchor_operation_id")) {
        preCheckHidden = true;
        return { rows: [] };
      }
      return pool.query(sql, params as never);
    },
    connect: async () => {
      const client = await pool.connect();
      return {
        query: async (sql: string, params?: unknown[]) => {
          if (sql.includes("INSERT INTO demo_certificate")) {
            const conflict = new Error("duplicate key value violates unique constraint") as Error & { code?: string };
            conflict.code = "23505";
            throw conflict;
          }
          return client.query(sql, params as never);
        },
        release: () => client.release(),
      };
    },
  } as unknown as typeof pool;
  const raced = await issueWorkflowCertificate({ ...deps, pool: racingPool }, request);
  assert.equal(raced.replayed, true);
  assert.equal(raced.certificateId, winner.certificateId);
  assert.equal(Number((await pool.query(
    `SELECT count(*) AS n FROM demo_certificate WHERE registry_id=$1 AND anchor_operation_id=$2 AND internal_record_id='R-1'
       AND record_version=1 AND disclosure_mode='SELECTIVE_FIELDS' AND disclosed_paths=ARRAY['payload.amount']`,
    [REGISTRY, reviewed.operationId],
  )).rows[0].n), 1, "exactly one certificate row for the raced disclosure");
});
