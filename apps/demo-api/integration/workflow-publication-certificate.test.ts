// End-to-end workflow -> durable publication -> certificate -> verifier.
//
// Proves the vertical slice on a real disposable PostgreSQL and the finalized
// fake chain: a committed workflow version is reviewed, approved by exact intent
// hash, published, anchored, turned into a Certificate Package, and verified by
// the real verifier code against the same anchor. It also asserts the honest
// lifecycle boundary (V2 never claims CURRENT) and the approval gate (no unseen
// signing).
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey } from "node:crypto";
import test from "node:test";
import { address, getAddressEncoder, getBase58Encoder } from "@solana/kit";
import { decodeCertificatePackageBase64url } from "../../verifier/src/certificate-codec.ts";
import { verifyCertificateV2 } from "../../verifier/src/verify-v2.ts";
import type { ChainReader, IncidentIndex, ObservedAnchor, ObservedRegistry } from "../../verifier/src/verify.ts";
import type { TrustPolicy } from "../../verifier/src/trust-policy.ts";
import { registryIdHash } from "../../../packages/canonical-ts/src/index.ts";
import { WorkflowPublicationRuntime } from "../src/workflow-runtime.ts";
import { issueWorkflowCertificate } from "../src/workflow-certificate.ts";
import { isolatedPostgres } from "./support/postgres.ts";
import { approvalService, APPROVAL_ACTOR, APPROVAL_DEVICE, CONFIG_PDA, FakeChain, PROGRAM_ID, REGISTRY, SEGMENT_PDA, TEST_CLUSTER, TEST_GENESIS, TestSigner, append } from "./support/publication-fake-chain.ts";

const GENESIS = "synthetic-genesis";
const ISSUER_SEED = new Uint8Array(32).fill(9);
const ISSUER_KEY_ID = "synthetic-demo-issuer-1";
const encoder = getAddressEncoder();
const base58 = getBase58Encoder();

function trustPolicy(programId: string, configPda: string): TrustPolicy {
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), ISSUER_SEED]),
    format: "der", type: "pkcs8",
  });
  const publicKey = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);
  return {
    version: 1, revision: 1, validUntil: "2099-01-01T00:00:00Z", genesisHash: GENESIS,
    registryId: REGISTRY, programIdHex: Buffer.from(encoder.encode(address(programId))).toString("hex"),
    configPdaHex: Buffer.from(encoder.encode(address(configPda))).toString("hex"),
    schemaVersions: [1], registryVersions: ["3"],
    issuers: [{ keyId: ISSUER_KEY_ID, publicKeyHex: Buffer.from(publicKey).toString("hex"), algorithm: "Ed25519",
      validFrom: "2020-01-01T00:00:00Z", validUntil: "2099-01-01T00:00:00Z", revoked: false }],
  } as unknown as TrustPolicy;
}

function verifierChain(chain: FakeChain, anchorRow: any, intent: any): ChainReader {
  return {
    async getGenesisHash() { return GENESIS; },
    async getRegistryConfig(_body): Promise<ObservedRegistry> {
      return { configPda: new Uint8Array(encoder.encode(CONFIG_PDA)), programId: new Uint8Array(encoder.encode(PROGRAM_ID)), registryIdHash: registryIdHash(REGISTRY), paused: false };
    },
    async getAnchor(_body): Promise<ObservedAnchor> {
      const segmentPda = new Uint8Array(encoder.encode(address(String(anchorRow.segment_pda))));
      return {
        registryConfigPda: new Uint8Array(encoder.encode(CONFIG_PDA)), programId: new Uint8Array(encoder.encode(PROGRAM_ID)),
        segmentPda, derivedSegmentPda: segmentPda,
        batchSequence: BigInt(intent.batchSequence), registryVersion: BigInt(intent.registryVersion),
        merkleRoot: Uint8Array.from(Buffer.from(intent.merkleRoot, "hex")), manifestHash: Uint8Array.from(Buffer.from(intent.manifestHash, "hex")),
        transactionSignature: new Uint8Array(base58.encode(String(anchorRow.signature))),
        slot: BigInt(anchorRow.slot), commitment: "finalized",
      };
    },
    async getFinalizedHeadSlot() { return chain.slot; },
  };
}

const incidentsFor = (chain: FakeChain): IncidentIndex => ({
  async query(registryId) { return { registryId, indexedThroughSlot: chain.slot, incidents: [] }; },
});

test("workflow -> reviewed publication -> certificate verifies; lifecycle stays honest", { timeout: 60_000 }, async context => {
  const { pool } = await isolatedPostgres(context);
  const chain = new FakeChain();
  const signer = new TestSigner();
  const runtime = new WorkflowPublicationRuntime(pool, chain, signer, {
    registryId: REGISTRY, programId: PROGRAM_ID, configPda: CONFIG_PDA, operatorKeyId: "synthetic-operator", keys: { idKey: new Uint8Array(32).fill(7), fieldKeyMaster: new Uint8Array(32).fill(8) },
    cluster: TEST_CLUSTER, genesisHash: TEST_GENESIS,
  }, approvalService());
  await append(pool, "R-1", { name: "Ada", amount: 42 });

  // 1. Review builds and exposes the exact durable intent without sending.
  const pending = await runtime.review(REGISTRY, "worker-1");
  assert.match(pending.review.intentHash, /^[0-9a-f]{64}$/);
  assert.equal(pending.review.members.length, 1);
  assert.equal(pending.review.members[0]!.recordId, "R-1");
  assert.equal(pending.review.operator, String(signer.address));
  assert.equal(pending.review.simulation?.ok, true);
  assert.equal(chain.sent.length, 0, "review must not send");

  // 2. Running without the reviewed attempt plan refuses to sign.
  await assert.rejects(runtime.run(REGISTRY, "worker-1"), (error: { code?: string }) => error.code === "PUBLICATION_INTENT_APPROVAL_REQUIRED");
  assert.equal(chain.sent.length, 0, "no unseen signing");

  // 3a. A wrong semantic intent hash is refused.
  await assert.rejects(runtime.run(REGISTRY, "worker-1", { intentHash: "00".repeat(32) }), (error: { code?: string }) => error.code === "PUBLICATION_INTENT_APPROVAL_MISMATCH");
  // 3b. A wrong/stale per-attempt plan hash is refused.
  await assert.rejects(runtime.run(REGISTRY, "worker-1", { attemptPlanHash: "00".repeat(32), actor: APPROVAL_ACTOR, device: APPROVAL_DEVICE }), (error: { code?: string }) => error.code === "PUBLICATION_ATTEMPT_PLAN_MISMATCH");
  assert.equal(chain.sent.length, 0);

  // 4. Submitting the exact reviewed attempt plan publishes, anchors and finalizes.
  const submitted = await runtime.run(REGISTRY, "worker-1", { attemptPlanHash: pending.review.attemptPlanHash!, actor: APPROVAL_ACTOR, device: APPROVAL_DEVICE });
  assert.equal(submitted.status, "SUBMITTED");
  assert.equal(chain.sent.length, 1);
  const finalized = await runtime.run(REGISTRY, "worker-1");
  assert.equal(finalized.status, "FINALIZED");
  assert.equal((await pool.query("SELECT state FROM wf_publication WHERE operation_id=$1", [pending.operationId])).rows[0].state, "FINALIZED");

  const anchorRow = (await pool.query(
    "SELECT segment_pda, signature, slot::text, batch_sequence::text FROM wf_publication_anchor WHERE operation_id=$1",
    [pending.operationId],
  )).rows[0];
  const intent = JSON.parse((await pool.query("SELECT intent_bytes FROM wf_publication_intent WHERE operation_id=$1", [pending.operationId])).rows[0].intent_bytes.toString("utf8"));

  const deps = {
    pool, registryId: REGISTRY, programId: PROGRAM_ID,
    keys: { idKey: new Uint8Array(32).fill(7), fieldKeyMaster: new Uint8Array(32).fill(8) },
    issuerSecretKey: ISSUER_SEED, issuerKeyId: ISSUER_KEY_ID, publicBaseUrl: "http://127.0.0.1:8090", now: () => new Date("2026-09-24T12:05:00Z"),
  };
  const certificate = await issueWorkflowCertificate(deps, { operationId: pending.operationId, recordId: "R-1", version: 1 });
  assert.equal(certificate.disclosureMode, "FULL_RECORD");
  assert.equal(certificate.replayed, false);

  // Idempotent: the same command returns the same certificate.
  const replay = await issueWorkflowCertificate(deps, { operationId: pending.operationId, recordId: "R-1", version: 1 });
  assert.equal(replay.replayed, true);
  assert.equal(replay.certificateId, certificate.certificateId);

  // 5. The real verifier proves the certificate against the finalized anchor.
  const stored = (await pool.query("SELECT package_base64url FROM demo_certificate WHERE certificate_id=$1", [certificate.certificateId])).rows[0];
  const signed = decodeCertificatePackageBase64url(stored.package_base64url);
  const result = await verifyCertificateV2(signed, verifierChain(chain, anchorRow, intent), incidentsFor(chain), { trustPolicy: trustPolicy(PROGRAM_ID, CONFIG_PDA) });
  assert.equal(result.proofs.status, "VERIFIED");
  assert.equal(result.registry.status, "CHECKED");
  assert.equal(result.incidents.status, "CHECKED");
  // Honest lifecycle: an advisory source is reported, never CURRENT.
  assert.equal(result.status, "UNKNOWN");
  assert.equal(result.lifecycle.status === "UNAUTHENTICATED" || result.lifecycle.status === "UNKNOWN", true);
  assert.equal(result.disclosedFields?.["payload.name"], "Ada");
  assert.equal(result.disclosedFields?.operation, "upsert");

  // 6. Selective disclosure still verifies and omitted fields are not exposed.
  const selective = await issueWorkflowCertificate(deps, { operationId: pending.operationId, recordId: "R-1", version: 1, disclosedPaths: ["payload.name"] });
  assert.equal(selective.disclosureMode, "SELECTIVE_FIELDS");
  const selectiveStored = (await pool.query("SELECT package_base64url FROM demo_certificate WHERE certificate_id=$1", [selective.certificateId])).rows[0];
  const selectiveSigned = decodeCertificatePackageBase64url(selectiveStored.package_base64url);
  const selectiveResult = await verifyCertificateV2(selectiveSigned, verifierChain(chain, anchorRow, intent), incidentsFor(chain), { trustPolicy: trustPolicy(PROGRAM_ID, CONFIG_PDA) });
  assert.equal(selectiveResult.proofs.status, "VERIFIED");
  assert.equal(selectiveResult.disclosedFields?.["payload.name"], "Ada");
  assert.equal(selectiveResult.disclosedFields?.["payload.amount"], undefined);

  // 7. A version that is not a member of the operation is refused.
  await assert.rejects(
    issueWorkflowCertificate(deps, { operationId: pending.operationId, recordId: "R-1", version: 2 }),
    (error: { code?: string }) => error.code === "PUBLICATION_VERSION_NOT_IN_OPERATION",
  );
});
