import assert from "node:assert/strict";
import test from "node:test";
import { proof } from "../../../packages/merkle-ts/src/index.ts";
import {
  batchLeafHash,
  buildFieldTree,
  fieldSalt,
  recordCommitment,
  registryIdHash,
  signCertificate,
  type CertificateBody,
  type SignedCertificate,
} from "../../../packages/canonical-ts/src/index.ts";
import {
  verifyCertificate,
  type ChainReader,
  type IncidentIndex,
  type IncidentIndexResponse,
  type LifecycleIndex,
  type ObservedAnchor,
  type ObservedRegistry,
  type RecordLifecycle,
} from "../src/verify.ts";

const signingKey = new Uint8Array(32).fill(7);

function signedCertificate(): SignedCertificate {
  const recordFieldKey = new Uint8Array(32).fill(4);
  const fields = [
    { path: "area", value: { type: "text", value: "1234.50" } as const },
    { path: "status", value: { type: "text", value: "ACTIVE" } as const },
  ];
  const fieldTree = buildFieldTree(recordFieldKey, fields);
  const recordId = new Uint8Array(32).fill(2);
  const commitment = recordCommitment(registryIdHash("gov.registry.land"), recordId, 1n, fieldTree.root);
  const batchLeaf = batchLeafHash(commitment);
  const body: CertificateBody = {
    certificateId: new Uint8Array(16).fill(1),
    registryId: "gov.registry.land",
    issuedAt: "2026-07-31T00:00:00Z",
    recordIdCommitment: recordId,
    recordVersion: 1n,
    schemaVersion: 1,
    disclosureMode: "FULL_RECORD",
    disclosedFields: Object.fromEntries(fields.map((field) => [field.path, field.value])),
    fieldSalts: Object.fromEntries(fields.map((field) => [field.path, fieldSalt(recordFieldKey, field.path)])),
    fieldRoot: fieldTree.root,
    fieldProofs: [],
    batchProof: {
      leafIndex: 0,
      leafHash: batchLeaf,
      siblings: proof([batchLeaf], 0),
      expectedRoot: batchLeaf,
    },
    anchor: {
      batchSequence: 1n,
      registryVersion: 1n,
      merkleRoot: batchLeaf,
      manifestHash: new Uint8Array(32).fill(3),
      solanaProgramId: new Uint8Array(32).fill(4),
      segmentIndex: 0,
      segmentPda: new Uint8Array(32).fill(5),
      transactionSignature: new Uint8Array(64).fill(6),
      anchorSlot: 1_000n,
    },
    issuerKeyId: "pilot-issuer-1",
    issuerPublicKey: new Uint8Array(32),
  };
  return signCertificate(body, signingKey);
}

function observed(signed: SignedCertificate): ObservedAnchor {
  return {
    programId: signed.body.anchor.solanaProgramId,
    segmentPda: signed.body.anchor.segmentPda,
    derivedSegmentPda: signed.body.anchor.segmentPda,
    batchSequence: signed.body.anchor.batchSequence,
    registryVersion: signed.body.anchor.registryVersion,
    merkleRoot: signed.body.anchor.merkleRoot,
    manifestHash: signed.body.anchor.manifestHash,
    transactionSignature: signed.body.anchor.transactionSignature,
    slot: signed.body.anchor.anchorSlot,
    commitment: "finalized",
  };
}

function registry(signed: SignedCertificate, paused = false): ObservedRegistry {
  return { registryIdHash: registryIdHash(signed.body.registryId), paused };
}

function chain(signed: SignedCertificate, overrides: Partial<ObservedAnchor> = {}, head = 1_050n): ChainReader {
  return {
    async getRegistryConfig() {
      return registry(signed);
    },
    async getAnchor() {
      return { ...observed(signed), ...overrides };
    },
    async getFinalizedHeadSlot() {
      return head;
    },
  };
}

function index(response: IncidentIndexResponse | null): IncidentIndex {
  return { async query() { return response; } };
}

test("returns VERIFIED only after finalized anchor and fresh scoped incident index", async () => {
  const signed = signedCertificate();
  const result = await verifyCertificate(
    signed,
    chain(signed),
    index({ registryId: signed.body.registryId, indexedThroughSlot: 1_040n, incidents: [] }),
  );
  assert.equal(result.status, "VERIFIED");
  assert.equal(result.incidentIndexStatus, "CHECKED");
  assert.equal(result.indexLagSlots, "10");
});

test("a paused registry refuses QR verification", async () => {
  const signed = signedCertificate();
  const reader = chain(signed);
  reader.getRegistryConfig = async () => registry(signed, true);
  const result = await verifyCertificate(
    signed,
    reader,
    index({ registryId: signed.body.registryId, indexedThroughSlot: 1_040n, incidents: [] }),
  );
  assert.equal(result.status, "INVALID");
  assert.equal(result.code, "REGISTRY_PAUSED");
});

test("stale watermark cannot produce VERIFIED", async () => {
  const signed = signedCertificate();
  const result = await verifyCertificate(
    signed,
    chain(signed, {}, 1_500n),
    index({ registryId: signed.body.registryId, indexedThroughSlot: 1_100n, incidents: [] }),
  );
  assert.equal(result.status, "VERIFIED_NO_INCIDENT_CHECK");
  assert.equal(result.incidentIndexStatus, "STALE");
});

test("open incident covering the batch produces DISPUTED", async () => {
  const signed = signedCertificate();
  const result = await verifyCertificate(
    signed,
    chain(signed),
    index({
      registryId: signed.body.registryId,
      indexedThroughSlot: 1_040n,
      incidents: [{ firstBatchSequence: 1n, lastBatchSequence: 3n, status: "OPEN" }],
    }),
  );
  assert.equal(result.status, "DISPUTED");
});

test("derived segment PDA mismatch invalidates the certificate", async () => {
  const signed = signedCertificate();
  const result = await verifyCertificate(
    signed,
    chain(signed, { derivedSegmentPda: new Uint8Array(32).fill(9) }),
    index({ registryId: signed.body.registryId, indexedThroughSlot: 1_040n, incidents: [] }),
  );
  assert.equal(result.status, "INVALID");
  assert.equal(result.code, "SEGMENT_PDA_MISMATCH");
});

test("tampered disclosed value fails before chain access", async () => {
  const signed = signedCertificate();
  signed.body.disclosedFields.status = { type: "text", value: "REVOKED" };
  const resigned = signCertificate(signed.body, signingKey);
  let chainCalled = false;
  const reader: ChainReader = {
    async getRegistryConfig() {
      return registry(resigned);
    },
    async getAnchor() {
      chainCalled = true;
      return observed(resigned);
    },
    async getFinalizedHeadSlot() {
      return 1_050n;
    },
  };
  const result = await verifyCertificate(
    resigned,
    reader,
    index({ registryId: resigned.body.registryId, indexedThroughSlot: 1_040n, incidents: [] }),
  );
  assert.equal(result.status, "INVALID");
  assert.equal(result.code, "FIELD_PROOF_INVALID");
  assert.equal(chainCalled, false);
});

function lifecycle(record: RecordLifecycle | null): LifecycleIndex {
  return { async query() { return record; } };
}

const fresh = (signed: SignedCertificate): IncidentIndexResponse => ({
  registryId: signed.body.registryId,
  indexedThroughSlot: 1_040n,
  incidents: [],
});

test("a newer record version downgrades VERIFIED to VERIFIED_HISTORICAL", async () => {
  const signed = signedCertificate();
  const result = await verifyCertificate(signed, chain(signed), index(fresh(signed)), {
    lifecycle: lifecycle({
      registryId: signed.body.registryId,
      currentRecordVersion: 4n,
      certificateStatus: "ACTIVE",
    }),
  });
  assert.equal(result.status, "VERIFIED_HISTORICAL");
  assert.equal(result.code, "RECORD_SUPERSEDED");
  assert.equal(result.recordVersion, "1");
  assert.equal(result.currentRecordVersion, "4");
});

test("a replaced certificate produces SUPERSEDED", async () => {
  const signed = signedCertificate();
  const result = await verifyCertificate(signed, chain(signed), index(fresh(signed)), {
    lifecycle: lifecycle({
      registryId: signed.body.registryId,
      currentRecordVersion: 1n,
      certificateStatus: "SUPERSEDED",
    }),
  });
  assert.equal(result.status, "SUPERSEDED");
  assert.equal(result.certificateLifecycle, "SUPERSEDED");
});

test("an open incident outranks record lifecycle", async () => {
  const signed = signedCertificate();
  const result = await verifyCertificate(
    signed,
    chain(signed),
    index({
      registryId: signed.body.registryId,
      indexedThroughSlot: 1_040n,
      incidents: [{ firstBatchSequence: 1n, lastBatchSequence: 3n, status: "OPEN" }],
    }),
    {
      lifecycle: lifecycle({
        registryId: signed.body.registryId,
        currentRecordVersion: 9n,
        certificateStatus: "SUPERSEDED",
      }),
    },
  );
  assert.equal(result.status, "DISPUTED");
  assert.equal(result.currentRecordVersion, "9");
});

test("unavailable lifecycle keeps the anchored status and reports the gap", async () => {
  const signed = signedCertificate();
  const result = await verifyCertificate(signed, chain(signed), index(fresh(signed)), {
    lifecycle: lifecycle(null),
  });
  assert.equal(result.status, "VERIFIED");
  assert.equal(result.code, "CURRENT_STATUS_UNAVAILABLE");
  assert.match(result.warnings.join(" "), /Current record status/);
});

test("a lifecycle answer for another registry is not trusted", async () => {
  const signed = signedCertificate();
  const result = await verifyCertificate(signed, chain(signed), index(fresh(signed)), {
    lifecycle: lifecycle({
      registryId: "gov.registry.other",
      currentRecordVersion: 9n,
      certificateStatus: "SUPERSEDED",
    }),
  });
  assert.equal(result.status, "VERIFIED");
  assert.equal(result.code, "CURRENT_STATUS_UNAVAILABLE");
});

test("an invalid certificate is never enriched with lifecycle data", async () => {
  const signed = signedCertificate();
  const tampered: SignedCertificate = {
    ...signed,
    body: { ...signed.body, recordVersion: 2n },
  };
  const result = await verifyCertificate(tampered, chain(signed), index(fresh(signed)), {
    lifecycle: lifecycle({
      registryId: signed.body.registryId,
      currentRecordVersion: 9n,
      certificateStatus: "ACTIVE",
    }),
  });
  assert.equal(result.status, "INVALID");
  assert.equal(result.currentRecordVersion, undefined);
});
