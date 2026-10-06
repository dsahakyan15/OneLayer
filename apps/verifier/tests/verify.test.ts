import { verifyCertificateV2 } from "../src/verify-v2.ts";
import assert from "node:assert/strict";
import test from "node:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadTrustPolicy, policyDigest } from "../src/trust-state.ts";
import type { TrustPolicy } from "../src/trust-policy.ts";
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
  verifyCertificate as verifyWithPolicy,
  type VerifyOptions,
  type ChainReader,
  type IncidentIndex,
  type IncidentIndexResponse,
  type LifecycleIndex,
  type ObservedAnchor,
  type ObservedRegistry,
  type RecordLifecycle,
} from "../src/verify.ts";

function verifyCertificate(signed: SignedCertificate, reader: ChainReader, incidents: IncidentIndex, options: VerifyOptions = {}) {
  return verifyWithPolicy(signed, reader, incidents, { trustPolicy: policyFor(signedCertificate()), ...options });
}

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
    registryConfigPda: new Uint8Array(32).fill(8),
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
  return { configPda: new Uint8Array(32).fill(8), programId: signed.body.anchor.solanaProgramId, registryIdHash: registryIdHash(signed.body.registryId), paused };
}

function chain(signed: SignedCertificate, overrides: Partial<ObservedAnchor> = {}, head = 1_050n): ChainReader {
  return {
    async getGenesisHash() { return "synthetic-genesis"; },
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
    async getGenesisHash() { return "synthetic-genesis"; },
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

test("regression: re-signing an anchored disclosure with an unauthorized issuer fails", async () => {
  const original = signedCertificate();
  const forged = signCertificate({ ...original.body, certificateId: new Uint8Array(16).fill(9), issuerKeyId: "attacker" }, new Uint8Array(32).fill(9));
  const result = await verifyCertificate(forged, chain(forged), index(fresh(forged)), { trustPolicy: policyFor(original) } as any);
  assert.equal(result.status, "INVALID");
  assert.equal(result.code, "ISSUER_UNTRUSTED");
});

test("regression: a valid proof under an unauthorized program fails", async () => {
  const original = signedCertificate();
  const forged = signCertificate({ ...original.body, anchor: { ...original.body.anchor, solanaProgramId: new Uint8Array(32).fill(9) } }, signingKey);
  const result = await verifyCertificate(forged, chain(forged), index(fresh(forged)), { trustPolicy: policyFor(original) } as any);
  assert.equal(result.status, "INVALID");
  assert.equal(result.code, "PROGRAM_UNTRUSTED");
});

function policyFor(signed: SignedCertificate): any {
  return { version: 1, revision: 1, validUntil: "2099-01-01T00:00:00Z", genesisHash: "synthetic-genesis", registryId: signed.body.registryId, programIdHex: Buffer.from(signed.body.anchor.solanaProgramId).toString("hex"), configPdaHex: "08".repeat(32), schemaVersions: [1], registryVersions: ["1"], issuers: [{ keyId: signed.body.issuerKeyId, publicKeyHex: Buffer.from(signed.body.issuerPublicKey).toString("hex"), algorithm: "Ed25519", validFrom: "2020-01-01T00:00:00Z", validUntil: "2099-01-01T00:00:00Z", revoked: false }] };
}

test("missing trust policy fails closed before accessing the chain", async () => {
  const signed = signedCertificate();
  let called = false;
  const reader = chain(signed);
  reader.getGenesisHash = async () => { called = true; throw new Error("must not call"); };
  const result = await verifyWithPolicy(signed, reader, index(fresh(signed)));
  assert.equal(result.code, "TRUST_POLICY_UNAVAILABLE");
  assert.equal(result.disclosedFields, undefined);
  assert.equal(called, false);
});

for (const [name, alter, expected] of [
  ["another cluster", (reader: ChainReader) => { reader.getGenesisHash = async () => "other-genesis"; }, "CLUSTER_UNTRUSTED"],
  ["config PDA mismatch", (reader: ChainReader) => { reader.getRegistryConfig = async () => ({ ...registry(signedCertificate()), configPda: new Uint8Array(32).fill(9) }); }, "REGISTRY_CONFIG_UNTRUSTED"],
  ["registry account owner mismatch", (reader: ChainReader) => { reader.getRegistryConfig = async () => ({ ...registry(signedCertificate()), programId: new Uint8Array(32).fill(9) }); }, "REGISTRY_CONFIG_UNTRUSTED"],
  ["ledger of another registry", (reader: ChainReader) => { reader.getAnchor = async () => ({ ...observed(signedCertificate()), registryConfigPda: new Uint8Array(32).fill(9) }); }, "LEDGER_REGISTRY_MISMATCH"],
] as const) {
  test(`trust rejects ${name} despite otherwise valid proofs`, async () => {
    const signed = signedCertificate();
    const reader = chain(signed);
    alter(reader);
    const result = await verifyCertificate(signed, reader, index(fresh(signed)));
    assert.equal(result.status, "INVALID");
    assert.equal(result.code, expected);
    assert.equal(result.disclosedFields, undefined);
  });
}

test("explicit retired key interval permits legitimate historical issuance after rotation", async () => {
  const signed = signedCertificate();
  const policy = policyFor(signed);
  policy.issuers[0].validUntil = "2026-08-01T00:00:00Z";
  policy.issuers.push({ ...policy.issuers[0], keyId: "replacement", publicKeyHex: "09".repeat(32), validFrom: "2026-08-01T00:00:00Z", validUntil: "2099-01-01T00:00:00Z" });
  assert.equal((await verifyCertificate(signed, chain(signed), index(fresh(signed)), { trustPolicy: policy })).status, "VERIFIED");
  policy.issuers[0].revoked = true;
  assert.equal((await verifyCertificate(signed, chain(signed), index(fresh(signed)), { trustPolicy: policy })).code, "ISSUER_REVOKED");
});

test("rotation lifecycle through the durable policy store: legal history, interval limits, revocation cannot be rolled back", async context => {
  const dir = await mkdtemp(join(tmpdir(), "onelayer-rotation-"));
  context.after(() => rm(dir, { recursive: true, force: true }));
  await mkdir(join(dir, "policy"), { mode: 0o700 });
  await mkdir(join(dir, "state"), { mode: 0o700 });
  const policyFile = join(dir, "policy", "policy.json");
  let bootstrapDigest: string | undefined;
  const load = async (policy: unknown) => {
    const text = JSON.stringify(policy);
    await writeFile(policyFile, text);
    bootstrapDigest ??= policyDigest(Buffer.from(text)); // first-run operator bootstrap only
    return (await loadTrustPolicy({ policyFile, stateFile: join(dir, "state", "accepted.json"), minimumRevision: 1, mode: { kind: "unsigned" }, bootstrapDigest })).policy;
  };
  const verifyUnder = async (signed: SignedCertificate, policy: TrustPolicy) =>
    verifyWithPolicy(signed, chain(signed), index(fresh(signed)), { trustPolicy: policy });
  const historical = signedCertificate(); // old key, issuedAt 2026-07-31
  const replacementKey = new Uint8Array(32).fill(0x0b);
  const afterRotation = signCertificate({ ...historical.body, issuerKeyId: "replacement", issuedAt: "2026-08-02T00:00:00Z" }, replacementKey);
  const revision1 = policyFor(historical);
  const revision2 = { ...revision1, revision: 2, issuers: [
    { ...revision1.issuers[0], validUntil: "2026-08-01T00:00:00Z" },
    { ...revision1.issuers[0], keyId: "replacement", publicKeyHex: Buffer.from(afterRotation.body.issuerPublicKey).toString("hex"), validFrom: "2026-08-01T00:00:00Z" },
  ] };
  assert.equal((await verifyUnder(historical, await load(revision1))).status, "VERIFIED");
  const rotated = await load(revision2);
  assert.equal((await verifyUnder(historical, rotated)).status, "VERIFIED", "legal history of the retired key");
  assert.equal((await verifyUnder(afterRotation, rotated)).status, "VERIFIED", "replacement key inside its interval");
  const oldKeyAfterRetirement = signCertificate({ ...historical.body, issuedAt: "2026-08-02T00:00:00Z" }, signingKey);
  assert.equal((await verifyUnder(oldKeyAfterRetirement, rotated)).code, "ISSUER_TIME_INVALID");
  const replacementBeforeActivation = signCertificate({ ...afterRotation.body, issuedAt: "2026-07-31T00:00:00Z" }, replacementKey);
  assert.equal((await verifyUnder(replacementBeforeActivation, rotated)).code, "ISSUER_TIME_INVALID");
  const revision3 = { ...revision2, revision: 3, issuers: [{ ...revision2.issuers[0], revoked: true }, revision2.issuers[1]] };
  const revoked = await load(revision3);
  assert.equal((await verifyUnder(historical, revoked)).code, "ISSUER_REVOKED");
  assert.equal((await verifyUnder(afterRotation, revoked)).status, "VERIFIED");
  // Restoring revision 2 would silently re-trust the compromised key.
  await assert.rejects(load(revision2), /TRUST_POLICY_ROLLBACK/);
});

test("issuer validity boundaries, future issuance and policy expiry fail closed", async () => {
  const signed = signedCertificate();
  for (const [change, code] of [
    [(p: any) => { p.issuers[0].validUntil = signed.body.issuedAt; }, "ISSUER_TIME_INVALID"],
    [(p: any) => { p.issuers[0].validFrom = "2026-08-01T00:00:00Z"; }, "ISSUER_TIME_INVALID"],
    [(p: any) => { p.validUntil = "2020-01-01T00:00:00Z"; }, "TRUST_POLICY_EXPIRED"],
  ] as const) {
    const policy = policyFor(signed);
    change(policy);
    assert.equal((await verifyCertificate(signed, chain(signed), index(fresh(signed)), { trustPolicy: policy })).code, code);
  }
  const future = signCertificate({ ...signed.body, issuedAt: "2098-01-01T00:00:00Z" }, signingKey);
  assert.equal((await verifyCertificate(future, chain(future), index(fresh(future)))).code, "ISSUER_TIME_INVALID");
});


test("V2 separates historical proof from unproven current suitability", async () => {
  const signed = signedCertificate();
  const incidents = index({ registryId: signed.body.registryId, indexedThroughSlot: 1_040n, incidents: [] });
  const query = async (source?: LifecycleIndex) => verifyCertificateV2(signed, chain(signed), incidents,
    { trustPolicy: policyFor(signed), lifecycle: source });
  for (const source of [undefined, lifecycle(null), { async query() { throw new Error("offline"); } }]) {
    const result = await query(source);
    assert.equal(result.status, "UNKNOWN");
    assert.equal(result.proofs.status, "VERIFIED");
    assert.equal(result.resultVersion, 2);
    assert.equal(result.incidents.finalizedHeadSlot, "1050");
  }
  const record = { registryId: signed.body.registryId, certificateId: Buffer.from(signed.body.certificateId).toString("hex"),
    currentRecordVersion: 1n, certificateStatus: "ACTIVE" as const };
  assert.equal((await query(lifecycle(record))).status, "UNKNOWN");
  assert.equal((await query(lifecycle(record))).lifecycle.status, "UNAUTHENTICATED");
  assert.equal((await query(lifecycle({ ...record, certificateStatus: "REVOKED" }))).status, "REVOKED");
  assert.equal((await query(lifecycle({ ...record, currentRecordVersion: 2n }))).status, "HISTORICAL");
  for (const bad of [{ ...record, certificateId: "ff".repeat(16) }, { ...record, registryId: "foreign" },
    { ...record, currentRecordVersion: 0n }, { ...record, currentRecordVersion: 0x1_0000_0000_0000_0000n },
    { ...record, certificateId: undefined }]) {
    const result = await query(lifecycle(bad));
    assert.equal(result.status, "UNKNOWN");
    assert.equal(result.lifecycle.code, "LIFECYCLE_RESPONSE_INVALID");
    assert.equal(result.lifecycle.reported, undefined);
  }
  for (const resolutionStatus of ["OPEN", "CONFIRMED", "RESOLVED"] as const) {
    for (const certificateStatus of ["ACTIVE", "SUPERSEDED", "REVOKED"] as const) {
      const disputed = await verifyCertificateV2(signed, chain(signed), index({ registryId: signed.body.registryId,
        indexedThroughSlot: 1_040n, incidents: [{ firstBatchSequence: 1n, lastBatchSequence: 1n,
          status: resolutionStatus === "OPEN" ? "OPEN" : "RESOLVED", resolutionStatus }] }),
        { trustPolicy: policyFor(signed), lifecycle: lifecycle({ ...record, certificateStatus }) });
      assert.equal(disputed.status, "DISPUTED", `${resolutionStatus} must block despite advisory ${certificateStatus}`);
    }
  }
  // Incomplete incident evidence and advisory lifecycle must never establish
  // currentness; the proof, source availability and advisory report stay separate.
  for (const response of [null,
    { registryId: signed.body.registryId, indexedThroughSlot: 1n, incidents: [] },
    { registryId: signed.body.registryId, indexedThroughSlot: 2_000n, incidents: [] }]) {
    const uncertain = await verifyCertificateV2(signed, chain(signed), index(response),
      { trustPolicy: policyFor(signed), lifecycle: lifecycle(record) });
    assert.equal(uncertain.status, "UNKNOWN");
    assert.equal(uncertain.proofs.status, "VERIFIED");
    assert.equal(uncertain.lifecycle.status, "UNAUTHENTICATED");
    assert.notEqual(uncertain.incidents.status, "CHECKED");
    assert.ok(Number.isFinite(Date.parse(uncertain.checkedAt)));
  }
  let invalidLifecycleReads = 0;
  const neverRead = { async query() { invalidLifecycleReads++; return record; } };
  const forged = { ...signed, issuerSignature: new Uint8Array(64) };
  const refused = await verifyCertificateV2(forged, chain(signed), incidents,
    { trustPolicy: policyFor(signed), lifecycle: neverRead });
  assert.equal(refused.status, "INVALID");
  assert.equal(refused.proofs.status, "NOT_ESTABLISHED");
  assert.equal(refused.registry.status, "NOT_ESTABLISHED");
  assert.equal(refused.disclosedFields, undefined);
  assert.equal(refused.lifecycle.reported, undefined);
  assert.equal(invalidLifecycleReads, 0);
  const invalid = await verifyCertificateV2(signed, chain(signed), incidents);
  assert.equal(invalid.status, "INVALID");
  assert.equal(invalid.disclosedFields, undefined);
});

test("ADR-0008: only FALSE_POSITIVE lifts an incident's block; RESOLVED stays DISPUTED like CONFIRMED", async () => {
  const signed = signedCertificate();
  const cases: Array<[import("../src/verify.ts").IncidentNotice, string]> = [
    [{ firstBatchSequence: 1n, lastBatchSequence: 3n, status: "OPEN", resolutionStatus: "OPEN", blocking: true }, "DISPUTED"],
    [{ firstBatchSequence: 1n, lastBatchSequence: 3n, status: "OPEN", resolutionStatus: "CONFIRMED", blocking: true }, "DISPUTED"],
    [{ firstBatchSequence: 1n, lastBatchSequence: 3n, status: "OPEN", resolutionStatus: "RESOLVED", blocking: true }, "DISPUTED"],
    [{ firstBatchSequence: 1n, lastBatchSequence: 3n, status: "RESOLVED", resolutionStatus: "FALSE_POSITIVE", blocking: false }, "VERIFIED"],
    // Inconsistent or legacy signals are combined fail-closed.
    [{ firstBatchSequence: 1n, lastBatchSequence: 3n, status: "RESOLVED", resolutionStatus: "RESOLVED" }, "DISPUTED"],
    [{ firstBatchSequence: 1n, lastBatchSequence: 3n, status: "RESOLVED", resolutionStatus: "CONFIRMED", blocking: false }, "DISPUTED"],
    [{ firstBatchSequence: 1n, lastBatchSequence: 3n, status: "RESOLVED", resolutionStatus: "FALSE_POSITIVE", blocking: true }, "DISPUTED"],
    [{ firstBatchSequence: 1n, lastBatchSequence: 3n, status: "OPEN", resolutionStatus: "FALSE_POSITIVE", blocking: false }, "DISPUTED"],
    [{ firstBatchSequence: 1n, lastBatchSequence: 3n, status: "RESOLVED" }, "DISPUTED"],
    // A FALSE_POSITIVE lifts only its own block.
    [{ firstBatchSequence: 1n, lastBatchSequence: 3n, status: "RESOLVED", resolutionStatus: "FALSE_POSITIVE", blocking: false }, "VERIFIED"],
    // Outside the suspect range nothing blocks.
    [{ firstBatchSequence: 5n, lastBatchSequence: 9n, status: "OPEN", resolutionStatus: "RESOLVED", blocking: true }, "VERIFIED"],
  ];
  for (const [incident, expected] of cases) {
    const result = await verifyCertificate(signed, chain(signed),
      index({ registryId: signed.body.registryId, indexedThroughSlot: 1_040n, incidents: [incident] }));
    assert.equal(result.status, expected, JSON.stringify(incident, (_k, v) => typeof v === "bigint" ? v.toString() : v));
  }
  const both = await verifyCertificate(signed, chain(signed), index({ registryId: signed.body.registryId, indexedThroughSlot: 1_040n, incidents: [
    { firstBatchSequence: 1n, lastBatchSequence: 3n, status: "RESOLVED", resolutionStatus: "FALSE_POSITIVE", blocking: false },
    { firstBatchSequence: 1n, lastBatchSequence: 1n, status: "OPEN", resolutionStatus: "RESOLVED", blocking: true },
  ] }));
  assert.equal(both.status, "DISPUTED", "another blocking incident still applies after a FALSE_POSITIVE");
});

test("HTTP incident adapter carries resolutionStatus/blocking and rejects malformed values", async (context) => {
  const { HttpIncidentIndex } = await import("../src/http-adapters.ts");
  const original = globalThis.fetch;
  context.after(() => { globalThis.fetch = original; });
  let incidents: unknown[] = [];
  globalThis.fetch = (async () => new Response(JSON.stringify({ registryId: "r", indexedThroughSlot: "10", incidents }), { status: 200 })) as typeof fetch;
  const adapter = new HttpIncidentIndex("http://index.invalid");
  incidents = [{ firstBatchSequence: "1", lastBatchSequence: "3", status: "OPEN", resolutionStatus: "RESOLVED", blocking: true },
    { firstBatchSequence: "1", lastBatchSequence: "3", status: "RESOLVED" }];
  assert.deepEqual((await adapter.query("r", 2n))?.incidents, [
    { firstBatchSequence: 1n, lastBatchSequence: 3n, status: "OPEN", resolutionStatus: "RESOLVED", blocking: true },
    { firstBatchSequence: 1n, lastBatchSequence: 3n, status: "RESOLVED" },
  ]);
  for (const bad of [{ resolutionStatus: "CLEARED" }, { blocking: "no" }]) {
    incidents = [{ firstBatchSequence: "1", lastBatchSequence: "3", status: "RESOLVED", ...bad }];
    await assert.rejects(adapter.query("r", 2n), TypeError);
  }
});
