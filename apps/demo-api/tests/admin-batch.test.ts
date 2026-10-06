import { syntheticTrustPolicy, SYNTHETIC_CONFIG, SYNTHETIC_GENESIS } from "../../../tests/support/trust-fixtures.ts";
import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeCertificatePackageBase64url } from "../../verifier/src/certificate-codec.ts";
import { verifyCertificate, type ChainReader, type IncidentIndex } from "../../verifier/src/verify.ts";
import { genesisAnchorHash, registryIdHash, toHex } from "../../../packages/canonical-ts/src/index.ts";
import {
  batchReview,
  buildBatch,
  issueCertificate,
  type SyntheticRecordRow,
} from "../src/admin-batch.ts";

const REGISTRY_ID = "gov.registry.land";
const issuerSecret = new Uint8Array(32).fill(9);
const programId = new Uint8Array(32).fill(4);
const segmentPda = new Uint8Array(32).fill(5);
const signature = new Uint8Array(64).fill(6);
const trustPolicy = syntheticTrustPolicy({ programId, issuerSeed: issuerSecret });

const rows: SyntheticRecordRow[] = [
  { internalRecordId: "SYNTHETIC-1", sourceCursor: 1n, recordVersion: 1n, status: "ACTIVE", recordFieldKeyHex: "01".repeat(32) },
  { internalRecordId: "SYNTHETIC-2", sourceCursor: 2n, recordVersion: 1n, status: "ACTIVE", recordFieldKeyHex: "02".repeat(32) },
];

function batch(overrides: Partial<SyntheticRecordRow>[] = []) {
  const source = overrides.length === 0 ? rows : rows.map((row, index) => ({ ...row, ...overrides[index] }));
  return buildBatch(source, {
    registryId: REGISTRY_ID,
    batchSequence: 1n,
    registryVersion: 1n,
    previousAnchorHash: genesisAnchorHash(registryIdHash(REGISTRY_ID)),
    createdAt: "2026-07-31T00:00:00Z",
    operatorKeyId: "synthetic-demo-operator-1",
  });
}

test("rebuilding the same range yields the same roots and manifest hash", () => {
  const first = batch();
  const second = batch();
  assert.equal(toHex(first.merkleRoot), toHex(second.merkleRoot));
  assert.equal(toHex(first.manifestHash), toHex(second.manifestHash));
  assert.equal(first.leafCount, 2);
  assert.equal(first.cursorStart, 1n);
  assert.equal(first.cursorEnd, 2n);
});

test("changing a disclosed value changes the anchored root", () => {
  assert.notEqual(
    toHex(batch().merkleRoot),
    toHex(batch([{ status: "REVOKED" }, {}]).merkleRoot),
  );
});

test("non-synthetic records and empty batches are refused", () => {
  assert.throws(() => buildBatch([], {
    registryId: REGISTRY_ID,
    batchSequence: 1n,
    registryVersion: 1n,
    previousAnchorHash: new Uint8Array(32),
    createdAt: "2026-07-31T00:00:00Z",
    operatorKeyId: "k",
  }), RangeError);
  assert.throws(() => buildBatch([{ ...rows[0], internalRecordId: "REAL-1" }], {
    registryId: REGISTRY_ID,
    batchSequence: 1n,
    registryVersion: 1n,
    previousAnchorHash: new Uint8Array(32),
    createdAt: "2026-07-31T00:00:00Z",
    operatorKeyId: "k",
  }), TypeError);
});

test("the review payload carries no key material", () => {
  const review = JSON.stringify(batchReview(batch()));
  assert.doesNotMatch(review, /01010101/);
  assert.doesNotMatch(review, /recordFieldKey/);
  assert.match(review, /merkleRoot/);
});

test("an issued certificate verifies against the anchored batch", async () => {
  const prepared = batch();
  const issued = issueCertificate(
    prepared,
    { solanaProgramId: programId, segmentIndex: 0, segmentPda, transactionSignature: signature, anchorSlot: 1_000n },
    {
      internalRecordId: "SYNTHETIC-1",
      certificateId: new Uint8Array(16).fill(8),
      issuedAt: "2026-07-31T00:00:00Z",
      issuerKeyId: "synthetic-demo-issuer-1",
      issuerSecretKey: issuerSecret,
      publicBaseUrl: "http://127.0.0.1:8091",
    },
  );
  assert.match(issued.qrUrl, /^http:\/\/127\.0\.0\.1:8091\/c\/(?:08){16}\?h=[A-Za-z0-9_-]{43}$/);

  const signed = decodeCertificatePackageBase64url(issued.packageBase64url);
  const chain: ChainReader = {
    async getGenesisHash() { return SYNTHETIC_GENESIS; },
    async getRegistryConfig(body) {
      return { registryIdHash: registryIdHash(body.registryId), paused: false, configPda: SYNTHETIC_CONFIG, programId };
    },
    async getAnchor() {
      return {
        registryConfigPda: SYNTHETIC_CONFIG,
        programId,
        segmentPda,
        derivedSegmentPda: segmentPda,
        batchSequence: 1n,
        registryVersion: 1n,
        merkleRoot: prepared.merkleRoot,
        manifestHash: prepared.manifestHash,
        transactionSignature: signature,
        slot: 1_000n,
        commitment: "finalized" as const,
      };
    },
    async getFinalizedHeadSlot() {
      return 1_010n;
    },
  };
  const incidents: IncidentIndex = {
    async query() {
      return { registryId: REGISTRY_ID, indexedThroughSlot: 1_005n, incidents: [] };
    },
  };
  assert.equal((await verifyCertificate(signed, chain, incidents, { trustPolicy })).status, "VERIFIED");
});

test("a tampered package byte fails verification", async () => {
  const prepared = batch();
  const issued = issueCertificate(
    prepared,
    { solanaProgramId: programId, segmentIndex: 0, segmentPda, transactionSignature: signature, anchorSlot: 1_000n },
    {
      internalRecordId: "SYNTHETIC-2",
      certificateId: new Uint8Array(16).fill(7),
      issuedAt: "2026-07-31T00:00:00Z",
      issuerKeyId: "synthetic-demo-issuer-1",
      issuerSecretKey: issuerSecret,
      publicBaseUrl: "http://127.0.0.1:8091",
    },
  );
  const bytes = Buffer.from(issued.packageBase64url, "base64url");
  bytes[bytes.length - 1] ^= 0x01;
  const chain: ChainReader = {
    async getGenesisHash() { return SYNTHETIC_GENESIS; },
    async getRegistryConfig(body) {
      return { registryIdHash: registryIdHash(body.registryId), paused: false, configPda: SYNTHETIC_CONFIG, programId };
    },
    async getAnchor() {
      return {
        registryConfigPda: SYNTHETIC_CONFIG,
        programId,
        segmentPda,
        derivedSegmentPda: segmentPda,
        batchSequence: 1n,
        registryVersion: 1n,
        merkleRoot: prepared.merkleRoot,
        manifestHash: prepared.manifestHash,
        transactionSignature: signature,
        slot: 1_000n,
        commitment: "finalized" as const,
      };
    },
    async getFinalizedHeadSlot() {
      return 1_010n;
    },
  };
  const incidents: IncidentIndex = {
    async query() {
      return { registryId: REGISTRY_ID, indexedThroughSlot: 1_005n, incidents: [] };
    },
  };
  let status: string;
  try {
    status = (await verifyCertificate(
      decodeCertificatePackageBase64url(bytes.toString("base64url")),
      chain,
      incidents,
      { trustPolicy },
    )).status;
  } catch {
    status = "INVALID";
  }
  assert.equal(status, "INVALID");
});

const MULTI_FIELD: SyntheticRecordRow[] = [
  {
    ...rows[0],
    fields: [
      { path: "cadastralNumber", type: "text", value: "01-004-0123-045" },
      { path: "areaSquareMeters", type: "decimal", value: "1250.50" },
      { path: "encumbered", type: "bool", value: "false" },
    ],
  },
  rows[1],
];

function multiFieldBatch(source: SyntheticRecordRow[] = MULTI_FIELD) {
  return buildBatch(source, {
    registryId: REGISTRY_ID,
    batchSequence: 1n,
    registryVersion: 1n,
    previousAnchorHash: genesisAnchorHash(registryIdHash(REGISTRY_ID)),
    createdAt: "2026-07-31T00:00:00Z",
    operatorKeyId: "synthetic-demo-operator-1",
  });
}

function anchorReader(prepared: ReturnType<typeof buildBatch>): ChainReader {
  return {
    async getGenesisHash() { return SYNTHETIC_GENESIS; },
    async getRegistryConfig() {
      return { registryIdHash: registryIdHash(REGISTRY_ID), paused: false, configPda: SYNTHETIC_CONFIG, programId };
    },
    async getAnchor() {
      return {
        registryConfigPda: SYNTHETIC_CONFIG,
        programId,
        segmentPda,
        derivedSegmentPda: segmentPda,
        batchSequence: 1n,
        registryVersion: 1n,
        merkleRoot: prepared.merkleRoot,
        manifestHash: prepared.manifestHash,
        transactionSignature: signature,
        slot: 1_000n,
        commitment: "finalized" as const,
      };
    },
    async getFinalizedHeadSlot() {
      return 1_010n;
    },
  };
}

const cleanIndex: IncidentIndex = {
  async query() {
    return { registryId: REGISTRY_ID, indexedThroughSlot: 1_005n, incidents: [] };
  },
};

test("the imported fields are part of the commitment, not decoration", () => {
  const withFields = multiFieldBatch();
  const statusOnly = batch();
  assert.notEqual(toHex(withFields.merkleRoot), toHex(statusOnly.merkleRoot));

  const changed = multiFieldBatch([
    {
      ...MULTI_FIELD[0],
      fields: [
        { path: "cadastralNumber", type: "text", value: "01-004-0123-045" },
        // Same number with a different scale: a different commitment.
        { path: "areaSquareMeters", type: "decimal", value: "1250.5" },
        { path: "encumbered", type: "bool", value: "false" },
      ],
    },
    MULTI_FIELD[1],
  ]);
  assert.notEqual(toHex(withFields.merkleRoot), toHex(changed.merkleRoot));

  const review: any = batchReview(withFields);
  const record = review.records.find((entry: any) => entry.internalRecordId === "SYNTHETIC-1");
  assert.equal(record.fields.length, 4);
  assert.equal(record.disclosedFields.areaSquareMeters, "1250.50");
  assert.match(record.fields[0].fieldCommitment, /^[0-9a-f]{64}$/);
});

test("a selective disclosure verifies and carries only the chosen paths", async () => {
  const prepared = multiFieldBatch();
  const anchor = {
    solanaProgramId: programId,
    segmentIndex: 0,
    segmentPda,
    transactionSignature: signature,
    anchorSlot: 1_000n,
  };
  const request = {
    internalRecordId: "SYNTHETIC-1",
    certificateId: new Uint8Array(16).fill(3),
    issuedAt: "2026-07-31T00:00:00Z",
    issuerKeyId: "synthetic-demo-issuer-1",
    issuerSecretKey: issuerSecret,
    publicBaseUrl: "http://127.0.0.1:8091",
  };
  const full = issueCertificate(prepared, anchor, request);
  const selective = issueCertificate(prepared, anchor, {
    ...request,
    certificateId: new Uint8Array(16).fill(4),
    disclosedPaths: ["status", "areaSquareMeters"],
  });

  assert.equal(full.disclosureMode, "FULL_RECORD");
  assert.equal(selective.disclosureMode, "SELECTIVE_FIELDS");
  assert.deepEqual(selective.disclosedPaths, ["areaSquareMeters", "status"]);
  assert.equal(selective.fieldCount, 4);

  const signed = decodeCertificatePackageBase64url(selective.packageBase64url);
  assert.deepEqual(Object.keys(signed.body.disclosedFields).sort(), ["areaSquareMeters", "status"]);
  assert.deepEqual(Object.keys(signed.body.fieldSalts).sort(), ["areaSquareMeters", "status"]);
  assert.equal(signed.body.fieldProofs.length, 2);
  // The undisclosed value never leaves the server.
  assert.doesNotMatch(Buffer.from(selective.packageBase64url, "base64url").toString("utf8"), /01-004-0123-045/);

  // Same field root and same anchor as the full disclosure: the selective
  // package proves a subset of exactly the same record version.
  const fullSigned = decodeCertificatePackageBase64url(full.packageBase64url);
  assert.equal(toHex(signed.body.fieldRoot), toHex(fullSigned.body.fieldRoot));

  const result = await verifyCertificate(signed, anchorReader(prepared), cleanIndex, { trustPolicy });
  assert.equal(result.status, "VERIFIED");
  assert.equal(result.disclosureMode, "SELECTIVE_FIELDS");
  assert.deepEqual(Object.keys(result.disclosedFields ?? {}), ["areaSquareMeters", "status"]);
});

test("an unknown disclosure path is refused", () => {
  assert.throws(
    () => issueCertificate(
      multiFieldBatch(),
      { solanaProgramId: programId, segmentIndex: 0, segmentPda, transactionSignature: signature, anchorSlot: 1n },
      {
        internalRecordId: "SYNTHETIC-1",
        certificateId: new Uint8Array(16).fill(5),
        issuedAt: "2026-07-31T00:00:00Z",
        issuerKeyId: "k",
        issuerSecretKey: issuerSecret,
        publicBaseUrl: "http://127.0.0.1:8091",
        disclosedPaths: ["ownerFullName"],
      },
    ),
    RangeError,
  );
});

test("a record outside the batch cannot be certified", () => {
  assert.throws(
    () => issueCertificate(
      batch(),
      { solanaProgramId: programId, segmentIndex: 0, segmentPda, transactionSignature: signature, anchorSlot: 1n },
      {
        internalRecordId: "SYNTHETIC-9",
        certificateId: new Uint8Array(16),
        issuedAt: "2026-07-31T00:00:00Z",
        issuerKeyId: "k",
        issuerSecretKey: issuerSecret,
        publicBaseUrl: "http://127.0.0.1:8091",
      },
    ),
    RangeError,
  );
});
