import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { proof, root } from "../../merkle-ts/src/index.ts";
import {
  anchorHash,
  anchorPreimage,
  batchLeafHash,
  buildFieldTree,
  certificateBodyCbor,
  certificatePackageCbor,
  decodeCanonical,
  encode,
  fieldCommitment,
  fieldSalt,
  fromHex,
  manifestHash,
  manifestUnsignedCbor,
  recordCommitment,
  recordIdCommitment,
  registryIdHash,
  signManifest,
  signCertificate,
  toHex,
  verifyManifestSignature,
  verifyCertificateSignature,
  type AnchorFields,
  type CertificateBody,
  type CborValue,
  type ManifestFields,
} from "../src/index.ts";

async function load(name: string): Promise<any> {
  return JSON.parse(await readFile(new URL(`../../../spec/vectors/${name}`, import.meta.url), "utf8"));
}

test("deterministic CBOR matches every shared vector", async () => {
  const document = await load("canonical.json");
  for (const vector of document.vectors) {
    const encoded = encode(vector.input as CborValue);
    assert.equal(toHex(encoded), vector.expected.cbor_hex, vector.id);
    assert.equal(encoded.length, vector.expected.byte_len, vector.id);
    assert.deepEqual(encode(decodeCanonical(encoded)), encoded, vector.id);
  }
});

test("CBOR decoder rejects non-canonical and trailing encodings", () => {
  assert.throws(() => decodeCanonical(Uint8Array.of(0x18, 0x00)), /non-shortest/);
  assert.throws(() => decodeCanonical(Uint8Array.of(0xa2, 0x61, 0x62, 0x00, 0x61, 0x61, 0x00)), /canonical/);
  assert.throws(() => decodeCanonical(Uint8Array.of(0x00, 0x00)), /trailing bytes/);
});

test("field and record commitments match shared vectors", async () => {
  const document = await load("leaf.json");
  for (const vector of document.vectors) {
    const key = fromHex(vector.input.record_field_key);
    const fields = vector.fields.map((field: any) => ({ path: field.path, value: field.value as CborValue }));
    const tree = buildFieldTree(key, fields);

    for (const field of vector.fields) {
      const salt = fieldSalt(key, field.path);
      const commitment = fieldCommitment(field.path, field.value, salt);
      assert.equal(toHex(salt), field.field_salt, `${vector.id}:${field.path}:salt`);
      assert.equal(toHex(commitment), field.field_commitment, `${vector.id}:${field.path}:commitment`);
      const actual = tree.entries.find((entry) => entry.path.normalize("NFC") === field.path.normalize("NFC"));
      assert.equal(toHex(actual!.leafHash), field.field_tree_leaf_hash, `${vector.id}:${field.path}:leaf`);
    }

    const registryHash = registryIdHash(vector.input.registry_id);
    const commitment = recordCommitment(
      registryHash,
      fromHex(vector.input.record_id_commitment),
      BigInt(vector.input.record_version),
      tree.root,
    );
    assert.equal(toHex(registryHash), vector.expected.registry_id_hash, vector.id);
    assert.equal(toHex(tree.root), vector.expected.field_root, vector.id);
    assert.equal(toHex(commitment), vector.expected.record_commitment, vector.id);
    assert.equal(toHex(batchLeafHash(commitment)), vector.expected.batch_leaf_hash, vector.id);
  }
});

test("batch record identity and root match shared vector", async () => {
  const document = await load("batch.json");
  for (const vector of document.vectors) {
    const registryHash = registryIdHash(vector.input.registry_id);
    const idKey = fromHex(vector.input.id_key);
    const records = vector.input.records.map((record: any) => {
      const recordId = recordIdCommitment(idKey, vector.input.registry_id, record.internal_record_id);
      const commitment = recordCommitment(
        registryHash,
        recordId,
        BigInt(record.record_version),
        fromHex(record.field_root),
      );
      assert.equal(toHex(recordId), record.record_id_commitment, record.internal_record_id);
      assert.equal(toHex(commitment), record.record_commitment, record.internal_record_id);
      return { recordId, version: BigInt(record.record_version), leaf: batchLeafHash(commitment) };
    });
    records.sort((left: any, right: any) => {
      const idOrder = Buffer.compare(left.recordId, right.recordId);
      return idOrder === 0 ? (left.version < right.version ? -1 : left.version > right.version ? 1 : 0) : idOrder;
    });
    assert.deepEqual(records.map((record: any) => toHex(record.leaf)), vector.expected.leaf_order);
    assert.equal(toHex(root(records.map((record: any) => record.leaf))), vector.expected.merkle_root);
  }
});

test("anchor preimages and hashes match shared vectors", async () => {
  const document = await load("anchor.json");
  for (const vector of document.vectors) {
    const input = vector.input;
    const fields: AnchorFields = {
      registryIdHash: fromHex(input.registry_id_hash),
      batchSequence: BigInt(input.batch_sequence),
      registryVersion: BigInt(input.registry_version),
      sourceCursorStart: BigInt(input.source_cursor_start),
      sourceCursorEnd: BigInt(input.source_cursor_end),
      merkleRoot: fromHex(input.merkle_root),
      manifestHash: fromHex(input.manifest_hash),
      snapshotHash: fromHex(input.snapshot_hash),
      previousAnchorHash: fromHex(input.previous_anchor_hash),
      leafCount: input.leaf_count,
      schemaVersion: input.schema_version,
      flags: input.flags,
      hashAlgorithm: input.hash_algorithm,
      treeAlgorithm: input.tree_algorithm,
      operatorPubkey: fromHex(input.operator_pubkey),
      publishedAt: BigInt(input.published_at),
    };
    assert.equal(toHex(anchorPreimage(fields)), vector.expected.anchor_preimage, vector.id);
    assert.equal(toHex(anchorHash(fields)), vector.expected.anchor_hash, vector.id);
  }
});

test("manifest CBOR, hash, and Ed25519 signature match shared vectors", async () => {
  const document = await load("manifest.json");
  for (const vector of document.vectors) {
    const input = vector.input;
    const fields: ManifestFields = {
      registryIdHash: fromHex(input.registry_id_hash),
      batchSequence: BigInt(input.batch_sequence),
      registryVersion: BigInt(input.registry_version),
      sourceCursorStart: BigInt(input.source_cursor_start),
      sourceCursorEnd: BigInt(input.source_cursor_end),
      createdAt: input.created_at,
      schemaVersion: input.schema_version,
      leafCount: input.leaf_count,
      merkleRoot: fromHex(input.merkle_root),
      previousAnchorHash: fromHex(input.previous_anchor_hash),
      snapshotHash: input.snapshot_hash === null ? null : fromHex(input.snapshot_hash),
      leavesObjectUri: input.leaves_object_uri,
      leavesObjectHash: fromHex(input.leaves_object_hash),
      builderVersion: input.builder_version,
      operatorKeyId: input.operator_key_id,
    };
    const signed = signManifest(fields, fromHex(input.test_signing_key));
    assert.equal(toHex(manifestUnsignedCbor(fields)), vector.expected.unsigned_manifest_cbor, vector.id);
    assert.equal(toHex(manifestHash(fields)), vector.expected.manifest_hash, vector.id);
    assert.equal(toHex(signed.operatorPublicKey), vector.expected.operator_public_key, vector.id);
    assert.equal(toHex(signed.manifestSignature), vector.expected.manifest_signature, vector.id);
    assert.equal(verifyManifestSignature(signed), true, vector.id);
  }
});

test("record commitment changes when only record identity changes", () => {
  const registryHash = registryIdHash("gov.registry.land");
  const fieldRoot = new Uint8Array(32).fill(7);
  assert.notEqual(
    toHex(recordCommitment(registryHash, new Uint8Array(32).fill(1), 1n, fieldRoot)),
    toHex(recordCommitment(registryHash, new Uint8Array(32).fill(2), 1n, fieldRoot)),
  );
});

test("certificate bodies and issuer signatures match shared vectors", async () => {
  const document = await load("certificate.json");
  for (const vector of document.vectors) {
    const input = vector.input;
    const recordFieldKey = fromHex(input.record_field_key);
    const fields = input.fields.map((field: any) => ({ path: field.path, value: field.value as CborValue }));
    const fieldTree = buildFieldTree(recordFieldKey, fields);
    const recordCommitmentHash = recordCommitment(
      registryIdHash(input.registry_id),
      fromHex(input.record_id_commitment),
      BigInt(input.record_version),
      fieldTree.root,
    );
    const batchLeaf = batchLeafHash(recordCommitmentHash);
    const disclosedFields = Object.fromEntries(
      fields.filter((field: any) => input.disclosed_paths.includes(field.path)).map((field: any) => [field.path, field.value]),
    );
    const fieldSalts = Object.fromEntries(
      fields
        .filter((field: any) => input.disclosed_paths.includes(field.path))
        .map((field: any) => [field.path, fieldSalt(recordFieldKey, field.path)]),
    );
    const fieldProofs =
      input.disclosure_mode === "FULL_RECORD"
        ? []
        : input.disclosed_paths.map((path: string) => {
            const leafIndex = fieldTree.entries.findIndex((entry) => entry.path === path);
            return {
              path,
              leafIndex,
              siblings: proof(
                fieldTree.entries.map((entry) => entry.leafHash),
                leafIndex,
              ).map((step) => ({ side: step.side, sibling: step.sibling })),
            };
          });
    const unsignedBody: CertificateBody = {
      certificateId: fromHex(input.certificate_id),
      registryId: input.registry_id,
      issuedAt: input.issued_at,
      recordIdCommitment: fromHex(input.record_id_commitment),
      recordVersion: BigInt(input.record_version),
      schemaVersion: input.schema_version,
      disclosureMode: input.disclosure_mode,
      disclosedFields,
      fieldSalts,
      fieldRoot: fieldTree.root,
      fieldProofs,
      batchProof: { leafIndex: 0, leafHash: batchLeaf, siblings: [], expectedRoot: batchLeaf },
      anchor: {
        batchSequence: 1n,
        registryVersion: 1n,
        merkleRoot: batchLeaf,
        manifestHash: new Uint8Array(32).fill(0x44),
        solanaProgramId: new Uint8Array(32).fill(0x55),
        segmentIndex: 0,
        segmentPda: new Uint8Array(32).fill(0x66),
        transactionSignature: new Uint8Array(64).fill(0x77),
        anchorSlot: 412345678n,
      },
      issuerKeyId: "pilot-issuer-1",
      issuerPublicKey: new Uint8Array(32),
    };
    const signed = signCertificate(unsignedBody, fromHex(input.test_signing_key));
    if (vector.expected.result === "CERT_SIGNATURE_INVALID") signed.issuerSignature[0] ^= 0x80;

    assert.equal(toHex(fieldTree.root), vector.expected.field_root, vector.id);
    assert.equal(toHex(recordCommitmentHash), vector.expected.record_commitment, vector.id);
    assert.equal(toHex(batchLeaf), vector.expected.batch_leaf_hash, vector.id);
    assert.equal(toHex(certificateBodyCbor(signed.body)), vector.expected.certificate_body_cbor, vector.id);
    assert.equal(toHex(signed.certificateHash), vector.expected.certificate_hash, vector.id);
    assert.equal(toHex(signed.body.issuerPublicKey), vector.expected.issuer_public_key, vector.id);
    assert.equal(toHex(signed.issuerSignature), vector.expected.issuer_signature, vector.id);
    assert.equal(
      toHex(certificatePackageCbor(signed.body, signed.issuerSignature)),
      vector.expected.certificate_package_cbor,
      vector.id,
    );
    assert.equal(
      verifyCertificateSignature(signed),
      vector.expected.result !== "CERT_SIGNATURE_INVALID",
      vector.id,
    );
  }
});
