// Batch preparation and certificate issuance for the browser publish path.
//
// This is the second, independent user of the frozen protocol: the CLI happy
// path stays in Rust, the Admin UI path runs here on `packages/canonical-ts`.
// Nothing in this module talks to Solana or to the database.
import { createHash } from "node:crypto";
import {
  batchLeafHash,
  buildFieldTree,
  certificatePackageCbor,
  encode,
  fieldSalt,
  manifestHash as manifestHashOf,
  recordCommitment,
  recordIdCommitment,
  registryIdHash,
  signCertificate,
  toHex,
  type CborValue,
  type CertificateBody,
  type ManifestFields,
} from "../../../packages/canonical-ts/src/index.ts";
import { proof, root, type Hash } from "../../../packages/merkle-ts/src/index.ts";
import { cborValue, STATUS_PATH, type ValidatedField } from "./record-schema.ts";

export const BUILDER_VERSION = "onelayer-mvp-web/0.1.0";
export const SCHEMA_VERSION = 1;
/** Same synthetic record-ID key as the Rust demo pipeline. */
export const DEMO_ID_KEY = new Uint8Array(32).fill(9);

export interface SyntheticRecordRow {
  internalRecordId: string;
  sourceCursor: bigint;
  recordVersion: bigint;
  status: string;
  recordFieldKeyHex: string;
  /** Every schema path except `status`, which stays a column of the record. */
  fields?: readonly ValidatedField[];
}

export interface PreparedRecord {
  internalRecordId: string;
  recordVersion: bigint;
  recordIdCommitment: Hash;
  fieldRoot: Hash;
  recordCommitment: Hash;
  batchLeafHash: Hash;
  leafIndex: number;
  fields: Array<{ path: string; value: CborValue; text: string }>;
  /** Field-tree leaves in canonical path order; the source of field proofs. */
  fieldLeaves: Array<{ path: string; commitment: Hash; leafHash: Hash }>;
  recordFieldKey: Uint8Array;
}

export interface PreparedBatch {
  registryId: string;
  batchSequence: bigint;
  registryVersion: bigint;
  cursorStart: bigint;
  cursorEnd: bigint;
  leafCount: number;
  merkleRoot: Hash;
  manifestHash: Hash;
  previousAnchorHash: Hash;
  records: PreparedRecord[];
}

export interface BatchRequest {
  registryId: string;
  batchSequence: bigint;
  registryVersion: bigint;
  previousAnchorHash: Hash;
  createdAt: string;
  operatorKeyId: string;
}

/**
 * Canonical field set of one record: the `status` column plus whatever the
 * imported certificate carried. The same function feeds the batch builder, the
 * preview and the reconcile check — three field sets that must agree, or a
 * clean database would report itself as tampered with.
 */
export function fieldsOf(
  row: Pick<SyntheticRecordRow, "status" | "fields">,
): Array<{ path: string; value: CborValue; text: string }> {
  const fields = [
    { path: STATUS_PATH, value: { type: "text", value: row.status } as CborValue, text: row.status },
    ...(row.fields ?? []).map((field) => ({
      path: field.path,
      value: cborValue(field),
      text: field.value,
    })),
  ];
  const paths = new Set(fields.map((field) => field.path));
  if (paths.size !== fields.length) throw new RangeError("CANONICALIZATION_FAILED: duplicate field path");
  return fields;
}

export function buildBatch(rows: readonly SyntheticRecordRow[], request: BatchRequest): PreparedBatch {
  if (rows.length === 0) throw new RangeError("batch requires at least one record");
  const registryHash = registryIdHash(request.registryId);
  const prepared = rows.map((row) => {
    if (!/^SYNTHETIC-[1-9][0-9]*$/.test(row.internalRecordId)) {
      throw new TypeError("non-synthetic record rejected");
    }
    if (!/^[0-9a-f]{64}$/.test(row.recordFieldKeyHex)) throw new TypeError("record field key is invalid");
    const recordFieldKey = Uint8Array.from(Buffer.from(row.recordFieldKeyHex, "hex"));
    const fields = fieldsOf(row);
    const tree = buildFieldTree(recordFieldKey, fields);
    const fieldRoot = tree.root;
    const identifier = recordIdCommitment(DEMO_ID_KEY, request.registryId, row.internalRecordId);
    const commitment = recordCommitment(registryHash, identifier, row.recordVersion, fieldRoot);
    return {
      internalRecordId: row.internalRecordId,
      recordVersion: row.recordVersion,
      recordIdCommitment: identifier,
      fieldRoot,
      recordCommitment: commitment,
      batchLeafHash: batchLeafHash(commitment),
      leafIndex: 0,
      fields,
      fieldLeaves: tree.entries.map((entry) => ({
        path: entry.path,
        commitment: entry.commitment,
        leafHash: entry.leafHash,
      })),
      recordFieldKey,
    } satisfies PreparedRecord;
  });
  prepared.sort((left, right) =>
    Buffer.compare(left.recordIdCommitment, right.recordIdCommitment) ||
    (left.recordVersion < right.recordVersion ? -1 : left.recordVersion > right.recordVersion ? 1 : 0)
  );
  prepared.forEach((record, index) => { record.leafIndex = index; });
  for (let index = 1; index < prepared.length; index += 1) {
    const previous = prepared[index - 1];
    const current = prepared[index];
    if (
      Buffer.compare(previous.recordIdCommitment, current.recordIdCommitment) === 0 &&
      previous.recordVersion === current.recordVersion
    ) {
      throw new RangeError("duplicate record version in batch");
    }
  }
  const merkleRoot = root(prepared.map((record) => record.batchLeafHash));
  const cursors = rows.map((row) => row.sourceCursor).sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
  const manifest: ManifestFields = {
    registryIdHash: registryHash,
    batchSequence: request.batchSequence,
    registryVersion: request.registryVersion,
    sourceCursorStart: cursors[0],
    sourceCursorEnd: cursors[cursors.length - 1],
    createdAt: request.createdAt,
    schemaVersion: SCHEMA_VERSION,
    leafCount: prepared.length,
    merkleRoot,
    previousAnchorHash: request.previousAnchorHash,
    snapshotHash: null,
    leavesObjectUri: `synthetic://onelayer-mvp-web/batch-${request.batchSequence}/leaves.cbor`,
    leavesObjectHash: leavesObjectHash(prepared),
    builderVersion: BUILDER_VERSION,
    operatorKeyId: request.operatorKeyId,
  };
  return {
    registryId: request.registryId,
    batchSequence: request.batchSequence,
    registryVersion: request.registryVersion,
    cursorStart: manifest.sourceCursorStart,
    cursorEnd: manifest.sourceCursorEnd,
    leafCount: prepared.length,
    merkleRoot,
    manifestHash: manifestHashOf(manifest),
    previousAnchorHash: request.previousAnchorHash,
    records: prepared,
  };
}

/** SHA-256 over the deterministic CBOR encoding of the batch leaves. */
function leavesObjectHash(records: readonly PreparedRecord[]): Hash {
  const encoded = encode({
    type: "array",
    items: records.map((record) => ({
      type: "map" as const,
      entries: {
        recordIdCommitment: { type: "bytes" as const, hex: toHex(record.recordIdCommitment) },
        recordVersion: { type: "int" as const, value: record.recordVersion.toString() },
        fieldRoot: { type: "bytes" as const, hex: toHex(record.fieldRoot) },
        recordCommitment: { type: "bytes" as const, hex: toHex(record.recordCommitment) },
      },
    })),
  });
  return new Uint8Array(createHash("sha256").update(encoded).digest());
}

/** Canonical review payload shown before signing; contains no secrets. */
export function batchReview(batch: PreparedBatch): Record<string, unknown> {
  return {
    registryId: batch.registryId,
    batchSequence: batch.batchSequence.toString(),
    registryVersion: batch.registryVersion.toString(),
    cursorStart: batch.cursorStart.toString(),
    cursorEnd: batch.cursorEnd.toString(),
    leafCount: batch.leafCount,
    merkleRoot: toHex(batch.merkleRoot),
    manifestHash: toHex(batch.manifestHash),
    previousAnchorHash: toHex(batch.previousAnchorHash),
    records: batch.records.map((record) => ({
      internalRecordId: record.internalRecordId,
      recordVersion: record.recordVersion.toString(),
      recordIdCommitment: toHex(record.recordIdCommitment),
      fieldRoot: toHex(record.fieldRoot),
      recordCommitment: toHex(record.recordCommitment),
      batchLeafHash: toHex(record.batchLeafHash),
      leafIndex: record.leafIndex,
      disclosedFields: Object.fromEntries(record.fields.map((field) => [field.path, field.text])),
      // Per-path commitments make the field tree visible before signing: the
      // reviewer sees what each value contributes to `fieldRoot`.
      fields: record.fieldLeaves.map((leaf, index) => ({
        path: leaf.path,
        value: record.fields.find((field) => field.path === leaf.path)?.text ?? null,
        fieldCommitment: toHex(leaf.commitment),
        fieldLeafIndex: index,
      })),
    })),
  };
}

export interface AnchorReference {
  solanaProgramId: Uint8Array;
  segmentIndex: number;
  segmentPda: Uint8Array;
  transactionSignature: Uint8Array;
  anchorSlot: bigint;
}

export interface CertificateRequest {
  internalRecordId: string;
  certificateId: Uint8Array;
  issuedAt: string;
  issuerKeyId: string;
  issuerSecretKey: Uint8Array;
  publicBaseUrl: string;
  /** Paths to disclose; absent or complete means FULL_RECORD. */
  disclosedPaths?: readonly string[];
}

export interface IssuedCertificate {
  certificateId: string;
  certificateHash: string;
  packageBase64url: string;
  qrUrl: string;
  recordVersion: bigint;
  internalRecordId: string;
  disclosureMode: "FULL_RECORD" | "SELECTIVE_FIELDS";
  disclosedPaths: string[];
  fieldCount: number;
}

/**
 * Certificate for one record of a finalized batch. The QR carries the
 * certificate hash so a swapped package fails before any chain lookup.
 *
 * With a subset of paths the package is `SELECTIVE_FIELDS`: it carries the
 * values, the salts and a field proof of those paths only. `fieldRoot` is
 * unchanged, so the batch proof and the anchor stay the same as for a full
 * disclosure of the same record version.
 */
export function issueCertificate(
  batch: PreparedBatch,
  anchor: AnchorReference,
  request: CertificateRequest,
): IssuedCertificate {
  const record = batch.records.find((entry) => entry.internalRecordId === request.internalRecordId);
  if (record === undefined) throw new RangeError("record is not part of the batch");
  if (request.certificateId.length !== 16) throw new RangeError("certificateId must be 16 bytes");

  const available = record.fieldLeaves.map((leaf) => leaf.path);
  const requested = request.disclosedPaths === undefined
    ? available
    : [...new Set(request.disclosedPaths)];
  if (requested.length === 0) throw new RangeError("disclosure requires at least one field");
  for (const path of requested) {
    if (!available.includes(path)) throw new RangeError(`unknown disclosure path ${path}`);
  }
  const selective = requested.length < available.length;
  const disclosed = record.fields.filter((field) => requested.includes(field.path));
  const leafHashes = record.fieldLeaves.map((leaf) => leaf.leafHash);

  const body: CertificateBody = {
    certificateId: request.certificateId,
    registryId: batch.registryId,
    issuedAt: request.issuedAt,
    recordIdCommitment: record.recordIdCommitment,
    recordVersion: record.recordVersion,
    schemaVersion: SCHEMA_VERSION,
    disclosureMode: selective ? "SELECTIVE_FIELDS" : "FULL_RECORD",
    disclosedFields: Object.fromEntries(disclosed.map((field) => [field.path, field.value])),
    // Only the salts of disclosed paths leave the server: the record field key
    // never does, so an undisclosed salt cannot be derived from these (§2.1).
    fieldSalts: Object.fromEntries(
      disclosed.map((field) => [field.path, fieldSalt(record.recordFieldKey, field.path)]),
    ),
    fieldRoot: record.fieldRoot,
    fieldProofs: selective
      ? disclosed.map((field) => {
          const leafIndex = record.fieldLeaves.findIndex((leaf) => leaf.path === field.path);
          return {
            path: field.path,
            leafIndex,
            siblings: proof(leafHashes, leafIndex),
          };
        })
      : [],
    batchProof: {
      leafIndex: record.leafIndex,
      leafHash: record.batchLeafHash,
      siblings: proof(batch.records.map((entry) => entry.batchLeafHash), record.leafIndex),
      expectedRoot: batch.merkleRoot,
    },
    anchor: {
      batchSequence: batch.batchSequence,
      registryVersion: batch.registryVersion,
      merkleRoot: batch.merkleRoot,
      manifestHash: batch.manifestHash,
      solanaProgramId: anchor.solanaProgramId,
      segmentIndex: anchor.segmentIndex,
      segmentPda: anchor.segmentPda,
      transactionSignature: anchor.transactionSignature,
      anchorSlot: anchor.anchorSlot,
    },
    issuerKeyId: request.issuerKeyId,
    // `signCertificate` derives and substitutes the real public key.
    issuerPublicKey: new Uint8Array(32),
  };
  const signed = signCertificate(body, request.issuerSecretKey);
  const packageBytes = certificatePackageCbor(signed.body, signed.issuerSignature);
  const certificateId = Buffer.from(request.certificateId).toString("hex");
  const hash = signed.certificateHash;
  const qrUrl = `${request.publicBaseUrl}/c/${certificateId}?h=${Buffer.from(hash).toString("base64url")}`;
  return {
    certificateId,
    certificateHash: toHex(hash),
    packageBase64url: Buffer.from(packageBytes).toString("base64url"),
    qrUrl,
    recordVersion: record.recordVersion,
    internalRecordId: record.internalRecordId,
    disclosureMode: body.disclosureMode,
    disclosedPaths: disclosed.map((field) => field.path).sort(),
    fieldCount: available.length,
  };
}
