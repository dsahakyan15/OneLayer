// Certificate issuance for a finalized workflow publication (ticket 09).
//
// The publication layer commits each workflow version to a chain anchor through
// ONELAYER:WORKFLOW:FIELDMAP:V1. This module turns one published version back
// into a Certificate Package using the exact same field mapping and deployment
// keys that produced the intent, so the package's field proof and batch proof
// verify against the finalized anchor. It re-derives every commitment from the
// stored payload and refuses if anything disagrees with the intent leaf.
//
// The certificate is stored in demo_certificate (with the workflow anchor id
// recorded) so the existing public lookup, QR and verifier routes keep working.
// Idempotent per (operation, record, version, disclosure).
import { createHash, randomBytes } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { address, getAddressEncoder, type Address } from "@solana/kit";
import {
  buildFieldTree,
  batchLeafHash as batchLeafHashOf,
  recordCommitment as recordCommitmentOf,
  recordIdCommitment as recordIdCommitmentOf,
  registryIdHash,
  type CborValue,
} from "../../../packages/canonical-ts/src/index.ts";
import { issueCertificate, type PreparedBatch, type PreparedRecord } from "./admin-batch.ts";
import { recordFieldKey, workflowFields, type PublicationIntent, type PublicationKeys } from "./publication-intent.ts";
import { workflowHash } from "./registry-workflow.ts";

export class WorkflowCertificateError extends Error {
  constructor(public status: number, public code: string) { super(code); }
}

export interface WorkflowCertificateDeps {
  pool: Pool;
  registryId: string;
  programId: Address;
  keys: PublicationKeys;
  issuerSecretKey: Uint8Array;
  issuerKeyId: string;
  publicBaseUrl: string;
  now: () => Date;
}

export interface WorkflowCertificateRequest {
  operationId: string;
  recordId: string;
  version: number;
  disclosedPaths?: readonly string[];
}

export interface WorkflowIssuedCertificate {
  certificateId: string;
  certificateHash: string;
  qrUrl: string;
  recordVersion: string;
  disclosureMode: "FULL_RECORD" | "SELECTIVE_FIELDS";
  disclosedPaths: string[];
  fieldCount: number;
  anchor: { batchSequence: string; anchorSlot: string; transactionSignature: string; merkleRoot: string };
  replayed: boolean;
}

function fieldText(value: CborValue): string {
  const plain = (entry: CborValue): unknown =>
    entry.type === "null" ? null
    : entry.type === "bool" ? entry.value
    : entry.type === "text" ? entry.value
    : entry.type === "int" ? entry.value
    : entry.type === "bytes" ? entry.hex
    : entry.type === "array" ? entry.items.map(plain)
    : Object.fromEntries(Object.entries(entry.entries).map(([k, v]) => [k, plain(v)]));
  const converted = plain(value);
  return typeof converted === "string" ? converted : JSON.stringify(converted);
}

function leafRow(row: any): { recordId: string; version: number; payload: Record<string, unknown>; operation: "upsert" | "tombstone" } {
  return { recordId: row.record_id, version: row.version, payload: row.payload, operation: row.operation };
}

export function preparedRecordForLeaf(
  leaf: PublicationIntent["items"][number],
  version: { payload: Record<string, unknown>; operation: "upsert" | "tombstone" },
  registryId: string,
  keys: PublicationKeys,
): PreparedRecord {
  const item = { operation: version.operation, payload: version.payload };
  if (workflowHash(item) !== leaf.payloadHash) throw new WorkflowCertificateError(409, "PUBLICATION_PAYLOAD_MISMATCH");
  const fields = workflowFields(item).map((field) => ({ path: field.path, value: field.value, text: fieldText(field.value) }));
  const recordFieldKeyBytes = recordFieldKey(keys, registryId, leaf.recordId, leaf.version);
  const tree = buildFieldTree(recordFieldKeyBytes, fields);
  if (Buffer.from(tree.root).toString("hex") !== leaf.fieldRoot) throw new WorkflowCertificateError(409, "PUBLICATION_FIELD_ROOT_MISMATCH");
  const identifier = recordIdCommitmentOf(keys.idKey, registryId, leaf.recordId);
  if (Buffer.from(identifier).toString("hex") !== leaf.recordIdCommitment) throw new WorkflowCertificateError(409, "PUBLICATION_RECORD_ID_MISMATCH");
  const commitment = recordCommitmentOf(registryIdHash(registryId), identifier, BigInt(leaf.version), tree.root);
  if (Buffer.from(commitment).toString("hex") !== leaf.recordCommitment) throw new WorkflowCertificateError(409, "PUBLICATION_RECORD_COMMITMENT_MISMATCH");
  const leafHash = batchLeafHashOf(commitment);
  if (Buffer.from(leafHash).toString("hex") !== leaf.leafHash) throw new WorkflowCertificateError(409, "PUBLICATION_LEAF_HASH_MISMATCH");
  return {
    internalRecordId: leaf.recordId,
    recordVersion: BigInt(leaf.version),
    recordIdCommitment: Uint8Array.from(identifier),
    fieldRoot: Uint8Array.from(tree.root),
    recordCommitment: Uint8Array.from(commitment),
    batchLeafHash: Uint8Array.from(leafHash),
    leafIndex: leaf.leafIndex,
    fields,
    fieldLeaves: tree.entries.map((entry) => ({ path: entry.path, commitment: entry.commitment, leafHash: entry.leafHash })),
    recordFieldKey: recordFieldKeyBytes,
  };
}

async function loadFinalizedOperation(pool: Pool, registryId: string, operationId: string) {
  const result = await pool.query(
    `SELECT p.state, i.intent_bytes, i.intent_hash, i.batch_sequence::text AS batch_sequence,
            a.signature, a.slot::text AS slot, a.segment_pda, a.anchor_hash, a.merkle_root, a.manifest_hash,
            tx.segment_index
       FROM wf_publication p
       JOIN wf_publication_intent i USING(operation_id)
       JOIN wf_publication_anchor a USING(operation_id)
       JOIN wf_publication_tx tx ON tx.attempt_id = a.attempt_id
      WHERE p.operation_id = $1 AND p.registry_id = $2`,
    [operationId, registryId],
  );
  if (result.rows.length === 0) throw new WorkflowCertificateError(404, "PUBLICATION_NOT_FOUND");
  const row = result.rows[0];
  if (row.state !== "FINALIZED") throw new WorkflowCertificateError(409, "ANCHOR_NOT_FINALIZED");
  if (row.slot === null) throw new WorkflowCertificateError(409, "ANCHOR_SLOT_UNAVAILABLE");
  let intent: PublicationIntent;
  try { intent = JSON.parse(Buffer.from(row.intent_bytes).toString("utf8")); }
  catch { throw new WorkflowCertificateError(409, "PUBLICATION_INTENT_INVALID"); }
  const storedHash = createHash("sha256").update("ONELAYER:WORKFLOW:PUBLICATION:INTENT:V1\n").update(row.intent_bytes).digest("hex");
  if (storedHash !== row.intent_hash || intent.operationId !== operationId || intent.registryId !== registryId) {
    throw new WorkflowCertificateError(409, "PUBLICATION_INTENT_INVALID");
  }
  return { row, intent };
}

async function loadVersionPayloads(pool: Pool, registryId: string, leaves: PublicationIntent["items"]): Promise<ReturnType<typeof leafRow>[]> {
  const versions = await Promise.all(leaves.map((leaf) => pool.query(
    `SELECT record_id, version, payload, operation FROM wf_version WHERE registry_id = $1 AND record_id = $2 AND version = $3`,
    [registryId, leaf.recordId, leaf.version],
  )));
  return versions.map((result, index) => {
    const row = result.rows[0];
    if (row === undefined) throw new WorkflowCertificateError(409, `PUBLICATION_VERSION_MISSING:${leaves[index].recordId}`);
    return leafRow(row);
  });
}

export async function issueWorkflowCertificate(
  deps: WorkflowCertificateDeps,
  request: WorkflowCertificateRequest,
): Promise<WorkflowIssuedCertificate> {
  const { pool, registryId, keys } = deps;
  const { row, intent } = await loadFinalizedOperation(pool, registryId, request.operationId);
  const target = intent.items.find((leaf) => leaf.recordId === request.recordId && leaf.version === request.version);
  if (target === undefined) throw new WorkflowCertificateError(404, "PUBLICATION_VERSION_NOT_IN_OPERATION");
  const payloads = await loadVersionPayloads(pool, registryId, intent.items);
  const records = intent.items.map((leaf, index) => preparedRecordForLeaf(leaf, payloads[index], registryId, keys));
  records.sort((left, right) => left.leafIndex - right.leafIndex);

  // Idempotency: one certificate per (operation, record, version, disclosure
  // set). The request is normalized exactly like issueCertificate normalizes it:
  // an explicit list that covers every field of this version is FULL_RECORD; a
  // shorter list is SELECTIVE_FIELDS keyed by its sorted unique paths. Applying
  // the same rule to stored rows means an omitted disclosure, a reordered full
  // list and a repeated selective set all resolve to one certificate instead of
  // racing the unique index.
  const targetRecord = records.find((record) => record.internalRecordId === request.recordId)!;
  const availablePaths = targetRecord.fields.map((field) => field.path);
  const requested = request.disclosedPaths === undefined ? undefined : [...new Set(request.disclosedPaths)];
  if (requested !== undefined) {
    if (requested.length === 0) throw new WorkflowCertificateError(400, "PUBLICATION_DISCLOSURE_EMPTY");
    const unknown = requested.find((path) => !availablePaths.includes(path));
    if (unknown !== undefined) throw new WorkflowCertificateError(400, "PUBLICATION_DISCLOSURE_PATH_UNKNOWN");
  }
  const selective = requested !== undefined && requested.length < availablePaths.length;
  const disclosureKey = selective ? [...requested!].sort().join("\u0000") : "FULL";
  // A stored row is compared with the same normalization, so a legacy
  // SELECTIVE_FIELDS row whose path set covers the whole version is recognized
  // as the same full disclosure. An unrecognized shape never matches.
  const storedKey = (mode: unknown, paths: unknown): string | null => {
    if (mode === "FULL_RECORD") return "FULL";
    if (mode !== "SELECTIVE_FIELDS" || !Array.isArray(paths)) return null;
    const unique = [...new Set(paths as string[])];
    return unique.length >= availablePaths.length ? "FULL" : unique.sort().join("\u0000");
  };
  const storedCertificate = (stored: any): WorkflowIssuedCertificate => ({
    certificateId: stored.certificate_id,
    certificateHash: stored.certificate_hash,
    qrUrl: stored.qr_url,
    recordVersion: stored.record_version,
    disclosureMode: stored.disclosure_mode,
    disclosedPaths: stored.disclosed_paths,
    fieldCount: availablePaths.length,
    anchor: { batchSequence: row.batch_sequence, anchorSlot: row.slot, transactionSignature: row.signature, merkleRoot: row.merkle_root },
    replayed: true,
  });
  const existing = await pool.query(
    `SELECT certificate_id, encode(certificate_hash,'hex') AS certificate_hash, qr_url, record_version::text,
            disclosure_mode, disclosed_paths
       FROM demo_certificate
      WHERE registry_id = $1 AND anchor_operation_id = $2 AND internal_record_id = $3 AND record_version = $4`,
    [registryId, request.operationId, request.recordId, request.version],
  );
  for (const candidate of existing.rows) {
    if (storedKey(candidate.disclosure_mode, candidate.disclosed_paths) !== disclosureKey) continue;
    return storedCertificate(candidate);
  }

  const batch: PreparedBatch = {
    registryId,
    batchSequence: BigInt(row.batch_sequence),
    registryVersion: BigInt(intent.registryVersion),
    cursorStart: BigInt(intent.cursorStart),
    cursorEnd: BigInt(intent.cursorEnd),
    leafCount: intent.leafCount,
    merkleRoot: Uint8Array.from(Buffer.from(intent.merkleRoot, "hex")),
    manifestHash: Uint8Array.from(Buffer.from(intent.manifestHash, "hex")),
    previousAnchorHash: Uint8Array.from(Buffer.from(intent.previousAnchorHash, "hex")),
    records,
  };
  const encoder = getAddressEncoder();
  const issued = issueCertificate(
    batch,
    {
      solanaProgramId: new Uint8Array(encoder.encode(deps.programId)),
      segmentIndex: row.segment_index,
      segmentPda: new Uint8Array(encoder.encode(address(String(row.segment_pda)))),
      transactionSignature: new Uint8Array(getBase58Bytes(String(row.signature))),
      anchorSlot: BigInt(row.slot),
    },
    {
      internalRecordId: request.recordId,
      certificateId: new Uint8Array(randomBytes(16)),
      issuedAt: deps.now().toISOString().replace(/\.\d{3}Z$/, "Z"),
      issuerKeyId: deps.issuerKeyId,
      issuerSecretKey: deps.issuerSecretKey,
      publicBaseUrl: deps.publicBaseUrl,
      disclosedPaths: selective ? requested : undefined,
    },
  );

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // The legacy certificate projection has a foreign key to demo_anchor, so the
    // same finalized workflow anchor is projected there for lookup routes.
    await client.query(
      `INSERT INTO demo_anchor (
         registry_id, batch_sequence, registry_version, merkle_root, manifest_hash, anchor_hash,
         program_id, segment_pda, transaction_signature, anchor_slot, commitment, finalized_at
       ) VALUES ($1,$2,$3,decode($4,'hex'),decode($5,'hex'),decode($6,'hex'),$7,$8,$9,$10,'finalized',now())
       ON CONFLICT (registry_id, batch_sequence) DO NOTHING`,
      [registryId, row.batch_sequence, intent.registryVersion, intent.merkleRoot, intent.manifestHash, row.anchor_hash,
        deps.programId, row.segment_pda, row.signature, row.slot],
    );
    await client.query(
      `INSERT INTO demo_certificate (
         certificate_id, registry_id, batch_sequence, certificate_hash, package_base64url, qr_url,
         status, issued_at, internal_record_id, record_version, disclosure_mode, disclosed_paths,
         anchor_operation_id, anchor_intent_hash
       ) VALUES ($1,$2,$3,decode($4,'hex'),$5,$6,'ACTIVE',now(),$7,$8,$9,$10,$11,$12)`,
      [issued.certificateId, registryId, row.batch_sequence, issued.certificateHash, issued.packageBase64url, issued.qrUrl,
        request.recordId, issued.recordVersion.toString(), issued.disclosureMode, issued.disclosedPaths,
        request.operationId, row.intent_hash],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    if ((error as { code?: string }).code === "23505") {
      // A concurrent identical issuance won; return it instead of a 500. The
      // lookup uses the same normalized comparison as the pre-check, so an
      // explicit-full vs omitted-full race still resolves to one certificate.
      const concurrent = await pool.query(
        `SELECT certificate_id, encode(certificate_hash,'hex') AS certificate_hash, qr_url, record_version::text,
                disclosure_mode, disclosed_paths
           FROM demo_certificate
          WHERE registry_id = $1 AND anchor_operation_id = $2 AND internal_record_id = $3 AND record_version = $4`,
        [registryId, request.operationId, request.recordId, request.version],
      );
      const found = concurrent.rows.find((candidate) => storedKey(candidate.disclosure_mode, candidate.disclosed_paths) === disclosureKey);
      if (found !== undefined) return storedCertificate(found);
      // A unique-index collision that does not resolve to this normalized
      // disclosure is surfaced as a coded conflict, never as a raw pg 23505.
      throw new WorkflowCertificateError(409, "PUBLICATION_CERTIFICATE_CONFLICT");
    }
    throw error;
  } finally {
    client.release();
  }
  return {
    certificateId: issued.certificateId,
    certificateHash: issued.certificateHash,
    qrUrl: issued.qrUrl,
    recordVersion: issued.recordVersion.toString(),
    disclosureMode: issued.disclosureMode,
    disclosedPaths: [...issued.disclosedPaths].sort(),
    fieldCount: issued.fieldCount,
    anchor: { batchSequence: row.batch_sequence, anchorSlot: row.slot, transactionSignature: row.signature, merkleRoot: row.merkle_root },
    replayed: false,
  };
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function getBase58Bytes(value: string): Uint8Array {
  let number = 0n;
  for (const character of value) {
    const index = BASE58_ALPHABET.indexOf(character);
    if (index < 0) throw new WorkflowCertificateError(409, "ANCHOR_SIGNATURE_INVALID");
    number = number * 58n + BigInt(index);
  }
  const bytes: number[] = [];
  while (number > 0n) { bytes.unshift(Number(number & 0xffn)); number >>= 8n; }
  let leading = 0;
  while (leading < value.length && value[leading] === "1") leading += 1;
  return Uint8Array.from([...new Array(leading).fill(0), ...bytes]);
}
