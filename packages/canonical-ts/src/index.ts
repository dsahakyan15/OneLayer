import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from "node:crypto";
import { leafHash, root, type Hash } from "../../merkle-ts/src/index.ts";

const textEncoder = new TextEncoder();

export const DOMAIN_FIELDSALT = textEncoder.encode("ONELAYER:FIELDSALT:V1");
export const DOMAIN_FIELD = textEncoder.encode("ONELAYER:FIELD:V1");
export const DOMAIN_RECORD = textEncoder.encode("ONELAYER:RECORD:V1");
export const DOMAIN_GENESIS = textEncoder.encode("ONELAYER:GENESIS:V1");
export const DOMAIN_ANCHOR = textEncoder.encode("ONELAYER:ANCHOR:V1");
export const ANCHOR_PREIMAGE_LEN = 260;
export const MAX_PATH_BYTES = 65_535;

export type CborValue =
  | { type: "null" }
  | { type: "bool"; value: boolean }
  | { type: "int"; value: string }
  | { type: "text"; value: string }
  | { type: "bytes"; hex: string }
  | { type: "array"; items: CborValue[] }
  | { type: "map"; entries: Record<string, CborValue> };

export interface FieldInput {
  path: string;
  value: CborValue;
}

export interface FieldTree {
  root: Hash;
  entries: Array<{ path: string; pathBytes: Uint8Array; commitment: Hash; leafHash: Hash }>;
}

export interface AnchorFields {
  registryIdHash: Hash;
  batchSequence: bigint;
  registryVersion: bigint;
  sourceCursorStart: bigint;
  sourceCursorEnd: bigint;
  merkleRoot: Hash;
  manifestHash: Hash;
  snapshotHash: Hash;
  previousAnchorHash: Hash;
  leafCount: number;
  schemaVersion: number;
  flags: number;
  hashAlgorithm: number;
  treeAlgorithm: number;
  operatorPubkey: Uint8Array;
  publishedAt: bigint;
}

export interface ManifestFields {
  registryIdHash: Hash;
  batchSequence: bigint;
  registryVersion: bigint;
  sourceCursorStart: bigint;
  sourceCursorEnd: bigint;
  createdAt: string;
  schemaVersion: number;
  leafCount: number;
  merkleRoot: Hash;
  previousAnchorHash: Hash;
  snapshotHash: Hash | null;
  leavesObjectUri: string;
  leavesObjectHash: Hash;
  builderVersion: string;
  operatorKeyId: string;
}

export interface SignedManifest {
  manifestHash: Hash;
  operatorPublicKey: Uint8Array;
  manifestSignature: Uint8Array;
}

export type DisclosureMode = "FULL_RECORD" | "SELECTIVE_FIELDS";

export interface CertificateProofStep {
  side: "LEFT" | "RIGHT";
  sibling: Hash;
}

export interface CertificateFieldProof {
  path: string;
  leafIndex: number;
  siblings: CertificateProofStep[];
}

export interface CertificateMerkleProof {
  leafIndex: number;
  leafHash: Hash;
  siblings: CertificateProofStep[];
  expectedRoot: Hash;
}

export interface CertificateAnchorReference {
  batchSequence: bigint;
  registryVersion: bigint;
  merkleRoot: Hash;
  manifestHash: Hash;
  solanaProgramId: Uint8Array;
  segmentIndex: number;
  segmentPda: Uint8Array;
  transactionSignature: Uint8Array;
  anchorSlot: bigint;
}

export interface CertificateBody {
  certificateId: Uint8Array;
  registryId: string;
  issuedAt: string;
  recordIdCommitment: Hash;
  recordVersion: bigint;
  schemaVersion: number;
  disclosureMode: DisclosureMode;
  disclosedFields: Record<string, CborValue>;
  fieldSalts: Record<string, Hash>;
  fieldRoot: Hash;
  fieldProofs: CertificateFieldProof[];
  batchProof: CertificateMerkleProof;
  anchor: CertificateAnchorReference;
  issuerKeyId: string;
  issuerPublicKey: Uint8Array;
}

export interface SignedCertificate {
  body: CertificateBody;
  certificateHash: Hash;
  issuerSignature: Uint8Array;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function sha256(...parts: Uint8Array[]): Hash {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function assertUnsigned(value: bigint, bits: number): void {
  if (value < 0n || value >= 1n << BigInt(bits)) {
    throw new RangeError(`unsigned ${bits}-bit integer out of range: ${value}`);
  }
}

function unsigned(value: bigint, bytes: number): Uint8Array {
  assertUnsigned(value, bytes * 8);
  const result = new Uint8Array(bytes);
  let remaining = value;
  for (let index = bytes - 1; index >= 0; index -= 1) {
    result[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return result;
}

function signed64(value: bigint): Uint8Array {
  const min = -(1n << 63n);
  const max = (1n << 63n) - 1n;
  if (value < min || value > max) throw new RangeError(`signed 64-bit integer out of range: ${value}`);
  return unsigned(value < 0n ? (1n << 64n) + value : value, 8);
}

function head(major: number, argument: bigint): Uint8Array {
  assertUnsigned(argument, 64);
  const prefix = major << 5;
  if (argument <= 23n) return Uint8Array.of(prefix | Number(argument));
  if (argument <= 0xffn) return concat(Uint8Array.of(prefix | 24), unsigned(argument, 1));
  if (argument <= 0xffffn) return concat(Uint8Array.of(prefix | 25), unsigned(argument, 2));
  if (argument <= 0xffff_ffffn) return concat(Uint8Array.of(prefix | 26), unsigned(argument, 4));
  return concat(Uint8Array.of(prefix | 27), unsigned(argument, 8));
}

export function nfc(value: string): string {
  return value.normalize("NFC");
}

export function encode(value: CborValue): Uint8Array {
  switch (value.type) {
    case "null":
      return Uint8Array.of(0xf6);
    case "bool":
      return Uint8Array.of(value.value ? 0xf5 : 0xf4);
    case "int": {
      const integer = BigInt(value.value);
      return integer >= 0n ? head(0, integer) : head(1, -(integer + 1n));
    }
    case "text": {
      const bytes = textEncoder.encode(nfc(value.value));
      return concat(head(3, BigInt(bytes.length)), bytes);
    }
    case "bytes": {
      const bytes = fromHex(value.hex);
      return concat(head(2, BigInt(bytes.length)), bytes);
    }
    case "array":
      return concat(head(4, BigInt(value.items.length)), ...value.items.map(encode));
    case "map": {
      const entries = Object.entries(value.entries)
        .map(([key, entryValue]) => ({ key: encode({ type: "text", value: key }), value: encode(entryValue) }))
        .sort((left, right) => Buffer.compare(left.key, right.key));
      return concat(
        head(5, BigInt(entries.length)),
        ...entries.flatMap((entry) => [entry.key, entry.value]),
      );
    }
  }
}

class CborReader {
  #offset = 0;
  private readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  get offset(): number {
    return this.#offset;
  }

  readValue(): CborValue {
    const initial = this.readByte();
    const major = initial >> 5;
    const additional = initial & 0x1f;
    if (major === 7) {
      if (additional === 20) return { type: "bool", value: false };
      if (additional === 21) return { type: "bool", value: true };
      if (additional === 22) return { type: "null" };
      throw new TypeError("CBOR simple value is not supported");
    }
    const argument = this.readArgument(additional);
    if (major === 0) return { type: "int", value: argument.toString() };
    if (major === 1) return { type: "int", value: (-1n - argument).toString() };
    const length = this.safeLength(argument);
    if (major === 2) return { type: "bytes", hex: toHex(this.readBytes(length)) };
    if (major === 3) {
      const value = new TextDecoder("utf-8", { fatal: true }).decode(this.readBytes(length));
      return { type: "text", value };
    }
    if (major === 4) {
      const items: CborValue[] = [];
      for (let index = 0; index < length; index += 1) items.push(this.readValue());
      return { type: "array", items };
    }
    if (major === 5) {
      const entries: Record<string, CborValue> = {};
      for (let index = 0; index < length; index += 1) {
        const key = this.readValue();
        if (key.type !== "text") throw new TypeError("CBOR map key must be text");
        if (Object.hasOwn(entries, key.value)) throw new TypeError(`duplicate CBOR map key: ${key.value}`);
        Object.defineProperty(entries, key.value, {
          value: this.readValue(),
          enumerable: true,
          configurable: true,
          writable: true,
        });
      }
      return { type: "map", entries };
    }
    throw new TypeError(`CBOR major type ${major} is not supported`);
  }

  private readArgument(additional: number): bigint {
    if (additional < 24) return BigInt(additional);
    const bytes = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
    if (bytes === 0) throw new TypeError("indefinite-length CBOR is not supported");
    let value = 0n;
    for (let index = 0; index < bytes; index += 1) value = (value << 8n) | BigInt(this.readByte());
    const minimum = bytes === 1 ? 24n : bytes === 2 ? 0x100n : bytes === 4 ? 0x1_0000n : 0x1_0000_0000n;
    if (value < minimum) throw new TypeError("non-shortest CBOR integer or length");
    return value;
  }

  private safeLength(value: bigint): number {
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError("CBOR length exceeds safe integer range");
    return Number(value);
  }

  private readByte(): number {
    if (this.#offset >= this.bytes.length) throw new TypeError("truncated CBOR");
    return this.bytes[this.#offset++];
  }

  private readBytes(length: number): Uint8Array {
    const end = this.#offset + length;
    if (end > this.bytes.length) throw new TypeError("truncated CBOR");
    const value = this.bytes.slice(this.#offset, end);
    this.#offset = end;
    return value;
  }
}

export function decodeCanonical(input: Uint8Array): CborValue {
  const reader = new CborReader(input);
  const value = reader.readValue();
  if (reader.offset !== input.length) throw new TypeError("trailing bytes after CBOR value");
  if (!Buffer.from(encode(value)).equals(Buffer.from(input))) {
    throw new TypeError("CBOR encoding is not canonical");
  }
  return value;
}

export function pathBytes(path: string): Uint8Array {
  const bytes = textEncoder.encode(nfc(path));
  if (bytes.length > MAX_PATH_BYTES) {
    throw new RangeError(`CANONICALIZATION_FAILED: byte_len(path)=${bytes.length} > ${MAX_PATH_BYTES}`);
  }
  return bytes;
}

export function fieldSalt(recordFieldKey: Uint8Array, path: string): Hash {
  if (recordFieldKey.length !== 32) throw new RangeError("record_field_key must be 32 bytes");
  return createHmac("sha256", recordFieldKey).update(DOMAIN_FIELDSALT).update(pathBytes(path)).digest();
}

export function fieldCommitment(path: string, value: CborValue, salt: Hash): Hash {
  if (salt.length !== 32) throw new RangeError("field_salt must be 32 bytes");
  const pathEncoded = pathBytes(path);
  const valueCbor = encode(value);
  return sha256(
    DOMAIN_FIELD,
    unsigned(BigInt(pathEncoded.length), 2),
    pathEncoded,
    unsigned(BigInt(valueCbor.length), 4),
    valueCbor,
    salt,
  );
}

export function buildFieldTree(recordFieldKey: Uint8Array, fields: FieldInput[]): FieldTree {
  if (fields.length === 0) throw new RangeError("CANONICALIZATION_FAILED: record has no fields");
  const entries = fields
    .map((field) => {
      const encodedPath = pathBytes(field.path);
      const commitment = fieldCommitment(field.path, field.value, fieldSalt(recordFieldKey, field.path));
      return { path: field.path, pathBytes: encodedPath, commitment, leafHash: leafHash(commitment) };
    })
    .sort((left, right) => Buffer.compare(left.pathBytes, right.pathBytes));
  for (let index = 1; index < entries.length; index += 1) {
    if (Buffer.compare(entries[index - 1].pathBytes, entries[index].pathBytes) === 0) {
      throw new RangeError(`CANONICALIZATION_FAILED: duplicate path ${entries[index].path}`);
    }
  }
  return { entries, root: root(entries.map((entry) => entry.leafHash)) };
}

export function registryIdHash(registryId: string): Hash {
  return sha256(textEncoder.encode(nfc(registryId)));
}

export function recordIdCommitment(idKey: Uint8Array, registryId: string, internalRecordId: string): Hash {
  return createHmac("sha256", idKey)
    .update(textEncoder.encode(nfc(registryId)))
    .update(Uint8Array.of(0))
    .update(textEncoder.encode(nfc(internalRecordId)))
    .digest();
}

export function recordCommitment(
  registryHash: Hash,
  recordId: Hash,
  recordVersion: bigint,
  fieldRoot: Hash,
): Hash {
  return sha256(DOMAIN_RECORD, registryHash, recordId, unsigned(recordVersion, 8), fieldRoot);
}

export function batchLeafHash(commitment: Hash): Hash {
  return leafHash(commitment);
}

export function genesisAnchorHash(registryHash: Hash): Hash {
  return sha256(DOMAIN_GENESIS, registryHash);
}

export function manifestUnsignedCbor(fields: ManifestFields): Uint8Array {
  return encode({
    type: "map",
    entries: {
      manifestVersion: { type: "int", value: "1" },
      registryIdHash: { type: "bytes", hex: toHex(fields.registryIdHash) },
      batchSequence: { type: "int", value: fields.batchSequence.toString() },
      registryVersion: { type: "int", value: fields.registryVersion.toString() },
      sourceCursorStart: { type: "int", value: fields.sourceCursorStart.toString() },
      sourceCursorEnd: { type: "int", value: fields.sourceCursorEnd.toString() },
      createdAt: { type: "text", value: fields.createdAt },
      schemaVersion: { type: "int", value: fields.schemaVersion.toString() },
      hashAlgorithm: { type: "text", value: "SHA256" },
      treeAlgorithm: { type: "text", value: "RFC6962_SHA256_V1" },
      leafCount: { type: "int", value: fields.leafCount.toString() },
      merkleRoot: { type: "bytes", hex: toHex(fields.merkleRoot) },
      previousAnchorHash: { type: "bytes", hex: toHex(fields.previousAnchorHash) },
      snapshotHash:
        fields.snapshotHash === null
          ? { type: "null" }
          : { type: "bytes", hex: toHex(fields.snapshotHash) },
      leavesObjectUri: { type: "text", value: fields.leavesObjectUri },
      leavesObjectHash: { type: "bytes", hex: toHex(fields.leavesObjectHash) },
      builderVersion: { type: "text", value: fields.builderVersion },
      operatorKeyId: { type: "text", value: fields.operatorKeyId },
    },
  });
}

export function manifestHash(fields: ManifestFields): Hash {
  return sha256(manifestUnsignedCbor(fields));
}

export function signManifest(fields: ManifestFields, secretKey: Uint8Array): SignedManifest {
  if (secretKey.length !== 32) throw new RangeError("Ed25519 secret key must be 32 bytes");
  const privateDer = concat(fromHex("302e020100300506032b657004220420"), secretKey);
  const privateKey = createPrivateKey({ key: Buffer.from(privateDer), format: "der", type: "pkcs8" });
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const hash = manifestHash(fields);
  return {
    manifestHash: hash,
    operatorPublicKey: new Uint8Array(publicDer).slice(-32),
    manifestSignature: ed25519Sign(null, hash, privateKey),
  };
}

export function verifyManifestSignature(signed: SignedManifest): boolean {
  if (signed.operatorPublicKey.length !== 32 || signed.manifestSignature.length !== 64) return false;
  const publicDer = concat(fromHex("302a300506032b6570032100"), signed.operatorPublicKey);
  const publicKey = createPublicKey({ key: Buffer.from(publicDer), format: "der", type: "spki" });
  return ed25519Verify(null, signed.manifestHash, publicKey, signed.manifestSignature);
}

function certificateProofSteps(steps: CertificateProofStep[]): CborValue {
  return {
    type: "array",
    items: steps.map((step) => ({
      type: "map",
      entries: {
        side: { type: "text", value: step.side },
        hash: { type: "bytes", hex: toHex(step.sibling) },
      },
    })),
  };
}

function certificateBodyEntries(body: CertificateBody): Record<string, CborValue> {
  const fieldPaths = Object.keys(body.disclosedFields).sort();
  const saltPaths = Object.keys(body.fieldSalts).sort();
  if (fieldPaths.length === 0) throw new RangeError("CERTIFICATE_FORMAT_INVALID: empty disclosure");
  if (fieldPaths.join("\0") !== saltPaths.join("\0")) {
    throw new RangeError("CERTIFICATE_FORMAT_INVALID: disclosure paths mismatch");
  }
  const proofPaths = body.fieldProofs.map((proof) => proof.path).sort();
  if (body.disclosureMode === "FULL_RECORD" && proofPaths.length !== 0) {
    throw new RangeError("CERTIFICATE_FORMAT_INVALID: FULL_RECORD fieldProofs must be empty");
  }
  if (
    body.disclosureMode === "SELECTIVE_FIELDS" &&
    (fieldPaths.join("\0") !== proofPaths.join("\0") || proofPaths.length !== body.fieldProofs.length)
  ) {
    throw new RangeError("CERTIFICATE_FORMAT_INVALID: disclosure paths mismatch");
  }

  const disclosedEntries = Object.fromEntries(fieldPaths.map((path) => [path, body.disclosedFields[path]]));
  const saltEntries = Object.fromEntries(
    saltPaths.map((path) => [path, { type: "bytes", hex: toHex(body.fieldSalts[path]) } satisfies CborValue]),
  );
  return {
    format: { type: "text", value: "ONELAYER_CERTIFICATE" },
    version: { type: "int", value: "1" },
    certificateId: { type: "bytes", hex: toHex(body.certificateId) },
    registryId: { type: "text", value: body.registryId },
    issuedAt: { type: "text", value: body.issuedAt },
    recordIdCommitment: { type: "bytes", hex: toHex(body.recordIdCommitment) },
    recordVersion: { type: "int", value: body.recordVersion.toString() },
    schemaVersion: { type: "int", value: body.schemaVersion.toString() },
    disclosureMode: { type: "text", value: body.disclosureMode },
    disclosedFields: { type: "map", entries: disclosedEntries },
    fieldSalts: { type: "map", entries: saltEntries },
    fieldRoot: { type: "bytes", hex: toHex(body.fieldRoot) },
    fieldProofs: {
      type: "array",
      items: body.fieldProofs.map((fieldProof) => ({
        type: "map",
        entries: {
          path: { type: "text", value: fieldProof.path },
          leafIndex: { type: "int", value: fieldProof.leafIndex.toString() },
          siblings: certificateProofSteps(fieldProof.siblings),
        },
      })),
    },
    batchProof: {
      type: "map",
      entries: {
        treeAlgorithm: { type: "text", value: "RFC6962_SHA256_V1" },
        leafIndex: { type: "int", value: body.batchProof.leafIndex.toString() },
        leafHash: { type: "bytes", hex: toHex(body.batchProof.leafHash) },
        siblings: certificateProofSteps(body.batchProof.siblings),
        expectedRoot: { type: "bytes", hex: toHex(body.batchProof.expectedRoot) },
      },
    },
    anchor: {
      type: "map",
      entries: {
        batchSequence: { type: "int", value: body.anchor.batchSequence.toString() },
        registryVersion: { type: "int", value: body.anchor.registryVersion.toString() },
        merkleRoot: { type: "bytes", hex: toHex(body.anchor.merkleRoot) },
        manifestHash: { type: "bytes", hex: toHex(body.anchor.manifestHash) },
        solanaProgramId: { type: "bytes", hex: toHex(body.anchor.solanaProgramId) },
        segmentIndex: { type: "int", value: body.anchor.segmentIndex.toString() },
        segmentPda: { type: "bytes", hex: toHex(body.anchor.segmentPda) },
        transactionSignature: { type: "bytes", hex: toHex(body.anchor.transactionSignature) },
        anchorSlot: { type: "int", value: body.anchor.anchorSlot.toString() },
        commitmentRequired: { type: "text", value: "finalized" },
      },
    },
    issuer: {
      type: "map",
      entries: {
        keyId: { type: "text", value: body.issuerKeyId },
        publicKey: { type: "bytes", hex: toHex(body.issuerPublicKey) },
        signatureAlgorithm: { type: "text", value: "Ed25519" },
      },
    },
  };
}

export function certificateBodyCbor(body: CertificateBody): Uint8Array {
  return encode({ type: "map", entries: certificateBodyEntries(body) });
}

export function certificateHash(body: CertificateBody): Hash {
  return sha256(certificateBodyCbor(body));
}

export function signCertificate(body: CertificateBody, secretKey: Uint8Array): SignedCertificate {
  if (secretKey.length !== 32) throw new RangeError("Ed25519 secret key must be 32 bytes");
  const privateDer = concat(fromHex("302e020100300506032b657004220420"), secretKey);
  const privateKey = createPrivateKey({ key: Buffer.from(privateDer), format: "der", type: "pkcs8" });
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const signedBody = { ...body, issuerPublicKey: new Uint8Array(publicDer).slice(-32) };
  const hash = certificateHash(signedBody);
  return {
    body: signedBody,
    certificateHash: hash,
    issuerSignature: ed25519Sign(null, hash, privateKey),
  };
}

export function verifyCertificateSignature(signed: SignedCertificate): boolean {
  const publicDer = concat(fromHex("302a300506032b6570032100"), signed.body.issuerPublicKey);
  const publicKey = createPublicKey({ key: Buffer.from(publicDer), format: "der", type: "spki" });
  return (
    Buffer.compare(certificateHash(signed.body), signed.certificateHash) === 0 &&
    ed25519Verify(null, signed.certificateHash, publicKey, signed.issuerSignature)
  );
}

export function certificatePackageCbor(body: CertificateBody, signature: Uint8Array): Uint8Array {
  return encode({
    type: "map",
    entries: {
      ...certificateBodyEntries(body),
      issuerSignature: { type: "bytes", hex: toHex(signature) },
    },
  });
}

export function anchorPreimage(fields: AnchorFields): Uint8Array {
  const preimage = concat(
    DOMAIN_ANCHOR,
    fields.registryIdHash,
    unsigned(fields.batchSequence, 8),
    unsigned(fields.registryVersion, 8),
    unsigned(fields.sourceCursorStart, 8),
    unsigned(fields.sourceCursorEnd, 8),
    fields.merkleRoot,
    fields.manifestHash,
    fields.snapshotHash,
    fields.previousAnchorHash,
    unsigned(BigInt(fields.leafCount), 4),
    unsigned(BigInt(fields.schemaVersion), 2),
    unsigned(BigInt(fields.flags), 2),
    unsigned(BigInt(fields.hashAlgorithm), 1),
    unsigned(BigInt(fields.treeAlgorithm), 1),
    fields.operatorPubkey,
    signed64(fields.publishedAt),
  );
  if (preimage.length !== ANCHOR_PREIMAGE_LEN) {
    throw new RangeError(`anchor_preimage must be ${ANCHOR_PREIMAGE_LEN} bytes, got ${preimage.length}`);
  }
  return preimage;
}

export function anchorHash(fields: AnchorFields): Hash {
  return sha256(anchorPreimage(fields));
}

export function fromHex(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/.test(value)) throw new TypeError("invalid lowercase hex");
  return Buffer.from(value, "hex");
}

export function toHex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}
