import {
  certificateHash,
  decodeCanonical,
  fromHex,
  type CertificateBody,
  type CertificateFieldProof,
  type CertificateProofStep,
  type CborValue,
  type DisclosureMode,
  type SignedCertificate,
} from "../../../packages/canonical-ts/src/index.ts";

function map(value: CborValue, label: string): Record<string, CborValue> {
  if (value.type !== "map") throw new TypeError(`${label} must be a CBOR map`);
  return value.entries;
}

function exactKeys(value: Record<string, CborValue>, expected: string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.join("\0") !== wanted.join("\0")) throw new TypeError(`${label} fields are invalid`);
}

function text(value: CborValue, label: string): string {
  if (value.type !== "text") throw new TypeError(`${label} must be CBOR text`);
  return value.value;
}

function integer(value: CborValue, label: string, maximum: bigint): bigint {
  if (value.type !== "int") throw new TypeError(`${label} must be a CBOR integer`);
  const parsed = BigInt(value.value);
  if (parsed < 0n || parsed > maximum) throw new RangeError(`${label} is out of range`);
  return parsed;
}

function number(value: CborValue, label: string, maximum: number): number {
  return Number(integer(value, label, BigInt(maximum)));
}

function bytes(value: CborValue, label: string, length: number): Uint8Array {
  if (value.type !== "bytes") throw new TypeError(`${label} must be CBOR bytes`);
  const decoded = fromHex(value.hex);
  if (decoded.length !== length) throw new RangeError(`${label} must be ${length} bytes`);
  return decoded;
}

function array(value: CborValue, label: string): CborValue[] {
  if (value.type !== "array") throw new TypeError(`${label} must be a CBOR array`);
  return value.items;
}

function proofSteps(value: CborValue, label: string): CertificateProofStep[] {
  return array(value, label).map((item, index) => {
    const step = map(item, `${label}[${index}]`);
    exactKeys(step, ["side", "hash"], `${label}[${index}]`);
    const side = text(step.side, `${label}[${index}].side`);
    if (side !== "LEFT" && side !== "RIGHT") throw new TypeError(`${label}[${index}].side is invalid`);
    return { side, sibling: bytes(step.hash, `${label}[${index}].hash`, 32) };
  });
}

function fieldProofs(value: CborValue): CertificateFieldProof[] {
  return array(value, "fieldProofs").map((item, index) => {
    const proof = map(item, `fieldProofs[${index}]`);
    exactKeys(proof, ["path", "leafIndex", "siblings"], `fieldProofs[${index}]`);
    return {
      path: text(proof.path, `fieldProofs[${index}].path`),
      leafIndex: number(proof.leafIndex, `fieldProofs[${index}].leafIndex`, 0xffff_ffff),
      siblings: proofSteps(proof.siblings, `fieldProofs[${index}].siblings`),
    };
  });
}

function decodeBody(entries: Record<string, CborValue>): CertificateBody {
  if (text(entries.format, "format") !== "ONELAYER_CERTIFICATE") throw new TypeError("certificate format is invalid");
  if (integer(entries.version, "version", 0xffffn) !== 1n) throw new TypeError("certificate version is invalid");
  const disclosureMode = text(entries.disclosureMode, "disclosureMode") as DisclosureMode;
  if (disclosureMode !== "FULL_RECORD" && disclosureMode !== "SELECTIVE_FIELDS") {
    throw new TypeError("disclosureMode is invalid");
  }

  const disclosed = map(entries.disclosedFields, "disclosedFields");
  const salts = map(entries.fieldSalts, "fieldSalts");
  const batchProof = map(entries.batchProof, "batchProof");
  exactKeys(batchProof, ["treeAlgorithm", "leafIndex", "leafHash", "siblings", "expectedRoot"], "batchProof");
  if (text(batchProof.treeAlgorithm, "batchProof.treeAlgorithm") !== "RFC6962_SHA256_V1") {
    throw new TypeError("batchProof.treeAlgorithm is invalid");
  }

  const anchor = map(entries.anchor, "anchor");
  exactKeys(
    anchor,
    [
      "batchSequence", "registryVersion", "merkleRoot", "manifestHash", "solanaProgramId",
      "segmentIndex", "segmentPda", "transactionSignature", "anchorSlot", "commitmentRequired",
    ],
    "anchor",
  );
  if (text(anchor.commitmentRequired, "anchor.commitmentRequired") !== "finalized") {
    throw new TypeError("anchor commitment must be finalized");
  }

  const issuer = map(entries.issuer, "issuer");
  exactKeys(issuer, ["keyId", "publicKey", "signatureAlgorithm"], "issuer");
  if (text(issuer.signatureAlgorithm, "issuer.signatureAlgorithm") !== "Ed25519") {
    throw new TypeError("issuer signature algorithm is invalid");
  }

  return {
    certificateId: bytes(entries.certificateId, "certificateId", 16),
    registryId: text(entries.registryId, "registryId"),
    issuedAt: text(entries.issuedAt, "issuedAt"),
    recordIdCommitment: bytes(entries.recordIdCommitment, "recordIdCommitment", 32),
    recordVersion: integer(entries.recordVersion, "recordVersion", 0xffff_ffff_ffff_ffffn),
    schemaVersion: number(entries.schemaVersion, "schemaVersion", 0xffff),
    disclosureMode,
    disclosedFields: disclosed,
    fieldSalts: Object.fromEntries(
      Object.entries(salts).map(([path, salt]) => [path, bytes(salt, `fieldSalts.${path}`, 32)]),
    ),
    fieldRoot: bytes(entries.fieldRoot, "fieldRoot", 32),
    fieldProofs: fieldProofs(entries.fieldProofs),
    batchProof: {
      leafIndex: number(batchProof.leafIndex, "batchProof.leafIndex", 0xffff_ffff),
      leafHash: bytes(batchProof.leafHash, "batchProof.leafHash", 32),
      siblings: proofSteps(batchProof.siblings, "batchProof.siblings"),
      expectedRoot: bytes(batchProof.expectedRoot, "batchProof.expectedRoot", 32),
    },
    anchor: {
      batchSequence: integer(anchor.batchSequence, "anchor.batchSequence", 0xffff_ffff_ffff_ffffn),
      registryVersion: integer(anchor.registryVersion, "anchor.registryVersion", 0xffff_ffff_ffff_ffffn),
      merkleRoot: bytes(anchor.merkleRoot, "anchor.merkleRoot", 32),
      manifestHash: bytes(anchor.manifestHash, "anchor.manifestHash", 32),
      solanaProgramId: bytes(anchor.solanaProgramId, "anchor.solanaProgramId", 32),
      segmentIndex: number(anchor.segmentIndex, "anchor.segmentIndex", 0xffff),
      segmentPda: bytes(anchor.segmentPda, "anchor.segmentPda", 32),
      transactionSignature: bytes(anchor.transactionSignature, "anchor.transactionSignature", 64),
      anchorSlot: integer(anchor.anchorSlot, "anchor.anchorSlot", 0xffff_ffff_ffff_ffffn),
    },
    issuerKeyId: text(issuer.keyId, "issuer.keyId"),
    issuerPublicKey: bytes(issuer.publicKey, "issuer.publicKey", 32),
  };
}

export function decodeCertificatePackage(encoded: Uint8Array): SignedCertificate {
  const root = map(decodeCanonical(encoded), "certificate package");
  exactKeys(
    root,
    [
      "format", "version", "certificateId", "registryId", "issuedAt", "recordIdCommitment",
      "recordVersion", "schemaVersion", "disclosureMode", "disclosedFields", "fieldSalts",
      "fieldRoot", "fieldProofs", "batchProof", "anchor", "issuer", "issuerSignature",
    ],
    "certificate package",
  );
  const body = decodeBody(root);
  return {
    body,
    certificateHash: certificateHash(body),
    issuerSignature: bytes(root.issuerSignature, "issuerSignature", 64),
  };
}

export function decodeCertificatePackageBase64url(value: string): SignedCertificate {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError("certificatePackage must be unpadded base64url");
  const encoded = Buffer.from(value, "base64url");
  if (encoded.toString("base64url") !== value) throw new TypeError("certificatePackage base64url is not canonical");
  return decodeCertificatePackage(encoded);
}
