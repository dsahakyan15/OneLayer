import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { decodeCanonical, encode, nfc, toHex, type CborValue } from "../../canonical-ts/src/index.ts";

const CHUNK_DOMAIN = Buffer.from("ONELAYER:SNAPSHOT:CHUNK:V1");
const WRAP_DOMAIN = Buffer.from("ONELAYER:SNAPSHOT:DEKWRAP:V1");
const U32_MAX = 0xffff_ffff;

export interface SnapshotChunk {
  chunkIndex: number;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  authTag: Uint8Array;
}

export interface SnapshotPackageV1 {
  registryId: string;
  snapshotId: Uint8Array;
  snapshotVersion: bigint;
  chunkSize: number;
  chunks: SnapshotChunk[];
  wrappedDek: Uint8Array;
  wrappedDekNonce: Uint8Array;
  wrappedDekAuthTag: Uint8Array;
  keyEncryptionVersion: string;
  plaintextHash: Uint8Array;
  ciphertextHash: Uint8Array;
}

function unsigned(value: bigint, length: number): Uint8Array {
  if (value < 0n || value >= 1n << BigInt(length * 8)) throw new RangeError("integer out of range");
  const bytes = new Uint8Array(length);
  let remaining = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}

function encodedText(value: string): Uint8Array {
  const bytes = Buffer.from(nfc(value));
  if (bytes.length > 0xffff) throw new RangeError("text exceeds u16 byte length");
  return bytes;
}

function chunkAad(snapshot: Pick<SnapshotPackageV1, "registryId" | "snapshotId" | "snapshotVersion" | "chunkSize" | "plaintextHash">, index: number, total: number): Uint8Array {
  const registry = encodedText(snapshot.registryId);
  return concat(CHUNK_DOMAIN, unsigned(BigInt(registry.length), 2), registry, snapshot.snapshotId,
    unsigned(snapshot.snapshotVersion, 8), unsigned(BigInt(snapshot.chunkSize), 4),
    unsigned(BigInt(index), 4), unsigned(BigInt(total), 4), snapshot.plaintextHash);
}

function wrapAad(snapshot: Pick<SnapshotPackageV1, "registryId" | "snapshotId" | "snapshotVersion" | "keyEncryptionVersion">): Uint8Array {
  const registry = encodedText(snapshot.registryId);
  const keyVersion = encodedText(snapshot.keyEncryptionVersion);
  return concat(WRAP_DOMAIN, unsigned(BigInt(registry.length), 2), registry, snapshot.snapshotId,
    unsigned(snapshot.snapshotVersion, 8), unsigned(BigInt(keyVersion.length), 2), keyVersion);
}

function encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): { ciphertext: Uint8Array; authTag: Uint8Array } {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ciphertext, authTag: cipher.getAuthTag() };
}

function decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, authTag: Uint8Array, aad: Uint8Array): Uint8Array {
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function chunkNonce(index: number): Uint8Array {
  return concat(new Uint8Array(8), unsigned(BigInt(index), 4));
}

function chunkValue(chunk: SnapshotChunk): CborValue {
  return { type: "map", entries: {
    chunkIndex: { type: "int", value: chunk.chunkIndex.toString() },
    nonce: { type: "bytes", hex: toHex(chunk.nonce) },
    ciphertext: { type: "bytes", hex: toHex(chunk.ciphertext) },
    authTag: { type: "bytes", hex: toHex(chunk.authTag) },
  } };
}

function packageValue(snapshot: SnapshotPackageV1, includeHash: boolean): CborValue {
  const entries: Record<string, CborValue> = {
    formatVersion: { type: "int", value: "1" },
    registryId: { type: "text", value: snapshot.registryId },
    snapshotId: { type: "bytes", hex: toHex(snapshot.snapshotId) },
    snapshotVersion: { type: "int", value: snapshot.snapshotVersion.toString() },
    encryptionAlgorithm: { type: "text", value: "AES-256-GCM" },
    chunkSize: { type: "int", value: snapshot.chunkSize.toString() },
    totalChunks: { type: "int", value: snapshot.chunks.length.toString() },
    chunks: { type: "array", items: snapshot.chunks.map(chunkValue) },
    keyWrapAlgorithm: { type: "text", value: "AES-256-GCM" },
    wrappedDek: { type: "bytes", hex: toHex(snapshot.wrappedDek) },
    wrappedDekNonce: { type: "bytes", hex: toHex(snapshot.wrappedDekNonce) },
    wrappedDekAuthTag: { type: "bytes", hex: toHex(snapshot.wrappedDekAuthTag) },
    keyEncryptionVersion: { type: "text", value: snapshot.keyEncryptionVersion },
    plaintextHash: { type: "bytes", hex: toHex(snapshot.plaintextHash) },
  };
  if (includeHash) entries.ciphertextHash = { type: "bytes", hex: toHex(snapshot.ciphertextHash) };
  return { type: "map", entries };
}

function sha256(bytes: Uint8Array): Uint8Array {
  return createHash("sha256").update(bytes).digest();
}

export function createSnapshotPackage(input: {
  registryId: string;
  snapshotId: Uint8Array;
  snapshotVersion: bigint;
  chunkSize: number;
  plaintext: Uint8Array;
  keyEncryptionVersion: string;
  kek: Uint8Array;
}): SnapshotPackageV1 {
  if (input.snapshotId.length !== 16 || input.kek.length !== 32) throw new RangeError("snapshotId or KEK length is invalid");
  if (!Number.isSafeInteger(input.chunkSize) || input.chunkSize <= 0 || input.chunkSize > U32_MAX || input.plaintext.length === 0) throw new RangeError("snapshot chunk configuration is invalid");
  const totalChunks = Math.ceil(input.plaintext.length / input.chunkSize);
  if (totalChunks > U32_MAX) throw new RangeError("too many snapshot chunks");
  const plaintextHash = sha256(input.plaintext);
  const dek = randomBytes(32);
  const base = {
    registryId: nfc(input.registryId), snapshotId: input.snapshotId, snapshotVersion: input.snapshotVersion,
    chunkSize: input.chunkSize, keyEncryptionVersion: nfc(input.keyEncryptionVersion), plaintextHash,
  };
  const chunks = Array.from({ length: totalChunks }, (_unused, chunkIndex) => {
    const nonce = chunkNonce(chunkIndex);
    const plaintext = input.plaintext.subarray(chunkIndex * input.chunkSize, Math.min((chunkIndex + 1) * input.chunkSize, input.plaintext.length));
    return { chunkIndex, nonce, ...encrypt(dek, nonce, plaintext, chunkAad(base, chunkIndex, totalChunks)) };
  });
  const wrappedDekNonce = randomBytes(12);
  const wrapped = encrypt(input.kek, wrappedDekNonce, dek, wrapAad(base));
  const snapshot: SnapshotPackageV1 = { ...base, chunks, wrappedDek: wrapped.ciphertext, wrappedDekNonce, wrappedDekAuthTag: wrapped.authTag, ciphertextHash: new Uint8Array(32) };
  snapshot.ciphertextHash = sha256(encode(packageValue(snapshot, false)));
  dek.fill(0);
  return snapshot;
}

export function encodeSnapshotPackage(snapshot: SnapshotPackageV1): Uint8Array {
  validateShape(snapshot);
  const expectedHash = sha256(encode(packageValue(snapshot, false)));
  if (!timingSafeEqual(expectedHash, snapshot.ciphertextHash)) throw new TypeError("ciphertext hash mismatch");
  return encode(packageValue(snapshot, true));
}

function validateShape(snapshot: SnapshotPackageV1): void {
  if (snapshot.snapshotId.length !== 16 || snapshot.wrappedDek.length !== 32 || snapshot.wrappedDekNonce.length !== 12 || snapshot.wrappedDekAuthTag.length !== 16 || snapshot.plaintextHash.length !== 32 || snapshot.ciphertextHash.length !== 32) throw new TypeError("snapshot package shape is invalid");
  if (snapshot.chunkSize <= 0 || snapshot.chunks.length === 0) throw new TypeError("snapshot package has no chunks");
  snapshot.chunks.forEach((chunk, index) => {
    if (chunk.chunkIndex !== index || chunk.nonce.length !== 12 || chunk.authTag.length !== 16 || chunk.ciphertext.length === 0 || (index < snapshot.chunks.length - 1 && chunk.ciphertext.length !== snapshot.chunkSize) || chunk.ciphertext.length > snapshot.chunkSize) throw new TypeError("snapshot chunk layout is invalid");
  });
}

function map(value: CborValue): Record<string, CborValue> { if (value.type !== "map") throw new TypeError("CBOR map required"); return value.entries; }
function text(value: CborValue): string { if (value.type !== "text") throw new TypeError("CBOR text required"); return value.value; }
function integer(value: CborValue): bigint { if (value.type !== "int") throw new TypeError("CBOR integer required"); return BigInt(value.value); }
function bytes(value: CborValue): Uint8Array { if (value.type !== "bytes") throw new TypeError("CBOR bytes required"); return Buffer.from(value.hex, "hex"); }

export function decodeSnapshotPackage(encoded: Uint8Array): SnapshotPackageV1 {
  const entries = map(decodeCanonical(encoded));
  const expected = ["formatVersion", "registryId", "snapshotId", "snapshotVersion", "encryptionAlgorithm", "chunkSize", "totalChunks", "chunks", "keyWrapAlgorithm", "wrappedDek", "wrappedDekNonce", "wrappedDekAuthTag", "keyEncryptionVersion", "plaintextHash", "ciphertextHash"].sort();
  if (Object.keys(entries).sort().join("\0") !== expected.join("\0") || integer(entries.formatVersion) !== 1n || text(entries.encryptionAlgorithm) !== "AES-256-GCM" || text(entries.keyWrapAlgorithm) !== "AES-256-GCM" || entries.chunks.type !== "array") throw new TypeError("snapshot package fields are invalid");
  const chunks = entries.chunks.items.map((value) => {
    const item = map(value);
    return { chunkIndex: Number(integer(item.chunkIndex)), nonce: bytes(item.nonce), ciphertext: bytes(item.ciphertext), authTag: bytes(item.authTag) };
  });
  if (integer(entries.totalChunks) !== BigInt(chunks.length)) throw new TypeError("snapshot chunk count is invalid");
  const snapshot: SnapshotPackageV1 = {
    registryId: text(entries.registryId), snapshotId: bytes(entries.snapshotId), snapshotVersion: integer(entries.snapshotVersion),
    chunkSize: Number(integer(entries.chunkSize)), chunks, wrappedDek: bytes(entries.wrappedDek), wrappedDekNonce: bytes(entries.wrappedDekNonce),
    wrappedDekAuthTag: bytes(entries.wrappedDekAuthTag), keyEncryptionVersion: text(entries.keyEncryptionVersion), plaintextHash: bytes(entries.plaintextHash), ciphertextHash: bytes(entries.ciphertextHash),
  };
  validateShape(snapshot);
  const expectedHash = sha256(encode(packageValue(snapshot, false)));
  if (!timingSafeEqual(expectedHash, snapshot.ciphertextHash)) throw new TypeError("ciphertext hash mismatch");
  return snapshot;
}

export function restoreSnapshot(snapshot: SnapshotPackageV1, kek: Uint8Array): Uint8Array {
  if (kek.length !== 32) throw new RangeError("KEK must be 32 bytes");
  validateShape(snapshot);
  const expectedHash = sha256(encode(packageValue(snapshot, false)));
  if (!timingSafeEqual(expectedHash, snapshot.ciphertextHash)) throw new TypeError("ciphertext hash mismatch");
  const dek = decrypt(kek, snapshot.wrappedDekNonce, snapshot.wrappedDek, snapshot.wrappedDekAuthTag, wrapAad(snapshot));
  try {
    const plaintextChunks = snapshot.chunks.map((chunk) => decrypt(dek, chunk.nonce, chunk.ciphertext, chunk.authTag, chunkAad(snapshot, chunk.chunkIndex, snapshot.chunks.length)));
    const plaintext = Buffer.concat(plaintextChunks);
    if (!timingSafeEqual(sha256(plaintext), snapshot.plaintextHash)) throw new TypeError("plaintext hash mismatch");
    return plaintext;
  } finally {
    dek.fill(0);
  }
}

function gfMultiply(left: number, right: number): number {
  let product = 0;
  let a = left;
  let b = right;
  for (let bit = 0; bit < 8; bit += 1) {
    if ((b & 1) !== 0) product ^= a;
    const high = a & 0x80;
    a = (a << 1) & 0xff;
    if (high !== 0) a ^= 0x1b;
    b >>= 1;
  }
  return product;
}

function gfPower(value: number, exponent: number): number { let result = 1; let base = value; let power = exponent; while (power > 0) { if (power & 1) result = gfMultiply(result, base); base = gfMultiply(base, base); power >>= 1; } return result; }
function gfDivide(left: number, right: number): number { if (right === 0) throw new RangeError("duplicate Shamir share index"); return gfMultiply(left, gfPower(right, 254)); }

export interface KeyShare { index: number; bytes: Uint8Array; }

export function splitRecoveryKek(kek: Uint8Array): KeyShare[] {
  if (kek.length !== 32) throw new RangeError("KEK must be 32 bytes");
  const coefficients = randomBytes(kek.length * 2);
  return Array.from({ length: 5 }, (_unused, offset) => {
    const index = offset + 1;
    const bytes = new Uint8Array(kek.length);
    for (let byte = 0; byte < kek.length; byte += 1) bytes[byte] = kek[byte] ^ gfMultiply(coefficients[byte * 2], index) ^ gfMultiply(coefficients[byte * 2 + 1], gfMultiply(index, index));
    return { index, bytes };
  });
}

export function recoverRecoveryKek(shares: KeyShare[]): Uint8Array {
  if (shares.length < 3) throw new RangeError("at least 3 recovery shares are required");
  const selected = shares.slice(0, 3);
  if (selected.some((share) => share.index < 1 || share.index > 255 || share.bytes.length !== 32) || new Set(selected.map((share) => share.index)).size !== 3) throw new TypeError("recovery shares are invalid");
  const secret = new Uint8Array(32);
  for (let byte = 0; byte < secret.length; byte += 1) {
    for (let i = 0; i < selected.length; i += 1) {
      let basis = 1;
      for (let j = 0; j < selected.length; j += 1) if (i !== j) basis = gfMultiply(basis, gfDivide(selected[j].index, selected[i].index ^ selected[j].index));
      secret[byte] ^= gfMultiply(selected[i].bytes[byte], basis);
    }
  }
  return secret;
}
