import { readFileSync, writeFileSync } from "node:fs";
import { createSnapshotPackage, decodeSnapshotPackage, encodeSnapshotPackage, recoverRecoveryKek, restoreSnapshot, splitRecoveryKek } from "./index.ts";

function required(index: number, label: string): string {
  const value = process.argv[index];
  if (value === undefined || value.length === 0) throw new Error(`${label} is required`);
  return value;
}

function secret(path: string): Buffer {
  const bytes = readFileSync(path);
  if (bytes.length !== 32) throw new Error(`${path} must contain exactly 32 bytes`);
  return bytes;
}

function snapshotId(value: string): Uint8Array {
  if (!/^[0-9a-f]{32}$/.test(value)) throw new Error("snapshot id must be 32 lowercase hexadecimal characters");
  return Buffer.from(value, "hex");
}

function share(path: string): { index: number; bytes: Uint8Array } {
  const encoded = readFileSync(path);
  if (encoded.length !== 33 || encoded[0] < 1) throw new Error(`${path} is not a recovery share`);
  return { index: encoded[0], bytes: encoded.subarray(1) };
}

const command = required(2, "command");
if (command === "create") {
  const plaintext = readFileSync(required(3, "plaintext path"));
  const outputPath = required(4, "package path");
  const kek = secret(required(5, "KEK path"));
  try {
    const snapshot = createSnapshotPackage({
      registryId: required(6, "registry id"),
      snapshotId: snapshotId(required(7, "snapshot id")),
      snapshotVersion: BigInt(required(8, "snapshot version")),
      chunkSize: Number(required(9, "chunk size")),
      plaintext,
      keyEncryptionVersion: required(10, "key encryption version"),
      kek,
    });
    writeFileSync(outputPath, encodeSnapshotPackage(snapshot), { mode: 0o600 });
  } finally {
    plaintext.fill(0);
    kek.fill(0);
  }
} else if (command === "split-kek") {
  const kek = secret(required(3, "KEK path"));
  const outputPrefix = required(4, "share output prefix");
  if (!outputPrefix.startsWith("/run/onelayer-recovery/") && !outputPrefix.startsWith("/dev/shm/onelayer-recovery/shares/recovery-share-")) {
    throw new Error("shares must be written to an approved tmpfs path");
  }
  try {
    for (const shareValue of splitRecoveryKek(kek)) {
      writeFileSync(`${outputPrefix}${shareValue.index}`, Buffer.concat([Buffer.of(shareValue.index), shareValue.bytes]), { mode: 0o400 });
      shareValue.bytes.fill(0);
    }
  } finally {
    kek.fill(0);
  }
} else if (command === "restore") {
  const snapshot = decodeSnapshotPackage(readFileSync(required(3, "package path")));
  const outputPath = required(4, "plaintext output path");
  const shares = [share(required(5, "share 1")), share(required(6, "share 2")), share(required(7, "share 3"))];
  const kek = recoverRecoveryKek(shares);
  try {
    const plaintext = restoreSnapshot(snapshot, kek);
    try { writeFileSync(outputPath, plaintext, { mode: 0o600 }); } finally { plaintext.fill(0); }
  } finally {
    kek.fill(0);
    shares.forEach((value) => value.bytes.fill(0));
  }
} else if (command === "verify") {
  decodeSnapshotPackage(readFileSync(required(3, "package path")));
} else {
  throw new Error(`unsupported command: ${command}`);
}
