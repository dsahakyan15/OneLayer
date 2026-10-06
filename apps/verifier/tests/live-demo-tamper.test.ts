import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  batchLeafHash,
  buildFieldTree,
  certificateHash,
  certificatePackageCbor,
  fieldSalt,
  recordCommitment,
  registryIdHash,
  signCertificate,
  toHex,
  verifyCertificateSignature,
  type CertificateBody,
  type CborValue,
  type SignedCertificate,
} from "../../../packages/canonical-ts/src/index.ts";
import { proof } from "../../../packages/merkle-ts/src/index.ts";
import { decodeCertificatePackage } from "../src/certificate-codec.ts";
import {
  DEFAULT_FIELD,
  exportDocument,
  parseTamperInput,
  runTamper,
  tamperPackage,
  TamperRefusal,
  MAX_INPUT_BYTES,
} from "../scripts/live-demo-tamper.ts";

const run = promisify(execFile);
const SCRIPT = fileURLToPath(new URL("../scripts/live-demo-tamper.ts", import.meta.url));
const VECTORS = fileURLToPath(new URL("../../../spec/vectors/certificate.json", import.meta.url));
const NODE_ARGS = ["--experimental-strip-types", "--disable-warning=ExperimentalWarning"];

interface Vector {
  input: { registry_id: string; record_version: string };
  expected: { certificate_body_cbor: string; certificate_hash: string; certificate_package_cbor: string };
}

let vectors: Vector[] = [];
let workDir = "";

before(async () => {
  const parsed = JSON.parse(await readFile(VECTORS, "utf8")) as { vectors: Vector[] };
  vectors = parsed.vectors;
  workDir = await mkdtemp(path.join(tmpdir(), "live-demo-tamper-"));
});

after(async () => {
  await rm(workDir, { recursive: true, force: true });
});

function validVector(): Vector {
  const vector = vectors.find((entry) => entry.expected.certificate_package_cbor.length > 0);
  assert.ok(vector, "shared certificate vector is present");
  return vector;
}

function vectorExport(): Record<string, string> {
  const vector = validVector();
  return {
    package_base64url: Buffer.from(vector.expected.certificate_package_cbor, "hex").toString("base64url"),
    certificateHash: vector.expected.certificate_hash,
    qrUrl: `http://127.0.0.1:8090/c/${"01".repeat(16)}?h=${Buffer.from(vector.expected.certificate_hash, "hex").toString("base64url")}`,
  };
}

function signedDemoCertificate(): SignedCertificate {
  const recordFieldKey = new Uint8Array(32).fill(4);
  const fields = [
    { path: "status", value: { type: "text", value: "ACTIVE" } as CborValue },
    { path: "areaSquareMeters", value: { type: "text", value: "1250.50" } as CborValue },
    { path: "cadastralNumber", value: { type: "text", value: "01-004-0123-045" } as CborValue },
    { path: "flagged", value: { type: "bool", value: false } as CborValue },
  ];
  const tree = buildFieldTree(recordFieldKey, fields);
  const leafHashes = tree.entries.map((entry) => entry.leafHash);
  const disclosed = ["status", "areaSquareMeters"];
  const recordId = new Uint8Array(32).fill(2);
  const commitment = recordCommitment(registryIdHash("gov.registry.land"), recordId, 1n, tree.root);
  const batchLeaf = batchLeafHash(commitment);
  const body: CertificateBody = {
    certificateId: new Uint8Array(16).fill(1),
    registryId: "gov.registry.land",
    issuedAt: "2026-07-31T00:00:00Z",
    recordIdCommitment: recordId,
    recordVersion: 1n,
    schemaVersion: 1,
    disclosureMode: "SELECTIVE_FIELDS",
    disclosedFields: Object.fromEntries(
      fields.filter((field) => disclosed.includes(field.path)).map((field) => [field.path, field.value]),
    ),
    fieldSalts: Object.fromEntries(
      disclosed.map((name) => [name, fieldSalt(recordFieldKey, name)]),
    ),
    fieldRoot: tree.root,
    fieldProofs: disclosed.map((name) => {
      const leafIndex = tree.entries.findIndex((entry) => entry.path === name);
      return { path: name, leafIndex, siblings: proof(leafHashes, leafIndex) };
    }),
    batchProof: { leafIndex: 0, leafHash: batchLeaf, siblings: proof([batchLeaf], 0), expectedRoot: batchLeaf },
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
  return signCertificate(body, new Uint8Array(32).fill(7));
}

function exportFor(signed: SignedCertificate): Record<string, string> {
  const bytes = certificatePackageCbor(signed.body, signed.issuerSignature);
  const hash = toHex(certificateHash(signed.body));
  return {
    package_base64url: Buffer.from(bytes).toString("base64url"),
    certificateHash: hash,
    qrUrl: `http://127.0.0.1:8090/c/${Buffer.from(signed.body.certificateId).toString("hex")}?h=${Buffer.from(certificateHash(signed.body)).toString("base64url")}`,
  };
}

function plain(value: CborValue): string {
  if (value.type === "text" || value.type === "int") return value.value;
  throw new Error("unexpected value type");
}

async function expectRefusal(code: string, runCheck: () => Promise<unknown>): Promise<void> {
  await assert.rejects(runCheck, (error: unknown) => {
    assert.ok(error instanceof TamperRefusal, `expected TamperRefusal, got ${String(error)}`);
    assert.equal(error.code, code);
    return true;
  });
}

test("the shared canonical vector decodes to the pinned hash (Python-canonical compatible)", () => {
  const export_ = vectorExport();
  const parsed = parseTamperInput(JSON.stringify(export_));
  const signed = decodeCertificatePackage(Buffer.from(parsed.packageBase64url, "base64url"));
  // sha256(canonical body CBOR) is exactly what demo-api stores and what the
  // Python canonical hasher recomputes; the shared vector pins that digest.
  assert.equal(toHex(certificateHash(signed.body)), validVector().expected.certificate_hash);
  assert.equal(parsed.certificateHash, validVector().expected.certificate_hash);
});

test("area mode alters the disclosed value without re-signing and keeps the pinned QR/hash", async () => {
  const original = signedDemoCertificate();
  const before = decodeCertificatePackage(certificatePackageCbor(original.body, original.issuerSignature));
  const result = tamperPackage(parseTamperInput(JSON.stringify(exportFor(original))), {
    field: "areaSquareMeters",
    value: "99999.99",
  });
  assert.equal(result.mode, "area");
  assert.equal(result.field, "areaSquareMeters");
  assert.equal(result.originalValue, "1250.50");
  assert.equal(result.tamperedValue, "99999.99");
  assert.equal(result.bodyUnchanged, false);
  assert.equal(result.signatureValidBefore, true);
  assert.equal(result.signatureValidAfter, false, "the stale issuer signature must not validate");
  // Pinned QR/hash of the original certificate is preserved in the export.
  assert.equal(result.certificateHash, toHex(certificateHash(original.body)));
  assert.equal(result.qrUrl, exportFor(original).qrUrl);
  assert.notEqual(result.bodyHashAfter, result.bodyHashBefore);

  const tampered = decodeCertificatePackage(Buffer.from(result.packageBase64url, "base64url"));
  assert.equal(plain(tampered.body.disclosedFields.areaSquareMeters), "99999.99");
  assert.equal(plain(tampered.body.disclosedFields.status), "ACTIVE");
  assert.equal(verifyCertificateSignature(tampered), false);
  // Proofs, salts, the field root and the issuer signature are carried over.
  assert.deepEqual(tampered.body.fieldProofs, before.body.fieldProofs);
  assert.deepEqual(tampered.body.fieldSalts, before.body.fieldSalts);
  assert.deepEqual(tampered.body.fieldRoot, before.body.fieldRoot);
  assert.deepEqual(tampered.body.batchProof, before.body.batchProof);
  assert.deepEqual(tampered.issuerSignature, before.issuerSignature);
  // The exported claim still points at the original, so a hash check rejects.
  assert.notEqual(toHex(certificateHash(tampered.body)), result.certificateHash);
});

test("area mode defaults to areaSquareMeters and works on the shared vector field names", async () => {
  const original = signedDemoCertificate();
  const result = tamperPackage(parseTamperInput(JSON.stringify(exportFor(original))), {});
  assert.equal(result.field, DEFAULT_FIELD);
  assert.equal(result.tamperedValue, "99999.99");

  const vectorTamper = tamperPackage(parseTamperInput(JSON.stringify(vectorExport())), {
    field: "area",
    value: "99999.99",
  });
  assert.equal(vectorTamper.originalValue, "1234.50");
  assert.equal(vectorTamper.certificateHash, validVector().expected.certificate_hash);
  assert.equal(vectorTamper.signatureValidAfter, false);
});

test("qr-hash mode leaves the body byte-identical and breaks every hash binding", () => {
  const original = signedDemoCertificate();
  const export_ = exportFor(original);
  const result = tamperPackage(parseTamperInput(JSON.stringify(export_)), { mode: "qr-hash" });
  assert.equal(result.mode, "qr-hash");
  assert.equal(result.bodyUnchanged, true);
  assert.equal(result.packageBase64url, export_.package_base64url);
  assert.equal(result.signatureValidAfter, true, "the untouched body keeps its valid signature");
  assert.notEqual(result.certificateHash, result.bodyHashBefore);
  assert.match(result.certificateHash, /^[0-9a-f]{64}$/);
  const parsedQr = new URL(result.qrUrl);
  const qrHash = parsedQr.searchParams.get("h");
  assert.ok(qrHash);
  assert.match(qrHash, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(qrHash, Buffer.from(result.certificateHash, "hex").toString("base64url"));
  assert.notEqual(qrHash, export_.qrUrl.split("h=")[1]);
  // Deterministic: the same input always yields the same corrupted binding.
  const again = tamperPackage(parseTamperInput(JSON.stringify(export_)), { mode: "qr-hash" });
  assert.equal(again.certificateHash, result.certificateHash);
  assert.equal(again.qrUrl, result.qrUrl);
});

test("bare base64url and raw package inputs are accepted", () => {
  const original = signedDemoCertificate();
  const bytes = certificatePackageCbor(original.body, original.issuerSignature);
  const bare = Buffer.from(bytes).toString("base64url");
  const fromBare = tamperPackage(parseTamperInput(bare), { field: "areaSquareMeters", value: "1.00" });
  assert.equal(fromBare.certificateHash, toHex(certificateHash(original.body)));
  assert.match(fromBare.qrUrl, /^http:\/\/127\.0\.0\.1:8090\/c\/[0-9a-f]{32}\?h=[A-Za-z0-9_-]{43}$/);
  const fromRaw = tamperPackage(parseTamperInput(bytes), { field: "areaSquareMeters", value: "1.00" });
  assert.equal(fromRaw.packageBase64url, fromBare.packageBase64url);
});

test("a field that is not disclosed cannot be tampered", () => {
  const original = signedDemoCertificate();
  const input = parseTamperInput(JSON.stringify(exportFor(original)));
  assert.throws(
    () => tamperPackage(input, { field: "cadastralNumber", value: "x" }),
    (error: unknown) => {
      assert.ok(error instanceof TamperRefusal);
      assert.equal(error.code, "FIELD_NOT_DISCLOSED");
      return true;
    },
  );
});

test("non-scalar disclosed values are refused instead of coerced", () => {
  const recordFieldKey = new Uint8Array(32).fill(4);
  const fields = [
    { path: "flagged", value: { type: "bool", value: false } as CborValue },
    { path: "status", value: { type: "text", value: "ACTIVE" } as CborValue },
  ];
  const tree = buildFieldTree(recordFieldKey, fields);
  const leafHashes = tree.entries.map((entry) => entry.leafHash);
  const recordId = new Uint8Array(32).fill(2);
  const commitment = recordCommitment(registryIdHash("gov.registry.land"), recordId, 1n, tree.root);
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
    fieldRoot: tree.root,
    fieldProofs: [],
    batchProof: { leafIndex: 0, leafHash: batchLeaf, siblings: proof([batchLeaf], 0), expectedRoot: batchLeaf },
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
  const signed = signCertificate(body, new Uint8Array(32).fill(7));
  const input = parseTamperInput(JSON.stringify(exportFor(signed)));
  assert.throws(
    () => tamperPackage(input, { field: "flagged", value: "true" }),
    (error: unknown) => {
      assert.ok(error instanceof TamperRefusal);
      assert.equal(error.code, "FIELD_TYPE_UNSUPPORTED");
      return true;
    },
  );
});

test("malformed and oversized inputs are refused", async () => {
  await expectRefusal("PACKAGE_INVALID", async () => parseTamperInput("{not json"));
  await expectRefusal("PACKAGE_INVALID", async () => parseTamperInput(JSON.stringify({ no: "package" })));
  await expectRefusal("PACKAGE_INVALID", async () => tamperPackage(parseTamperInput("AA")));
  await expectRefusal("INPUT_TOO_LARGE", async () => parseTamperInput("x".repeat(MAX_INPUT_BYTES + 1)));
  await expectRefusal("PACKAGE_INVALID", async () =>
    tamperPackage({ packageBase64url: "AAAA", certificateHash: null, qrUrl: null }),
  );
  await expectRefusal("PACKAGE_INVALID", async () =>
    parseTamperInput(JSON.stringify({ package_base64url: "A".repeat(40), certificateHash: "zz" })),
  );
});

test("runTamper writes the export document without touching the input file", async () => {
  const original = signedDemoCertificate();
  const export_ = exportFor(original);
  const inputPath = path.join(workDir, "package.json");
  const outputPath = path.join(workDir, "tampered.json");
  await writeFile(inputPath, `${JSON.stringify(export_, null, 2)}\n`);
  const inputBefore = await readFile(inputPath);
  const result = await runTamper({ input: inputPath, output: outputPath, field: "areaSquareMeters", value: "42.00" });
  assert.equal(result.tamperedValue, "42.00");
  const inputAfter = await readFile(inputPath);
  assert.ok(inputBefore.equals(inputAfter), "the input file must be untouched");
  const document = JSON.parse(await readFile(outputPath, "utf8")) as Record<string, unknown>;
  assert.deepEqual(Object.keys(document).sort(), ["certificateHash", "package_base64url", "qrUrl"]);
  assert.equal(document.certificateHash, export_.certificateHash);
  assert.equal(document.qrUrl, export_.qrUrl);
  const decoded = decodeCertificatePackage(
    Buffer.from(String(document.package_base64url), "base64url"),
  );
  assert.equal(plain(decoded.body.disclosedFields.areaSquareMeters), "42.00");
  assert.equal(verifyCertificateSignature(decoded), false);
  // exportDocument is exactly what lands on disk.
  assert.deepEqual(document, exportDocument(result));
});

test("runTamper refuses an output path that resolves to the input", async () => {
  const export_ = exportFor(signedDemoCertificate());
  const inputPath = path.join(workDir, "same.json");
  await writeFile(inputPath, JSON.stringify(export_));
  await expectRefusal("OUTPUT_REFUSED", () =>
    runTamper({ input: inputPath, output: inputPath, field: "areaSquareMeters", value: "1.00" }),
  );
  await expectRefusal("OUTPUT_REFUSED", () =>
    runTamper({ input: inputPath, output: path.join(workDir, ".", "same.json"), field: "areaSquareMeters", value: "1.00" }),
  );
  await expectRefusal("INPUT_UNREADABLE", () =>
    runTamper({ input: path.join(workDir, "missing.json"), output: path.join(workDir, "out.json") }),
  );
});

test("the CLI writes the tampered export and reports the exact outcome", async () => {
  const export_ = exportFor(signedDemoCertificate());
  const inputPath = path.join(workDir, "cli-in.json");
  const outputPath = path.join(workDir, "cli-out.json");
  await writeFile(inputPath, JSON.stringify(export_));
  const { stdout } = await run(process.execPath, [
    ...NODE_ARGS,
    SCRIPT,
    "--in",
    inputPath,
    "--out",
    outputPath,
    "--field",
    "areaSquareMeters",
    "--value",
    "777777.77",
  ]);
  const summary = JSON.parse(stdout) as Record<string, unknown>;
  assert.equal(summary.mode, "area");
  assert.equal(summary.tamperedValue, "777777.77");
  assert.equal(summary.signatureValidAfter, false);
  assert.equal(summary.certificateHash, export_.certificateHash);
  const document = JSON.parse(await readFile(outputPath, "utf8")) as Record<string, string>;
  assert.equal(document.certificateHash, export_.certificateHash);
});

test("the CLI refuses bad arguments and unknown fields with stable exit codes", async () => {
  const export_ = exportFor(signedDemoCertificate());
  const inputPath = path.join(workDir, "cli-bad.json");
  await writeFile(inputPath, JSON.stringify(export_));

  await assert.rejects(
    run(process.execPath, [...NODE_ARGS, SCRIPT, "--in", inputPath, "--field", "nope"]),
    (error: unknown) => {
      const failure = error as { code?: number; stderr?: string };
      assert.equal(failure.code, 2);
      assert.match(String(failure.stderr), /REQUEST_INVALID/);
      return true;
    },
  );
  await assert.rejects(
    run(process.execPath, [
      ...NODE_ARGS,
      SCRIPT,
      "--in",
      inputPath,
      "--out",
      path.join(workDir, "cli-field-out.json"),
      "--field",
      "notDisclosed",
    ]),
    (error: unknown) => {
      const failure = error as { code?: number; stderr?: string };
      assert.equal(failure.code, 3);
      assert.match(String(failure.stderr), /FIELD_NOT_DISCLOSED/);
      return true;
    },
  );
  await assert.rejects(
    run(process.execPath, [
      ...NODE_ARGS,
      SCRIPT,
      "--in",
      inputPath,
      "--out",
      path.join(workDir, "cli-qr-out.json"),
      "--mode",
      "qr-hash",
      "--field",
      "areaSquareMeters",
    ]),
    (error: unknown) => {
      const failure = error as { code?: number; stderr?: string };
      assert.equal(failure.code, 2);
      assert.match(String(failure.stderr), /REQUEST_INVALID/);
      return true;
    },
  );
});

test("runTamper never overwrites an existing output file (reviewer clobber repro)", async () => {
  const export_ = exportFor(signedDemoCertificate());
  const inputPath = path.join(workDir, "clobber-in.json");
  const outputPath = path.join(workDir, "clobber-out.json");
  await writeFile(inputPath, JSON.stringify(export_));
  const sentinel = "precious user file — must survive";
  await writeFile(outputPath, sentinel);
  await expectRefusal("OUTPUT_REFUSED", () =>
    runTamper({ input: inputPath, output: outputPath, field: "areaSquareMeters", value: "1.00" }),
  );
  assert.equal(await readFile(outputPath, "utf8"), sentinel, "the pre-existing output is untouched");
});

test("runTamper refuses an output symlink and never touches its target (reviewer symlink repro)", async () => {
  const export_ = exportFor(signedDemoCertificate());
  const inputPath = path.join(workDir, "symlink-in.json");
  const victimPath = path.join(workDir, "victim.json");
  const linkPath = path.join(workDir, "out-link.json");
  await writeFile(inputPath, JSON.stringify(export_));
  const sentinel = "symlink target — must survive";
  await writeFile(victimPath, sentinel);
  await symlink(victimPath, linkPath);
  await expectRefusal("OUTPUT_REFUSED", () =>
    runTamper({ input: inputPath, output: linkPath, field: "areaSquareMeters", value: "1.00" }),
  );
  assert.equal(await readFile(victimPath, "utf8"), sentinel, "the symlink target is untouched");
});

test("oversized input is refused before reading and non-regular inputs are refused", async () => {
  const bigPath = path.join(workDir, "too-big.json");
  await writeFile(bigPath, Buffer.alloc(MAX_INPUT_BYTES + 1, 0x20));
  await expectRefusal("INPUT_TOO_LARGE", () =>
    runTamper({ input: bigPath, output: path.join(workDir, "too-big-out.json") }),
  );

  const dirPath = path.join(workDir, "a-directory");
  await mkdir(dirPath);
  await expectRefusal("INPUT_UNREADABLE", () =>
    runTamper({ input: dirPath, output: path.join(workDir, "dir-out.json") }),
  );

  // A FIFO would block (or stream without bound) on a plain read; the bounded
  // path refuses it as a non-regular file without opening it for data.
  const fifoPath = path.join(workDir, "a-fifo");
  await run("mkfifo", [fifoPath]);
  await expectRefusal("INPUT_UNREADABLE", () =>
    runTamper({ input: fifoPath, output: path.join(workDir, "fifo-out.json") }),
  );
});

test("the CLI refuses an existing output with exit 3 and leaves it untouched", async () => {
  const export_ = exportFor(signedDemoCertificate());
  const inputPath = path.join(workDir, "cli-exists-in.json");
  const outputPath = path.join(workDir, "cli-exists-out.json");
  await writeFile(inputPath, JSON.stringify(export_));
  const sentinel = "cli sentinel";
  await writeFile(outputPath, sentinel);
  await assert.rejects(
    run(process.execPath, [...NODE_ARGS, SCRIPT, "--in", inputPath, "--out", outputPath]),
    (error: unknown) => {
      const failure = error as { code?: number; stderr?: string };
      assert.equal(failure.code, 3);
      assert.match(String(failure.stderr), /OUTPUT_REFUSED/);
      return true;
    },
  );
  assert.equal(await readFile(outputPath, "utf8"), sentinel);
});
