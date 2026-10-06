// Tampered certificate-package builder for the live demo (A3).
//
// The demo "forged extract" scenario needs an artifact that alters one
// disclosed field of a real certificate WITHOUT re-signing it. This helper
// decodes an existing package (or package export), changes the disclosed value
// while keeping the issuer signature and every Merkle proof, and writes a new
// package export. The original file is never modified.
//
// Modes:
//   area     (default) the disclosed field value is altered; the export keeps
//            the pinned QR/hash of the original certificate, so every hash
//            binding check rejects it (INVALID / QR_HASH_MISMATCH) and the
//            verifier would answer CERT_SIGNATURE_INVALID on the stale
//            signature.
//   qr-hash  the package body is left byte-identical; only the QR/hash binding
//            is corrupted (the document's `certificateHash` claim and the
//            QR-carried `h` are replaced with two distinct wrong values), so
//            any binding comparison fails with QR_HASH_MISMATCH.
//
// Output is the same JSON document shape demo-api serves from
// `GET /v1/certificates/{id}/package`: {package_base64url, certificateHash,
// qrUrl}. That document is what the launcher saves and what the Python
// `verify package file` path consumes. No key material is involved anywhere.
//
// File safety: the input is read through a bounded path (regular file only,
// size checked before any read, descriptor identity re-checked after open) and
// the output is created exclusively — an existing file or symlink at the
// output path is refused, never overwritten and never followed.
import { createHash } from "node:crypto";
import { constants as fsConstants, type Stats } from "node:fs";
import { open, realpath, stat, unlink } from "node:fs/promises";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import {
  certificateHash,
  certificatePackageCbor,
  fromHex,
  toHex,
  verifyCertificateSignature,
  type CertificateBody,
  type CborValue,
} from "../../../packages/canonical-ts/src/index.ts";
import { decodeCertificatePackage } from "../src/certificate-codec.ts";

process.removeAllListeners("warning");
process.on("warning", () => undefined);

export type TamperMode = "area" | "qr-hash";

export const MAX_INPUT_BYTES = 262_144;
export const MAX_VALUE_CHARS = 256;
export const DEFAULT_FIELD = "areaSquareMeters";
export const DEFAULT_VALUE = "99999.99";
export const QR_HASH_DOMAIN = "ONELAYER:LIVE-DEMO-TAMPER:QRHASH:V1";
export const CERT_HASH_DOMAIN = "ONELAYER:LIVE-DEMO-TAMPER:CERTHASH:V1";

const HEX64 = /^[0-9a-f]{64}$/;
const FIELD_NAME = /^[A-Za-z0-9_./-]{1,64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

export class TamperRefusal extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

export interface TamperInput {
  packageBase64url: string;
  /** Exported `certificateHash` claim (64 lowercase hex) when present. */
  certificateHash: string | null;
  /** Exported `qrUrl` (the pinned QR) when present. */
  qrUrl: string | null;
}

export interface TamperOptions {
  mode?: TamperMode;
  field?: string;
  value?: string;
  /** Loopback base used to synthesize a pinned QR when the input has none. */
  qrBaseUrl?: string;
}

export interface TamperResult {
  mode: TamperMode;
  certificateId: string;
  /** Null in qr-hash mode: that mode changes no field value. */
  field: string | null;
  originalValue: string | null;
  tamperedValue: string | null;
  /** True when the package body was left byte-identical (qr-hash mode). */
  bodyUnchanged: boolean;
  packageBase64url: string;
  /** The export's certificateHash claim: pinned in area mode, broken in qr-hash. */
  certificateHash: string;
  qrUrl: string;
  bodyHashBefore: string;
  bodyHashAfter: string;
  signatureValidBefore: boolean;
  signatureValidAfter: boolean;
}

function plainValue(value: CborValue): string {
  if (value.type === "text" || value.type === "int") return value.value;
  if (value.type === "bool") return value.value ? "true" : "false";
  if (value.type === "bytes") return value.hex;
  throw new TamperRefusal("FIELD_TYPE_UNSUPPORTED");
}

function decodePackageText(value: string): Uint8Array {
  const normalized = value.replace(/=+$/, "");
  if (normalized.length < 20 || normalized.length > MAX_INPUT_BYTES || !BASE64URL.test(normalized)) {
    throw new TamperRefusal("PACKAGE_INVALID");
  }
  const bytes = Buffer.from(normalized, "base64url");
  if (bytes.length === 0 || bytes.toString("base64url") !== normalized) throw new TamperRefusal("PACKAGE_INVALID");
  return new Uint8Array(bytes);
}

/**
 * Accepts the three shapes the launcher may hand over: the JSON export
 * document demo-api serves, a bare base64url package, or raw package bytes.
 */
export function parseTamperInput(raw: Uint8Array | string): TamperInput {
  const bytes = typeof raw === "string" ? Buffer.from(raw, "utf8") : Buffer.from(raw);
  if (bytes.length === 0) throw new TamperRefusal("PACKAGE_INVALID");
  if (bytes.length > MAX_INPUT_BYTES) throw new TamperRefusal("INPUT_TOO_LARGE");
  const text = bytes.toString("utf8");
  const trimmed = text.trim();
  if (trimmed.startsWith("{")) {
    let document: unknown;
    try {
      document = JSON.parse(trimmed);
    } catch {
      throw new TamperRefusal("PACKAGE_INVALID");
    }
    if (typeof document !== "object" || document === null || Array.isArray(document)) {
      throw new TamperRefusal("PACKAGE_INVALID");
    }
    const record = document as Record<string, unknown>;
    const payload = record.package_base64url;
    if (typeof payload !== "string") throw new TamperRefusal("PACKAGE_INVALID");
    decodePackageText(payload);
    const claimed = record.certificateHash;
    if (claimed !== undefined && claimed !== null && (typeof claimed !== "string" || !HEX64.test(claimed))) {
      throw new TamperRefusal("PACKAGE_INVALID");
    }
    const qrUrl = record.qrUrl;
    if (qrUrl !== undefined && qrUrl !== null) {
      if (typeof qrUrl !== "string" || qrUrl.length > 2048) throw new TamperRefusal("PACKAGE_INVALID");
      try {
        const parsed = new URL(qrUrl);
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new TamperRefusal("PACKAGE_INVALID");
      } catch (error) {
        if (error instanceof TamperRefusal) throw error;
        throw new TamperRefusal("PACKAGE_INVALID");
      }
    }
    return {
      packageBase64url: payload.replace(/=+$/, ""),
      certificateHash: typeof claimed === "string" ? claimed : null,
      qrUrl: typeof qrUrl === "string" ? qrUrl : null,
    };
  }
  if (BASE64URL.test(trimmed) && trimmed.length >= 20) {
    return { packageBase64url: trimmed.replace(/=+$/, ""), certificateHash: null, qrUrl: null };
  }
  // Raw package bytes (canonical CBOR) are accepted as-is.
  return { packageBase64url: bytes.toString("base64url"), certificateHash: null, qrUrl: null };
}

function syntheticQrUrl(certificateId: Uint8Array, hashHex: string, base: string): string {
  return `${base.replace(/\/$/, "")}/c/${Buffer.from(certificateId).toString("hex")}?h=${Buffer.from(fromHex(hashHex)).toString("base64url")}`;
}

function replaceQrHash(qrUrl: string, hashBase64url: string): string {
  const parsed = new URL(qrUrl);
  parsed.searchParams.set("h", hashBase64url);
  return parsed.toString();
}

function brokenDigest(domain: string, pinnedHex: string): Buffer {
  return createHash("sha256").update(Buffer.from(domain, "utf8")).update(fromHex(pinnedHex)).digest();
}

/**
 * Builds the tampered export. The input document is only read; the caller
 * writes the returned export to its own output path.
 */
export function tamperPackage(input: TamperInput, options: TamperOptions = {}): TamperResult {
  const mode: TamperMode = options.mode ?? "area";
  if (mode !== "area" && mode !== "qr-hash") throw new TamperRefusal("REQUEST_INVALID");
  const bytes = Buffer.from(decodePackageText(input.packageBase64url));
  let decoded;
  try {
    decoded = decodeCertificatePackage(new Uint8Array(bytes));
  } catch {
    throw new TamperRefusal("PACKAGE_INVALID");
  }
  const body = decoded.body;
  const bodyHashBefore = toHex(certificateHash(body));
  const signatureValidBefore = verifyCertificateSignature(decoded);
  const certificateId = Buffer.from(body.certificateId).toString("hex");
  const pinnedHash = input.certificateHash ?? bodyHashBefore;
  const pinnedQrUrl = input.qrUrl ?? syntheticQrUrl(body.certificateId, pinnedHash, options.qrBaseUrl ?? "http://127.0.0.1:8090");

  if (mode === "qr-hash") {
    if (options.field !== undefined || options.value !== undefined) throw new TamperRefusal("REQUEST_INVALID");
    // Body untouched; the QR/hash binding pair is replaced by two distinct
    // wrong values so that any comparison (h vs claim, body vs claim, body vs
    // h) fails. Nothing else in the document is altered.
    const brokenClaim = brokenDigest(CERT_HASH_DOMAIN, bodyHashBefore).toString("hex");
    const brokenQr = brokenDigest(QR_HASH_DOMAIN, bodyHashBefore).toString("base64url");
    return {
      mode,
      certificateId,
      field: null,
      originalValue: null,
      tamperedValue: null,
      bodyUnchanged: true,
      packageBase64url: input.packageBase64url,
      certificateHash: brokenClaim,
      qrUrl: replaceQrHash(pinnedQrUrl, brokenQr),
      bodyHashBefore,
      bodyHashAfter: bodyHashBefore,
      signatureValidBefore,
      signatureValidAfter: signatureValidBefore,
    };
  }

  const field = options.field ?? DEFAULT_FIELD;
  if (!FIELD_NAME.test(field)) throw new TamperRefusal("REQUEST_INVALID");
  const value = options.value ?? DEFAULT_VALUE;
  if (value.length === 0 || value.length > MAX_VALUE_CHARS || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new TamperRefusal("REQUEST_INVALID");
  }
  const existing = body.disclosedFields[field];
  if (existing === undefined) throw new TamperRefusal("FIELD_NOT_DISCLOSED");
  const originalValue = plainValue(existing);
  let replacement: CborValue;
  if (existing.type === "text") {
    replacement = { type: "text", value };
  } else if (existing.type === "int") {
    if (!/^(0|[1-9][0-9]{0,19})$/.test(value)) throw new TamperRefusal("FIELD_TYPE_UNSUPPORTED");
    replacement = { type: "int", value };
  } else {
    throw new TamperRefusal("FIELD_TYPE_UNSUPPORTED");
  }
  const tamperedBody: CertificateBody = {
    ...body,
    disclosedFields: { ...body.disclosedFields, [field]: replacement },
  };
  // The issuer signature and every proof are carried over untouched: a
  // consumer that checks them must reject the package.
  const packageBytes = certificatePackageCbor(tamperedBody, decoded.issuerSignature);
  const bodyHashAfter = toHex(certificateHash(tamperedBody));
  const signatureValidAfter = verifyCertificateSignature({
    body: tamperedBody,
    certificateHash: certificateHash(tamperedBody),
    issuerSignature: decoded.issuerSignature,
  });
  return {
    mode,
    certificateId,
    field,
    originalValue,
    tamperedValue: value,
    bodyUnchanged: false,
    packageBase64url: Buffer.from(packageBytes).toString("base64url"),
    certificateHash: pinnedHash,
    qrUrl: pinnedQrUrl,
    bodyHashBefore,
    bodyHashAfter,
    signatureValidBefore,
    signatureValidAfter,
  };
}

/** The export document written to disk: exactly the demo-api response shape. */
export function exportDocument(result: TamperResult): Record<string, string> {
  return {
    package_base64url: result.packageBase64url,
    certificateHash: result.certificateHash,
    qrUrl: result.qrUrl,
  };
}

export interface RunOptions extends TamperOptions {
  input: string;
  output: string;
}

const OUTPUT_OPEN_FLAGS = fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW;

async function openInput(inputPath: string) {
  try {
    return await open(inputPath, fsConstants.O_RDONLY | fsConstants.O_NONBLOCK);
  } catch {
    throw new TamperRefusal("INPUT_UNREADABLE");
  }
}

async function openOutput(outputPath: string) {
  try {
    return await open(outputPath, OUTPUT_OPEN_FLAGS, 0o600);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "EEXIST" || code === "ELOOP") throw new TamperRefusal("OUTPUT_REFUSED");
    throw new TamperRefusal("OUTPUT_UNWRITABLE");
  }
}

/**
 * Bounded input read: a regular file only (a FIFO or device would block or
 * stream without bound), sized before any read, with the opened descriptor
 * re-checked against the stat that authorized the read.
 */
async function readBoundedInput(inputPath: string): Promise<Buffer> {
  let pre: Stats;
  try {
    pre = await stat(inputPath);
  } catch {
    throw new TamperRefusal("INPUT_UNREADABLE");
  }
  if (!pre.isFile()) throw new TamperRefusal("INPUT_UNREADABLE");
  if (pre.size > MAX_INPUT_BYTES) throw new TamperRefusal("INPUT_TOO_LARGE");
  const handle = await openInput(inputPath);
  try {
    const onDisk = await handle.stat();
    if (!onDisk.isFile()) throw new TamperRefusal("INPUT_UNREADABLE");
    if (onDisk.dev !== pre.dev || onDisk.ino !== pre.ino) throw new TamperRefusal("INPUT_UNREADABLE");
    if (onDisk.size > MAX_INPUT_BYTES) throw new TamperRefusal("INPUT_TOO_LARGE");
    const chunks: Buffer[] = [];
    let total = 0;
    for (;;) {
      const chunk = Buffer.allocUnsafe(65_536);
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > MAX_INPUT_BYTES) throw new TamperRefusal("INPUT_TOO_LARGE");
      chunks.push(chunk.subarray(0, bytesRead));
    }
    return Buffer.concat(chunks);
  } finally {
    await handle.close();
  }
}

/**
 * Exclusive output creation: `O_EXCL` refuses any existing directory entry
 * (a pre-existing file or an output symlink can never be clobbered or
 * followed) and `O_NOFOLLOW` refuses a concurrently swapped-in symlink.
 */
async function writeExportExclusive(outputPath: string, data: string): Promise<void> {
  const handle = await openOutput(outputPath);
  try {
    await handle.writeFile(data);
  } catch {
    await handle.close().catch(() => undefined);
    await unlink(outputPath).catch(() => undefined);
    throw new TamperRefusal("OUTPUT_UNWRITABLE");
  }
  await handle.close();
}

/**
 * Reads the input package, writes the tampered export and returns the summary.
 * The input file is opened read-only and never rewritten; the output target
 * must not already exist.
 */
export async function runTamper(options: RunOptions): Promise<TamperResult> {
  if (options.input === "" || options.output === "") throw new TamperRefusal("REQUEST_INVALID");
  const inputPath = path.resolve(options.input);
  const outputPath = path.resolve(options.output);
  if (inputPath === outputPath) throw new TamperRefusal("OUTPUT_REFUSED");
  const raw = await readBoundedInput(inputPath);
  try {
    const [inReal, outReal] = await Promise.all([
      realpath(inputPath).catch(() => inputPath),
      realpath(outputPath).catch(() => outputPath),
    ]);
    if (inReal === outReal) throw new TamperRefusal("OUTPUT_REFUSED");
  } catch (error) {
    if (error instanceof TamperRefusal) throw error;
    throw new TamperRefusal("INPUT_UNREADABLE");
  }
  const result = tamperPackage(parseTamperInput(raw), options);
  await writeExportExclusive(outputPath, `${JSON.stringify(exportDocument(result), null, 2)}\n`);
  return result;
}

const USAGE = `Usage: live-demo-tamper.ts --in FILE --out FILE [options]

Builds a tampered certificate package export for the live demo. The input is a
package export JSON document, a bare base64url package, or raw package bytes.
The input file is never modified; the tampered export is written to --out in
the same {package_base64url, certificateHash, qrUrl} shape demo-api serves.

Options:
  --in FILE         input package or package export (required)
  --out FILE        output export document (required; must differ from --in
                    and must not already exist — the target is created fresh,
                    an existing file or symlink is refused, never overwritten)
  --mode MODE       area (default) or qr-hash
  --field NAME      disclosed field to alter in area mode
                    (default: ${DEFAULT_FIELD})
  --value TEXT      replacement value in area mode (default: ${DEFAULT_VALUE})
  -h, --help        show this help

Modes:
  area      the disclosed value is altered without re-signing; the pinned
            QR/hash of the original certificate is preserved in the export.
  qr-hash   the package body is left byte-identical; only the QR/hash binding
            is corrupted (certificateHash and the QR-carried h).

Output (success): one JSON summary on stdout
Output (failure): {"error":{"code":"..."}} on stderr
Exit codes: 0 written, 2 refused request, 3 refused input or output
  (INPUT_UNREADABLE, INPUT_TOO_LARGE, PACKAGE_INVALID, FIELD_NOT_DISCLOSED,
  FIELD_TYPE_UNSUPPORTED, OUTPUT_REFUSED, OUTPUT_UNWRITABLE), 1 internal error.
`;

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const run: RunOptions = { input: "", output: "" };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "-h" || argument === "--help") {
      process.stdout.write(USAGE);
      return;
    }
    const take = (): string => {
      const value = args[index + 1];
      if (value === undefined || value === "") throw new TamperRefusal("REQUEST_INVALID");
      index += 1;
      return value;
    };
    if (argument === "--in") run.input = take();
    else if (argument === "--out") run.output = take();
    else if (argument === "--mode") {
      const value = take();
      if (value !== "area" && value !== "qr-hash") throw new TamperRefusal("REQUEST_INVALID");
      run.mode = value;
    } else if (argument === "--field") run.field = take();
    else if (argument === "--value") run.value = take();
    else throw new TamperRefusal("REQUEST_INVALID");
  }
  const result = await runTamper(run);
  const summary = {
    mode: result.mode,
    certificateId: result.certificateId,
    field: result.field,
    originalValue: result.originalValue,
    tamperedValue: result.tamperedValue,
    bodyUnchanged: result.bodyUnchanged,
    certificateHash: result.certificateHash,
    qrUrl: result.qrUrl,
    bodyHashBefore: result.bodyHashBefore,
    bodyHashAfter: result.bodyHashAfter,
    signatureValidBefore: result.signatureValidBefore,
    signatureValidAfter: result.signatureValidAfter,
  };
  process.stdout.write(`${JSON.stringify(summary)}\n`);
}

const entry = process.argv[1] === undefined ? "" : pathToFileURL(path.resolve(process.argv[1])).href;
if (entry !== "" && import.meta.url === entry) {
  main().catch((error: unknown) => {
    const code = error instanceof TamperRefusal ? error.code : "TAMPER_INTERNAL_ERROR";
    process.stderr.write(`${JSON.stringify({ error: { code } })}\n`);
    process.exit(error instanceof TamperRefusal ? (code === "REQUEST_INVALID" ? 2 : 3) : 1);
  });
}
