// Bounded QR PNG decoder for the live-demo launcher (A4).
//
// Reads one PNG (file argument or stdin) and prints ONLY the decoded QR
// payload — the loopback certificate URL the QR carries — on stdout. It never
// fetches that URL, never runs a command and never touches the network: the
// launcher's Python side parses and validates the payload (strict loopback
// shape) and performs the actual package lookup.
//
// Everything is bounded: input size, image dimensions and payload length. A
// non-printable or oversized payload is refused instead of being echoed.
//
// Declared dimensions are checked from the PNG IHDR BEFORE any decompression:
// pngjs trusts the IHDR and would allocate width*height*4 bytes, so a small
// compressed PNG can request a huge bitmap. The same bounds are re-asserted on
// the decoded image. File input is stat-checked and read through a bounded
// path (regular files only).
//
// The IHDR encoding fields are validated in the same pass, still before any
// decompression. Interlaced (Adam7) PNGs are refused outright
// (IMAGE_UNSUPPORTED): pngjs inflates interlaced IDAT with a bare
// zlib.inflateSync and no size cap (parser-sync.js), so a tiny 1x1 interlaced
// PNG can expand to gigabytes. Illegal compression/filter methods or
// bit-depth/colour-type combinations are refused as INPUT_NOT_PNG. The full
// refusal-code and exit-code contract is documented in USAGE below.
import { constants as fsConstants } from "node:fs";
import { open, stat } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import jsQR from "jsqr";
import { PNG } from "pngjs";

export const MAX_PNG_BYTES = 2 * 1024 * 1024;
export const MAX_DIMENSION = 4096;
export const MAX_PIXELS = 16_000_000;
export const MAX_PAYLOAD_CHARS = 2048;

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

// PNG spec colour types and their legal bit depths (bit depth 16 and the
// sub-byte depths are cheap to accept: pngjs decodes them within the already
// bounded width*height budget). Anything outside this table is not a PNG.
const LEGAL_BIT_DEPTHS = {
  0: [1, 2, 4, 8, 16],
  2: [8, 16],
  3: [1, 2, 4, 8],
  4: [8, 16],
  6: [8, 16],
};

export class QrDecodeRefusal extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

/**
 * Reads width/height from the PNG IHDR (the first chunk) without decoding any
 * pixel data, validating the encoding fields first. Returns {width, height} as
 * declared; throws QrDecodeRefusal for a malformed header (INPUT_NOT_PNG), for
 * an illegal compression/filter method or bit-depth/colour-type combination
 * (INPUT_NOT_PNG), and — before any decompression — for interlaced images
 * (IMAGE_UNSUPPORTED).
 */
export function readIhdrDimensions(buffer) {
  // signature (8) + length (4) + type (4) + 13-byte IHDR body
  if (buffer.length < 29) throw new QrDecodeRefusal("INPUT_NOT_PNG");
  const length = buffer.readUInt32BE(8);
  const type = buffer.toString("latin1", 12, 16);
  if (length !== 13 || type !== "IHDR") throw new QrDecodeRefusal("INPUT_NOT_PNG");
  const bitDepth = buffer[24];
  const colorType = buffer[25];
  const compressionMethod = buffer[26];
  const filterMethod = buffer[27];
  const interlaceMethod = buffer[28];
  // The PNG spec defines only compression method 0 and filter method 0.
  if (compressionMethod !== 0 || filterMethod !== 0) throw new QrDecodeRefusal("INPUT_NOT_PNG");
  const legalDepths = LEGAL_BIT_DEPTHS[colorType];
  if (legalDepths === undefined || !legalDepths.includes(bitDepth)) {
    throw new QrDecodeRefusal("INPUT_NOT_PNG");
  }
  // Adam7 interlacing is refused here, before pngjs can inflate its IDAT with a
  // bare inflateSync that has no output cap. Any other interlace method value
  // is not a PNG at all.
  if (interlaceMethod === 1) throw new QrDecodeRefusal("IMAGE_UNSUPPORTED");
  if (interlaceMethod !== 0) throw new QrDecodeRefusal("INPUT_NOT_PNG");
  return { width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20) };
}

/**
 * Decodes the first QR code found in a PNG buffer.
 *
 * Returns the payload text exactly as encoded. Throws QrDecodeRefusal with a
 * stable code for every refused input.
 */
export function decodeQrPng(bytes) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buffer.length === 0) throw new QrDecodeRefusal("INPUT_INVALID");
  if (buffer.length > MAX_PNG_BYTES) throw new QrDecodeRefusal("INPUT_TOO_LARGE");
  if (!buffer.subarray(0, 8).equals(PNG_SIGNATURE)) throw new QrDecodeRefusal("INPUT_NOT_PNG");
  // Dimension bounds (and the interlace/encoding refusal above) are enforced
  // on the declared IHDR BEFORE pngjs decodes: decompression cost is
  // attacker-controlled through these fields.
  const declared = readIhdrDimensions(buffer);
  if (!Number.isInteger(declared.width) || !Number.isInteger(declared.height) || declared.width < 1 || declared.height < 1) {
    throw new QrDecodeRefusal("IMAGE_INVALID");
  }
  if (declared.width > MAX_DIMENSION || declared.height > MAX_DIMENSION || declared.width * declared.height > MAX_PIXELS) {
    throw new QrDecodeRefusal("IMAGE_TOO_LARGE");
  }
  let image;
  try {
    image = PNG.sync.read(buffer);
  } catch {
    throw new QrDecodeRefusal("INPUT_NOT_PNG");
  }
  const { width, height, data } = image;
  if (!Number.isInteger(width) || !Number.isInteger(height) || width < 1 || height < 1) {
    throw new QrDecodeRefusal("IMAGE_INVALID");
  }
  if (width > MAX_DIMENSION || height > MAX_DIMENSION || width * height > MAX_PIXELS) {
    throw new QrDecodeRefusal("IMAGE_TOO_LARGE");
  }
  const code = jsQR(new Uint8ClampedArray(data), width, height);
  if (code === null || typeof code.data !== "string") throw new QrDecodeRefusal("QR_NOT_FOUND");
  const payload = code.data;
  if (payload.length === 0 || payload.length > MAX_PAYLOAD_CHARS) throw new QrDecodeRefusal("QR_PAYLOAD_INVALID");
  // The payload becomes an HTTP target for the caller: only printable text
  // without line breaks is ever printed on the protocol channel.
  if (/[\u0000-\u001f\u007f]/.test(payload)) throw new QrDecodeRefusal("QR_PAYLOAD_INVALID");
  return payload;
}

const USAGE = `Usage: live-demo-qr-decode.mjs [FILE]

Decodes one QR code from a PNG image and prints only the payload text (the
certificate URL the code carries) on stdout. Reads FILE, or stdin when no FILE
is given. The URL is never fetched and no command is run.

Output (success): the payload text followed by a newline
Output (failure): {"error":{"code":"..."}} on stderr
Exit codes: 0 decoded, 2 refused request (REQUEST_INVALID), 3 refused input
  or image (INPUT_INVALID, INPUT_UNREADABLE, INPUT_NOT_PNG, INPUT_TOO_LARGE,
  IMAGE_INVALID, IMAGE_TOO_LARGE, IMAGE_UNSUPPORTED), 4 no usable QR
  (QR_NOT_FOUND, QR_PAYLOAD_INVALID).
Only non-interlaced PNGs are decoded: an interlaced PNG is refused as
IMAGE_UNSUPPORTED before any decompression, and an illegal compression method,
filter method or bit-depth/colour-type combination is refused as INPUT_NOT_PNG.
`;

async function readStdin() {
  const chunks = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    const buffer = Buffer.from(chunk);
    total += buffer.length;
    if (total > MAX_PNG_BYTES) throw new QrDecodeRefusal("INPUT_TOO_LARGE");
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

/**
 * Bounded file read: a regular file only (a FIFO or device would block or
 * stream without bound), sized before any read, descriptor re-checked after
 * open and the read itself capped at MAX_PNG_BYTES.
 */
async function readBoundedFile(file) {
  let pre;
  try {
    pre = await stat(file);
  } catch {
    throw new QrDecodeRefusal("INPUT_UNREADABLE");
  }
  if (!pre.isFile()) throw new QrDecodeRefusal("INPUT_UNREADABLE");
  if (pre.size > MAX_PNG_BYTES) throw new QrDecodeRefusal("INPUT_TOO_LARGE");
  let handle;
  try {
    handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NONBLOCK);
  } catch {
    throw new QrDecodeRefusal("INPUT_UNREADABLE");
  }
  try {
    const onDisk = await handle.stat();
    if (!onDisk.isFile()) throw new QrDecodeRefusal("INPUT_UNREADABLE");
    if (onDisk.dev !== pre.dev || onDisk.ino !== pre.ino) throw new QrDecodeRefusal("INPUT_UNREADABLE");
    if (onDisk.size > MAX_PNG_BYTES) throw new QrDecodeRefusal("INPUT_TOO_LARGE");
    const chunks = [];
    let total = 0;
    for (;;) {
      const chunk = Buffer.allocUnsafe(65_536);
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > MAX_PNG_BYTES) throw new QrDecodeRefusal("INPUT_TOO_LARGE");
      chunks.push(chunk.subarray(0, bytesRead));
    }
    return Buffer.concat(chunks);
  } finally {
    await handle.close();
  }
}

async function main() {
  const args = process.argv.slice(2);
  let source = null;
  for (const argument of args) {
    if (argument === "-h" || argument === "--help") {
      process.stdout.write(USAGE);
      return;
    }
    if (source !== null) throw new QrDecodeRefusal("REQUEST_INVALID");
    source = argument;
  }
  const bytes = source === null ? await readStdin() : await readBoundedFile(source);
  process.stdout.write(`${decodeQrPng(bytes)}\n`);
}

const entry = process.argv[1] === undefined ? "" : pathToFileURL(process.argv[1]).href;
if (entry !== "" && import.meta.url === entry) {
  main().catch((error) => {
    const code = error instanceof QrDecodeRefusal ? error.code : "QR_DECODE_INTERNAL_ERROR";
    process.stderr.write(`${JSON.stringify({ error: { code } })}\n`);
    process.exit(
      error instanceof QrDecodeRefusal
        ? code === "REQUEST_INVALID"
          ? 2
          : code === "QR_NOT_FOUND" || code === "QR_PAYLOAD_INVALID"
            ? 4
            : 3
        : 1,
    );
  });
}
