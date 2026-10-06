// Tests for live-demo-qr-decode.mjs. Run with:
//   node --test apps/mvp-web/scripts/live-demo-qr-decode.test.mjs
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { Readable } from "node:stream";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { createDeflate, crc32, inflateSync } from "node:zlib";
import QRCode from "qrcode";
import { PNG } from "pngjs";
import {
  decodeQrPng,
  MAX_PNG_BYTES,
  QrDecodeRefusal,
  readIhdrDimensions,
} from "./live-demo-qr-decode.mjs";

const exec = promisify(execFile);
const SCRIPT = fileURLToPath(new URL("./live-demo-qr-decode.mjs", import.meta.url));
const URL_PAYLOAD = "http://127.0.0.1:8090/c/01010101010101010101010101010101?h=h5EbHogO9fiEjwhwNsiUSvBBVqcG_JH4m2PI8Sejdio";

let workDir = "";

async function pngFor(payload) {
  return QRCode.toBuffer(payload, { type: "png", errorCorrectionLevel: "M", margin: 2, width: 512 });
}

function solidPng(width, height, fill = [0, 0, 0, 255]) {
  const image = new PNG({ width, height });
  for (let offset = 0; offset < image.data.length; offset += 4) {
    image.data[offset] = fill[0];
    image.data[offset + 1] = fill[1];
    image.data[offset + 2] = fill[2];
    image.data[offset + 3] = fill[3];
  }
  return PNG.sync.write(image);
}

function pngChunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const typeBuf = Buffer.from(type, "latin1");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])) >>> 0);
  return Buffer.concat([length, typeBuf, data, crc]);
}

function ihdrChunk(width, height, fields = {}) {
  const data = Buffer.alloc(13);
  data.writeUInt32BE(width, 0);
  data.writeUInt32BE(height, 4);
  data[8] = fields.bitDepth ?? 8;
  data[9] = fields.colorType ?? 6;
  data[10] = fields.compressionMethod ?? 0;
  data[11] = fields.filterMethod ?? 0;
  data[12] = fields.interlaceMethod ?? 0;
  return pngChunk("IHDR", data);
}

function pngFromParts(width, height, fields, idatData) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return Buffer.concat([
    signature,
    ihdrChunk(width, height, fields),
    pngChunk("IDAT", idatData),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

/**
 * A structurally valid PNG whose IHDR declares a huge bitmap and whose IDAT is
 * deliberately broken. Nothing in the test decompresses anything: the refusal
 * must come from the declared dimensions alone, before pngjs runs.
 */
function adversarialHugePng(width, height) {
  return pngFromParts(width, height, {}, Buffer.from([0x00, 0x01, 0x02, 0x03]));
}

/**
 * Streaming deflate of `totalBytes` zeros: builds a genuine bomb-shaped IDAT
 * (a tiny compressed stream whose payload is much larger) while never holding
 * more than one chunk of plaintext at a time.
 */
async function deflateZeros(totalBytes) {
  const source = Readable.from(
    (function* () {
      const chunk = Buffer.alloc(65_536, 0);
      let sent = 0;
      while (sent < totalBytes) {
        const size = Math.min(chunk.length, totalBytes - sent);
        sent += size;
        yield chunk.subarray(0, size);
      }
    })(),
  );
  const chunks = [];
  for await (const piece of source.pipe(createDeflate({ level: 9 }))) chunks.push(piece);
  return Buffer.concat(chunks);
}

before(async () => {
  workDir = await mkdtemp(path.join(tmpdir(), "live-demo-qr-decode-"));
});

after(async () => {
  await rm(workDir, { recursive: true, force: true });
});

test("decodes a demo loopback QR PNG to the exact URL", async () => {
  const png = await pngFor(URL_PAYLOAD);
  assert.equal(decodeQrPng(png), URL_PAYLOAD);

  const imagePath = path.join(workDir, "qr.png");
  await writeFile(imagePath, png);
  const { stdout, stderr } = await exec(process.execPath, [SCRIPT, imagePath]);
  assert.equal(stdout, `${URL_PAYLOAD}\n`, "stdout carries the payload and nothing else");
  assert.equal(stderr, "");
});

test("reads the PNG from stdin and prints only the URL", async () => {
  const png = await pngFor(URL_PAYLOAD);
  const child = spawn(process.execPath, [SCRIPT], { stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => {
    stdout += String(chunk);
  });
  child.stderr.on("data", (chunk) => {
    stderr += String(chunk);
  });
  const exit = new Promise((resolve) => child.on("close", resolve));
  child.stdin.end(png);
  assert.equal(await exit, 0);
  assert.equal(stdout, `${URL_PAYLOAD}\n`);
  assert.equal(stderr, "");
});

test("non-PNG input is refused", async () => {
  assert.throws(
    () => decodeQrPng(Buffer.from("not a png at all")),
    (error) => {
      assert.ok(error instanceof QrDecodeRefusal);
      assert.equal(error.code, "INPUT_NOT_PNG");
      return true;
    },
  );
  const badPath = path.join(workDir, "bad.png");
  await writeFile(badPath, "not a png at all");
  await assert.rejects(exec(process.execPath, [SCRIPT, badPath]), (error) => {
    assert.equal(error.code, 3);
    assert.match(String(error.stderr), /INPUT_NOT_PNG/);
    return true;
  });
});

test("a PNG without a QR code is refused", async () => {
  const plain = solidPng(256, 256, [255, 255, 255, 255]);
  assert.throws(
    () => decodeQrPng(plain),
    (error) => {
      assert.ok(error instanceof QrDecodeRefusal);
      assert.equal(error.code, "QR_NOT_FOUND");
      return true;
    },
  );
  const plainPath = path.join(workDir, "plain.png");
  await writeFile(plainPath, plain);
  await assert.rejects(exec(process.execPath, [SCRIPT, plainPath]), (error) => {
    assert.equal(error.code, 4);
    assert.match(String(error.stderr), /QR_NOT_FOUND/);
    return true;
  });
});

test("oversized input and oversized dimensions are refused", async () => {
  assert.throws(
    () => decodeQrPng(Buffer.alloc(MAX_PNG_BYTES + 1, 0x89)),
    (error) => {
      assert.ok(error instanceof QrDecodeRefusal);
      assert.equal(error.code, "INPUT_TOO_LARGE");
      return true;
    },
  );
  const wide = solidPng(4097, 1, [255, 255, 255, 255]);
  assert.throws(
    () => decodeQrPng(wide),
    (error) => {
      assert.ok(error instanceof QrDecodeRefusal);
      assert.equal(error.code, "IMAGE_TOO_LARGE");
      return true;
    },
  );
  const empty = path.join(workDir, "empty.png");
  await writeFile(empty, Buffer.alloc(MAX_PNG_BYTES + 1, 0x89));
  await assert.rejects(exec(process.execPath, [SCRIPT, empty]), (error) => {
    assert.equal(error.code, 3);
    assert.match(String(error.stderr), /INPUT_TOO_LARGE/);
    return true;
  });
});

test("an overlong QR payload is refused instead of echoed", async () => {
  const longPayload = `http://127.0.0.1:8090/c/${"a".repeat(2100)}`;
  const png = await QRCode.toBuffer(longPayload, { type: "png", errorCorrectionLevel: "L", margin: 2, width: 2048 });
  assert.throws(
    () => decodeQrPng(png),
    (error) => {
      assert.ok(error instanceof QrDecodeRefusal);
      assert.equal(error.code, "QR_PAYLOAD_INVALID");
      return true;
    },
  );
});

test("a payload with line breaks is refused", async () => {
  const payload = `http://127.0.0.1:8090/c/x\nignored`;
  const png = await pngFor(payload);
  assert.throws(
    () => decodeQrPng(png),
    (error) => {
      assert.ok(error instanceof QrDecodeRefusal);
      assert.equal(error.code, "QR_PAYLOAD_INVALID");
      return true;
    },
  );
});

test("usage errors exit 2 and missing files exit 3", async () => {
  await assert.rejects(exec(process.execPath, [SCRIPT, "a.png", "b.png"]), (error) => {
    assert.equal(error.code, 2);
    assert.match(String(error.stderr), /REQUEST_INVALID/);
    return true;
  });
  await assert.rejects(exec(process.execPath, [SCRIPT, path.join(workDir, "missing.png")]), (error) => {
    assert.equal(error.code, 3);
    assert.match(String(error.stderr), /INPUT_UNREADABLE/);
    return true;
  });
});

test("a crafted huge-dimension PNG is refused before any decompression (reviewer repro)", async () => {
  // Reviewer repro: a small PNG declaring 12000x12000 must not be allowed to
  // decompress into a 576 MB RGBA bitmap. The IDAT here is broken on purpose:
  // if the IHDR gate were removed, pngjs would either run first (and this call
  // would report INPUT_NOT_PNG) or allocate the declared bitmap (RSS below).
  const png = adversarialHugePng(12000, 12000);
  assert.ok(png.length < 1024, "the adversarial file itself is tiny");
  assert.deepEqual(readIhdrDimensions(png), { width: 12000, height: 12000 });

  const rssBefore = process.memoryUsage().rss;
  assert.throws(
    () => decodeQrPng(png),
    (error) => {
      assert.ok(error instanceof QrDecodeRefusal);
      assert.equal(error.code, "IMAGE_TOO_LARGE");
      return true;
    },
  );
  const rssGrowth = process.memoryUsage().rss - rssBefore;
  assert.ok(
    rssGrowth < 64 * 1024 * 1024,
    `refusal must happen before decompression, RSS grew ${rssGrowth} bytes`,
  );

  const hugePath = path.join(workDir, "huge.png");
  await writeFile(hugePath, png);
  await assert.rejects(exec(process.execPath, [SCRIPT, hugePath]), (error) => {
    assert.equal(error.code, 3);
    assert.match(String(error.stderr), /IMAGE_TOO_LARGE/);
    return true;
  });
});

test("IHDR parsing refuses malformed headers and zero dimensions", () => {
  const notIhdr = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk("IDAT", Buffer.alloc(4)),
  ]);
  assert.throws(
    () => readIhdrDimensions(notIhdr),
    (error) => {
      assert.ok(error instanceof QrDecodeRefusal);
      assert.equal(error.code, "INPUT_NOT_PNG");
      return true;
    },
  );
  assert.throws(
    () => readIhdrDimensions(Buffer.from([0x89, 0x50, 0x4e, 0x47])),
    (error) => {
      assert.ok(error instanceof QrDecodeRefusal);
      assert.equal(error.code, "INPUT_NOT_PNG");
      return true;
    },
  );
  const zero = adversarialHugePng(0, 5);
  assert.throws(
    () => decodeQrPng(zero),
    (error) => {
      assert.ok(error instanceof QrDecodeRefusal);
      assert.equal(error.code, "IMAGE_INVALID");
      return true;
    },
  );
});

test("empty input is refused as INPUT_INVALID with exit 3", async () => {
  assert.throws(
    () => decodeQrPng(Buffer.alloc(0)),
    (error) => {
      assert.ok(error instanceof QrDecodeRefusal);
      assert.equal(error.code, "INPUT_INVALID");
      return true;
    },
  );
  const emptyFile = path.join(workDir, "empty-input.png");
  await writeFile(emptyFile, Buffer.alloc(0));
  await assert.rejects(exec(process.execPath, [SCRIPT, emptyFile]), (error) => {
    assert.equal(error.code, 3);
    assert.match(String(error.stderr), /INPUT_INVALID/);
    return true;
  });

  const child = spawn(process.execPath, [SCRIPT], { stdio: ["pipe", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += String(chunk);
  });
  const exit = new Promise((resolve) => child.on("close", resolve));
  child.stdin.end();
  assert.equal(await exit, 3);
  assert.match(stderr, /INPUT_INVALID/);
});

test("non-regular input files are refused without hanging (FIFO, directory)", async () => {
  const fifoPath = path.join(workDir, "a-fifo");
  await exec("mkfifo", [fifoPath]);
  // If the decoder opened the FIFO before checking the file type it would
  // block here forever; the timeout turns that into a test failure.
  await assert.rejects(exec(process.execPath, [SCRIPT, fifoPath], { timeout: 5000 }), (error) => {
    assert.equal(error.code, 3);
    assert.match(String(error.stderr), /INPUT_UNREADABLE/);
    return true;
  });
  const dirPath = path.join(workDir, "a-directory");
  await exec("mkdir", [dirPath]);
  await assert.rejects(exec(process.execPath, [SCRIPT, dirPath]), (error) => {
    assert.equal(error.code, 3);
    assert.match(String(error.stderr), /INPUT_UNREADABLE/);
    return true;
  });
});

test("a tiny interlaced PNG with a larger compressed payload is refused before pngjs runs", async () => {
  // Second-review repro, bounded: IHDR 1x1 interlace=1 with an IDAT whose
  // zlib payload expands to 8 MiB. pngjs inflates interlaced IDAT with a bare
  // inflateSync and no size cap, so this must be refused from the IHDR alone.
  // The IDAT is built by streaming deflate (never more than one 64 KiB chunk of
  // plaintext in memory) and the pngjs entry point is watched directly: if the
  // IHDR gate were removed, decodeCalls would be non-zero and the run would
  // inflate the payload.
  const payloadBytes = 8 * 1024 * 1024;
  const compressed = await deflateZeros(payloadBytes);
  const png = pngFromParts(1, 1, { interlaceMethod: 1 }, compressed);
  assert.ok(png.length < 32 * 1024, `fixture must stay tiny, got ${png.length} bytes`);
  assert.equal(
    inflateSync(compressed, { maxOutputLength: payloadBytes }).length,
    payloadBytes,
    "the IDAT is a genuine larger zlib payload",
  );

  const originalRead = PNG.sync.read;
  let decodeCalls = 0;
  PNG.sync.read = (...args) => {
    decodeCalls += 1;
    return originalRead(...args);
  };
  try {
    // Calibrate the seam: a real non-interlaced PNG must reach pngjs exactly
    // once through this same PNG.sync.read, otherwise a zero count would prove
    // nothing about the interlaced case.
    const calibration = await pngFor(URL_PAYLOAD);
    assert.equal(decodeQrPng(calibration), URL_PAYLOAD);
    assert.equal(decodeCalls, 1, "the seam observes decoder invocations");
    decodeCalls = 0;

    const rssBefore = process.memoryUsage().rss;
    assert.throws(
      () => decodeQrPng(png),
      (error) => {
        assert.ok(error instanceof QrDecodeRefusal);
        assert.equal(error.code, "IMAGE_UNSUPPORTED");
        return true;
      },
    );
    assert.equal(decodeCalls, 0, "pngjs must never run for an interlaced PNG");
    const rssGrowth = process.memoryUsage().rss - rssBefore;
    assert.ok(
      rssGrowth < 4 * 1024 * 1024,
      `refusal must happen before inflation, RSS grew ${rssGrowth} bytes`,
    );
  } finally {
    PNG.sync.read = originalRead;
  }
  assert.throws(
    () => readIhdrDimensions(png),
    (error) => {
      assert.ok(error instanceof QrDecodeRefusal);
      assert.equal(error.code, "IMAGE_UNSUPPORTED");
      return true;
    },
  );

  const bombPath = path.join(workDir, "interlaced-bomb.png");
  await writeFile(bombPath, png);
  await assert.rejects(exec(process.execPath, [SCRIPT, bombPath]), (error) => {
    assert.equal(error.code, 3);
    assert.match(String(error.stderr), /IMAGE_UNSUPPORTED/);
    return true;
  });
});

test("a malformed interlace byte is refused as INPUT_NOT_PNG", () => {
  for (const interlaceMethod of [2, 255]) {
    const png = pngFromParts(1, 1, { interlaceMethod }, Buffer.from([0x00, 0x01]));
    assert.throws(
      () => decodeQrPng(png),
      (error) => {
        assert.ok(error instanceof QrDecodeRefusal);
        assert.equal(error.code, "INPUT_NOT_PNG", `interlaceMethod=${interlaceMethod}`);
        return true;
      },
    );
    assert.throws(
      () => readIhdrDimensions(png),
      (error) => {
        assert.ok(error instanceof QrDecodeRefusal);
        assert.equal(error.code, "INPUT_NOT_PNG");
        return true;
      },
    );
  }
});

test("illegal PNG method/bit-depth/colour fields are refused; legal encodings still reach the decoder", () => {
  const illegal = [
    { compressionMethod: 1 },
    { filterMethod: 1 },
    { colorType: 1 },
    { colorType: 5 },
    { colorType: 6, bitDepth: 3 },
    { colorType: 2, bitDepth: 4 },
    { colorType: 3, bitDepth: 16 },
    { bitDepth: 7 },
  ];
  for (const fields of illegal) {
    const png = pngFromParts(1, 1, fields, Buffer.from([0x00, 0x01]));
    assert.throws(
      () => decodeQrPng(png),
      (error) => {
        assert.ok(error instanceof QrDecodeRefusal);
        assert.equal(error.code, "INPUT_NOT_PNG", JSON.stringify(fields));
        return true;
      },
    );
  }
  // A legal grayscale 8-bit header passes the gate and reaches the decode
  // path: the gate must not over-refuse. pngjs reconstructs the 1x1 bitmap
  // even from a stub IDAT, so jsQR is the one that reports no code.
  const legal = pngFromParts(1, 1, { colorType: 0, bitDepth: 8 }, Buffer.from([0x00, 0x01]));
  assert.deepEqual(readIhdrDimensions(legal), { width: 1, height: 1 });
  assert.throws(
    () => decodeQrPng(legal),
    (error) => {
      assert.ok(error instanceof QrDecodeRefusal);
      assert.equal(error.code, "QR_NOT_FOUND");
      return true;
    },
  );
});

test("non-interlaced QR PNGs are unaffected (happy path)", async () => {
  const png = await pngFor(URL_PAYLOAD);
  assert.equal(png[28], 0, "launcher QR PNGs are non-interlaced");
  const declared = readIhdrDimensions(png);
  assert.ok(Number.isInteger(declared.width) && declared.width >= 1);
  assert.ok(Number.isInteger(declared.height) && declared.height >= 1);
  assert.equal(decodeQrPng(png), URL_PAYLOAD);
});

test("usage documents the interlace refusal contract", async () => {
  const { stdout, stderr } = await exec(process.execPath, [SCRIPT, "--help"]);
  assert.equal(stderr, "");
  assert.match(stdout, /IMAGE_UNSUPPORTED/);
  assert.match(stdout, /interlaced/i);
  assert.match(stdout, /INPUT_NOT_PNG/);
});
