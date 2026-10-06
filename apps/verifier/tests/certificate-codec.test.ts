import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { verifyCertificateSignature } from "../../../packages/canonical-ts/src/index.ts";
import {
  decodeCertificatePackage,
  decodeCertificatePackageBase64url,
} from "../src/certificate-codec.ts";

test("decodes the canonical shared certificate package", async () => {
  const vectors = JSON.parse(
    await readFile(new URL("../../../spec/vectors/certificate.json", import.meta.url), "utf8"),
  );
  const vector = vectors.vectors.find((entry: any) => entry.expected.result === "VALID");
  const encoded = Buffer.from(vector.expected.certificate_package_cbor, "hex");
  const signed = decodeCertificatePackage(encoded);
  assert.equal(signed.body.registryId, vector.input.registry_id);
  assert.equal(signed.body.recordVersion, BigInt(vector.input.record_version));
  assert.equal(verifyCertificateSignature(signed), true);

  const fromBase64 = decodeCertificatePackageBase64url(encoded.toString("base64url"));
  assert.deepEqual(fromBase64, signed);
});

test("rejects non-canonical package bytes before field parsing", () => {
  assert.throws(() => decodeCertificatePackage(Uint8Array.of(0xa0, 0x00)), /trailing bytes/);
  assert.throws(() => decodeCertificatePackageBase64url("AA=="), /unpadded base64url/);
});
