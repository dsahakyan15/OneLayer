import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { decodeCertificatePackage } from "../src/certificate-codec.ts";
import { createVerifierServer } from "../src/server.ts";

async function fixture() {
  const vectors = JSON.parse(
    await readFile(new URL("../../../spec/vectors/certificate.json", import.meta.url), "utf8"),
  );
  const vector = vectors.vectors.find((entry: any) => entry.expected.result === "VALID");
  const packageBytes = Buffer.from(vector.expected.certificate_package_cbor, "hex");
  return { packageBytes, signed: decodeCertificatePackage(packageBytes) };
}

test("public REST verifies canonical package and exposes scoped lookups", async (context) => {
  const { packageBytes, signed } = await fixture();
  const body = signed.body;
  const server = createVerifierServer({
    chain: {
      async getAnchor() {
        return {
          programId: body.anchor.solanaProgramId,
          segmentPda: body.anchor.segmentPda,
          derivedSegmentPda: body.anchor.segmentPda,
          batchSequence: body.anchor.batchSequence,
          registryVersion: body.anchor.registryVersion,
          merkleRoot: body.anchor.merkleRoot,
          manifestHash: body.anchor.manifestHash,
          transactionSignature: body.anchor.transactionSignature,
          slot: body.anchor.anchorSlot,
          commitment: "finalized" as const,
        };
      },
      async getFinalizedHeadSlot() { return body.anchor.anchorSlot + 10n; },
    },
    incidents: {
      async query(registryId) {
        return { registryId, indexedThroughSlot: body.anchor.anchorSlot + 5n, incidents: [] };
      },
    },
    lookup: {
      async getAnchor(sequence) { return sequence === body.anchor.batchSequence ? { batchSequence: sequence } : null; },
      async getCertificateStatus(id) { return id === Buffer.from(body.certificateId).toString("hex") ? { status: "ACTIVE" } : null; },
    },
    corsAllowedOrigin: "http://127.0.0.1:8090",
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  context.after(() => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("server did not bind TCP");
  const base = `http://127.0.0.1:${address.port}`;

  const verification = await fetch(`${base}/v1/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      certificatePackage: packageBytes.toString("base64url"),
      requiredCommitment: "finalized",
    }),
  });
  assert.equal(verification.status, 200);
  assert.equal((await verification.json()).status, "VERIFIED");

  const preflight = await fetch(`${base}/v1/verify`, {
    method: "OPTIONS",
    headers: { origin: "http://127.0.0.1:8090", "access-control-request-method": "POST" },
  });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get("access-control-allow-origin"), "http://127.0.0.1:8090");

  const rejectedPreflight = await fetch(`${base}/v1/verify`, {
    method: "OPTIONS",
    headers: { origin: "https://example.invalid", "access-control-request-method": "POST" },
  });
  assert.equal(rejectedPreflight.status, 403);
  assert.equal(rejectedPreflight.headers.get("access-control-allow-origin"), null);

  const incidents = await fetch(
    `${base}/v1/incidents?registryId=${encodeURIComponent(body.registryId)}&batchSequence=${body.anchor.batchSequence}`,
  );
  assert.equal(incidents.status, 200);
  assert.equal((await incidents.json()).registryId, body.registryId);

  const invalidCommitment = await fetch(`${base}/v1/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ certificatePackage: packageBytes.toString("base64url"), requiredCommitment: "confirmed" }),
  });
  assert.equal(invalidCommitment.status, 400);
  assert.equal((await invalidCommitment.json()).code, "ANCHOR_NOT_FINALIZED");
});
