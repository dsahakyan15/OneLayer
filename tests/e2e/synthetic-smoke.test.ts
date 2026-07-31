import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { decodeCertificatePackageBase64url } from "../../apps/verifier/src/certificate-codec.ts";
import { verifyCertificate, type ChainReader, type IncidentIndex } from "../../apps/verifier/src/verify.ts";

test("Rust synthetic pipeline certificate reaches VERIFIED in the TypeScript verifier", async () => {
  const encoded = execFileSync(
    "cargo",
    ["run", "--quiet", "-p", "onelayer-pilot-pipeline", "--bin", "synthetic_smoke_fixture"],
    { cwd: new URL("../..", import.meta.url), encoding: "utf8" },
  ).trim();
  const signed = decodeCertificatePackageBase64url(encoded);
  const chain: ChainReader = {
    async getAnchor(body) {
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
        commitment: "finalized",
      };
    },
    async getFinalizedHeadSlot() { return 1_050n; },
  };
  const incidents: IncidentIndex = {
    async query(registryId) { return { registryId, indexedThroughSlot: 1_040n, incidents: [] }; },
  };
  const result = await verifyCertificate(signed, chain, incidents);
  assert.equal(result.status, "VERIFIED");
  assert.equal(result.incidentIndexStatus, "CHECKED");
});
