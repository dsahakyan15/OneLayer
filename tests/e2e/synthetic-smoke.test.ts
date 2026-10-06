import { syntheticTrustPolicy, SYNTHETIC_CONFIG, SYNTHETIC_GENESIS } from "../support/trust-fixtures.ts";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { registryIdHash } from "../../packages/canonical-ts/src/index.ts";
import { decodeCertificatePackageBase64url } from "../../apps/verifier/src/certificate-codec.ts";
import { verifyCertificate, type ChainReader, type IncidentIndex } from "../../apps/verifier/src/verify.ts";

test("Rust synthetic pipeline certificate reaches VERIFIED in the TypeScript verifier", async () => {
  const encoded = execFileSync(
    "cargo",
    ["run", "--quiet", "-p", "onelayer-pilot-pipeline", "--bin", "synthetic_smoke_fixture"],
    { cwd: new URL("../..", import.meta.url), encoding: "utf8" },
  ).trim();
  const signed = decodeCertificatePackageBase64url(encoded);
  const trustPolicy = syntheticTrustPolicy({ programId: new Uint8Array(32).fill(5), issuerSeed: new Uint8Array(32).fill(9), issuerKeyId: "pilot-issuer-1" });
  const chain: ChainReader = {
    async getGenesisHash() { return SYNTHETIC_GENESIS; },
    async getRegistryConfig(body) {
      return { registryIdHash: registryIdHash(body.registryId), paused: false, configPda: SYNTHETIC_CONFIG, programId: body.anchor.solanaProgramId };
    },
    async getAnchor(body) {
      return {
        registryConfigPda: SYNTHETIC_CONFIG,
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
  const result = await verifyCertificate(signed, chain, incidents, { trustPolicy });
  assert.equal(result.status, "VERIFIED");
  assert.equal(result.incidentIndexStatus, "CHECKED");
});
