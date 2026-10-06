import { createPrivateKey, createPublicKey } from "node:crypto";
import type { TrustPolicy } from "../../apps/verifier/src/trust-policy.ts";

export const SYNTHETIC_GENESIS = "synthetic-genesis";
export const SYNTHETIC_CONFIG = new Uint8Array(32).fill(8);

/** Test-owned pins. Never derive authorized identities from a package under test. */
export function syntheticTrustPolicy(input: {
  programId: Uint8Array;
  issuerSeed: Uint8Array;
  issuerKeyId?: string;
}): TrustPolicy {
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), input.issuerSeed]),
    format: "der", type: "pkcs8",
  });
  const publicKey = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);
  return {
    version: 1, revision: 1, validUntil: "2099-01-01T00:00:00Z",
    genesisHash: SYNTHETIC_GENESIS, registryId: "gov.registry.land",
    programIdHex: Buffer.from(input.programId).toString("hex"),
    configPdaHex: Buffer.from(SYNTHETIC_CONFIG).toString("hex"),
    schemaVersions: [1], registryVersions: ["1"],
    issuers: [{
      keyId: input.issuerKeyId ?? "synthetic-demo-issuer-1", publicKeyHex: publicKey.toString("hex"),
      algorithm: "Ed25519", validFrom: "2020-01-01T00:00:00Z", validUntil: "2099-01-01T00:00:00Z", revoked: false,
    }],
  };
}
