// Provisioning utility for the synthetic native demo, not verifier runtime.
// Public pins come from deployment configuration and the local issuer seed;
// no identity is learned from certificate packages or an unauthenticated API.
//
// Watermark bootstrap is one-time: it happens only in the run that creates the
// policy file. A retained policy whose watermark disappeared fails closed with
// recovery instructions (restore the watermark, or deliberately re-provision).
// Rotation step: when the demo policy expires, move the expired policy file
// aside and run this again (the native launcher does so on `start`); the new
// policy gets revision = accepted watermark + 1 and the watermark advances.
import { createPrivateKey, createPublicKey } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { address, getAddressEncoder } from "@solana/kit";
import { registryIdHash } from "../../../packages/canonical-ts/src/index.ts";
import { findRegistryConfigPda } from "../../../packages/onchain-client/src/index.ts";
import { parseTrustPolicy, type TrustPolicy } from "../src/trust-policy.ts";
import { assertPrivateStateLocation, loadTrustPolicy, readAcceptedRevision, readTrustPolicyDocument, TrustStateError } from "../src/trust-state.ts";

const [issuerFile, outputFile, stateFile] = process.argv.slice(2);
if (!issuerFile || !outputFile || !stateFile || process.argv.length !== 5) {
  throw new Error("usage: create-demo-trust-policy.ts <synthetic issuer seed file> <policy file> <private verifier state file>");
}
await mkdir(dirname(stateFile), { recursive: true, mode: 0o700 });
// Refuse an unsafe state location before any policy file is created.
await assertPrivateStateLocation(stateFile, outputFile);
const acceptedRevision = await readAcceptedRevision(stateFile);
const seedHex = (await readFile(issuerFile, "utf8")).trim();
if (!/^[0-9a-f]{64}$/.test(seedHex)) throw new Error("synthetic issuer seed must be exactly 32 hex bytes");
const seed = Buffer.from(seedHex, "hex");
const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
const publicKeyHex = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
seed.fill(0);
der.fill(0);
const registryId = "gov.registry.land";
const programAddress = address("6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo");
const [config] = await findRegistryConfigPda(registryIdHash(registryId), { programAddress });
const addressBytes = getAddressEncoder();
// Full getGenesisHash result from the official devnet RPC, not the truncated
// CAIP-2 network identifier. Re-provision explicitly if devnet is reset.
const genesisHash = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const policy: TrustPolicy = {
  version: 1, revision: (acceptedRevision ?? 0) + 1,
  validUntil: new Date(Date.now() + 30 * 24 * 60 * 60 * 1_000).toISOString().replace(/\.\d{3}Z$/, "Z"),
  genesisHash, registryId,
  programIdHex: Buffer.from(addressBytes.encode(programAddress)).toString("hex"),
  configPdaHex: Buffer.from(addressBytes.encode(config)).toString("hex"),
  schemaVersions: [1], registryVersions: ["1"],
  issuers: [{
    keyId: "synthetic-demo-issuer-1", publicKeyHex, algorithm: "Ed25519",
    validFrom: "2026-01-01T00:00:00Z", validUntil: "2099-01-01T00:00:00Z", revoked: false,
  }],
};
parseTrustPolicy(policy, 1);
let created = false;
try {
  await writeFile(outputFile, `${JSON.stringify(policy, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  created = true;
  process.stdout.write("synthetic verifier trust policy provisioned (30-day validity)\n");
} catch (error) {
  if (!(error instanceof Error) || !("code" in error) || error.code !== "EEXIST") throw error;
  const existing = parseTrustPolicy(JSON.parse(await readFile(outputFile, "utf8")), 1);
  if (Date.parse(existing.validUntil) <= Date.now() ||
      existing.registryId !== registryId || existing.genesisHash !== genesisHash ||
      existing.programIdHex !== policy.programIdHex || existing.configPdaHex !== policy.configPdaHex ||
      !existing.schemaVersions.includes(1) || !existing.registryVersions.includes("1") ||
      !existing.issuers.some(key => key.keyId === policy.issuers[0].keyId && key.publicKeyHex === publicKeyHex &&
        !key.revoked && Date.parse(key.validFrom) <= Date.now() && Date.now() < Date.parse(key.validUntil))) {
    throw new Error("existing demo trust policy expired or does not authorize this deployment; explicitly review and rotate it (not overwritten)");
  }
  process.stdout.write("existing synthetic verifier trust policy retained\n");
}
const demo = { policyFile: outputFile, stateFile, minimumRevision: 1, mode: { kind: "unsigned" } as const };
const { digest } = await readTrustPolicyDocument(demo);
try {
  // Bootstrap digest only for the document this very run created; otherwise the
  // existing watermark is enforced and a missing one is not silently recreated.
  await loadTrustPolicy({ ...demo, bootstrapDigest: created ? digest : undefined });
} catch (error) {
  if (!(error instanceof TrustStateError) || error.code !== "TRUST_STATE_MISSING") throw error;
  throw new Error(`verifier trust watermark ${stateFile} is missing for the existing policy ${outputFile} (fail-closed, nothing changed). ` +
    "Restore the watermark from backup, or, as a deliberate operator reset of anti-rollback, move the policy file aside and run start again.");
}
