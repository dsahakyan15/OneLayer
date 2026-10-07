// Provisioning utility for the synthetic native demo, not verifier runtime.
// Public pins come from deployment configuration and the local issuer seed;
// no identity is learned from certificate packages or an unauthenticated API.
//
// Namespace: the policy pins the registry namespace this deployment serves
// (ONELAYER_REGISTRY_ID, else the legacy default). A policy provisioned for one
// namespace never authorizes another (ADR-0010); the config PDA is derived from
// the namespace hash, so an isolated namespace gets its own policy + PDA.
//
// Watermark bootstrap is one-time: it happens only in the run that creates the
// policy file. A retained policy whose watermark disappeared fails closed with
// recovery instructions (restore the watermark, or deliberately re-provision).
// This script never overwrites, rotates or resets existing trust on its own.
// Exit codes let the launcher distinguish the remediation without parsing text:
//   0  provisioned or retained (authorizes this deployment)
//  10  existing policy EXPIRED — a deliberate, floor-preserving rotation is the
//      only remediation (create-demo never rotates in place)
//  11  anti-rollback watermark MISSING — fail closed, never implicitly
//      bootstrapped; restore from backup or deliberately reset
//  12  existing policy does NOT authorize this deployment (namespace/issuer/
//      program/config mismatch or corrupt) — fail closed, never auto-retired
import { createPrivateKey, createPublicKey } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { address, getAddressEncoder } from "@solana/kit";
import { registryIdHash } from "../../../packages/canonical-ts/src/index.ts";
import { findRegistryConfigPda } from "../../../packages/onchain-client/src/index.ts";
import { parseTrustPolicy, type TrustPolicy } from "../src/trust-policy.ts";
import { assertPrivateStateLocation, loadTrustPolicy, readAcceptedRevision, readTrustPolicyDocument, TrustStateError } from "../src/trust-state.ts";

const EXIT_OK = 0;
const EXIT_EXPIRED = 10;
const EXIT_TRUST_STATE_MISSING = 11;
const EXIT_POLICY_INVALID = 12;

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
// Explicit namespace selection (M3): the served registry id, never hardcoded.
const registryId = process.env.ONELAYER_REGISTRY_ID ?? "gov.registry.land";
const programAddress = address("6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo");
const [config] = await findRegistryConfigPda(registryIdHash(registryId), { programAddress });
const addressBytes = getAddressEncoder();
// Full getGenesisHash result from the official devnet RPC, not the truncated
// CAIP-2 network identifier. Re-provision explicitly if devnet is reset.
const cluster = process.env.ONELAYER_PUBLICATION_CLUSTER ?? "solana:devnet";
const devnetGenesis = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const genesisHash = cluster === "solana:devnet" ? devnetGenesis : process.env.ONELAYER_RPC_GENESIS_HASH;
if (!genesisHash || (cluster !== "solana:devnet" && cluster !== "solana:local")) {
  throw new Error("explicit supported cluster and expected genesis are required for synthetic trust");
}
if (cluster === "solana:devnet" && process.env.ONELAYER_RPC_GENESIS_HASH && process.env.ONELAYER_RPC_GENESIS_HASH !== devnetGenesis) {
  throw new Error("devnet genesis cannot be overridden");
}
// The explicitly synthetic local program starts at registry version zero.
const registryVersion = cluster === "solana:local" ? "0" : "1";
const policy: TrustPolicy = {
  version: 1, revision: (acceptedRevision ?? 0) + 1,
  validUntil: new Date(Date.now() + 30 * 24 * 60 * 60 * 1_000).toISOString().replace(/\.\d{3}Z$/, "Z"),
  genesisHash, registryId,
  programIdHex: Buffer.from(addressBytes.encode(programAddress)).toString("hex"),
  configPdaHex: Buffer.from(addressBytes.encode(config)).toString("hex"),
  schemaVersions: [1], registryVersions: [registryVersion],
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
  // Expired is distinguished from "does not authorize" so the launcher can
  // offer a floor-preserving rotation ONLY for the clean expiry case. This
  // script never rotates in place: an expired policy is left untouched here.
  if (Date.parse(existing.validUntil) <= Date.now()) {
    console.error("existing demo trust policy expired; explicitly review and rotate it (not overwritten)");
    process.exit(EXIT_EXPIRED);
  }
  if (existing.registryId !== registryId || existing.genesisHash !== genesisHash ||
      existing.programIdHex !== policy.programIdHex || existing.configPdaHex !== policy.configPdaHex ||
      !existing.schemaVersions.includes(1) || !existing.registryVersions.includes(registryVersion) ||
      !existing.issuers.some(key => key.keyId === policy.issuers[0].keyId && key.publicKeyHex === publicKeyHex &&
        !key.revoked && Date.parse(key.validFrom) <= Date.now() && Date.now() < Date.parse(key.validUntil))) {
    console.error("existing demo trust policy does not authorize this deployment; explicitly review and rotate it (not overwritten)");
    process.exit(EXIT_POLICY_INVALID);
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
  // Missing watermark is fail-closed with an actionable code (M4): never an
  // implicit trust bootstrap. The watermark is independent of the policy file.
  console.error(`verifier trust watermark ${stateFile} is missing for the existing policy ${outputFile} (fail-closed, nothing changed). ` +
    "Restore the watermark from backup, or, as a deliberate operator reset of anti-rollback, move the policy file aside and run start again.");
  process.exit(EXIT_TRUST_STATE_MISSING);
}
process.exit(EXIT_OK);
