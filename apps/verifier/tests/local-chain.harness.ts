// Opt-in live-chain harness (`npm run test:local-chain`): real solana-test-validator,
// the built onelayer_registry program, real account constraints read through
// SolanaRpcChainReader. Synthetic keys only; the ledger is a temp dir.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { access, mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  address, appendTransactionMessageInstructions, createSolanaRpc, createTransactionMessage, generateKeyPairSigner,
  getAddressEncoder, getBase58Encoder, getBase64EncodedWireTransaction, getProgramDerivedAddress, getSignatureFromTransaction,
  lamports, pipe, setTransactionMessageFeePayerSigner, setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners, type Address, type KeyPairSigner,
} from "@solana/kit";
import { proof } from "../../../packages/merkle-ts/src/index.ts";
import {
  batchLeafHash, buildFieldTree, fieldSalt, recordCommitment, registryIdHash, signCertificate,
  type CertificateBody, type SignedCertificate,
} from "../../../packages/canonical-ts/src/index.ts";
import {
  findLedgerSegmentPda, findRegistryConfigPda, getCreateLedgerSegmentInstruction, getGrantOperatorInstruction,
  getInitializeRegistryInstruction, getPublishAnchorInstruction, getRegistryConfigDecoder, ONELAYER_REGISTRY_PROGRAM_ADDRESS,
} from "../../../packages/onchain-client/src/index.ts";
import { SolanaRpcChainReader } from "../src/solana-rpc.ts";
import { verifyCertificate, type IncidentIndex } from "../src/verify.ts";
import type { TrustPolicy } from "../src/trust-policy.ts";

const programSo = fileURLToPath(new URL("../../../onchain/target/deploy/onelayer_registry.so", import.meta.url));
const REGISTRY = "gov.registry.land";
const OTHER_REGISTRY = "synthetic.registry.other";
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const addressBytes = (value: Address) => new Uint8Array(getAddressEncoder().encode(value));

async function freePort(): Promise<number> {
  const server = createServer().listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = (server.address() as { port: number }).port;
  await new Promise<void>(resolve => server.close(() => resolve()));
  return port;
}

type Rpc = ReturnType<typeof createSolanaRpc>;

async function until<T>(what: string, probe: () => Promise<T | undefined>, timeoutMs = 90_000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try { const value = await probe(); if (value !== undefined) return value; } catch (error) { if ((error as { fatal?: boolean }).fatal) throw error; /* not ready */ }
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise(resolve => setTimeout(resolve, 400));
  }
}

async function send(rpc: Rpc, payer: KeyPairSigner, instructions: any[]): Promise<{ signature: string; slot: bigint }> {
  const { value: blockhash } = await rpc.getLatestBlockhash({ commitment: "confirmed" }).send();
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    draft => setTransactionMessageFeePayerSigner(payer, draft),
    draft => setTransactionMessageLifetimeUsingBlockhash(blockhash, draft),
    draft => appendTransactionMessageInstructions(instructions, draft),
  );
  const transaction = await signTransactionMessageWithSigners(message);
  const signature = getSignatureFromTransaction(transaction);
  await rpc.sendTransaction(getBase64EncodedWireTransaction(transaction), { encoding: "base64", preflightCommitment: "confirmed" }).send();
  const started = Date.now();
  const status = await until(`finalized ${signature}`, async () => {
    const [value] = (await rpc.getSignatureStatuses([signature]).send()).value;
    if (value?.err) throw Object.assign(new Error(`transaction failed: ${JSON.stringify(value.err)}`), { fatal: true });
    return value?.confirmationStatus === "finalized" ? value : undefined;
  });
  process.stderr.write(`finalized after ${Date.now() - started}ms\n`);
  return { signature, slot: BigInt(status.slot) };
}

/** initialize → grant operator → create today's segment → publish batch 1 with `merkleRoot`. */
async function anchorRegistry(rpc: Rpc, payer: KeyPairSigner, programAddress: Address, registryId: string, merkleRoot: Uint8Array, manifestHash: Uint8Array) {
  const idHash = registryIdHash(registryId);
  const [config] = await findRegistryConfigPda(idHash, { programAddress });
  const [role] = await getProgramDerivedAddress({ programAddress, seeds: [new TextEncoder().encode("operator"), addressBytes(config), addressBytes(payer.address)] });
  // The program's utc_day is the calendar date as YYYYMMDD (onchain lib.rs utc_day), not days since epoch.
  const blockTime = await rpc.getBlockTime(await rpc.getSlot({ commitment: "confirmed" }).send()).send();
  const date = new Date(Number(blockTime) * 1_000);
  const dayUtc = date.getUTCFullYear() * 10_000 + (date.getUTCMonth() + 1) * 100 + date.getUTCDate();
  const [segment] = await findLedgerSegmentPda({ config, dayUtc, segmentIndex: 0 }, { programAddress });
  await send(rpc, payer, [
    getInitializeRegistryInstruction({ config, governance: payer, registryIdHash: idHash, emergencyAuthority: payer.address, schemaVersion: 1, hashAlgorithm: 1, treeAlgorithm: 1, anchorIntervalSeconds: 60, maxEntriesPerDay: 46 }, { programAddress }),
    getGrantOperatorInstruction({ config, role, operator: payer.address, governanceAuthority: payer, permissions: 0b11, validFrom: 0, validUntil: 0, keyIdHash: new Uint8Array(32) }, { programAddress }),
    getCreateLedgerSegmentInstruction({ config, role, operator: payer, segment, dayUtc, segmentIndex: 0, capacity: 46 }, { programAddress }),
  ]);
  const account = await rpc.getAccountInfo(config, { encoding: "base64", commitment: "finalized" }).send();
  const previousAnchorHash = getRegistryConfigDecoder().decode(Buffer.from(account.value!.data[0], "base64")).lastAnchorHash;
  const anchored = await send(rpc, payer, [getPublishAnchorInstruction({
    config, role, operator: payer, segment, batchSequence: 1n, registryVersion: 1n, sourceCursorStart: 0n, sourceCursorEnd: 1n,
    merkleRoot, manifestHash, snapshotHash: new Uint8Array(32), previousAnchorHash, leafCount: 1, schemaVersion: 1, flags: 0, hashAlgorithm: 1, treeAlgorithm: 1,
  }, { programAddress })]);
  return { config, segment, ...anchored };
}

function leafFor(registryId: string) {
  const recordFieldKey = new Uint8Array(32).fill(4);
  const fields = [{ path: "area", value: { type: "text", value: "1234.50" } as const }, { path: "status", value: { type: "text", value: "ACTIVE" } as const }];
  const fieldTree = buildFieldTree(recordFieldKey, fields);
  const recordId = new Uint8Array(32).fill(2);
  const leaf = batchLeafHash(recordCommitment(registryIdHash(registryId), recordId, 1n, fieldTree.root));
  return { recordFieldKey, fields, fieldTree, recordId, leaf };
}

function certificate(registryId: string, programAddress: Address, anchor: { segment: Address; signature: string; slot: bigint }, manifestHash: Uint8Array, issuerSeed: Uint8Array): SignedCertificate {
  const { recordFieldKey, fields, fieldTree, recordId, leaf } = leafFor(registryId);
  const body: CertificateBody = {
    certificateId: new Uint8Array(16).fill(1), registryId, issuedAt: new Date(Date.now() - 60_000).toISOString().replace(/\.\d{3}Z$/, "Z"),
    recordIdCommitment: recordId, recordVersion: 1n, schemaVersion: 1, disclosureMode: "FULL_RECORD",
    disclosedFields: Object.fromEntries(fields.map(field => [field.path, field.value])),
    fieldSalts: Object.fromEntries(fields.map(field => [field.path, fieldSalt(recordFieldKey, field.path)])),
    fieldRoot: fieldTree.root, fieldProofs: [],
    batchProof: { leafIndex: 0, leafHash: leaf, siblings: proof([leaf], 0), expectedRoot: leaf },
    anchor: {
      batchSequence: 1n, registryVersion: 1n, merkleRoot: leaf, manifestHash, solanaProgramId: addressBytes(programAddress),
      segmentIndex: 0, segmentPda: addressBytes(anchor.segment), transactionSignature: new Uint8Array(getBase58Encoder().encode(anchor.signature)), anchorSlot: anchor.slot,
    },
    issuerKeyId: "synthetic-issuer-1", issuerPublicKey: new Uint8Array(32),
  };
  return signCertificate(body, issuerSeed);
}

test("live local validator: trusted anchor verifies; foreign cluster, unpinned program, other registry config/ledger, unpinned issuer are rejected", { timeout: 240_000 }, async context => {
  try { await access(programSo); } catch { context.skip(`program not built: ${programSo}`); return; }
  const dir = await mkdtemp(join(tmpdir(), "onelayer-validator-"));
  context.after(() => rm(dir, { recursive: true, force: true }));
  const [rpcPort, faucetPort, gossipPort] = [await freePort(), await freePort(), await freePort()];
  const dynamicStart = 20_000 + Math.floor(Math.random() * 30_000);
  const validator = spawn("solana-test-validator", [
    "--reset", "--quiet", "--ledger", join(dir, "ledger"), "--bind-address", "127.0.0.1",
    "--rpc-port", String(rpcPort), "--faucet-port", String(faucetPort), "--gossip-port", String(gossipPort),
    "--dynamic-port-range", `${dynamicStart}-${dynamicStart + 50}`,
    "--bpf-program", ONELAYER_REGISTRY_PROGRAM_ADDRESS, programSo,
  ], { stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  validator.stderr.on("data", data => { stderr += String(data); });
  const spawnError = once(validator, "error").then(([error]) => { throw error; });
  context.after(async () => { if (validator.exitCode === null) { validator.kill("SIGINT"); await once(validator, "exit").catch(() => undefined); } });
  const rpcUrl = `http://127.0.0.1:${rpcPort}`;
  const rpc = createSolanaRpc(rpcUrl);
  await Promise.race([spawnError, until("validator health", async () => (await rpc.getHealth().send()) === "ok" ? true : undefined)])
    .catch(error => { throw new Error(`${(error as Error).message}\n${stderr}`); });

  const payer = await generateKeyPairSigner();
  await rpc.requestAirdrop(payer.address, lamports(10_000_000_000n)).send();
  await until("airdrop", async () => (await rpc.getBalance(payer.address, { commitment: "finalized" }).send()).value > 0n ? true : undefined);

  const program = address(ONELAYER_REGISTRY_PROGRAM_ADDRESS);
  const manifestHash = new Uint8Array(32).fill(3);
  // A second deployment of this binary under another address is impossible (Anchor
  // declare_id => DeclaredProgramIdMismatch); a foreign program needs its own build.
  const [trusted, otherRegistry] = await Promise.all([
    anchorRegistry(rpc, payer, program, REGISTRY, leafFor(REGISTRY).leaf, manifestHash),
    anchorRegistry(rpc, payer, program, OTHER_REGISTRY, leafFor(REGISTRY).leaf, manifestHash),
  ]);
  context.diagnostic(`anchored at slots ${trusted.slot}/${otherRegistry.slot}`);

  const issuerSeed = new Uint8Array(32).fill(0x31);
  const good = certificate(REGISTRY, program, trusted, manifestHash, issuerSeed);
  const genesisHash = await rpc.getGenesisHash().send();
  const policy: TrustPolicy = {
    version: 1, revision: 1, validUntil: "2099-01-01T00:00:00Z", genesisHash, registryId: REGISTRY,
    programIdHex: hex(addressBytes(program)), configPdaHex: hex(addressBytes(trusted.config)), schemaVersions: [1], registryVersions: ["1"],
    issuers: [{ keyId: "synthetic-issuer-1", publicKeyHex: hex(good.body.issuerPublicKey), algorithm: "Ed25519", validFrom: "2020-01-01T00:00:00Z", validUntil: "2099-01-01T00:00:00Z", revoked: false }],
  };
  const reader = new SolanaRpcChainReader(rpcUrl);
  const incidents: IncidentIndex = { async query(registryId) {
    return { registryId, indexedThroughSlot: BigInt(await rpc.getSlot({ commitment: "finalized" }).send()), incidents: [] };
  } };
  const run = (signed: SignedCertificate, trust: TrustPolicy = policy) => verifyCertificate(signed, reader, incidents, { trustPolicy: trust, maxIndexLagSlots: 1_000n });

  const ok = await run(good);
  assert.equal(ok.status, "VERIFIED", JSON.stringify(ok));
  assert.equal(ok.solanaSlot, trusted.slot.toString());

  assert.equal((await run(good, { ...policy, genesisHash: "11111111111111111111111111111111" })).code, "CLUSTER_UNTRUSTED");
  // Policy pinned to a different (real, program-owned) registry config account.
  assert.equal((await run(good, { ...policy, configPdaHex: hex(addressBytes(otherRegistry.config)) })).code, "REGISTRY_CONFIG_UNTRUSTED");
  // Same real anchor, certificate claims an unpinned program id (policy check precedes chain reads).
  const unpinnedProgram = (await generateKeyPairSigner()).address;
  assert.equal((await run(certificate(REGISTRY, unpinnedProgram, trusted, manifestHash, issuerSeed))).code, "PROGRAM_UNTRUSTED");
  // Policy trusting that program still fails closed: no program-owned config exists under it.
  assert.equal((await run(certificate(REGISTRY, unpinnedProgram, trusted, manifestHash, issuerSeed), { ...policy, programIdHex: hex(addressBytes(unpinnedProgram)) })).code, "REGISTRY_STATUS_UNAVAILABLE");
  // Real anchor of another registry's ledger presented as ours.
  assert.equal((await run(certificate(REGISTRY, program, otherRegistry, manifestHash, issuerSeed))).code, "LEDGER_REGISTRY_MISMATCH");
  // Re-signed by an unpinned issuer over the same real anchor.
  assert.equal((await run(certificate(REGISTRY, program, trusted, manifestHash, new Uint8Array(32).fill(0x32)))).code, "ISSUER_UNTRUSTED");
  // Pinned registry whose config account does not exist on this cluster fails closed.
  const absent = "synthetic.registry.absent";
  assert.equal((await run(certificate(absent, program, trusted, manifestHash, issuerSeed), { ...policy, registryId: absent })).code, "REGISTRY_STATUS_UNAVAILABLE");
});
