// Ticket 09 review: the lab signer must actually sign the one real transaction
// the publisher reserves (B1) and refuse every tampered variant. The first test
// is negative-only; the second builds the exact `prepareAnchorTransaction`
// message for a real allowed key and verifies the returned signature
// cryptographically, then tampers with each guard. H5: signing also requires an
// independently issued approval receipt verified against a pinned approval key.
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { address, type Address } from "@solana/kit";
import { findLedgerSegmentPda, findRegistryConfigPda, findRolePda } from "../../../packages/onchain-client/src/index.ts";
import { registryIdHash } from "../../../packages/canonical-ts/src/index.ts";
import { prepareAnchorTransaction, validateSignedTransaction } from "../src/admin-transaction.ts";
import { attemptPlanHash, buildPublicationIntent, type PublicationKeys } from "../src/publication-intent.ts";
import { workflowHash } from "../src/registry-workflow.ts";
import { PublicationApprovalIssuer } from "../src/publication-approval.ts";
import { LocalKeyPublicationSigner, PublicationSignerError } from "../src/publication-signer.ts";
import type { SignRequest } from "../src/publication-worker.ts";
import { defaultKeyFile, ensureKeyPair } from "../scripts/live-demo-key-store.ts";

const PROGRAM_ID = "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo";
const CONFIG = "11111111111111111111111111111111";
const CLUSTER = "solana:synthetic";
const GENESIS = "1".repeat(32);
const OPERATION_ID = "22222222-2222-2222-2222-222222222222";

async function approvalIssuer(home: string) {
  const keyFile = join(home, ".local", "state", "onelayer-devnet-demo", "keys", "approval-issuer.json");
  await ensureKeyPair({ home, keyFile });
  return PublicationApprovalIssuer.create(keyFile, { cluster: CLUSTER, genesisHash: GENESIS }, { home });
}

test("lab signer refuses out-of-scope and unapproved requests before signing", async () => {
  const home = await mkdtemp(join(tmpdir(), "onelayer-signer-"));
  try {
    const created = await ensureKeyPair({ home });
    const approvals = await approvalIssuer(home);
    const signer = await LocalKeyPublicationSigner.create(defaultKeyFile({ home }), {
      registryId: "gov.registry.land", programId: PROGRAM_ID, configPda: CONFIG,
      cluster: CLUSTER, genesisHash: GENESIS, approvalPublicKey: approvals.publicKey,
    }, { home });
    assert.equal(String(signer.address), created.address);
    const base = {
      transactionBase64: "", messageBase64: "", intentHash: "00".repeat(32), simulation: { ok: true, error: null, logs: [], unitsConsumed: 1 },
      operationId: OPERATION_ID, segmentPda: CONFIG, segmentIndex: 0, dayUtc: 20260924, blockhash: CONFIG, cluster: CLUSTER,
      intent: { registryId: "gov.registry.land", programId: PROGRAM_ID, configPda: CONFIG, operator: created.address, operatorKeyId: "demo" },
    } as unknown as SignRequest;

    await assert.rejects(signer.signTransaction({ ...base, intent: { ...base.intent, registryId: "other.registry" } }), (error: { code?: string }) => error.code === "PUBLICATION_SIGNER_SCOPE");
    await assert.rejects(signer.signTransaction({ ...base, intent: { ...base.intent, programId: CONFIG } }), (error: { code?: string }) => error.code === "PUBLICATION_SIGNER_SCOPE");
    await assert.rejects(signer.signTransaction({ ...base, intent: { ...base.intent, operator: CONFIG } }), (error: { code?: string }) => error.code === "PUBLICATION_SIGNER_MISMATCH");
    // Scope and operator match, but the recomputed intent hash does not.
    await assert.rejects(signer.signTransaction(base), (error: { code?: string }) => error.code === "PUBLICATION_SIGNER_INTENT_MISMATCH");

    // A signer cannot even load a key without a pinned, distinct approval key.
    await assert.rejects(
      LocalKeyPublicationSigner.create(defaultKeyFile({ home }), { registryId: "gov.registry.land", programId: PROGRAM_ID, configPda: CONFIG, cluster: CLUSTER, genesisHash: GENESIS }, { home }),
      (error: { code?: string }) => error.code === "PUBLICATION_SIGNER_APPROVAL_KEY_REQUIRED",
    );
    await assert.rejects(
      LocalKeyPublicationSigner.create(defaultKeyFile({ home }), { registryId: "gov.registry.land", programId: PROGRAM_ID, configPda: CONFIG, cluster: CLUSTER, genesisHash: GENESIS, approvalPublicKey: created.address }, { home }),
      (error: { code?: string }) => error.code === "PUBLICATION_SIGNER_APPROVAL_KEY_REUSED",
    );
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test("lab signer signs the exact reserved publish transaction and refuses every tampered guard", async () => {
  const home = await mkdtemp(join(tmpdir(), "onelayer-signer-positive-"));
  try {
    const created = await ensureKeyPair({ home });
    const approvals = await approvalIssuer(home);
    const operator = created.address as Address;
    const registryId = "demo.synthetic.onelayer";
    const keys: PublicationKeys = { idKey: new Uint8Array(32).fill(7), fieldKeyMaster: new Uint8Array(32).fill(8) };
    const [configPda] = await findRegistryConfigPda(registryIdHash(registryId), { programAddress: PROGRAM_ID as Address });
    const [rolePda] = await findRolePda({ config: configPda, operator }, { programAddress: PROGRAM_ID as Address });
    const dayUtc = 20261006;
    const [segmentPda] = await findLedgerSegmentPda({ config: configPda, dayUtc, segmentIndex: 0 }, { programAddress: PROGRAM_ID as Address });
    const payload = { name: "Ada", amount: 42 };
    const item = { eventId: "11111111-1111-1111-1111-111111111111", recordId: "R-1", version: 1, operation: "upsert" as const, payload, payloadHash: workflowHash({ operation: "upsert", payload }) };
    const encoded = buildPublicationIntent([item], {
      operationId: OPERATION_ID, registryId, programId: PROGRAM_ID, configPda: String(configPda),
      operator: String(operator), operatorKeyId: "demo-operator-1", batchSequence: 1n, registryVersion: 1n,
      previousAnchorHashHex: "00".repeat(32), publishedBefore: 0n, createdAt: "2026-10-06T12:00:00Z",
      schemaVersion: 1, hashAlgorithm: 1, treeAlgorithm: 1,
    }, keys);
    const blockhash = CONFIG;
    const cluster = CLUSTER;
    const feeLamports = "5000";
    const feeLimitLamports = "100000";
    const planFor = (messageBase64: string) => attemptPlanHash({
      intentHash: encoded.hash, attemptNo: 1, cluster, programId: PROGRAM_ID, configPda: String(configPda),
      operator: String(operator), registryId, segmentPda: String(segmentPda), segmentIndex: 0, dayUtc,
      recentBlockhash: blockhash, lastValidBlockHeight: "100", feeLamports, feeLimitLamports, messageBase64,
    });
    const receiptFor = (attemptPlanHash: string) =>
      approvals.issue({ operationId: OPERATION_ID, intentHash: encoded.hash, attemptPlanHash }, "synthetic-approver", "synthetic-device");
    const prepare = (overrides: { rolePda?: Address; merkleRoot?: Uint8Array; operator?: Address } = {}) => prepareAnchorTransaction({
      programId: PROGRAM_ID as Address, configPda, rolePda: overrides.rolePda ?? rolePda, segmentPda,
      operator: overrides.operator ?? operator, blockhash, lastValidBlockHeight: 100n,
      batchSequence: 1n, registryVersion: 1n, cursorStart: 1n, cursorEnd: 1n,
      merkleRoot: overrides.merkleRoot ?? Buffer.from(encoded.intent.merkleRoot, "hex"),
      manifestHash: Buffer.from(encoded.intent.manifestHash, "hex"),
      previousAnchorHash: Buffer.from(encoded.intent.previousAnchorHash, "hex"), leafCount: 1,
      schemaVersion: 1, hashAlgorithm: 1, treeAlgorithm: 1,
    });
    const prepared = prepare();
    const signer = await LocalKeyPublicationSigner.create(defaultKeyFile({ home }), {
      registryId, programId: PROGRAM_ID, configPda: String(configPda),
      cluster, genesisHash: GENESIS, approvalPublicKey: approvals.publicKey,
    }, { home });
    const base = {
      transactionBase64: prepared.transactionBase64, messageBase64: prepared.messageBase64,
      intentHash: encoded.hash, operationId: OPERATION_ID, intent: encoded.intent, simulation: { ok: true, error: null, logs: [], unitsConsumed: 1 },
      segmentPda: String(segmentPda), segmentIndex: 0, dayUtc, blockhash,
      lastValidBlockHeight: "100", attemptNo: 1, cluster, feeLamports, feeLimitLamports,
      attemptPlanHash: planFor(prepared.messageBase64),
      approvalReceipt: receiptFor(planFor(prepared.messageBase64)),
    } as SignRequest;
    const refused = async (request: SignRequest, code = "PUBLICATION_SIGNER_TRANSACTION_INVALID") =>
      assert.rejects(signer.signTransaction(request), (error: unknown) => error instanceof PublicationSignerError && error.code === code);

    // The unsigned reservation is not accepted as a signed transaction...
    assert.throws(() => validateSignedTransaction(prepared.transactionBase64, prepared.messageBase64, operator), /SIGNED_TRANSACTION_UNSIGNED/);
    // ...and the positive path signs the exact reserved bytes with the real key.
    const signed = await signer.signTransaction(base);
    assert.equal(validateSignedTransaction(signed, prepared.messageBase64, operator).length > 0, true);

    // H5: no receipt, or a self-generated matching plan without a receipt, is refused.
    await refused({ ...base, approvalReceipt: undefined as unknown as SignRequest["approvalReceipt"] }, "PUBLICATION_SIGNER_APPROVAL_REQUIRED");
    // A pre-signed transaction is never re-signed into a second signature.
    await refused({ ...base, transactionBase64: signed });
    // A different message than the reserved one is refused.
    await refused({ ...base, messageBase64: prepare({ merkleRoot: Buffer.alloc(32, 9) }).messageBase64 });
    // The lifetime blockhash is bound to the reserved attempt.
    await refused({ ...base, blockhash: "So11111111111111111111111111111111111111112" });
    // H5: the receipt binds the plan hash. A swapped plan hash is refused by the
    // receipt verifier before the self-consistency check runs.
    await refused({ ...base, attemptPlanHash: "00".repeat(32) }, "PUBLICATION_APPROVAL_MISMATCH");
    // Fields committed by the plan hash, changed without re-approval, are
    // refused by the independent recomputation.
    await refused({ ...base, feeLamports: "6000" }, "PUBLICATION_SIGNER_APPROVAL_MISMATCH");
    await refused({ ...base, cluster: "solana:devnet" }, "PUBLICATION_SIGNER_SCOPE");
    await refused({ ...base, attemptNo: 2 }, "PUBLICATION_SIGNER_APPROVAL_MISMATCH");
    await refused({ ...base, lastValidBlockHeight: "101" }, "PUBLICATION_SIGNER_APPROVAL_MISMATCH");
    // Ledger destination: segment PDA, index and day are committed by the plan.
    await refused({ ...base, segmentPda: String(configPda) }, "PUBLICATION_SIGNER_APPROVAL_MISMATCH");
    await refused({ ...base, segmentIndex: 1 }, "PUBLICATION_SIGNER_APPROVAL_MISMATCH");
    await refused({ ...base, dayUtc: dayUtc + 1 }, "PUBLICATION_SIGNER_APPROVAL_MISMATCH");
    // Every instruction field is committed: a transaction whose merkle root
    // differs from the approved intent decodes and re-encodes, but no longer
    // matches the intent (the plan hash is recomputed for the new message so the
    // deeper intent guard is what refuses it).
    const otherRoot = prepare({ merkleRoot: Buffer.alloc(32, 9) });
    await refused({ ...base, ...otherRoot, attemptPlanHash: planFor(otherRoot.messageBase64), approvalReceipt: receiptFor(planFor(otherRoot.messageBase64)) }, "PUBLICATION_SIGNER_INTENT_MISMATCH");
    // The role PDA and the operator account must be the exact derived ones.
    const [otherRole] = await findRolePda({ config: configPda, operator: address(CONFIG) }, { programAddress: PROGRAM_ID as Address });
    const otherRoleTx = prepare({ rolePda: otherRole });
    await refused({ ...base, ...otherRoleTx, attemptPlanHash: planFor(otherRoleTx.messageBase64), approvalReceipt: receiptFor(planFor(otherRoleTx.messageBase64)) });
    const otherOpTx = prepare({ operator: address(CONFIG) });
    await refused({ ...base, ...otherOpTx, attemptPlanHash: planFor(otherOpTx.messageBase64), approvalReceipt: receiptFor(planFor(otherOpTx.messageBase64)) });

    // A deployment cluster policy is enforced independently of the plan hash.
    const devnetSigner = await LocalKeyPublicationSigner.create(defaultKeyFile({ home }), {
      registryId, programId: PROGRAM_ID, configPda: String(configPda), cluster: "solana:devnet", approvalPublicKey: approvals.publicKey,
    }, { home });
    await assert.rejects(devnetSigner.signTransaction(base), (error: unknown) => error instanceof PublicationSignerError && error.code === "PUBLICATION_SIGNER_SCOPE");
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
