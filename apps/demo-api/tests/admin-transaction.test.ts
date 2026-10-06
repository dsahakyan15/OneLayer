import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, sign as ed25519Sign } from "node:crypto";
import { test } from "node:test";
import {
  getAddressDecoder,
  getTransactionDecoder,
  getTransactionEncoder,
  type Address,
} from "@solana/kit";
import {
  prepareAnchorTransaction,
  SignedTransactionError,
  validateSignedTransaction,
  type AnchorTransactionInput,
} from "../src/admin-transaction.ts";
import { findLedgerSegmentPda, findRegistryConfigPda, findRolePda } from "../../../packages/onchain-client/src/index.ts";
import { registryIdHash } from "../../../packages/canonical-ts/src/index.ts";

const PROGRAM_ID = "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo" as Address;
const operatorSecret = new Uint8Array(32).fill(3);

function operatorKeys(): { address: Address; privateKey: ReturnType<typeof createPrivateKey> } {
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(operatorSecret)]),
    format: "der",
    type: "pkcs8",
  });
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const raw = new Uint8Array(publicDer).slice(-32);
  return { address: getAddressDecoder().decode(raw), privateKey };
}

async function input(): Promise<AnchorTransactionInput> {
  const [configPda] = await findRegistryConfigPda(registryIdHash("gov.registry.land"), { programAddress: PROGRAM_ID });
  const { address } = operatorKeys();
  const [rolePda] = await findRolePda({ config: configPda, operator: address }, { programAddress: PROGRAM_ID });
  const [segmentPda] = await findLedgerSegmentPda(
    { config: configPda, dayUtc: 20_665, segmentIndex: 0 },
    { programAddress: PROGRAM_ID },
  );
  return {
    programId: PROGRAM_ID,
    configPda,
    rolePda,
    segmentPda,
    operator: address,
    blockhash: "11111111111111111111111111111111",
    lastValidBlockHeight: 1_000n,
    batchSequence: 1n,
    registryVersion: 1n,
    cursorStart: 1n,
    cursorEnd: 2n,
    merkleRoot: new Uint8Array(32).fill(0xaa),
    manifestHash: new Uint8Array(32).fill(0xbb),
    previousAnchorHash: new Uint8Array(32).fill(0xcc),
    leafCount: 2,
    schemaVersion: 1,
    hashAlgorithm: 1,
    treeAlgorithm: 1,
  };
}

function walletSign(transactionBase64: string): string {
  const { privateKey, address } = operatorKeys();
  const transaction = getTransactionDecoder().decode(Buffer.from(transactionBase64, "base64"));
  const signature = ed25519Sign(null, Buffer.from(transaction.messageBytes), privateKey);
  const signed = {
    ...transaction,
    signatures: { ...transaction.signatures, [address]: new Uint8Array(signature) },
  };
  return Buffer.from(getTransactionEncoder().encode(signed)).toString("base64");
}

test("the prepared transaction exposes every account with its signer and writable flags", async () => {
  const prepared = prepareAnchorTransaction(await input());
  assert.equal(prepared.accounts.length, 4);
  assert.deepEqual(
    prepared.accounts.map((account) => account.role),
    ["writable", "readonly", "signer", "writable"],
  );
  assert.equal(Buffer.from(prepared.instructionDataBase64, "base64").length, 8 + 32 + 128 + 4 + 4 + 2);
  assert.ok(prepared.messageBase64.length > 0);
});

test("preparation is deterministic for the same intent", async () => {
  const parameters = await input();
  assert.equal(
    prepareAnchorTransaction(parameters).messageBase64,
    prepareAnchorTransaction(parameters).messageBase64,
  );
});

test("a wallet signature over the prepared bytes is accepted", async () => {
  const prepared = prepareAnchorTransaction(await input());
  const signature = validateSignedTransaction(
    walletSign(prepared.transactionBase64),
    prepared.messageBase64,
    operatorKeys().address,
  );
  assert.match(signature, /^[1-9A-HJ-NP-Za-km-z]{80,90}$/);
});

test("a wallet that returns different message bytes is refused", async () => {
  const prepared = prepareAnchorTransaction(await input());
  const other = prepareAnchorTransaction({ ...(await input()), batchSequence: 2n });
  assert.throws(
    () => validateSignedTransaction(walletSign(other.transactionBase64), prepared.messageBase64, operatorKeys().address),
    (error: SignedTransactionError) => error.code === "SIGNED_TRANSACTION_MESSAGE_MISMATCH",
  );
});

test("an unsigned or malformed response never reaches broadcast", async () => {
  const prepared = prepareAnchorTransaction(await input());
  assert.throws(
    () => validateSignedTransaction(prepared.transactionBase64, prepared.messageBase64, operatorKeys().address),
    (error: SignedTransactionError) => error.code === "SIGNED_TRANSACTION_UNSIGNED",
  );
  assert.throws(
    () => validateSignedTransaction("not-base64!!", prepared.messageBase64, operatorKeys().address),
    (error: SignedTransactionError) => error.code === "SIGNED_TRANSACTION_MALFORMED",
  );
});

test("a signature made by another key is refused", async () => {
  const prepared = prepareAnchorTransaction(await input());
  const foreign = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 9)]),
    format: "der",
    type: "pkcs8",
  });
  const transaction = getTransactionDecoder().decode(Buffer.from(prepared.transactionBase64, "base64"));
  const signed = {
    ...transaction,
    signatures: {
      ...transaction.signatures,
      [operatorKeys().address]: new Uint8Array(ed25519Sign(null, Buffer.from(transaction.messageBytes), foreign)),
    },
  };
  assert.throws(
    () => validateSignedTransaction(
      Buffer.from(getTransactionEncoder().encode(signed)).toString("base64"),
      prepared.messageBase64,
      operatorKeys().address,
    ),
    (error: SignedTransactionError) => error.code === "SIGNED_TRANSACTION_SIGNATURE_INVALID",
  );
});
