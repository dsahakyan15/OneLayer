// Preparation, review payload and post-signature validation of the devnet
// anchor transaction (OL-C-23, OL-C-24, OL-C-33).
//
// The browser signs exactly the bytes prepared here. Before broadcast the
// backend re-decodes the signed wire transaction and requires byte-identical
// message bytes plus a valid operator signature — a wallet that returns a
// different transaction is rejected instead of published.
import { createPublicKey, verify as ed25519Verify } from "node:crypto";
import {
  appendTransactionMessageInstruction,
  compileTransaction,
  createNoopSigner,
  createTransactionMessage,
  getAddressEncoder,
  getBase58Decoder,
  getTransactionDecoder,
  getTransactionEncoder,
  pipe,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  type Address,
  type Blockhash,
} from "@solana/kit";
import { getPublishAnchorInstruction } from "../../../packages/onchain-client/src/index.ts";

export interface AnchorTransactionInput {
  programId: Address;
  configPda: Address;
  rolePda: Address;
  segmentPda: Address;
  operator: Address;
  blockhash: string;
  lastValidBlockHeight: bigint;
  batchSequence: bigint;
  registryVersion: bigint;
  cursorStart: bigint;
  cursorEnd: bigint;
  merkleRoot: Uint8Array;
  manifestHash: Uint8Array;
  previousAnchorHash: Uint8Array;
  leafCount: number;
  schemaVersion: number;
  hashAlgorithm: number;
  treeAlgorithm: number;
}

export interface AccountReview {
  address: string;
  role: "signer-writable" | "signer" | "writable" | "readonly";
}

export interface PreparedTransaction {
  transactionBase64: string;
  messageBase64: string;
  accounts: AccountReview[];
  instructionDataBase64: string;
}

function accountRole(role: number): AccountReview["role"] {
  // Kit's AccountRole bit flags: 0b01 writable, 0b10 signer.
  const writable = (role & 0b01) !== 0;
  const signer = (role & 0b10) !== 0;
  if (signer && writable) return "signer-writable";
  if (signer) return "signer";
  return writable ? "writable" : "readonly";
}

export function prepareAnchorTransaction(input: AnchorTransactionInput): PreparedTransaction {
  const operator = createNoopSigner(input.operator);
  const instruction = getPublishAnchorInstruction(
    {
      config: input.configPda,
      role: input.rolePda,
      operator,
      segment: input.segmentPda,
      batchSequence: input.batchSequence,
      registryVersion: input.registryVersion,
      sourceCursorStart: input.cursorStart,
      sourceCursorEnd: input.cursorEnd,
      merkleRoot: input.merkleRoot,
      manifestHash: input.manifestHash,
      snapshotHash: new Uint8Array(32),
      previousAnchorHash: input.previousAnchorHash,
      leafCount: input.leafCount,
      schemaVersion: input.schemaVersion,
      flags: 0,
      hashAlgorithm: input.hashAlgorithm,
      treeAlgorithm: input.treeAlgorithm,
    },
    { programAddress: input.programId },
  );
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (draft) => setTransactionMessageFeePayerSigner(operator, draft),
    (draft) => setTransactionMessageLifetimeUsingBlockhash(
      { blockhash: input.blockhash as Blockhash, lastValidBlockHeight: input.lastValidBlockHeight },
      draft,
    ),
    (draft) => appendTransactionMessageInstruction(instruction, draft),
  );
  const transaction = compileTransaction(message);
  return {
    transactionBase64: Buffer.from(getTransactionEncoder().encode(transaction)).toString("base64"),
    messageBase64: Buffer.from(transaction.messageBytes).toString("base64"),
    accounts: instruction.accounts.map((account) => ({
      address: account.address,
      role: accountRole(account.role),
    })),
    instructionDataBase64: Buffer.from(instruction.data).toString("base64"),
  };
}

export class SignedTransactionError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

/**
 * Checks a wallet response against the stored intent and returns the base58
 * transaction signature. Every failure is a refusal to broadcast.
 */
export function validateSignedTransaction(
  signedBase64: string,
  expectedMessageBase64: string,
  operator: Address,
): string {
  let decoded;
  try {
    decoded = getTransactionDecoder().decode(Buffer.from(signedBase64, "base64"));
  } catch {
    throw new SignedTransactionError("SIGNED_TRANSACTION_MALFORMED");
  }
  const messageBytes = Buffer.from(decoded.messageBytes);
  if (messageBytes.toString("base64") !== expectedMessageBase64) {
    throw new SignedTransactionError("SIGNED_TRANSACTION_MESSAGE_MISMATCH");
  }
  const signature = decoded.signatures[operator];
  if (signature === undefined || signature === null) {
    throw new SignedTransactionError("SIGNED_TRANSACTION_UNSIGNED");
  }
  const publicKey = createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(getAddressEncoder().encode(operator)),
    ]),
    format: "der",
    type: "spki",
  });
  if (!ed25519Verify(null, messageBytes, publicKey, Buffer.from(signature))) {
    throw new SignedTransactionError("SIGNED_TRANSACTION_SIGNATURE_INVALID");
  }
  return getBase58Decoder().decode(signature);
}
