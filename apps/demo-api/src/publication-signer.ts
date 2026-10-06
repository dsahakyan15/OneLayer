// Lab signer adapter for the workflow publication runtime.
//
// Boundary contract: the publisher reserves the exact publish-anchor message
// bytes in its durable journal and asks this adapter to sign only those bytes.
// The adapter independently re-checks that the transaction is a single
// publish_anchor instruction for this deployment's registry, program and config
// PDA, that it belongs to the configured operator, and that its instruction
// data matches every intent field before touching the private key. The key is
// read from the hardened demo key store and never leaves this module.
//
// This is an explicitly local, software lab signer. Production signer isolation
// and custody remain open (tickets 16/22); this module does not claim them.
import { sign as ed25519Sign, type KeyObject } from "node:crypto";
import {
  getAddressEncoder,
  getCompiledTransactionMessageDecoder,
  getTransactionDecoder,
  getTransactionEncoder,
  type Address,
} from "@solana/kit";
import {
  getPublishAnchorDiscriminatorBytes,
  getPublishAnchorInstructionDataDecoder,
  type AnchorEntryV1,
} from "../../../packages/onchain-client/src/index.ts";
import { canonicalWorkflow } from "./registry-workflow.ts";
import { anchorEntryMismatch, intentBytesHash, type PublicationIntent } from "./publication-intent.ts";
import type { PublicationSigner, SignRequest } from "./publication-worker.ts";
import { loadSigningKey, type KeyStoreOptions } from "../scripts/live-demo-key-store.ts";

export class PublicationSignerError extends Error {
  readonly code: string;
  constructor(code: string) { super(code); this.code = code; }
}

export interface PublicationSignerPolicy {
  registryId: string;
  programId: string;
  configPda: string;
}

export class LocalKeyPublicationSigner implements PublicationSigner {
  private constructor(
    readonly address: Address,
    private readonly privateKey: KeyObject,
    private readonly policy: PublicationSignerPolicy,
  ) {}

  /** Loads the operator key once; the imported KeyObject stays in this process. */
  static async create(keyFile: string, policy: PublicationSignerPolicy, options: KeyStoreOptions = {}): Promise<LocalKeyPublicationSigner> {
    let loaded;
    try { loaded = await loadSigningKey(keyFile, options); }
    catch { throw new PublicationSignerError("PUBLICATION_SIGNER_KEY_UNAVAILABLE"); }
    return new LocalKeyPublicationSigner(loaded.address, loaded.privateKey, policy);
  }

  async signTransaction(request: SignRequest): Promise<string> {
    const intent = request.intent;
    if (intent.registryId !== this.policy.registryId || intent.programId !== this.policy.programId || intent.configPda !== this.policy.configPda) {
      throw new PublicationSignerError("PUBLICATION_SIGNER_SCOPE");
    }
    const operator = String(this.address);
    if (intent.operator !== operator) throw new PublicationSignerError("PUBLICATION_SIGNER_MISMATCH");
    if (intentBytesHash(Buffer.from(canonicalWorkflow(intent), "utf8")) !== request.intentHash) {
      throw new PublicationSignerError("PUBLICATION_SIGNER_INTENT_MISMATCH");
    }
    let transaction;
    try { transaction = getTransactionDecoder().decode(Buffer.from(request.transactionBase64, "base64")); }
    catch { throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID"); }
    const messageBytes = Buffer.from(transaction.messageBytes);
    if (messageBytes.toString("base64") !== request.messageBase64) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    for (const signature of Object.values(transaction.signatures)) {
      if (signature !== null && signature !== undefined) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    }
    try { this.checkApprovedMessage(messageBytes, operator, intent); }
    catch (error) {
      if (error instanceof PublicationSignerError) throw error;
      throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    }
    const signature = ed25519Sign(null, messageBytes, this.privateKey);
    const signed = { ...transaction, signatures: { ...transaction.signatures, [operator]: new Uint8Array(signature) } };
    return Buffer.from(getTransactionEncoder().encode(signed)).toString("base64");
  }

  private checkApprovedMessage(messageBytes: Buffer, operator: string, intent: PublicationIntent): void {
    const message: any = getCompiledTransactionMessageDecoder().decode(messageBytes);
    if (message.version !== 0 || (message.addressTableLookups ?? []).length > 0) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    if (message.instructions.length !== 1) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    const keys: string[] = message.staticAccounts;
    const [ix] = message.instructions;
    if (keys[0] !== operator || keys[ix.programAddressIndex] !== intent.programId) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    const accounts: string[] = (ix.accountIndices ?? []).map((index: number) => keys[index]);
    // The role PDA is a pure function of config + operator and the segment PDA
    // is proven on landing by the publisher; the adapter enforces the deployment
    // accounts and the full intent field commitment below.
    if (accounts.length !== 4 || accounts[0] !== intent.configPda || accounts[2] !== operator) {
      throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    }
    const data = Uint8Array.from(ix.data ?? []);
    if (data.length < 8 || !Buffer.from(data.subarray(0, 8)).equals(Buffer.from(getPublishAnchorDiscriminatorBytes()))) {
      throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    }
    const decoded = getPublishAnchorInstructionDataDecoder().decode(data);
    const mismatch = anchorEntryMismatch(intent, { ...decoded, operator, pad0: new Uint8Array(0), publishedAt: 0n } as unknown as AnchorEntryV1);
    if (mismatch !== null) throw new PublicationSignerError("PUBLICATION_SIGNER_INTENT_MISMATCH");
  }
}
