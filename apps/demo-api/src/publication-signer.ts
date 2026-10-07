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
  findLedgerSegmentPda,
  findRolePda,
  getPublishAnchorDiscriminatorBytes,
  getPublishAnchorInstructionDataDecoder,
  getPublishAnchorInstructionDataEncoder,
  type AnchorEntryV1,
} from "../../../packages/onchain-client/src/index.ts";
import { canonicalWorkflow } from "./registry-workflow.ts";
import { anchorEntryMismatch, attemptPlanHash, intentBytesHash, type PublicationIntent } from "./publication-intent.ts";
import { PublicationApprovalError, verifyPublicationApproval } from "./publication-approval.ts";
import { assertClusterLabel, expectedGenesisHash, PublicationIdentityError } from "./publication-identity.ts";
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
  /** Explicit deployment cluster. REQUIRED: the signer refuses to load a key
   * without one; there is no optional/unchecked cluster path (M4). */
  cluster: string;
  /** Pinned expected genesis hash; defaults to the known hash of `cluster`. */
  genesisHash?: string;
  /** Pinned Ed25519 public key (base58) of the trusted approval issuer (H5).
   * REQUIRED and must differ from the operator key; the signer refuses to load
   * a key without it, so no unapproved signature can ever be produced. */
  approvalPublicKey?: string;
  /** Clock seam for receipt expiry tests; defaults to the wall clock. */
  now?: () => Date;
}

export class LocalKeyPublicationSigner implements PublicationSigner {
  private readonly approvalPublicKey: string;
  private readonly genesisHash: string;
  private readonly now: () => Date;
  private constructor(
    readonly address: Address,
    private readonly privateKey: KeyObject,
    private readonly policy: PublicationSignerPolicy,
  ) {
    try {
      const cluster = assertClusterLabel(policy.cluster);
      this.genesisHash = expectedGenesisHash(cluster, policy.genesisHash);
    } catch (error) {
      if (error instanceof PublicationIdentityError) throw new PublicationSignerError("PUBLICATION_SIGNER_IDENTITY_UNCONFIGURED");
      throw error;
    }
    if (typeof policy.approvalPublicKey !== "string" || policy.approvalPublicKey.length === 0) {
      throw new PublicationSignerError("PUBLICATION_SIGNER_APPROVAL_KEY_REQUIRED");
    }
    if (policy.approvalPublicKey === String(address)) throw new PublicationSignerError("PUBLICATION_SIGNER_APPROVAL_KEY_REUSED");
    this.approvalPublicKey = policy.approvalPublicKey;
    this.now = policy.now ?? (() => new Date());
  }

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
    if (request.cluster !== this.policy.cluster) throw new PublicationSignerError("PUBLICATION_SIGNER_SCOPE");
    if (intentBytesHash(Buffer.from(canonicalWorkflow(intent), "utf8")) !== request.intentHash) {
      throw new PublicationSignerError("PUBLICATION_SIGNER_INTENT_MISMATCH");
    }
    // H5: the operator's approval must arrive as an independently signed receipt
    // verified against the separately pinned approval public key. The publisher
    // can compute matching plan hashes all it wants; without this receipt (or
    // with a self-minted one) the key is never used.
    if (request.approvalReceipt === undefined) throw new PublicationSignerError("PUBLICATION_SIGNER_APPROVAL_REQUIRED");
    try {
      verifyPublicationApproval(request.approvalReceipt, {
        operationId: request.operationId,
        intentHash: request.intentHash,
        attemptPlanHash: request.attemptPlanHash,
        approvalPublicKey: this.approvalPublicKey,
        cluster: this.policy.cluster,
        genesisHash: this.genesisHash,
        now: this.now,
      });
    } catch (error) {
      if (error instanceof PublicationApprovalError) throw new PublicationSignerError(error.code);
      throw new PublicationSignerError("PUBLICATION_SIGNER_APPROVAL_REQUIRED");
    }
    let transaction;
    try { transaction = getTransactionDecoder().decode(Buffer.from(request.transactionBase64, "base64")); }
    catch { throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID"); }
    const messageBytes = Buffer.from(transaction.messageBytes);
    if (messageBytes.toString("base64") !== request.messageBase64) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    for (const signature of Object.values(transaction.signatures)) {
      if (signature !== null && signature !== undefined) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    }
    try { await this.checkApprovedMessage(messageBytes, operator, request); }
    catch (error) {
      if (error instanceof PublicationSignerError) throw error;
      throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    }
    const signature = ed25519Sign(null, messageBytes, this.privateKey);
    const signed = { ...transaction, signatures: { ...transaction.signatures, [operator]: new Uint8Array(signature) } };
    return Buffer.from(getTransactionEncoder().encode(signed)).toString("base64");
  }

  private async checkApprovedMessage(messageBytes: Buffer, operator: string, request: SignRequest): Promise<void> {
    const intent = request.intent;
    const message: any = getCompiledTransactionMessageDecoder().decode(messageBytes);
    if (message.version !== 0 || (message.addressTableLookups ?? []).length > 0) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    // The signed message must carry exactly the reserved lifetime blockhash; a
    // stale or substituted blockhash is a different transaction and is refused.
    if (message.lifetimeToken !== request.blockhash) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    // Independently recompute the operator-approved per-attempt commitment from
    // the ACTUAL decoded message bytes plus the committed lifetime/plan fields
    // and refuse any mismatch. This binds the key to the approval, not merely to
    // the publisher's own request.
    const approved = attemptPlanHash({
      intentHash: request.intentHash, attemptNo: request.attemptNo, cluster: request.cluster,
      programId: intent.programId, configPda: intent.configPda, operator,
      registryId: intent.registryId, segmentPda: request.segmentPda, segmentIndex: request.segmentIndex,
      dayUtc: request.dayUtc, recentBlockhash: request.blockhash, lastValidBlockHeight: request.lastValidBlockHeight,
      feeLamports: request.feeLamports, feeLimitLamports: request.feeLimitLamports,
      messageBase64: messageBytes.toString("base64"),
    });
    if (approved !== request.attemptPlanHash) throw new PublicationSignerError("PUBLICATION_SIGNER_APPROVAL_MISMATCH");
    if (message.instructions.length !== 1) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    const keys: string[] = message.staticAccounts;
    // Exactly the fee payer, the four publish_anchor accounts and the program.
    // An extra static account is not part of any reserved attempt.
    if (keys.length !== 5 || new Set(keys).size !== keys.length) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    const [ix] = message.instructions;
    if (!Number.isInteger(ix.programAddressIndex) || keys[ix.programAddressIndex] !== intent.programId) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    if (keys[0] !== operator) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    const accounts: string[] = (ix.accountIndices ?? []).map((index: number) => keys[index]);
    // Independently derive the exact role and ledger PDAs the reserved intent
    // targets. A wrong or extra account, or wrong privileges, is refused here so
    // the key never signs a transaction the operator did not review.
    const [rolePda] = await findRolePda(
      { config: intent.configPda as Address, operator: operator as Address },
      { programAddress: intent.programId as Address },
    );
    const [segmentPda] = await findLedgerSegmentPda(
      { config: intent.configPda as Address, dayUtc: request.dayUtc, segmentIndex: request.segmentIndex },
      { programAddress: intent.programId as Address },
    );
    if (accounts.length !== 4
      || accounts[0] !== intent.configPda || accounts[1] !== String(rolePda)
      || accounts[2] !== operator || accounts[3] !== String(segmentPda)) {
      throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    }
    if (String(segmentPda) !== request.segmentPda) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    // Header/account privileges: exactly one signer (the fee payer, which Solana
    // always marks writable), config writable, role readonly, segment writable.
    // The IDL declares the operator readonly, but the fee-payer merge promotes
    // it to a writable signer in the compiled message; requiring readonly here
    // contradicted `keys[0] === keys[operatorIndex]` and refused every real
    // transaction the publisher builds.
    const header = message.header;
    if (header.numSignerAccounts !== 1 || header.numReadonlySignerAccounts !== 0) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    const total = message.staticAccounts.length;
    const role = (index: number): { signer: boolean; writable: boolean } => ({
      signer: index < header.numSignerAccounts,
      writable: index < header.numSignerAccounts - header.numReadonlySignerAccounts
        || (index >= header.numSignerAccounts && index < total - header.numReadonlyNonSignerAccounts),
    });
    const [configIndex, roleIndex, operatorIndex, segmentIndex] = ix.accountIndices as number[];
    const expected: Array<[number, { signer: boolean; writable: boolean }]> = [
      [configIndex, { signer: false, writable: true }],
      [roleIndex, { signer: false, writable: false }],
      [operatorIndex, { signer: true, writable: true }],
      [segmentIndex, { signer: false, writable: true }],
    ];
    if (keys[0] !== keys[operatorIndex] || !role(0).signer || !role(0).writable) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    for (const [index, want] of expected) {
      const got = role(index);
      if (got.signer !== want.signer || got.writable !== want.writable) throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    }
    const data = Uint8Array.from(ix.data ?? []);
    if (data.length < 8 || !Buffer.from(data.subarray(0, 8)).equals(Buffer.from(getPublishAnchorDiscriminatorBytes()))) {
      throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    }
    let decoded;
    try { decoded = getPublishAnchorInstructionDataDecoder().decode(data); }
    catch { throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID"); }
    // Re-encode and compare: a canonical decode that is shorter than the input
    // (trailing bytes, alternate encoding) is refused rather than signed.
    if (!Buffer.from(getPublishAnchorInstructionDataEncoder().encode(decoded)).equals(Buffer.from(data))) {
      throw new PublicationSignerError("PUBLICATION_SIGNER_TRANSACTION_INVALID");
    }
    const mismatch = anchorEntryMismatch(intent, { ...decoded, operator, pad0: new Uint8Array(0), publishedAt: 0n } as unknown as AnchorEntryV1);
    if (mismatch !== null) throw new PublicationSignerError("PUBLICATION_SIGNER_INTENT_MISMATCH");
  }
}
