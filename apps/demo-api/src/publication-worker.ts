// Durable workflow publisher (ticket 09): intent -> fenced attempt journal ->
// send -> reconciliation -> trusted finalized completion, plus two-person
// maintenance procedures for operations that cannot complete normally.
//
// Internal worker interface only; there is no HTTP route and no method that
// marks an operation FINALIZED on request. FINALIZED is written only by
// `complete()`, after either (a) a finalized successful status of a journaled
// signature, or (b) when status history is unavailable, a finalized ledger
// entry in the segment of exactly one journaled signed attempt that agrees
// with the stored intent on every field `anchorEntryMismatch` compares (the
// manifest hash commits the operation ID through `leavesObjectUri`, and the
// entry's operator is our signer). In both cases the recomputed anchor hash is
// cross-checked with program state where observable.
//
// Journal guarantees (and limits):
// - intent bytes/hash are durable before any attempt; attempts reference them;
// - an attempt's message bytes are reserved (PREPARED) before the signer is
//   asked, and the signer only ever sees reserved bytes; signed bytes and
//   signature are durable (SIGNED) before send; only journaled bytes are sent;
// - every journal write re-checks the caller's current fence under a row lock
//   and compares the attempt's expected state (compare-and-set);
// - a new attempt is created only after every earlier attempt reached
//   CANCELLED (never signed), FAILED (finalized with an error) or EXPIRED.
//   EXPIRED is a judgement from RPC data, not a proof; before any new attempt
//   our signatures are searched and the registry/ledger state is re-read, and
//   a landing found then completes the operation from EXPIRED.
// - steps of one operation are serialized by a transaction-scoped advisory
//   lock held on a dedicated connection for the whole step (two connections
//   per step; compatible with PgBouncer transaction pooling because the lock
//   lives inside one open transaction; `idle_in_transaction_session_timeout`
//   must exceed the longest step, including signer approval).
import { createHash, randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { getCompiledTransactionMessageDecoder, getTransactionDecoder, getTransactionEncoder, getAddressEncoder, type Address } from "@solana/kit";
import { anchorHash, registryIdHash, toHex } from "../../../packages/canonical-ts/src/index.ts";
import {
  findLedgerSegmentPda,
  findRegistryConfigPda,
  findRolePda,
  getPublishAnchorDiscriminatorBytes,
  getPublishAnchorInstructionDataDecoder,
  type AnchorEntryV1,
  type RegistryConfig,
} from "../../../packages/onchain-client/src/index.ts";
import { prepareAnchorTransaction, SignedTransactionError, validateSignedTransaction } from "./admin-transaction.ts";
import { ledgerDay } from "./ledger-day.ts";
import {
  anchorEntryMismatch,
  attemptPlanHash,
  buildPublicationIntent,
  PublicationIntentError,
  verifyStoredIntent,
  workflowFields,
  type AttemptPlanCommitment,
  type PublicationIntent,
  type PublicationKeys,
} from "./publication-intent.ts";
import {
  PublicationApprovalError,
  publicationApprovalReceiptHash,
  verifyPublicationApproval,
  type PublicationApprovalReceipt,
  type PublicationApprovalVerifierPolicy,
} from "./publication-approval.ts";
import { assertClusterLabel, expectedGenesisHash, PublicationIdentityError } from "./publication-identity.ts";
import type { ArchivalChain, PublicationChain, SignatureStatus } from "./publication-rpc.ts";
import { canonicalWorkflow, workflowTransaction } from "./registry-workflow.ts";
import type { SimulationResult } from "./solana-rpc.ts";
import {
  assertPublicationLease,
  journal,
  lockRegistryPublication,
  PublicationError,
  WorkflowPublicationStore,
  type PublicationItem,
  type PublicationLease,
} from "./workflow-publication.ts";

export { ledgerDay } from "./ledger-day.ts";

/** Domain of the archival evidence hash (0017 recomputes it). */
export const ARCHIVAL_CHECK_DOMAIN = "ONELAYER:WORKFLOW:ARCHIVAL-CHECK:V1";
const ARCHIVAL_RULE = "ADR-0009: absent only if archive history covers the reservation slot, the archive reached the chain slot, and the blockhash expired by finalized height at that slot";
export type { ArchivalChain, PublicationChain } from "./publication-rpc.ts";

export interface SignRequest {
  /** Unsigned wire transaction built from the reserved message bytes. */
  transactionBase64: string;
  messageBase64: string;
  intentHash: string;
  /** Operation whose reserved attempt is being signed (bound by the receipt). */
  operationId: string;
  intent: PublicationIntent;
  simulation: SimulationResult;
  /** Reserved ledger destination; the signer re-derives both PDAs and checks
   * that the message accounts equal them before signing. */
  segmentPda: string;
  segmentIndex: number;
  dayUtc: number;
  /** Reserved lifetime blockhash (last_valid_block_height is enforced by the
   * publisher before it ever asks for a signature). */
  blockhash: string;
  lastValidBlockHeight: string;
  /** Attempt/plan identity the operator approved (H3). */
  attemptNo: number;
  cluster: string;
  /** Quoted fee and its bounded constraint, both committed by the plan hash. */
  feeLamports: string;
  feeLimitLamports: string;
  /** The operator-approved per-attempt approval commitment. The signer must
   * independently recompute it from the decoded message bytes plus these fields
   * and refuse a mismatch; it is not merely the publisher's own request. */
  attemptPlanHash: string;
  /** Independently issued approval receipt (H5). The signer verifies it against
   * its separately pinned approval public key; a publisher-self-minted receipt
   * or a missing one is refused before the key is touched. */
  approvalReceipt: PublicationApprovalReceipt;
}

/** Signs exactly the reserved message and returns the signed wire transaction
 * (base64). Throwing is a rejection. Native signer approval is still open; this
 * is the adapter boundary it must implement. */
export interface PublicationSigner {
  readonly address: Address;
  signTransaction(request: SignRequest): Promise<string>;
}

export interface PublisherConfig {
  registryId: string;
  programId: Address;
  configPda: Address;
  operatorKeyId: string;
  keys: PublicationKeys;
  segmentsPerDay?: number;
  /** FAILED on-chain attempts tolerated before the operation needs maintenance. */
  maxFailedAttempts?: number;
  /** No new attempt this close (seconds) to UTC midnight by chain block time. */
  dayBoundaryGuardSeconds?: number;
  /** Explicit deployment cluster label. REQUIRED at runtime: the constructor
   * refuses to build a publisher without one (M4). There is no default. */
  cluster?: string;
  /** Pinned expected genesis hash. Required for local/unknown clusters; the
   * public clusters are pinned from `KNOWN_GENESIS_HASHES`. */
  genesisHash?: string;
  /** Pinned approval-verifier capability (public key + identity). Built by the
   * runtime from the approval service. When absent, every signing path refuses
   * `PUBLICATION_APPROVAL_UNCONFIGURED`; the issuer private key is never here. */
  approvalVerifier?: PublicationApprovalVerifierPolicy;
  /** Upper bound on the quoted fee of a reserved attempt; a higher quote fails
   * closed. Defaults to 100_000 lamports (20x the base fee of a 1-signature tx). */
  maxFeeLamports?: bigint;
  /** Test seam: runs after signed bytes are durable and before any send. */
  afterAttemptStored?: (attemptId: string) => Promise<void>;
}

const DEFAULT_MAX_FEE_LAMPORTS = 100_000n;

export interface MaintenanceRequest {
  requestedBy: string;
  approvedBy: string;
  reason: string;
  incidentRef?: string;
  /** Required (its own reason, 10+ chars) to abandon an operation that is not blocked.
   * Never overrides ADR-0009: an anchor of unknown origin needs archival evidence. */
  forceReason?: string;
}

/** Trusted-host request for an ADR-0009 archival investigation. */
export interface ArchivalRequest {
  /** Operator running the investigation (procedural attribution; the decision
   * to cancel is taken separately by two authenticated principals). */
  requestedBy: string;
  reason: string;
  /** External reference of the investigation (ticket, incident, case). */
  evidenceRef: string;
}

/** ADR-0009 outcomes 2–5. FINALIZED: our publication was found and matches the
 * intent (п.2). ANCHOR_MISMATCH: our transaction created a wrong anchor (п.3);
 * the terminal record is `recordLandedDiscrepancy` with an incident reference,
 * no successor. FOREIGN_PROVEN: foreign conflict proven, none of our attempts
 * can execute or has landed (п.4); cancellation needs two independent
 * authenticated approvals of `evidenceHash`, after which `step` abandons the
 * operation. INCONCLUSIVE: the block stays, the investigation is recorded (п.5). */
export type ArchivalReconciliation =
  | { outcome: "FINALIZED"; checkId: string; signature: string; anchorHash: string }
  | { outcome: "ANCHOR_MISMATCH"; checkId: string }
  | { outcome: "FOREIGN_PROVEN"; checkId: string; evidenceHash: string; approvalsRequired: 2 }
  | { outcome: "INCONCLUSIVE"; checkId: string; unresolved: string[] };

export type PublicationStepResult =
  | { status: "SUBMITTED" | "UNKNOWN" | "PENDING" | "FAILED"; operationId: string; attemptId: string; attemptNo: number; signature: string | null }
  | { status: "FINALIZED"; operationId: string; attemptId: string; attemptNo: number; signature: string; slot: string | null; anchorHash: string; proof: LandingProof["kind"] }
  /** Executed ADR-0009 decision: approved archival cancellation (ABANDONED) or
   * effective version exclusion (SUPERSEDED). The successor, if any, holds the
   * remaining membership and is claimed next. */
  | { status: "ABANDONED" | "SUPERSEDED"; operationId: string; successorOperationId: string | null; archivalCheckId?: string; excludedEventIds?: string[] };

/** No-send review returned by {@link WorkflowPublisher.review}. Carries every
 * field an operator must approve before the exact reserved intent is signed. */
export interface PublicationReview {
  operationId: string;
  intentHash: string;
  registryId: string;
  programId: string;
  configPda: string;
  operator: string;
  operatorKeyId: string;
  batchSequence: string;
  registryVersion: string;
  previousAnchorHash: string;
  cursorStart: string;
  cursorEnd: string;
  merkleRoot: string;
  manifestHash: string;
  leafCount: number;
  members: Array<{ eventId: string; recordId: string; version: number; operation: string; payloadHash: string }>;
  blockedReason: string | null;
  attemptStates: Array<{ attemptNo: number; state: AttemptState }>;
  hasSignedAttempt: boolean;
  /** A signed attempt in a non-terminal state: it can be reconciled or its
   * stored bytes re-sent without producing a new signature. */
  hasLiveSignedAttempt: boolean;
  segmentPda: string | null;
  segmentIndex: number | null;
  blockhash: string | null;
  lastValidBlockHeight: string | null;
  simulation: SimulationResult | null;
  /** Cluster the attempt plan is bound to. */
  cluster: string;
  /** Pinned genesis hash the connected chain must report (M4). */
  genesisHash: string;
  /** Durable per-attempt approval commitment over the exact reserved unsigned
   * bytes + lifetime + fee quote + attempt/day/segment/cluster (H3). Null when
   * no new signature could be produced (a live signed attempt is reconciled, or
   * the operation is blocked). Pass this verbatim to `run`. */
  attemptPlanHash: string | null;
  attemptNo: number | null;
  /** Quoted fee of the reserved attempt and its bound (null when no plan). */
  feeLamports: string | null;
  feeLimitLamports: string;
  /** Base64 of the exact reserved unsigned message the plan hash commits to
   * (null when no plan). `run` signs exactly these bytes. */
  messageBase64: string | null;
}

type AttemptState = "PREPARED" | "SIGNED" | "CANCELLED" | "SUBMITTED" | "UNKNOWN" | "EXPIRED" | "FAILED" | "FINALIZED" | "ANCHOR_MISMATCH";
/** Mirrored by `wf_publication_event_guard` in migration 0013. */
const TRANSITIONS: Record<AttemptState, readonly AttemptState[]> = {
  PREPARED: ["SIGNED", "CANCELLED"],
  SIGNED: ["SUBMITTED", "UNKNOWN", "EXPIRED"],
  SUBMITTED: ["UNKNOWN", "EXPIRED", "FAILED", "FINALIZED", "ANCHOR_MISMATCH"],
  UNKNOWN: ["EXPIRED", "FAILED", "FINALIZED", "ANCHOR_MISMATCH"],
  // Only with a proven landing of this attempt.
  EXPIRED: ["FINALIZED", "ANCHOR_MISMATCH"],
  CANCELLED: [], FAILED: [], FINALIZED: [], ANCHOR_MISMATCH: [],
};
const LIVE: readonly AttemptState[] = ["PREPARED", "SIGNED", "SUBMITTED", "UNKNOWN"];

interface Attempt {
  attemptId: string;
  operationId: string;
  attemptNo: number;
  intentHash: string;
  segmentPda: string;
  segmentIndex: number;
  dayUtc: number;
  recentBlockhash: string;
  lastValidBlockHeight: bigint;
  /** Finalized slot at reservation; the transaction cannot have landed before it. */
  contextSlot: bigint;
  messageBytes: Buffer;
  simulation: SimulationResult;
  signedBytes: Buffer | null;
  signature: string | null;
  state: AttemptState;
  /** Per-attempt approval plan (H3); null on pre-approval rows only. */
  cluster: string | null;
  feeLamports: bigint | null;
  feeLimitLamports: bigint | null;
  planHash: string | null;
}

type LandingProof =
  | { kind: "SIGNATURE_STATUS"; slot: bigint }
  | { kind: "ARCHIVAL_TRANSACTION"; slot: bigint; checkId: string }
  | { kind: "LEDGER_ENTRY"; contextSlot: bigint };
type Landing =
  | { kind: "none"; config: RegistryConfig; contextSlot: bigint }
  | { kind: "ours"; attempt: Attempt; proof: LandingProof }
  | { kind: "unproven" }
  | { kind: "foreign"; reason: string; error: string; contextSlot: bigint };

const ATTEMPTS_SQL = `SELECT t.attempt_id,t.operation_id,t.attempt_no,t.intent_hash,t.segment_pda,t.segment_index,t.day_utc,t.recent_blockhash,t.last_valid_block_height::text AS lvbh,t.context_slot::text AS cslot,
    t.message_bytes,t.simulation,t.cluster,t.fee_lamports::text AS fee,t.fee_limit_lamports::text AS feelimit,t.plan_hash,
    s.signed_bytes,s.signature,wf_publication_tx_state(t.attempt_id) AS state
  FROM wf_publication_tx t LEFT JOIN wf_publication_tx_signed s USING(attempt_id) WHERE t.operation_id=$1`;
const attemptOf = (r: any): Attempt => ({
  attemptId: r.attempt_id, operationId: r.operation_id, attemptNo: r.attempt_no, intentHash: r.intent_hash, segmentPda: r.segment_pda, segmentIndex: r.segment_index, dayUtc: r.day_utc,
  recentBlockhash: r.recent_blockhash, lastValidBlockHeight: BigInt(r.lvbh), contextSlot: BigInt(r.cslot), messageBytes: r.message_bytes,
  simulation: r.simulation, signedBytes: r.signed_bytes, signature: r.signature, state: r.state,
  cluster: r.cluster, feeLamports: r.fee === null ? null : BigInt(r.fee), feeLimitLamports: r.feelimit === null ? null : BigInt(r.feelimit), planHash: r.plan_hash,
});
const hexOf = (value: ArrayLike<number>) => toHex(Uint8Array.from(value));
const max = (a: bigint, b: bigint) => (a > b ? a : b);
const intentError = (error: unknown): never => {
  if (error instanceof PublicationIntentError) throw new PublicationError(error.code);
  throw error;
};

/** Procedural normalization of a maintenance participant until ticket 07
 * supplies authenticated principals: NFKC, no control/format (incl. zero-width)
 * characters, collapsed whitespace, 1..128 chars. Mirrored in migration 0013. */
export function maintenancePerson(value: unknown): string {
  if (typeof value !== "string") throw new PublicationError("MAINTENANCE_IDENTITY_INVALID");
  const normalized = value.normalize("NFKC").replace(/[\p{Cc}\p{Cf}]/gu, "").replace(/\s+/gu, " ").trim();
  if (!normalized || normalized.length > 128) throw new PublicationError("MAINTENANCE_IDENTITY_INVALID");
  return normalized;
}
const samePerson = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
function maintenanceText(value: unknown, code: string, min = 10): string {
  const text = typeof value === "string" ? value.normalize("NFKC").replace(/[\p{Cc}\p{Cf}]/gu, " ").replace(/\s+/gu, " ").trim() : "";
  if (text.length < min || text.length > 2000) throw new PublicationError(code);
  return text;
}

export class WorkflowPublisher {
  private readonly store: WorkflowPublicationStore;
  private bindingChecked = false;
  constructor(
    private readonly pool: Pool,
    private readonly chain: PublicationChain,
    private readonly signer: PublicationSigner,
    private readonly config: PublisherConfig,
  ) {
    try {
      const cluster = assertClusterLabel(config.cluster);
      expectedGenesisHash(cluster, config.genesisHash);
    } catch (error) {
      if (error instanceof PublicationIdentityError) throw new PublicationError(error.code);
      throw error;
    }
    this.store = new WorkflowPublicationStore(pool);
  }

  /** Advances the leased operation by one durable step. Repeating it (double
   * click, restart, second worker after reclaim) resumes from the journal.
   *
   * There is no unguarded path: any step that would mint a NEW signature
   * requires an independently issued approval receipt whose `attemptPlanHash`
   * equals the exact reserved (PREPARED) attempt. Reconciliation and re-send of
   * an already signed attempt need no approval and never sign. A fresh attempt
   * is only ever reserved by `review()`; `step` never reserves one. */
  async step(lease: PublicationLease, options: { approval?: PublicationApprovalReceipt } = {}): Promise<PublicationStepResult> {
    lease = { ...lease };
    if (lease.registryId !== this.config.registryId) throw new PublicationError("PUBLICATION_LEASE_LOST");
    return this.exclusive(lease.operationId, () => this.stepLocked(lease, options.approval));
  }

  private validateRequest(request: MaintenanceRequest, needIncident: boolean) {
    const requestedBy = maintenancePerson(request.requestedBy), approvedBy = maintenancePerson(request.approvedBy);
    if (samePerson(requestedBy, approvedBy)) throw new PublicationError("MAINTENANCE_SELF_APPROVAL");
    const reason = maintenanceText(request.reason, "MAINTENANCE_REASON_REQUIRED");
    if (needIncident && request.incidentRef === undefined) throw new PublicationError("MAINTENANCE_INCIDENT_REQUIRED");
    const incidentRef = request.incidentRef === undefined ? null : maintenancePerson(request.incidentRef);
    const forceReason = request.forceReason === undefined ? null : maintenanceText(request.forceReason, "MAINTENANCE_FORCE_REASON_REQUIRED");
    return { requestedBy, approvedBy, reason, incidentRef, forceReason };
  }

  /** Blocks whose conflicting anchor has unknown origin (ADR-0009). With a
   * signed attempt of ours that is not proven FAILED, leaving them needs
   * archival evidence (`reconcileWithArchive`); `forceReason` never overrides. */
  private static ambiguous(blockedReason: string | null): boolean {
    return blockedReason !== null && (blockedReason === "CHAIN_CONFLICT" || blockedReason.startsWith("ANCHOR_MISMATCH_UNATTRIBUTED"));
  }

  /** A signed attempt that is not proven FAILED may have landed (EXPIRED is a
   * judgement from RPC data, and a null status is not evidence of absence). */
  private static mayHaveLanded(attempts: readonly Attempt[]): boolean {
    return attempts.some((a) => a.signature !== null && a.state !== "FAILED");
  }

  /**
   * Maintenance exit for an operation whose anchor did NOT land: two different
   * people, a reason, an audit record; the membership moves to a successor
   * operation linked by `superseded_by`; journals are kept. Allowed only for a
   * blocked operation, or with an explicit `forceReason`. Refused with
   * `PUBLICATION_ARCHIVAL_RECONCILIATION_REQUIRED` whenever a signed attempt of
   * ours may have landed and the sequence is occupied by an anchor of unknown
   * origin, or the landing is unproven (ADR-0009): the exit is then
   * `reconcileWithArchive` plus two authenticated approvals, and `forceReason`
   * does not override it. Identities here are procedural strings.
   */
  async abandonForMaintenance(lease: PublicationLease, request: MaintenanceRequest): Promise<{ abandonedOperationId: string; successorOperationId: string | null }> {
    lease = { ...lease };
    const r = this.validateRequest(request, false);
    if (lease.registryId !== this.config.registryId) throw new PublicationError("PUBLICATION_LEASE_LOST");
    return this.exclusive(lease.operationId, async () => {
      const op = await this.operation(lease);
      if (op.blockedReason === null && r.forceReason === null) throw new PublicationError("MAINTENANCE_NOT_BLOCKED");
      const items = await this.store.items(lease);
      let slot = await this.chain.finalizedSlot(op.contextSlot);
      const stored = await this.storedIntent(lease.operationId);
      if (stored) {
        const intent = this.verify(stored, items, lease, await this.publishedBefore(lease.registryId));
        let attempts = await this.attempts(lease);
        await this.verifyAttempts(attempts, intent, stored.hash);
        // Our transaction landed with a discrepancy: a successor would anchor twice.
        if (attempts.some((a) => a.state === "ANCHOR_MISMATCH")) throw new PublicationError("PUBLICATION_FINALIZED_LANDING");
        if (WorkflowPublisher.mayHaveLanded(attempts) && WorkflowPublisher.ambiguous(op.blockedReason)) {
          throw new PublicationError("PUBLICATION_ARCHIVAL_RECONCILIATION_REQUIRED", { blockedReason: op.blockedReason });
        }
        for (const attempt of attempts.filter((a) => LIVE.includes(a.state))) {
          if (attempt.state === "PREPARED") { await this.transition(lease, attempt, "CANCELLED", { code: "ABANDONED_BEFORE_SIGNING" }, slot); continue; }
          const x = await this.chain.finalizedSlot(slot);
          slot = max(slot, x);
          const block = await this.chain.finalizedBlock(x);
          const [status] = await this.statuses([attempt.signature!], x);
          if (status?.finalized && !status.failed) throw new PublicationError("PUBLICATION_FINALIZED_LANDING");
          if (status?.finalized) {
            if (attempt.state === "SIGNED") await this.transition(lease, attempt, "UNKNOWN", { code: "RECOVERED_AFTER_CRASH" }, x);
            await this.transition(lease, attempt, "FAILED", { code: "TRANSACTION_FAILED" }, x);
            continue;
          }
          if (status !== null || block.blockHeight <= attempt.lastValidBlockHeight) throw new PublicationError("PUBLICATION_ATTEMPT_LIVE");
          await this.transition(lease, attempt, "EXPIRED", { code: "BLOCKHASH_EXPIRED", height: block.blockHeight.toString() }, x);
        }
        attempts = await this.attempts(lease);
        const landing = await this.findLanding(intent, attempts, slot);
        if (landing.kind === "ours") throw new PublicationError("PUBLICATION_FINALIZED_LANDING");
        // The sequence is occupied (or the landing is unproven) while an attempt
        // of ours may have landed: its origin is unknown until the archive says.
        if (landing.kind !== "none" && WorkflowPublisher.mayHaveLanded(attempts)) {
          throw new PublicationError("PUBLICATION_ARCHIVAL_RECONCILIATION_REQUIRED", { landing: landing.kind === "foreign" ? landing.reason : "LANDING_UNPROVEN" });
        }
      }
      let successor: string | null = null;
      await workflowTransaction(this.pool, async (c) => { successor = await this.abandonIn(c, lease, r, {}); });
      return { abandonedOperationId: lease.operationId, successorOperationId: successor };
    });
  }

  /** Abandonment write set (inside the caller's transaction and step lock).
   * Returns the successor, or null when every member was excluded. */
  private async abandonIn(c: PoolClient, lease: PublicationLease, r: ReturnType<WorkflowPublisher["validateRequest"]>,
    extra: { archivalCheckId?: string; excludedEventIds?: string[] }): Promise<string | null> {
    await lockRegistryPublication(c, lease.registryId);
    await assertPublicationLease(c, lease);
    const blocked = (await c.query("SELECT blocked_reason FROM wf_publication WHERE operation_id=$1", [lease.operationId])).rows[0].blocked_reason;
    const excluded = extra.excludedEventIds ?? [];
    const remaining = (await c.query("SELECT event_id FROM wf_publication_item WHERE operation_id=$1 AND NOT (event_id = ANY($2::uuid[])) ORDER BY ordinal", [lease.operationId, excluded])).rows;
    const successor = remaining.length ? randomUUID() : null;
    await c.query(`INSERT INTO wf_publication_abandonment(operation_id,successor_operation_id,requested_by,approved_by,reason,incident_ref,blocked_reason,force_reason,archival_check_id,excluded_event_ids,fence,worker)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::uuid[],$11,$12)`, [lease.operationId, successor, r.requestedBy, r.approvedBy, r.reason, r.incidentRef, blocked, r.forceReason,
      extra.archivalCheckId ?? null, excluded, lease.fence, lease.worker]);
    await journal(c, lease, "ABANDON");
    await c.query("UPDATE wf_publication SET state='ABANDONED',superseded_by=$2,lease_until=clock_timestamp() WHERE operation_id=$1", [lease.operationId, successor]);
    if (successor) {
      // The successor starts with an expired lease: the next claim reclaims it with a new fence.
      await c.query("INSERT INTO wf_publication(operation_id,registry_id,owner,lease_until) VALUES($1,$2,$3,clock_timestamp())", [successor, lease.registryId, lease.worker]);
      for (const [ordinal, row] of remaining.entries()) await c.query("INSERT INTO wf_publication_item VALUES($1,$2,$3)", [successor, ordinal, row.event_id]);
    }
    await c.query("INSERT INTO wf_audit(registry_id,actor,action,details) VALUES($1,$2,'PUBLICATION_ABANDONED',$3)", [lease.registryId, r.approvedBy,
      JSON.stringify({ operationId: lease.operationId, successorOperationId: successor, ...r, blockedReason: blocked, archivalCheckId: extra.archivalCheckId ?? null, excludedEventIds: excluded, fence: lease.fence })]);
    return successor;
  }

  /**
   * Terminal maintenance outcome for "our transaction is finalized on chain but
   * the anchor disagrees with the intent" (ANCHOR_MISMATCH attempt, including
   * one found by `reconcileWithArchive`, ADR-0009 п.3). No successor is created
   * (that would anchor the same membership twice); the membership stays
   * consumed, an incident reference is mandatory and an audit row is written;
   * the newest OURS_FOUND archival check, if any, is linked. Later registry
   * work can proceed. Identities are procedural strings (see evidence).
   */
  async recordLandedDiscrepancy(lease: PublicationLease, request: MaintenanceRequest): Promise<void> {
    lease = { ...lease };
    const r = this.validateRequest(request, true);
    if (lease.registryId !== this.config.registryId) throw new PublicationError("PUBLICATION_LEASE_LOST");
    await this.exclusive(lease.operationId, async () => {
      const op = await this.operation(lease);
      if (op.blockedReason === null) throw new PublicationError("MAINTENANCE_NOT_BLOCKED");
      const mismatch = (await this.attempts(lease)).find((a) => a.state === "ANCHOR_MISMATCH");
      if (!mismatch) throw new PublicationError("PUBLICATION_NO_LANDED_DISCREPANCY");
      await workflowTransaction(this.pool, async (c) => {
        await lockRegistryPublication(c, lease.registryId);
        await assertPublicationLease(c, lease);
        const blocked = (await c.query("SELECT blocked_reason FROM wf_publication WHERE operation_id=$1", [lease.operationId])).rows[0].blocked_reason;
        const check = (await c.query(`SELECT check_id FROM wf_publication_archival_check WHERE operation_id=$1 AND outcome='OURS_FOUND' ORDER BY check_no DESC LIMIT 1`, [lease.operationId])).rows[0]?.check_id ?? null;
        await c.query(`INSERT INTO wf_publication_discrepancy(operation_id,attempt_id,signature,blocked_reason,requested_by,approved_by,reason,incident_ref,archival_check_id,fence,worker)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, [lease.operationId, mismatch.attemptId, mismatch.signature, blocked, r.requestedBy, r.approvedBy, r.reason, r.incidentRef, check, lease.fence, lease.worker]);
        await journal(c, lease, "DISCREPANCY");
        await c.query("UPDATE wf_publication SET state='LANDED_DISCREPANCY',lease_until=clock_timestamp() WHERE operation_id=$1", [lease.operationId]);
        await c.query("INSERT INTO wf_audit(registry_id,actor,action,details) VALUES($1,$2,'PUBLICATION_LANDED_DISCREPANCY',$3)", [lease.registryId, r.approvedBy,
          JSON.stringify({ operationId: lease.operationId, attemptId: mismatch.attemptId, signature: mismatch.signature, blockedReason: blocked, archivalCheckId: check, ...r, fence: lease.fence })]);
      });
    });
  }

  /**
   * ADR-0009 archival reconciliation (trusted host / worker interface, no HTTP).
   * Every journaled signature is looked up in a separate archival source; the
   * finalized ledger is compared with the stored intent through the existing
   * trusted `complete()`. Each run appends an immutable check with canonical
   * evidence bytes and hash. Absence in the archive counts only when the
   * archive's history covers the attempt's reservation slot, the archive has
   * reached the main-chain finalized slot X, and the attempt's blockhash had
   * expired by finalized height at X. A null from the primary RPC is never used.
   */
  async reconcileWithArchive(lease: PublicationLease, archive: ArchivalChain, request: ArchivalRequest): Promise<ArchivalReconciliation> {
    lease = { ...lease };
    const requestedBy = maintenancePerson(request.requestedBy);
    const reason = maintenanceText(request.reason, "MAINTENANCE_REASON_REQUIRED");
    const evidenceRef = maintenancePerson(request.evidenceRef);
    const archiveId = maintenancePerson(archive.archiveId);
    if (lease.registryId !== this.config.registryId) throw new PublicationError("PUBLICATION_LEASE_LOST");
    return this.exclusive(lease.operationId, async () => {
      await this.checkChainIdentity();
      const op = await this.operation(lease);
      const stored = await this.storedIntent(lease.operationId);
      if (!stored) throw new PublicationError("PUBLICATION_ARCHIVAL_NOT_APPLICABLE");
      const items = await this.store.items(lease);
      const intent = this.verify(stored, items, lease, await this.publishedBefore(lease.registryId));
      const attempts = await this.attempts(lease);
      await this.verifyAttempts(attempts, intent, stored.hash);
      // Our landing is already recorded: the exit is recordLandedDiscrepancy.
      if (attempts.some((a) => a.state === "ANCHOR_MISMATCH")) throw new PublicationError("PUBLICATION_ARCHIVAL_NOT_APPLICABLE");
      const signed = attempts.filter((a) => a.signature !== null);
      // Nothing of ours was ever signed: nothing can have landed; ordinary maintenance applies.
      if (!signed.length) throw new PublicationError("PUBLICATION_ARCHIVAL_NOT_APPLICABLE");
      // Main-chain view first: expiry is judged at X, and the archive must have reached X.
      const x = await this.chain.finalizedSlot(op.contextSlot);
      const block = await this.chain.finalizedBlock(x);
      const config = this.checkConfig((await this.chain.registryConfig(this.config.configPda, x)).value, intent);
      const historyFrom = await archive.historyFromSlot();
      const archiveTip = await archive.finalizedSlot();
      const lookups: Array<{ attempt: Attempt; tx: { slot: bigint; failed: boolean } | null }> = [];
      for (const attempt of signed) lookups.push({ attempt, tx: await archive.transaction(attempt.signature!) });
      const sequenceTaken = config.currentBatchSequence >= BigInt(intent.batchSequence);
      const evidence = lookups.map(({ attempt, tx }) => {
        let proof: string;
        if (tx !== null) proof = tx.failed ? "FAILED_ON_CHAIN" : "LANDED";
        else if (historyFrom === null) proof = "UNRESOLVED:HISTORY_COMPLETENESS_UNKNOWN";
        else if (historyFrom > attempt.contextSlot) proof = "UNRESOLVED:HISTORY_NOT_COVERED";
        else if (archiveTip < x) proof = "UNRESOLVED:ARCHIVE_BEHIND_CHAIN";
        else if (block.blockHeight <= attempt.lastValidBlockHeight) proof = "UNRESOLVED:BLOCKHASH_NOT_EXPIRED";
        else proof = "ABSENT_AND_EXPIRED";
        return { attemptId: attempt.attemptId, attemptNo: attempt.attemptNo, signature: attempt.signature!, journalState: attempt.state,
          reservedAtSlot: attempt.contextSlot.toString(), lastValidBlockHeight: attempt.lastValidBlockHeight.toString(),
          archive: tx === null ? "NOT_FOUND" : tx.failed ? "FAILED" : "SUCCEEDED", archiveSlot: tx === null ? null : tx.slot.toString(), proof };
      });
      const succeeded = lookups.filter((l) => l.tx !== null && !l.tx.failed);
      const outcome = succeeded.length === 1 ? "OURS_FOUND"
        : succeeded.length === 0 && sequenceTaken && evidence.every((e) => e.proof === "FAILED_ON_CHAIN" || e.proof === "ABSENT_AND_EXPIRED") ? "FOREIGN_PROVEN"
        : "INCONCLUSIVE";
      const detail = {
        version: 1, rule: ARCHIVAL_RULE, operationId: lease.operationId, registryId: lease.registryId, intentHash: stored.hash,
        batchSequence: intent.batchSequence, blockedReason: op.blockedReason, archiveId, archiveHistoryFromSlot: historyFrom?.toString() ?? null,
        archiveFinalizedSlot: archiveTip.toString(), chainFinalizedSlot: x.toString(), chainBlockHeight: block.blockHeight.toString(),
        registrySequence: config.currentBatchSequence.toString(), sequenceTaken, outcome, attempts: evidence,
      };
      const bytes = Buffer.from(canonicalWorkflow(detail), "utf8");
      const evidenceHash = createHash("sha256").update(ARCHIVAL_CHECK_DOMAIN + "\n").update(bytes).digest("hex");
      const checkId = randomUUID();
      await workflowTransaction(this.pool, async (c) => {
        await assertPublicationLease(c, lease);
        await c.query(`INSERT INTO wf_publication_archival_check(check_id,operation_id,archive_id,evidence_ref,outcome,detail_bytes,detail_hash,requested_by,reason,fence,worker)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, [checkId, lease.operationId, archiveId, evidenceRef, outcome, bytes, evidenceHash, requestedBy, reason, lease.fence, lease.worker]);
        await journal(c, lease, "ARCHIVAL_CHECK");
        await this.bump(c, lease, x);
        // A proven foreign conflict keeps (or puts) the operation in maintenance.
        if (outcome === "FOREIGN_PROVEN") await this.blockIn(c, lease, "CHAIN_CONFLICT");
        await c.query("INSERT INTO wf_audit(registry_id,actor,action,details) VALUES($1,$2,'PUBLICATION_ARCHIVAL_CHECK',$3)", [lease.registryId, requestedBy,
          JSON.stringify({ operationId: lease.operationId, checkId, outcome, evidenceHash, evidenceRef, archiveId, reason, fence: lease.fence })]);
      });
      if (outcome === "OURS_FOUND") {
        const { attempt, tx } = succeeded[0];
        try {
          const done = await this.complete(lease, intent, attempt, { kind: "ARCHIVAL_TRANSACTION", slot: tx!.slot, checkId });
          if (done.status !== "FINALIZED") throw new PublicationError("PUBLICATION_JOURNAL_INVALID");
          return { outcome: "FINALIZED", checkId, signature: done.signature, anchorHash: done.anchorHash };
        } catch (error) {
          if (error instanceof PublicationError && error.code === "ANCHOR_COMMITMENT_MISMATCH") return { outcome: "ANCHOR_MISMATCH", checkId };
          throw error;
        }
      }
      if (outcome === "FOREIGN_PROVEN") return { outcome, checkId, evidenceHash, approvalsRequired: 2 };
      return { outcome: "INCONCLUSIVE", checkId, unresolved: evidence.filter((e) => e.proof !== "FAILED_ON_CHAIN" && e.proof !== "ABSENT_AND_EXPIRED").map((e) => `${e.attemptNo}:${e.proof}`)
        .concat(sequenceTaken ? [] : ["SEQUENCE_NOT_TAKEN"], succeeded.length > 1 ? ["SEVERAL_SUCCEEDED"] : []) };
    });
  }

  /** Newest archival check of the operation when it is FOREIGN_PROVEN and has two approvals. */
  private async approvedCancellation(operationId: string): Promise<{ checkId: string; detail: any; approvers: [string, string] } | null> {
    const check = (await this.pool.query(`SELECT check_id,outcome,detail_bytes FROM wf_publication_archival_check WHERE operation_id=$1 ORDER BY check_no DESC LIMIT 1`, [operationId])).rows[0];
    if (!check || check.outcome !== "FOREIGN_PROVEN") return null;
    const approvals = (await this.pool.query("SELECT principal FROM wf_publication_cancel_approval WHERE check_id=$1 ORDER BY ordinal", [check.check_id])).rows;
    if (approvals.length !== 2) return null;
    return { checkId: check.check_id, detail: JSON.parse(check.detail_bytes.toString("utf8")), approvers: [approvals[0].principal, approvals[1].principal] };
  }

  /** Executes an approved ADR-0009 п.4 cancellation: closes our attempts per the
   * archival evidence and abandons with a successor, referencing the check. */
  private async executeCancellation(lease: PublicationLease, attempts: Attempt[], approved: NonNullable<Awaited<ReturnType<WorkflowPublisher["approvedCancellation"]>>>, slot: bigint): Promise<PublicationStepResult> {
    const byId = new Map<string, { proof: string }>(approved.detail.attempts.map((a: any) => [a.attemptId, a]));
    for (const attempt of attempts) {
      if (attempt.signature !== null && !byId.has(attempt.attemptId)) throw new PublicationError("PUBLICATION_ARCHIVAL_EVIDENCE_STALE");
      if (attempt.state === "PREPARED") { await this.transition(lease, attempt, "CANCELLED", { code: "ABANDONED_BEFORE_SIGNING" }, slot); continue; }
      if (!["SIGNED", "SUBMITTED", "UNKNOWN"].includes(attempt.state)) continue;
      const proof = byId.get(attempt.attemptId)!.proof;
      if (proof === "FAILED_ON_CHAIN") {
        if (attempt.state === "SIGNED") await this.transition(lease, attempt, "UNKNOWN", { code: "ARCHIVAL_RECONCILIATION", checkId: approved.checkId }, slot);
        await this.transition(lease, attempt, "FAILED", { code: "ARCHIVE_TRANSACTION_FAILED", checkId: approved.checkId }, slot);
      } else if (proof === "ABSENT_AND_EXPIRED") {
        await this.transition(lease, attempt, "EXPIRED", { code: "ARCHIVE_ABSENT_AND_EXPIRED", checkId: approved.checkId }, slot);
      } else throw new PublicationError("PUBLICATION_ARCHIVAL_EVIDENCE_STALE");
    }
    const r = { requestedBy: approved.approvers[0], approvedBy: approved.approvers[1],
      reason: `ADR-0009: foreign anchor proven by archival check ${approved.checkId}; cancellation approved by two authenticated principals`,
      incidentRef: null, forceReason: null };
    let successor: string | null = null;
    await workflowTransaction(this.pool, async (c) => { successor = await this.abandonIn(c, lease, r, { archivalCheckId: approved.checkId }); });
    return { status: "ABANDONED", operationId: lease.operationId, successorOperationId: successor, archivalCheckId: approved.checkId };
  }

  /** ADR-0009 (B): members excluded by an effective two-person decision leave
   * the queue deterministically; the rest moves to a successor operation. */
  private async supersedeExcluded(lease: PublicationLease, excluded: Array<{ event_id: string; exclusion_id: string }>): Promise<PublicationStepResult> {
    // Exclusion requires an unpublishable version, so no intent can exist (0017 also forbids it).
    if (await this.storedIntent(lease.operationId)) throw new PublicationError("PUBLICATION_JOURNAL_INVALID");
    const ids = excluded.map((row) => row.exclusion_id);
    const approvers = (await this.pool.query("SELECT principal FROM wf_version_exclusion_approval WHERE exclusion_id=$1 ORDER BY ordinal", [ids[0]])).rows.map((row) => row.principal as string);
    if (approvers.length !== 2) throw new PublicationError("PUBLICATION_JOURNAL_INVALID");
    const r = { requestedBy: approvers[0], approvedBy: approvers[1], reason: `ADR-0009: version exclusion ${ids.join(",")}`, incidentRef: null, forceReason: null };
    const eventIds = excluded.map((row) => row.event_id);
    let successor: string | null = null;
    await workflowTransaction(this.pool, async (c) => {
      await lockRegistryPublication(c, lease.registryId);
      await assertPublicationLease(c, lease);
      await this.blockIn(c, lease, "VERSION_EXCLUDED");
      successor = await this.abandonIn(c, lease, r, { excludedEventIds: eventIds });
    });
    return { status: "SUPERSEDED", operationId: lease.operationId, successorOperationId: successor, excludedEventIds: eventIds };
  }

  /** Transaction-scoped advisory lock on a dedicated connection for the whole call. */
  private async exclusive<T>(operationId: string, fn: () => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    let broken = false;
    try {
      await client.query("BEGIN");
      const locked = (await client.query("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0)) AS ok", ["publication-step:" + operationId])).rows[0].ok;
      if (!locked) throw new PublicationError("PUBLICATION_STEP_BUSY");
      return await fn();
    } finally {
      // ROLLBACK ends the (otherwise empty) transaction and releases the lock;
      // if that fails the connection is destroyed, which also releases it.
      try { await client.query("ROLLBACK"); } catch { broken = true; }
      client.release(broken || undefined);
    }
  }

  private async stepLocked(lease: PublicationLease, approval?: PublicationApprovalReceipt): Promise<PublicationStepResult> {
    await this.checkChainIdentity();
    const op = await this.operation(lease);
    const items = await this.store.items(lease);
    // Effective exclusions (ADR-0009 B) are honoured before any intent work.
    const excluded = (await this.pool.query(`SELECT i.event_id,x.exclusion_id FROM wf_publication_item i JOIN wf_version_excluded x USING(event_id)
      WHERE i.operation_id=$1 ORDER BY i.ordinal`, [lease.operationId])).rows;
    if (excluded.length) return this.supersedeExcluded(lease, excluded);
    let slot = await this.chain.finalizedSlot(op.contextSlot);
    const { intent, hash } = await this.ensureIntent(lease, items, slot);
    const attempts = await this.attempts(lease);
    await this.verifyAttempts(attempts, intent, hash);
    if (op.blockedReason !== null) {
      // A recorded discrepancy of our own landing is terminal: never re-run
      // completion (it would loop); only maintenance ends it.
      if (attempts.some((a) => a.state === "ANCHOR_MISMATCH")) throw new PublicationError("PUBLICATION_MAINTENANCE_REQUIRED");
      // Otherwise a blocked operation can still finish if its own landing is proven.
      const landing = await this.findLanding(intent, attempts, slot);
      if (landing.kind === "ours") return this.complete(lease, intent, landing.attempt, landing.proof);
      // ADR-0009 п.4: archival evidence proved a foreign conflict and two
      // authenticated principals approved the cancellation of exactly that evidence.
      const approved = await this.approvedCancellation(lease.operationId);
      if (approved) return this.executeCancellation(lease, attempts, approved, slot);
      throw new PublicationError("PUBLICATION_MAINTENANCE_REQUIRED");
    }
    const live = attempts.filter((a) => LIVE.includes(a.state));
    if (live.length > 1) throw new PublicationError("PUBLICATION_JOURNAL_INVALID");
    if (live.length === 1) {
      const outcome = await this.reconcile(lease, intent, hash, live[0], slot, approval);
      if (typeof outcome !== "bigint") return outcome;
      // Later reads must be at least as new as the view that justified EXPIRED/CANCELLED.
      slot = max(slot, outcome);
    }
    return this.advance(lease, intent, hash, await this.attempts(lease), slot, approval);
  }

  /** Derives the config/registry PDA binding once and re-checks the connected
   * node's genesis hash on every call: a wrong or unreachable chain fails closed
   * before any reservation or signature (M4). */
  private async checkChainIdentity(): Promise<void> {
    if (!this.bindingChecked) {
      const [expected] = await findRegistryConfigPda(registryIdHash(this.config.registryId), { programAddress: this.config.programId });
      if (expected !== this.config.configPda) throw new PublicationError("PUBLICATION_CONFIG_BINDING");
      this.bindingChecked = true;
    }
    let actual: string;
    try { actual = await this.chain.genesisHash(); }
    catch { throw new PublicationError("PUBLICATION_CHAIN_IDENTITY_UNAVAILABLE"); }
    if (actual !== this.genesis()) throw new PublicationError("PUBLICATION_CHAIN_IDENTITY_MISMATCH");
  }

  private checkConfig(config: RegistryConfig | null, intent?: PublicationIntent): RegistryConfig {
    if (config === null) throw new PublicationError("REGISTRY_NOT_INITIALIZED");
    if (config.version !== 1 || hexOf(config.registryIdHash) !== toHex(registryIdHash(this.config.registryId))) throw new PublicationError("PUBLICATION_CONFIG_BINDING");
    if (intent && (config.schemaVersion !== intent.schemaVersion || config.hashAlgorithm !== intent.hashAlgorithm || config.treeAlgorithm !== intent.treeAlgorithm)) {
      throw new PublicationError("PUBLICATION_CONFIG_BINDING");
    }
    return config;
  }

  private async operation(lease: PublicationLease): Promise<{ blockedReason: string | null; contextSlot: bigint }> {
    return workflowTransaction(this.pool, async (c) => {
      await assertPublicationLease(c, lease);
      const r = (await c.query("SELECT blocked_reason,context_slot::text AS slot FROM wf_publication WHERE operation_id=$1", [lease.operationId])).rows[0];
      return { blockedReason: r.blocked_reason, contextSlot: BigInt(r.slot) };
    });
  }

  private async bump(c: PoolClient, lease: PublicationLease, slot: bigint | undefined): Promise<void> {
    if (slot !== undefined) await c.query("UPDATE wf_publication SET context_slot=GREATEST(context_slot,$2) WHERE operation_id=$1", [lease.operationId, slot.toString()]);
  }

  /** Events already anchored on chain by earlier operations (finalized, or landed with a recorded discrepancy). */
  private async publishedBefore(registryId: string): Promise<bigint> {
    const r = await this.pool.query(`SELECT count(*)::text AS n FROM wf_publication_item i JOIN wf_publication p USING(operation_id)
      WHERE p.registry_id=$1 AND p.state IN ('FINALIZED','LANDED_DISCREPANCY')`, [registryId]);
    return BigInt(r.rows[0].n);
  }

  private async storedIntent(operationId: string): Promise<{ bytes: Buffer; hash: string } | null> {
    const r = await this.pool.query("SELECT intent_bytes,intent_hash FROM wf_publication_intent WHERE operation_id=$1", [operationId]);
    return r.rowCount ? { bytes: r.rows[0].intent_bytes, hash: r.rows[0].intent_hash } : null;
  }

  private verify(stored: { bytes: Buffer; hash: string }, items: PublicationItem[], lease: PublicationLease, publishedBefore: bigint): PublicationIntent {
    let intent: PublicationIntent;
    try {
      intent = verifyStoredIntent(stored, items, this.config.keys, { operationId: lease.operationId, registryId: lease.registryId, publishedBefore });
    } catch (error) { return intentError(error); }
    if (intent.programId !== this.config.programId || intent.configPda !== this.config.configPda) throw new PublicationError("PUBLICATION_INTENT_MISMATCH");
    return intent;
  }

  private async ensureIntent(lease: PublicationLease, items: PublicationItem[], slot: bigint): Promise<{ intent: PublicationIntent; hash: string }> {
    const publishedBefore = await this.publishedBefore(lease.registryId);
    const existing = await this.storedIntent(lease.operationId);
    if (existing) return { intent: this.verify(existing, items, lease, publishedBefore), hash: existing.hash };
    // A committed version the field mapping cannot represent (e.g. a V1 float)
    // stops this registry's queue; name it so an owner can act (evidence 09).
    for (const item of items) {
      try { workflowFields(item); }
      catch (error) {
        if (!(error instanceof PublicationIntentError)) throw error;
        await this.block(lease, "UNPUBLISHABLE_VERSION");
        throw new PublicationError("PUBLICATION_UNPUBLISHABLE_VERSION", { eventId: item.eventId, recordId: item.recordId, version: item.version, cause: error.message });
      }
    }
    const read = await this.chain.registryConfig(this.config.configPda, slot);
    const config = this.checkConfig(read.value);
    if (config.paused) throw new PublicationError("REGISTRY_PAUSED");
    const createdAt = (await this.pool.query("SELECT clock_timestamp() AS now")).rows[0].now as Date;
    let encoded;
    try {
      encoded = buildPublicationIntent(items, {
        operationId: lease.operationId, registryId: lease.registryId, programId: this.config.programId,
        configPda: this.config.configPda, operator: this.signer.address, operatorKeyId: this.config.operatorKeyId,
        batchSequence: config.currentBatchSequence + 1n, registryVersion: config.currentRegistryVersion,
        previousAnchorHashHex: hexOf(config.lastAnchorHash), publishedBefore,
        createdAt: createdAt.toISOString().replace(/\.\d{3}Z$/, "Z"), schemaVersion: config.schemaVersion,
        hashAlgorithm: config.hashAlgorithm, treeAlgorithm: config.treeAlgorithm,
      }, this.config.keys);
    } catch (error) { return intentError(error); }
    await workflowTransaction(this.pool, async (c) => {
      await assertPublicationLease(c, lease);
      if ((await c.query("SELECT 1 FROM wf_publication_intent WHERE operation_id=$1", [lease.operationId])).rowCount) return;
      await c.query(`INSERT INTO wf_publication_intent(operation_id,registry_id,batch_sequence,intent_bytes,intent_hash,fence,worker)
        VALUES($1,$2,$3,$4,$5,$6,$7)`,
      [lease.operationId, lease.registryId, encoded.intent.batchSequence, encoded.bytes, encoded.hash, lease.fence, lease.worker]);
      await this.bump(c, lease, read.contextSlot);
    });
    const stored = (await this.storedIntent(lease.operationId))!;
    return { intent: this.verify(stored, items, lease, publishedBefore), hash: stored.hash };
  }

  private async attempts(lease: PublicationLease): Promise<Attempt[]> {
    return workflowTransaction(this.pool, async (c) => {
      await assertPublicationLease(c, lease);
      return (await c.query(ATTEMPTS_SQL + " ORDER BY t.attempt_no", [lease.operationId])).rows.map(attemptOf);
    });
  }

  /** Journaled bytes must still encode exactly the intent (and be signed by its operator). */
  private async verifyAttempts(attempts: Attempt[], intent: PublicationIntent, hash: string): Promise<void> {
    const [rolePda] = await findRolePda({ config: intent.configPda as Address, operator: intent.operator as Address }, { programAddress: intent.programId as Address });
    for (const attempt of attempts) {
      if (attempt.intentHash !== hash) throw new PublicationError("PUBLICATION_INTENT_MISMATCH");
      let ok = false;
      try {
        const message: any = getCompiledTransactionMessageDecoder().decode(attempt.messageBytes);
        const keys: string[] = message.staticAccounts;
        const [ix] = message.instructions;
        const accounts = (ix?.accountIndices ?? []).map((index: number) => keys[index]);
        const data = Uint8Array.from(ix?.data ?? []);
        const decoded = getPublishAnchorInstructionDataDecoder().decode(data);
        ok = message.instructions.length === 1 && keys[0] === intent.operator && keys[ix.programAddressIndex] === intent.programId
          && accounts.length === 4 && accounts[0] === intent.configPda && accounts[1] === rolePda && accounts[2] === intent.operator
          && accounts[3] === attempt.segmentPda && message.lifetimeToken === attempt.recentBlockhash
          && Buffer.from(data.subarray(0, 8)).equals(Buffer.from(getPublishAnchorDiscriminatorBytes()))
          && anchorEntryMismatch(intent, { ...decoded, operator: keys[0], pad0: new Uint8Array(0), publishedAt: 0n } as unknown as AnchorEntryV1) === null;
      } catch { ok = false; }
      if (!ok) throw new PublicationError("PUBLICATION_JOURNAL_INVALID");
      // The reserved attempt's approval commitment must still cover exactly this
      // message bytes, lifetime, fee, attempt/day/segment and cluster (H3).
      if (attempt.planHash !== null) {
        const recomputed = this.planHashFor(intent, hash, attempt);
        if (recomputed !== attempt.planHash) throw new PublicationError("PUBLICATION_JOURNAL_INVALID");
      }
      if (attempt.signedBytes !== null) {
        let signature: string;
        try { signature = validateSignedTransaction(attempt.signedBytes.toString("base64"), attempt.messageBytes.toString("base64"), intent.operator as Address); }
        catch { throw new PublicationError("PUBLICATION_JOURNAL_INVALID"); }
        if (signature !== attempt.signature) throw new PublicationError("PUBLICATION_JOURNAL_INVALID");
      }
    }
  }

  private cluster(): string { return assertClusterLabel(this.config.cluster); }
  private genesis(): string { return expectedGenesisHash(this.cluster(), this.config.genesisHash); }
  private feeLimit(): bigint { return this.config.maxFeeLamports ?? DEFAULT_MAX_FEE_LAMPORTS; }

  /** Commitment over a reserved attempt's exact bytes + lifetime + fee + plan. */
  private planHashFor(intent: PublicationIntent, hash: string, attempt: {
    attemptNo: number; segmentPda: string; segmentIndex: number; dayUtc: number;
    recentBlockhash: string; lastValidBlockHeight: bigint; messageBytes: Buffer;
    feeLamports: bigint | null; feeLimitLamports: bigint | null; cluster: string | null;
  }): string {
    const commitment: AttemptPlanCommitment = {
      intentHash: hash, attemptNo: attempt.attemptNo, cluster: attempt.cluster ?? this.cluster(),
      programId: intent.programId, configPda: intent.configPda, operator: intent.operator, registryId: intent.registryId,
      segmentPda: attempt.segmentPda, segmentIndex: attempt.segmentIndex, dayUtc: attempt.dayUtc,
      recentBlockhash: attempt.recentBlockhash, lastValidBlockHeight: attempt.lastValidBlockHeight.toString(),
      feeLamports: (attempt.feeLamports ?? 0n).toString(), feeLimitLamports: (attempt.feeLimitLamports ?? this.feeLimit()).toString(),
      messageBase64: attempt.messageBytes.toString("base64"),
    };
    return attemptPlanHash(commitment);
  }

  /**
   * A new signature may target only the reserved attempt whose plan hash the
   * independently issued approval receipt binds. There is no unguarded path:
   * a missing receipt is refused, a receipt whose binding/identity/signature/
   * expiry does not verify is refused, and a consumed receipt (already recorded
   * on a signed attempt) is refused. The issuer private key is never available
   * here; the publisher holds only the pinned verifier public key.
   */
  private requireApproval(attempt: Attempt, approval: PublicationApprovalReceipt | undefined): PublicationApprovalReceipt {
    const verifier = this.config.approvalVerifier;
    if (verifier === undefined) throw new PublicationError("PUBLICATION_APPROVAL_UNCONFIGURED");
    if (approval === undefined) throw new PublicationError("PUBLICATION_INTENT_APPROVAL_REQUIRED");
    if (attempt.planHash === null) throw new PublicationError("PUBLICATION_ATTEMPT_PLAN_MISMATCH");
    try {
      verifyPublicationApproval(approval, {
        operationId: attempt.operationId,
        intentHash: attempt.intentHash,
        attemptPlanHash: attempt.planHash,
        ...verifier,
        cluster: attempt.cluster ?? this.cluster(),
        genesisHash: this.genesis(),
      });
    } catch (error) {
      if (error instanceof PublicationApprovalError) throw new PublicationError(error.code);
      throw error;
    }
    return approval;
  }

  /** Compare-and-set state event under the current fence; optionally blocks the operation in the same transaction. */
  private async transition(lease: PublicationLease, attempt: Attempt, to: AttemptState, detail: Record<string, unknown>, slot?: bigint, blockReason?: string): Promise<void> {
    await workflowTransaction(this.pool, async (c) => {
      await assertPublicationLease(c, lease);
      const current = (await c.query("SELECT wf_publication_tx_state($1) AS state", [attempt.attemptId])).rows[0].state as AttemptState;
      if (current !== attempt.state) throw new PublicationError("PUBLICATION_STEP_RACE");
      if (!TRANSITIONS[current].includes(to)) throw new PublicationError("TRANSACTION_STATE_INVALID");
      await c.query("INSERT INTO wf_publication_tx_event(attempt_id,state,fence,worker,detail) VALUES($1,$2,$3,$4,$5)",
        [attempt.attemptId, to, lease.fence, lease.worker, JSON.stringify(detail)]);
      await this.bump(c, lease, slot);
      if (blockReason) await this.blockIn(c, lease, blockReason);
    });
    attempt.state = to;
  }

  private async blockIn(c: PoolClient, lease: PublicationLease, reason: string): Promise<void> {
    const r = await c.query("UPDATE wf_publication SET blocked_reason=$2 WHERE operation_id=$1 AND blocked_reason IS NULL", [lease.operationId, reason]);
    if (r.rowCount) await journal(c, lease, "BLOCK");
  }

  private async block(lease: PublicationLease, reason: string, slot?: bigint): Promise<void> {
    await workflowTransaction(this.pool, async (c) => {
      await assertPublicationLease(c, lease);
      await this.bump(c, lease, slot);
      await this.blockIn(c, lease, reason);
    });
  }

  /** Signature statuses from a node whose answer is at least `minContextSlot`. */
  private async statuses(signatures: string[], minContextSlot: bigint): Promise<Array<SignatureStatus | null>> {
    const read = await this.chain.signatureStatuses(signatures);
    if (read.contextSlot < minContextSlot) throw new PublicationError("RPC_CONTEXT_STALE");
    return read.value;
  }

  private result(status: "SUBMITTED" | "UNKNOWN" | "PENDING" | "FAILED", lease: PublicationLease, a: Attempt): PublicationStepResult {
    return { status, operationId: lease.operationId, attemptId: a.attemptId, attemptNo: a.attemptNo, signature: a.signature };
  }

  /** Returns a result, or the context slot of the view that ended the attempt
   * (EXPIRED/CANCELLED) when a landing search / new attempt is needed. */
  private async reconcile(lease: PublicationLease, intent: PublicationIntent, hash: string, attempt: Attempt, slot: bigint, approval?: PublicationApprovalReceipt): Promise<PublicationStepResult | bigint> {
    const x = await this.chain.finalizedSlot(slot);
    const block = await this.chain.finalizedBlock(x);
    if (attempt.state === "PREPARED") {
      // Never signed, so it cannot land. Resume signing while its blockhash is valid.
      if (block.blockHeight > attempt.lastValidBlockHeight) {
        await this.transition(lease, attempt, "CANCELLED", { code: "RESERVATION_EXPIRED" }, x);
        return x;
      }
      // A reserved-but-unsigned attempt is still an unseen signature: without a
      // valid receipt for exactly this reserved plan the publisher never signs.
      return this.signAndSend(lease, intent, hash, attempt, this.requireApproval(attempt, approval));
    }
    // Height is taken from the block at exactly slot x; the status answer must
    // be at least as new, so an inclusion at or before x would be visible
    // unless status history is pruned (covered by the landing search).
    const [status] = await this.statuses([attempt.signature!], x);
    if (status?.finalized) {
      if (status.failed) return this.failed(lease, attempt, status.slot);
      return this.complete(lease, intent, attempt, { kind: "SIGNATURE_STATUS", slot: status.slot });
    }
    if (status !== null) return this.result("PENDING", lease, attempt);
    if (block.blockHeight > attempt.lastValidBlockHeight) {
      await this.transition(lease, attempt, "EXPIRED", { code: "BLOCKHASH_EXPIRED", height: block.blockHeight.toString(), slot: x.toString() }, x);
      return x;
    }
    // Journaled but never confirmed as sent (crash between journal and send):
    // send the identical stored bytes; the signature cannot land twice.
    if (attempt.state === "SIGNED") return this.sendStored(lease, attempt);
    return this.result("PENDING", lease, attempt);
  }

  private async failed(lease: PublicationLease, attempt: Attempt, slot: bigint): Promise<PublicationStepResult> {
    if (attempt.state === "SIGNED") await this.transition(lease, attempt, "UNKNOWN", { code: "RECOVERED_AFTER_CRASH" }, slot);
    const failures = (await this.attempts(lease)).filter((a) => a.state === "FAILED").length + 1;
    const limit = this.config.maxFailedAttempts ?? 3;
    await this.transition(lease, attempt, "FAILED", { code: "TRANSACTION_FAILED", slot: slot.toString() }, slot,
      failures >= limit ? "FAILED_ATTEMPT_LIMIT" : undefined);
    return this.result("FAILED", lease, attempt);
  }

  /**
   * Decides whether the intent's batch sequence is already occupied on chain
   * and by whom. Our own successful finalized signature is checked first, so a
   * landing of ours is never classified as foreign.
   */
  private async findLanding(intent: PublicationIntent, attempts: Attempt[], slot: bigint): Promise<Landing> {
    const sequence = BigInt(intent.batchSequence);
    const x = await this.chain.finalizedSlot(slot);
    const candidates = attempts.filter((a) => a.signature !== null && a.state !== "FAILED" && a.state !== "CANCELLED");
    if (candidates.length) {
      const found = await this.statuses(candidates.map((a) => a.signature!), x);
      const index = found.findIndex((s) => s?.finalized && !s.failed);
      if (index >= 0) return { kind: "ours", attempt: candidates[index], proof: { kind: "SIGNATURE_STATUS", slot: found[index]!.slot } };
    }
    const read = await this.chain.registryConfig(this.config.configPda, x);
    const config = this.checkConfig(read.value, intent);
    if (config.currentBatchSequence < sequence) return { kind: "none", config, contextSlot: read.contextSlot };
    // The config already shows the sequence at read.contextSlot, so segment
    // reads at least that new must contain the entry if one of ours wrote it.
    const lookup = async (segmentPda: string, minSlot: bigint) => {
      const r = await this.chain.ledgerSegment(segmentPda, minSlot);
      const entry = r.value && r.value.registry === this.config.configPda
        ? r.value.entries.slice(0, r.value.entryCount).find((e) => e.batchSequence === sequence) : undefined;
      return { entry, contextSlot: r.contextSlot };
    };
    for (const segmentPda of [...new Set(candidates.map((a) => a.segmentPda))]) {
      let { entry, contextSlot } = await lookup(segmentPda, read.contextSlot);
      // Absence is only concluded from two consistent reads.
      if (entry === undefined) ({ entry, contextSlot } = await lookup(segmentPda, contextSlot));
      if (entry === undefined) continue;
      const mismatch = anchorEntryMismatch(intent, entry);
      if (mismatch !== null) {
        const again = await lookup(segmentPda, contextSlot);
        if (again.entry === undefined) return { kind: "unproven" };
        const second = anchorEntryMismatch(intent, again.entry);
        if (second === null) entry = again.entry;
        else if (second === mismatch) return { kind: "foreign", reason: `ANCHOR_MISMATCH_UNATTRIBUTED:${mismatch}`, error: "ANCHOR_COMMITMENT_MISMATCH", contextSlot: again.contextSlot };
        else return { kind: "unproven" };
      }
      // Proof by ledger entry (status history unavailable): every committed
      // field matches, including the manifest hash (commits the operation ID
      // via leavesObjectUri) and the operator; exactly one journaled signed
      // attempt targeted this segment, so the signature is attributable.
      const inSegment = candidates.filter((a) => a.segmentPda === segmentPda);
      if (inSegment.length !== 1) return { kind: "unproven" };
      return { kind: "ours", attempt: inSegment[0], proof: { kind: "LEDGER_ENTRY", contextSlot } };
    }
    return { kind: "foreign", reason: "CHAIN_CONFLICT", error: "PUBLICATION_CHAIN_CONFLICT", contextSlot: read.contextSlot };
  }

  private async advance(lease: PublicationLease, intent: PublicationIntent, hash: string, attempts: Attempt[], slot: bigint, approval?: PublicationApprovalReceipt): Promise<PublicationStepResult> {
    const landing = await this.findLanding(intent, attempts, slot);
    if (landing.kind === "ours") return this.complete(lease, intent, landing.attempt, landing.proof);
    if (landing.kind === "unproven") throw new PublicationError("PUBLICATION_LANDING_UNPROVEN");
    if (landing.kind === "foreign") {
      await this.block(lease, landing.reason, landing.contextSlot);
      throw new PublicationError(landing.error);
    }
    const config = landing.config;
    if (config.paused) throw new PublicationError("REGISTRY_PAUSED");
    if (config.currentBatchSequence + 1n !== BigInt(intent.batchSequence) || hexOf(config.lastAnchorHash) !== intent.previousAnchorHash) {
      await this.block(lease, "CHAIN_CONFLICT", landing.contextSlot);
      throw new PublicationError("PUBLICATION_CHAIN_CONFLICT");
    }
    if (attempts.filter((a) => a.state === "FAILED").length >= (this.config.maxFailedAttempts ?? 3)) {
      await this.block(lease, "FAILED_ATTEMPT_LIMIT");
      throw new PublicationError("PUBLICATION_MAINTENANCE_REQUIRED");
    }
    // A changed operator key cannot sign this intent; the exit is maintenance.
    if (this.signer.address !== intent.operator) throw new PublicationError("PUBLICATION_SIGNER_MISMATCH");
    // There is no live attempt here, so any approval is stale: a new attempt is
    // reserved only by `review` and signed only from a live PREPARED attempt in
    // `reconcile`. Nothing reserves or signs from `advance` any more.
    throw new PublicationError(approval === undefined ? "PUBLICATION_INTENT_APPROVAL_REQUIRED" : "PUBLICATION_ATTEMPT_PLAN_MISMATCH");
  }

  private async findOpenSegment(dayUtc: number, slot: bigint): Promise<{ address: Address; index: number }> {
    const count = this.config.segmentsPerDay ?? 3;
    for (let index = 0; index < count; index += 1) {
      const [address] = await findLedgerSegmentPda({ config: this.config.configPda, dayUtc, segmentIndex: index }, { programAddress: this.config.programId });
      const segment = (await this.chain.ledgerSegment(address, slot)).value;
      if (segment === null) {
        if (index === 0) throw new PublicationError("LEDGER_SEGMENT_MISSING");
        continue;
      }
      if (segment.sealed === 0 && segment.entryCount < segment.capacity) return { address, index };
    }
    throw new PublicationError("LEDGER_SEGMENT_FULL");
  }

  /**
   * Reserves the exact next unsigned attempt (PREPARED) durably, with a plan
   * hash over its bytes, lifetime, fee, attempt/day/segment and cluster. It
   * never signs or sends. The signer only ever sees bytes read back from here.
   */
  private async reserveAttempt(lease: PublicationLease, intent: PublicationIntent, hash: string, slot: bigint): Promise<Attempt> {
    const { segment, blockhash, prepared, simulation, feeLamports, feeLimitLamports, cluster } = await this.buildAttempt(intent, slot);
    if (!simulation.ok) throw new PublicationError("SIMULATION_FAILED");
    const attemptId = randomUUID();
    await workflowTransaction(this.pool, async (c) => {
      await assertPublicationLease(c, lease);
      const existing = (await c.query(ATTEMPTS_SQL, [lease.operationId])).rows.map(attemptOf);
      if (existing.some((a) => a.state !== "EXPIRED" && a.state !== "FAILED" && a.state !== "CANCELLED")) {
        throw new PublicationError("PUBLICATION_ATTEMPT_IN_FLIGHT");
      }
      const attemptNo = existing.length + 1;
      const planHash = attemptPlanHash({
        intentHash: hash, attemptNo, cluster, programId: intent.programId, configPda: intent.configPda,
        operator: intent.operator, registryId: intent.registryId, segmentPda: segment.address, segmentIndex: segment.index,
        dayUtc: blockhash.dayUtc, recentBlockhash: blockhash.blockhash,
        lastValidBlockHeight: blockhash.lastValidBlockHeight.toString(),
        feeLamports: feeLamports.toString(), feeLimitLamports: feeLimitLamports.toString(), messageBase64: prepared.messageBase64,
      });
      await c.query(`INSERT INTO wf_publication_tx(attempt_id,operation_id,attempt_no,intent_hash,fence,worker,segment_pda,segment_index,day_utc,
          recent_blockhash,last_valid_block_height,context_slot,message_bytes,simulation,cluster,fee_lamports,fee_limit_lamports,plan_hash)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
      [attemptId, lease.operationId, attemptNo, hash, lease.fence, lease.worker, segment.address, segment.index, blockhash.dayUtc,
        blockhash.blockhash, blockhash.lastValidBlockHeight.toString(), blockhash.contextSlot.toString(), Buffer.from(prepared.messageBase64, "base64"),
        JSON.stringify(simulation), cluster, feeLamports.toString(), feeLimitLamports.toString(), planHash]);
      await c.query("INSERT INTO wf_publication_tx_event(attempt_id,state,fence,worker,detail) VALUES($1,'PREPARED',$2,$3,$4)",
        [attemptId, lease.fence, lease.worker, JSON.stringify({ planHash, feeLamports: feeLamports.toString(), feeLimitLamports: feeLimitLamports.toString(), cluster })]);
      await this.bump(c, lease, blockhash.contextSlot);
    });
    return (await this.attempts(lease)).find((a) => a.attemptId === attemptId)!;
  }

  /**
   * Builds the next unsigned publish-anchor attempt for `slot` without
   * reserving or signing it. Quotes the fee and enforces the bound; a missing
   * quote fails closed. Used by review/reserve so an operator approves the exact
   * bytes, lifetime, fee and plan.
   */
  private async buildAttempt(intent: PublicationIntent, slot: bigint): Promise<{
    segment: { address: Address; index: number };
    blockhash: { blockhash: string; lastValidBlockHeight: bigint; contextSlot: bigint; dayUtc: number };
    prepared: ReturnType<typeof prepareAnchorTransaction>;
    simulation: SimulationResult;
    feeLamports: bigint;
    feeLimitLamports: bigint;
    cluster: string;
  }> {
    const x = await this.chain.finalizedSlot(slot);
    const block = await this.chain.finalizedBlock(x);
    const guard = BigInt(this.config.dayBoundaryGuardSeconds ?? 300);
    const secondOfDay = ((block.blockTime % 86_400n) + 86_400n) % 86_400n;
    if (secondOfDay < guard || secondOfDay >= 86_400n - guard) throw new PublicationError("PUBLICATION_LEDGER_DAY_BOUNDARY");
    const dayUtc = ledgerDay(new Date(Number(block.blockTime) * 1000));
    const segment = await this.findOpenSegment(dayUtc, x);
    const [rolePda] = await findRolePda({ config: this.config.configPda, operator: this.signer.address }, { programAddress: this.config.programId });
    const blockhash = await this.chain.latestBlockhash(x);
    const prepared = prepareAnchorTransaction({
      programId: this.config.programId, configPda: this.config.configPda, rolePda, segmentPda: segment.address,
      operator: this.signer.address, blockhash: blockhash.blockhash, lastValidBlockHeight: blockhash.lastValidBlockHeight,
      batchSequence: BigInt(intent.batchSequence), registryVersion: BigInt(intent.registryVersion),
      cursorStart: BigInt(intent.cursorStart), cursorEnd: BigInt(intent.cursorEnd),
      merkleRoot: Buffer.from(intent.merkleRoot, "hex"), manifestHash: Buffer.from(intent.manifestHash, "hex"),
      previousAnchorHash: Buffer.from(intent.previousAnchorHash, "hex"), leafCount: intent.leafCount,
      schemaVersion: intent.schemaVersion, hashAlgorithm: intent.hashAlgorithm, treeAlgorithm: intent.treeAlgorithm,
    });
    // Fail closed: no signature is ever produced without a bounded fee quote.
    let feeLamports: bigint;
    try { feeLamports = await this.chain.feeForMessage(prepared.messageBase64); }
    catch { throw new PublicationError("PUBLICATION_FEE_QUOTE_UNAVAILABLE"); }
    if (feeLamports < 0n) throw new PublicationError("PUBLICATION_FEE_QUOTE_UNAVAILABLE");
    const feeLimitLamports = this.feeLimit();
    if (feeLamports > feeLimitLamports) throw new PublicationError("PUBLICATION_FEE_EXCEEDS_LIMIT");
    const simulation = await this.chain.simulate(prepared.transactionBase64);
    return { segment, blockhash: { ...blockhash, contextSlot: x, dayUtc }, prepared, simulation, feeLamports, feeLimitLamports, cluster: this.cluster() };
  }

  /**
   * No-send review that RESERVES the exact next unsigned attempt (PREPARED) and
   * returns the durable `attemptPlanHash` the operator must approve. It never
   * signs or sends. When a live signed attempt exists there is nothing new to
   * approve (reconcile via `run` without a plan); when a valid reservation
   * already exists the same plan is returned; a reservation whose blockhash
   * expired is cancelled and replaced.
   */
  async review(lease: PublicationLease): Promise<PublicationReview> {
    lease = { ...lease };
    if (lease.registryId !== this.config.registryId) throw new PublicationError("PUBLICATION_LEASE_LOST");
    return this.exclusive(lease.operationId, async () => {
      await this.checkChainIdentity();
      const op = await this.operation(lease);
      const items = await this.store.items(lease);
      const excluded = (await this.pool.query(`SELECT 1 FROM wf_publication_item i JOIN wf_version_excluded x USING(event_id)
        WHERE i.operation_id=$1 LIMIT 1`, [lease.operationId])).rowCount;
      if (excluded) throw new PublicationError("PUBLICATION_VERSION_EXCLUDED");
      const slot = await this.chain.finalizedSlot(op.contextSlot);
      const { intent, hash } = await this.ensureIntent(lease, items, slot);
      let attempts = await this.attempts(lease);
      // Decide whether a plan must be (re)reserved. A live signed attempt is
      // reconciled without any approval; a valid reservation is reused; an
      // expired reservation is cancelled first.
      let reserved: Attempt | null = null;
      if (op.blockedReason === null && !attempts.some((a) => a.signature !== null && LIVE.includes(a.state))) {
        let prepared = attempts.find((a) => a.state === "PREPARED");
        if (prepared !== undefined) {
          const x = await this.chain.finalizedSlot(slot);
          const block = await this.chain.finalizedBlock(x);
          if (prepared.planHash !== null && block.blockHeight <= prepared.lastValidBlockHeight) {
            reserved = prepared;
          } else {
            await this.transition(lease, prepared, "CANCELLED", { code: "RESERVATION_EXPIRED" }, x);
            attempts = await this.attempts(lease);
          }
        }
        if (reserved === null) reserved = await this.reserveAttempt(lease, intent, hash, slot);
        attempts = await this.attempts(lease);
      }
      const base: PublicationReview = {
        operationId: lease.operationId, intentHash: hash, registryId: intent.registryId, programId: intent.programId,
        configPda: intent.configPda, operator: intent.operator, operatorKeyId: intent.operatorKeyId,
        batchSequence: intent.batchSequence, registryVersion: intent.registryVersion,
        previousAnchorHash: intent.previousAnchorHash, cursorStart: intent.cursorStart, cursorEnd: intent.cursorEnd,
        merkleRoot: intent.merkleRoot, manifestHash: intent.manifestHash, leafCount: intent.leafCount,
        members: items.map((item) => ({ eventId: item.eventId, recordId: item.recordId, version: item.version, operation: item.operation, payloadHash: item.payloadHash })),
        blockedReason: op.blockedReason,
        attemptStates: attempts.map((attempt) => ({ attemptNo: attempt.attemptNo, state: attempt.state })),
        hasSignedAttempt: attempts.some((attempt) => attempt.signature !== null),
        hasLiveSignedAttempt: attempts.some((attempt) => attempt.signature !== null && LIVE.includes(attempt.state)),
        segmentPda: null, segmentIndex: null, blockhash: null, lastValidBlockHeight: null, simulation: null,
        cluster: this.cluster(), genesisHash: this.genesis(), attemptPlanHash: null, attemptNo: null,
        feeLamports: null, feeLimitLamports: this.feeLimit().toString(),
        messageBase64: null,
      };
      if (reserved === null) return base;
      return {
        ...base,
        segmentPda: reserved.segmentPda, segmentIndex: reserved.segmentIndex,
        blockhash: reserved.recentBlockhash, lastValidBlockHeight: reserved.lastValidBlockHeight.toString(),
        simulation: reserved.simulation, attemptPlanHash: reserved.planHash, attemptNo: reserved.attemptNo,
        feeLamports: reserved.feeLamports === null ? null : reserved.feeLamports.toString(),
        messageBase64: reserved.messageBytes.toString("base64"),
      };
    });
  }

  /**
   * Non-reserving read used by the runtime's `run` pre-check: the semantic
   * intent hash, whether a live signed attempt exists, and the plan hash of an
   * already-reserved (still valid) attempt if one exists. It never reserves.
   */
  async inspect(lease: PublicationLease): Promise<{ intentHash: string; hasLiveSignedAttempt: boolean; attemptPlanHash: string | null }> {
    lease = { ...lease };
    if (lease.registryId !== this.config.registryId) throw new PublicationError("PUBLICATION_LEASE_LOST");
    return this.exclusive(lease.operationId, async () => {
      await this.checkChainIdentity();
      const op = await this.operation(lease);
      const items = await this.store.items(lease);
      const excluded = (await this.pool.query(`SELECT 1 FROM wf_publication_item i JOIN wf_version_excluded x USING(event_id)
        WHERE i.operation_id=$1 LIMIT 1`, [lease.operationId])).rowCount;
      if (excluded) throw new PublicationError("PUBLICATION_VERSION_EXCLUDED");
      const slot = await this.chain.finalizedSlot(op.contextSlot);
      const { hash } = await this.ensureIntent(lease, items, slot);
      const attempts = await this.attempts(lease);
      const hasLiveSignedAttempt = attempts.some((a) => a.signature !== null && LIVE.includes(a.state));
      let attemptPlanHash: string | null = null;
      if (op.blockedReason === null && !hasLiveSignedAttempt) {
        const prepared = attempts.find((a) => a.state === "PREPARED");
        if (prepared && prepared.planHash !== null) {
          const x = await this.chain.finalizedSlot(slot);
          const block = await this.chain.finalizedBlock(x);
          if (block.blockHeight <= prepared.lastValidBlockHeight) attemptPlanHash = prepared.planHash;
        }
      }
      return { intentHash: hash, hasLiveSignedAttempt, attemptPlanHash };
    });
  }

  private async signAndSend(lease: PublicationLease, intent: PublicationIntent, hash: string, attempt: Attempt, approval: PublicationApprovalReceipt): Promise<PublicationStepResult> {
    const operator = intent.operator as Address;
    const messageBase64 = attempt.messageBytes.toString("base64");
    const transactionBase64 = Buffer.from(getTransactionEncoder().encode({ messageBytes: attempt.messageBytes, signatures: { [operator]: null } } as any)).toString("base64");
    if (!Buffer.from(getTransactionDecoder().decode(Buffer.from(transactionBase64, "base64")).messageBytes).equals(attempt.messageBytes)) {
      throw new PublicationError("PUBLICATION_JOURNAL_INVALID");
    }
    if (attempt.planHash === null) throw new PublicationError("PUBLICATION_JOURNAL_INVALID");
    // A receipt is a one-shot capability for exactly one reserved plan: if it
    // was already consumed by a recorded signature, it cannot arm another one.
    const receiptHash = publicationApprovalReceiptHash(approval);
    const consumed = await this.pool.query(
      "SELECT 1 FROM wf_publication_tx_event WHERE state='SIGNED' AND detail->>'approvalReceiptHash'=$1 LIMIT 1",
      [receiptHash],
    );
    if (consumed.rowCount) throw new PublicationError("PUBLICATION_APPROVAL_CONSUMED");
    // The signer may wait for a human; the caller must keep renewing the lease
    // meanwhile. If the lease is lost, the SIGNED write below fails and the
    // PREPARED reservation is resumed (or cancelled after expiry) by the holder.
    let signed: string;
    try {
      signed = await this.signer.signTransaction({
        transactionBase64, messageBase64, intentHash: hash, intent, simulation: attempt.simulation,
        operationId: attempt.operationId,
        segmentPda: attempt.segmentPda, segmentIndex: attempt.segmentIndex, dayUtc: attempt.dayUtc,
        blockhash: attempt.recentBlockhash, lastValidBlockHeight: attempt.lastValidBlockHeight.toString(),
        attemptNo: attempt.attemptNo, cluster: attempt.cluster ?? this.cluster(),
        feeLamports: (attempt.feeLamports ?? 0n).toString(), feeLimitLamports: (attempt.feeLimitLamports ?? this.feeLimit()).toString(),
        attemptPlanHash: attempt.planHash, approvalReceipt: approval,
      });
    } catch {
      await this.transition(lease, attempt, "CANCELLED", { code: "SIGNING_REJECTED" });
      throw new PublicationError("SIGNING_REJECTED");
    }
    let signature: string;
    try { signature = validateSignedTransaction(signed, messageBase64, operator); }
    catch (error) {
      if (!(error instanceof SignedTransactionError)) throw error;
      await this.transition(lease, attempt, "CANCELLED", { code: error.code });
      throw new PublicationError(error.code);
    }
    await workflowTransaction(this.pool, async (c) => {
      await assertPublicationLease(c, lease);
      if ((await c.query("SELECT wf_publication_tx_state($1) AS s", [attempt.attemptId])).rows[0].s !== "PREPARED") throw new PublicationError("PUBLICATION_STEP_RACE");
      await c.query("INSERT INTO wf_publication_tx_signed(attempt_id,signed_bytes,signature) VALUES($1,$2,$3)", [attempt.attemptId, Buffer.from(signed, "base64"), signature]);
      await c.query("INSERT INTO wf_publication_tx_event(attempt_id,state,fence,worker,detail) VALUES($1,'SIGNED',$2,$3,$4)",
        [attempt.attemptId, lease.fence, lease.worker, JSON.stringify({ attemptPlanHash: attempt.planHash, approvalReceiptId: approval.claims.receiptId, approvalReceiptHash: receiptHash, approvalActor: approval.claims.actor, approvalDevice: approval.claims.device })]);
    });
    await this.config.afterAttemptStored?.(attempt.attemptId);
    const stored = (await this.attempts(lease)).find((a) => a.attemptId === attempt.attemptId)!;
    return this.sendStored(lease, stored);
  }

  /** The only send path: bytes come from the journal, never from memory. */
  private async sendStored(lease: PublicationLease, attempt: Attempt): Promise<PublicationStepResult> {
    if (attempt.state !== "SIGNED" || attempt.signedBytes === null) throw new PublicationError("TRANSACTION_STATE_INVALID");
    let returned: string | null = null;
    try { returned = await this.chain.send(attempt.signedBytes.toString("base64")); }
    catch { /* outcome unknown: reconciled by signature lookup, never by re-signing */ }
    if (returned === attempt.signature) {
      await this.transition(lease, attempt, "SUBMITTED", {});
      return this.result("SUBMITTED", lease, attempt);
    }
    await this.transition(lease, attempt, "UNKNOWN", { code: returned === null ? "SUBMIT_RESPONSE_UNKNOWN" : "SUBMIT_SIGNATURE_MISMATCH" });
    return this.result("UNKNOWN", lease, attempt);
  }

  /** Trusted completion of a landing of ours (see file header for the two proofs). */
  private async complete(lease: PublicationLease, intent: PublicationIntent, attempt: Attempt, proof: LandingProof): Promise<PublicationStepResult> {
    const sequence = BigInt(intent.batchSequence);
    const minSlot = proof.kind === "LEDGER_ENTRY" ? proof.contextSlot : proof.slot;
    const read = async (at: bigint) => {
      const r = await this.chain.ledgerSegment(attempt.segmentPda, at);
      const entry = r.value && r.value.registry === this.config.configPda
        ? r.value.entries.slice(0, r.value.entryCount).find((e) => e.batchSequence === sequence) : undefined;
      return { entry, contextSlot: r.contextSlot, segment: r.value };
    };
    const discrepancy = async (field: string, at: bigint) => {
      if (attempt.state === "SIGNED") await this.transition(lease, attempt, "UNKNOWN", { code: "RECOVERED_AFTER_CRASH" }, minSlot);
      await this.transition(lease, attempt, "ANCHOR_MISMATCH", { field, proof: proof.kind, ...(proof.kind === "ARCHIVAL_TRANSACTION" ? { archivalCheckId: proof.checkId } : {}) }, at, `ANCHOR_MISMATCH:${field}`);
      throw new PublicationError("ANCHOR_COMMITMENT_MISMATCH");
    };
    const first = await read(minSlot);
    // Missing segment/entry at a context >= the landing is an RPC
    // inconsistency, not evidence of a mismatch: retry later.
    if (first.entry === undefined) throw new PublicationError("PUBLICATION_ANCHOR_NOT_VISIBLE");
    let entry = first.entry;
    let contextSlot = first.contextSlot;
    const mismatch = anchorEntryMismatch(intent, entry);
    if (mismatch !== null) {
      const again = await read(first.contextSlot);
      if (again.entry === undefined) throw new PublicationError("PUBLICATION_ANCHOR_NOT_VISIBLE");
      const second = anchorEntryMismatch(intent, again.entry);
      if (second !== null && second === mismatch) return discrepancy(mismatch, again.contextSlot);
      if (second !== null) throw new PublicationError("PUBLICATION_ANCHOR_NOT_VISIBLE");
      entry = again.entry; contextSlot = again.contextSlot;
    }
    const anchorHashHex = toHex(anchorHash({
      registryIdHash: registryIdHash(intent.registryId), batchSequence: entry.batchSequence, registryVersion: entry.registryVersion,
      sourceCursorStart: entry.sourceCursorStart, sourceCursorEnd: entry.sourceCursorEnd, merkleRoot: Uint8Array.from(entry.merkleRoot),
      manifestHash: Uint8Array.from(entry.manifestHash), snapshotHash: Uint8Array.from(entry.snapshotHash),
      previousAnchorHash: Uint8Array.from(entry.previousAnchorHash), leafCount: entry.leafCount, schemaVersion: entry.schemaVersion,
      flags: entry.flags, hashAlgorithm: entry.hashAlgorithm, treeAlgorithm: entry.treeAlgorithm,
      operatorPubkey: new Uint8Array(getAddressEncoder().encode(entry.operator)), publishedAt: entry.publishedAt,
    }));
    // Cross-check the recomputed anchor hash with program state: equal to
    // lastAnchorHash while ours is the newest anchor, otherwise equal to the
    // successor entry's previousAnchorHash when that entry is in this segment.
    const configRead = await this.chain.registryConfig(this.config.configPda, contextSlot);
    const config = this.checkConfig(configRead.value, intent);
    if (config.currentBatchSequence < sequence) throw new PublicationError("PUBLICATION_ANCHOR_NOT_VISIBLE");
    const successor = config.currentBatchSequence === sequence ? null
      : (await read(configRead.contextSlot)).segment?.entries.find((e) => e.batchSequence === sequence + 1n);
    const expected = config.currentBatchSequence === sequence ? hexOf(config.lastAnchorHash) : successor ? hexOf(successor.previousAnchorHash) : null;
    // Terminal, recorded once: the blocked path never re-runs completion.
    if (expected !== null && expected !== anchorHashHex) return discrepancy("anchorHash", configRead.contextSlot);
    if (attempt.state === "SIGNED") await this.transition(lease, attempt, "UNKNOWN", { code: "RECOVERED_AFTER_CRASH" }, minSlot);
    const detail = proof.kind === "SIGNATURE_STATUS"
      ? { proof: "SIGNATURE_STATUS", slot: proof.slot.toString(), rationale: "finalized successful status of this journaled signature; ledger entry matches the intent" }
      : proof.kind === "ARCHIVAL_TRANSACTION"
      ? { proof: "ARCHIVAL_TRANSACTION", slot: proof.slot.toString(), archivalCheckId: proof.checkId, rationale: "archival RPC returned this journaled signature as finalized and successful; ledger entry matches the intent" }
      : { proof: "LEDGER_ENTRY", entryContextSlot: contextSlot.toString(),
          rationale: "signature status unavailable (pruned history); finalized ledger entry at this sequence matches every compared intent field, including manifestHash (commits operationId via leavesObjectUri) and operator (our signer), and exactly one journaled signed attempt targeted this segment",
          transactionSlot: null };
    await workflowTransaction(this.pool, async (c) => {
      await assertPublicationLease(c, lease);
      const current = (await c.query("SELECT wf_publication_tx_state($1) AS s", [attempt.attemptId])).rows[0].s as AttemptState;
      if (current !== attempt.state) throw new PublicationError("PUBLICATION_STEP_RACE");
      if (!TRANSITIONS[current].includes("FINALIZED")) throw new PublicationError("TRANSACTION_STATE_INVALID");
      await c.query("INSERT INTO wf_publication_tx_event(attempt_id,state,fence,worker,detail) VALUES($1,'FINALIZED',$2,$3,$4)",
        [attempt.attemptId, lease.fence, lease.worker, JSON.stringify({ ...detail, contextSlot: configRead.contextSlot.toString(), anchorHashCheck: expected === null ? "unavailable" : "matched" })]);
      await c.query(`INSERT INTO wf_publication_anchor(operation_id,attempt_id,registry_id,batch_sequence,intent_hash,merkle_root,manifest_hash,
          anchor_hash,signature,slot,proof,segment_pda,fence,worker) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
      [lease.operationId, attempt.attemptId, lease.registryId, intent.batchSequence, attempt.intentHash, intent.merkleRoot,
        intent.manifestHash, anchorHashHex, attempt.signature, proof.kind === "LEDGER_ENTRY" ? null : proof.slot.toString(), proof.kind,
        attempt.segmentPda, lease.fence, lease.worker]);
      await this.bump(c, lease, configRead.contextSlot);
      await c.query("UPDATE wf_publication SET state='FINALIZED',lease_until=clock_timestamp() WHERE operation_id=$1", [lease.operationId]);
    });
    return { status: "FINALIZED", operationId: lease.operationId, attemptId: attempt.attemptId, attemptNo: attempt.attemptNo,
      signature: attempt.signature!, slot: proof.kind === "LEDGER_ENTRY" ? null : proof.slot.toString(), anchorHash: anchorHashHex, proof: proof.kind };
  }
}
