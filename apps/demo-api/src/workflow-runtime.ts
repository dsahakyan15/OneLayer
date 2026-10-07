// Runtime consumer for the durable workflow publication (ticket 09).
//
// This is the missing link between a committed workflow version and a finalized
// on-chain anchor. It exposes exactly two operator-driven actions:
//
//   review(worker)  — ensures the deterministic intent is built and stored,
//                     then RESERVES the exact next unsigned attempt and returns
//                     the per-attempt approval commitment (program/config/
//                     operator, membership, root, reserved blockhash/lifetime,
//                     fee quote and bound, attempt/day/segment, simulation).
//                     It signs and sends nothing.
//   run(worker, { attemptPlanHash }) — advances the durable journal by one step.
//                     A NEW signature is produced only for the reserved attempt
//                     whose plan hash the caller presents; reconciliation of an
//                     already journaled signed attempt needs no fresh approval.
//
// The signer is a lab software adapter behind that explicit reviewed submit;
// production signer isolation is ticket 16/22.
import type { Address } from "@solana/kit";
import type { Pool } from "pg";
import {
  WorkflowPublisher,
  type PublicationReview,
  type PublicationSigner,
  type PublicationStepResult,
  type PublisherConfig,
} from "./publication-worker.ts";
import type { PublicationApprovalService } from "./publication-approval.ts";
import { expectedGenesisHash } from "./publication-identity.ts";
import type { PublicationChain } from "./publication-rpc.ts";
import { PublicationError, WorkflowPublicationStore, type PublicationLease } from "./workflow-publication.ts";

export class WorkflowRuntimeError extends Error {
  constructor(public status: number, public code: string) { super(code); }
}

export interface PublicationStatus {
  operations: Array<Record<string, unknown>>;
  anchors: Array<Record<string, unknown>>;
}

export type PublicationRunResult =
  | PublicationStepResult
  | { status: "IDLE" }
  | { status: "ERROR"; operationId: string; code: string };

export class WorkflowPublicationRuntime {
  readonly publisher: WorkflowPublisher;
  private readonly store: WorkflowPublicationStore;
  /** Issuer capability; deliberately NOT passed to the publisher, which only
   * receives the pinned verifier public key. */
  readonly #approvals: PublicationApprovalService | undefined;

  constructor(
    private readonly pool: Pool,
    chain: PublicationChain,
    signer: PublicationSigner,
    config: PublisherConfig,
    approvals?: PublicationApprovalService,
  ) {
    this.#approvals = approvals;
    const verifier = approvals === undefined || config.cluster === undefined ? {} : {
      approvalVerifier: {
        approvalPublicKey: approvals.publicKey,
        cluster: config.cluster,
        genesisHash: expectedGenesisHash(config.cluster, config.genesisHash),
      },
    };
    this.publisher = new WorkflowPublisher(pool, chain, signer, { ...config, ...verifier });
    this.store = new WorkflowPublicationStore(pool);
  }

  /** Open/blocked operations plus finalized anchors for one registry. */
  async status(registryId: string): Promise<PublicationStatus> {
    const [operations, anchors] = await Promise.all([
      this.pool.query(
        `SELECT p.operation_id::text, p.state, p.blocked_reason, p.created_at,
                (SELECT count(*) FROM wf_publication_item i WHERE i.operation_id = p.operation_id)::int AS record_count,
                a.batch_sequence::text AS batch_sequence, a.finalized_at,
                (SELECT count(*) FROM demo_certificate c WHERE c.anchor_operation_id = p.operation_id)::int AS certificate_count
           FROM wf_publication p
           LEFT JOIN wf_publication_anchor a USING(operation_id)
          WHERE p.registry_id = $1
          ORDER BY p.created_at DESC LIMIT 50`,
        [registryId],
      ),
      this.pool.query(
        `SELECT a.operation_id::text, a.batch_sequence::text, a.anchor_hash, a.signature, a.slot::text, a.finalized_at,
                (SELECT count(*) FROM demo_certificate c WHERE c.anchor_operation_id = a.operation_id)::int AS certificate_count
           FROM wf_publication_anchor a
          WHERE a.registry_id = $1
          ORDER BY a.finalized_at DESC LIMIT 50`,
        [registryId],
      ),
    ]);
    return {
      operations: operations.rows.map((row) => ({
        operationId: row.operation_id, state: row.state, blockedReason: row.blocked_reason,
        recordCount: row.record_count, batchSequence: row.batch_sequence,
        finalizedAt: row.finalized_at, certificateCount: row.certificate_count,
      })),
      anchors: anchors.rows.map((row) => ({
        operationId: row.operation_id, batchSequence: row.batch_sequence, anchorHash: row.anchor_hash,
        signature: row.signature, slot: row.slot, finalizedAt: row.finalized_at, certificateCount: row.certificate_count,
      })),
    };
  }

  /** Acquires (or reuses) this worker's lease, without reserving an attempt. */
  private async leaseFor(registryId: string, worker: string, operationId?: string): Promise<PublicationLease | null> {
    const current = await this.store.leaseFor(registryId, worker);
    if (current !== null && (operationId === undefined || current.operationId === operationId)) return this.store.renew(current);
    return this.store.claim(registryId, worker, 30000, 100, operationId);
  }

  /** No-send review of what the next approval would sign. */
  async review(registryId: string, worker: string, operationId?: string): Promise<{ operationId: string; review: PublicationReview }> {
    const lease = await this.leaseFor(registryId, worker, operationId);
    if (lease === null) throw new WorkflowRuntimeError(409, operationId === undefined ? "PUBLICATION_QUEUE_EMPTY" : "PUBLICATION_OPERATION_NOT_LEASED");
    try {
      return { operationId: lease.operationId, review: await this.publisher.review(lease) };
    } catch (error) {
      throw this.domain(error, lease.operationId);
    }
  }

  /**
   * Advances one durable step. Any NEW signature requires the
   * `approvedAttemptPlanHash` returned by `review`, which committed the exact
   * reserved unsigned bytes, lifetime, fee, attempt/day/segment and cluster,
   * plus the authenticated `actor`/`device` the approval is bound to. The
   * runtime mints the signed approval receipt for exactly the inspected
   * reservation and passes it to the publisher; the issuer key never reaches
   * the publisher. Reconciliation or re-send of an already signed attempt is
   * allowed without a fresh approval and never mints a signature. A
   * stale/consumed plan hash can never arm a new lifetime.
   */
  async run(
    registryId: string,
    worker: string,
    approval?: { attemptPlanHash?: string; intentHash?: string; actor?: string; device?: string },
    operationId?: string,
  ): Promise<PublicationRunResult> {
    const lease = await this.leaseFor(registryId, worker, operationId);
    if (lease === null) return { status: "IDLE" };
    try {
      const current = await this.publisher.inspect(lease);
      if (approval?.intentHash !== undefined && current.intentHash !== approval.intentHash) {
        throw new WorkflowRuntimeError(409, "PUBLICATION_INTENT_APPROVAL_MISMATCH");
      }
      if (approval?.attemptPlanHash !== undefined && current.attemptPlanHash !== approval.attemptPlanHash) {
        throw new WorkflowRuntimeError(409, "PUBLICATION_ATTEMPT_PLAN_MISMATCH");
      }
      if (approval?.attemptPlanHash === undefined && !current.hasLiveSignedAttempt) {
        throw new WorkflowRuntimeError(409, "PUBLICATION_INTENT_APPROVAL_REQUIRED");
      }
      if (approval?.attemptPlanHash === undefined) return await this.publisher.step(lease);
      // Mint the approval receipt at the authorized boundary for exactly the
      // reserved plan the caller presented. actor/device are session-derived by
      // the HTTP route, never read from the request body.
      if (this.#approvals === undefined) throw new WorkflowRuntimeError(503, "PUBLICATION_APPROVAL_UNAVAILABLE");
      const actor = approval.actor;
      const device = approval.device;
      if (typeof actor !== "string" || actor.length === 0 || typeof device !== "string" || device.length === 0) {
        throw new WorkflowRuntimeError(409, "PUBLICATION_APPROVAL_ACTOR_REQUIRED");
      }
      const receipt = this.#approvals.issue({
        operationId: lease.operationId,
        intentHash: current.intentHash,
        attemptPlanHash: approval.attemptPlanHash,
      }, actor, device);
      return await this.publisher.step(lease, { approval: receipt });
    } catch (error) {
      if (error instanceof WorkflowRuntimeError) throw error;
      if (error instanceof PublicationError) {
        // A live attempt that expired mid-step, a plan that went stale between
        // inspect and step, or a refused approval receipt: approval/identity
        // problems are 409, never a generic soft error. An unconfigured
        // approval boundary is a hard 503 (fail closed).
        if (error.code === "PUBLICATION_APPROVAL_UNCONFIGURED") throw new WorkflowRuntimeError(503, error.code);
        if (error.code.startsWith("PUBLICATION_APPROVAL_")
          || error.code === "PUBLICATION_INTENT_APPROVAL_REQUIRED"
          || error.code === "PUBLICATION_ATTEMPT_PLAN_MISMATCH"
          || error.code.startsWith("PUBLICATION_CHAIN_IDENTITY")) {
          throw new WorkflowRuntimeError(409, error.code);
        }
        return { status: "ERROR", operationId: lease.operationId, code: error.code };
      }
      throw this.domain(error, lease.operationId);
    }
  }

  private domain(error: unknown, operationId: string): WorkflowRuntimeError {
    if (error instanceof WorkflowRuntimeError) return error;
    if (error instanceof PublicationError) return new WorkflowRuntimeError(409, error.code);
    return new WorkflowRuntimeError(503, `PUBLICATION_RUNTIME_UNAVAILABLE:${operationId}`);
  }
}
