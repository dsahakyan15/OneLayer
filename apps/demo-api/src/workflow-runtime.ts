// Runtime consumer for the durable workflow publication (ticket 09).
//
// This is the missing link between a committed workflow version and a finalized
// on-chain anchor. It exposes exactly two operator-driven actions:
//
//   review(worker)  — ensures the deterministic intent is built and stored,
//                     then returns the exact bytes an operator must approve
//                     (program/config/operator, membership, root, simulation).
//                     It reserves, signs and sends nothing.
//   run(worker, approvedIntentHash) — advances the durable journal by one step.
//                     A NEW signature is produced only when the caller presents
//                     the intent hash returned by review; reconciliation of an
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

  constructor(
    private readonly pool: Pool,
    chain: PublicationChain,
    signer: PublicationSigner,
    config: PublisherConfig,
  ) {
    this.publisher = new WorkflowPublisher(pool, chain, signer, config);
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
    if (current !== null && (operationId === undefined || current.operationId === operationId)) return current;
    if (operationId !== undefined) return null;
    return this.store.claim(registryId, worker);
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
   * Advances one durable step. When no signed attempt exists yet, the caller
   * must present the `approvedIntentHash` returned by review; otherwise a new
   * payload would be signed unseen. Reconciliation of an already signed attempt
   * is allowed without a fresh approval.
   */
  async run(registryId: string, worker: string, approvedIntentHash?: string, operationId?: string): Promise<PublicationRunResult> {
    const lease = await this.leaseFor(registryId, worker, operationId);
    if (lease === null) return { status: "IDLE" };
    try {
      if (approvedIntentHash === undefined) {
        const current = await this.publisher.review(lease);
        if (!current.hasSignedAttempt) throw new WorkflowRuntimeError(409, "PUBLICATION_INTENT_APPROVAL_REQUIRED");
      } else {
        const current = await this.publisher.review(lease);
        if (current.intentHash !== approvedIntentHash) throw new WorkflowRuntimeError(409, "PUBLICATION_INTENT_APPROVAL_MISMATCH");
      }
      return await this.publisher.step(lease);
    } catch (error) {
      if (error instanceof PublicationError) {
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
