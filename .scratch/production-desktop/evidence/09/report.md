# Evidence 09 — Durable workflow publication handoff

Commit: working tree on `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2` (existing unrelated changes preserved).
Environment: Linux, Node v24.10.0, PostgreSQL 17.10; synthetic disposable local clusters created by `isolatedPostgres`, no application database URL consumed.
Dataset: inline synthetic workflow versions (`first`, `second`, `later`); no personal data or external chain writes.

## Implemented invariant and interface

Migration `0011_workflow_publication.sql` and `WorkflowPublicationStore` persist a single unresolved publication operation per registry, immutable outbox membership, and append-only lease history. Claim creation/membership/history commit in one transaction. Concurrent workers serialize through a registry lock; takeover increments a decimal-string fencing token and preserves logical operation identity. DB time controls expiry. `items`, `renew`, and `release` require the current unexpired worker/fence. Versions are sorted by C-collated record ID and numeric version, independent of clock ordering. Membership does not change when new workflow versions arrive. Read-back checks both outbox/version hash agreement and actual operation/payload hash.

This is an internal worker storage interface, not an HTTP endpoint or an operational publisher. It intentionally has no finalization, outbox deletion, logical completion, or certificate issuance method. A released/expired operation is reclaimed as the same operation; later work stays blocked behind it until the trusted publication integration exists.

## Commands and results

- `node --test --experimental-transform-types apps/demo-api/integration/workflow-publication.test.ts`: 2/2 PASS, actual PostgreSQL and all migrations.
- `npm --prefix apps/demo-api run typecheck`: PASS.

Negative cases: simultaneous publishers; same-worker duplicate claim; lease expiry and fresh-pool restart; stale worker read/renew/release; foreign registry lease; mutation after selection; journal-insert crash rolls back operation and membership; immutable membership/history; corrupted payload evidence; invalid duration. Independent registries can claim independently.

An initial test teardown closed the cluster before a secondary pool and failed with connection termination. The test now closes its secondary pool before cluster teardown; rerun passed. No test failure was converted to skip.

## Migration and compatibility

Additive migration references existing immutable `wf_outbox` and its version evidence, without altering the legacy demo publisher or workflow writer. No automatic rollback/drop is provided: deleting these tables would discard durable lease history and outstanding membership. Existing migrations and fixtures are exercised in disposable databases.

## Unresolved acceptance

Ticket 09 remains incomplete. This slice does not implement deterministic protocol Builder mapping of arbitrary workflow fields, independent commitment validation, simulation, native trusted signer approval, persisted signed bytes, send/reconciliation, expiry replacement, local-validator finalization, disclosure policy, or certificate/lifecycle issuance. Tickets 02/03/04/08 must satisfy their remaining acceptance before a full trusted publication gate can close. No claim of production readiness or local-chain acceptance.

Reviewer: coordinator review requested; pending disposition. Next integration must keep the operation ID and immutable membership as the logical publication identity, store exact intent/signed attempt bytes before send, and add a trusted finalized-chain completion path before advancing later work. Do not expose a generic user-controlled state transition to FINALIZED.

---

# Evidence 09 (continuation 2026-09-24, revised after review rounds 1 and 2) — Deterministic intent, attempt journal, reconciliation, trusted finalized completion, maintenance procedures

Commit: working tree on `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2` (uncommitted; other agents' changes preserved, nothing committed).
Environment / OS / versions: Linux 6.8, Node v24.10.0, PostgreSQL 17.10 (disposable `isolatedPostgres` clusters, SQL_ASCII encoding), `solana-test-validator` 3.1.10 (Agave), `onelayer_registry.so` built from source, sha256 `db0c7203d771ed15b87fa418b810a555446fa991350f9dc7b0c2f39d36618ef9`.
Dataset ID/hash: inline synthetic workflow versions and synthetic keys; no personal data, no devnet/mainnet traffic.

This section replaces the earlier continuations. Wording that overstated guarantees was corrected in both review rounds (see the two disposition tables).

## Problem and invariant

Target invariant: **at most one logical anchor per operation's membership, and FINALIZED only from finalized chain data that agrees with the stored intent**. The operation ID plus immutable membership is the logical publication identity. What is enforced, and under which assumptions:

1. **Deterministic intent** (`src/publication-intent.ts`). Built once from membership plus a context read at a recorded finalized context slot (registry config, DB-clock `createdAt`, operator, cursor = events of operations already anchored on chain, i.e. FINALIZED or LANDED_DISCREPANCY). Commitments come only from existing `canonical-ts` / `merkle-ts` builders. Field mapping `ONELAYER:WORKFLOW:FIELDMAP:V1`; CBOR maps are null-prototype + `defineProperty` (`__proto__` stays committed; pinned vector). Exact bytes + domain hash stored before any attempt; every step re-hashes and rebuilds byte-for-byte with the same Builder (not an independent verifier; one unit test recomputes a leaf from primitives).
2. **Attempt journal.** Message bytes are reserved (`PREPARED`) under the fence before the signer is called; the signer sees only an unsigned transaction rebuilt from reserved bytes. Signed bytes + signature (`SIGNED`) are durable before send; only journaled bytes are sent. Rejection/substitution → `CANCELLED`. Journal writes check the fence under the row lock and compare the expected attempt state. Steps (and maintenance calls) of one operation are serialized by `pg_try_advisory_xact_lock` inside a transaction held on a dedicated connection for the whole call (`PUBLICATION_STEP_BUSY`); this needs 2 connections per step, works with PgBouncer transaction pooling (the lock lives in one open transaction), and requires `idle_in_transaction_session_timeout` above the longest step including signer approval. Each step re-validates every journaled attempt (signature over message; decoded message vs intent).
3. **Reconciliation with context slots.** Monotonic finalized `context_slot` watermark per operation; reads use `minContextSlot`. Expiry uses the height of the finalized block at exactly slot X plus a signature-status answer with context ≥ X (else `RPC_CONTEXT_STALE`). `EXPIRED` is an RPC-based judgement, **not a proof**; after it, the landing search reads at ≥ X (round-2 N5). Landing search order: (i) finalized successful status of any journaled signature → ours; (ii) otherwise, if the registry sequence is taken, the ledger entry in our attempts' segments (absence confirmed by two reads) — matching entry with exactly one journaled signed attempt in that segment → ours by **ledger-entry proof**; matching entry with several candidates → `PUBLICATION_LANDING_UNPROVEN` (retry); confirmed mismatch without a successful signature of ours → foreign (`ANCHOR_MISMATCH_UNATTRIBUTED:<field>`); no entry in our segments → foreign `CHAIN_CONFLICT`. Foreign blocks the operation.
4. **Ledger-entry proof (round-2 N2).** Used only when status history is unavailable. Rationale recorded in the FINALIZED event: every compared intent field matches, including `manifestHash` (commits the operation ID through `leavesObjectUri`, plus `createdAt`) and `operator` (our signer key), and exactly one journaled signed attempt targeted that segment, so its signature is attributable. The anchor row then has `proof='LEDGER_ENTRY'` and `slot=NULL`; issuance must resolve the transaction slot (archival RPC) before putting it into a Certificate Package.
5. **Trusted completion.** Only `complete()` writes FINALIZED. Segment read at ≥ landing slot/context; missing entry → `PUBLICATION_ANCHOR_NOT_VISIBLE` (retry); field mismatch terminal only if a second read reproduces it. Compared fields: those in `anchorEntryMismatch` (sequence, registry version, cursors, merkle root, manifest hash, previous anchor, zero snapshot, leaf count, schema, flags, algorithms, operator); `publishedAt` and entry position are not compared. Anchor hash is checked against `lastAnchorHash` (ours newest) or the next entry's `previousAnchorHash` in the same segment; otherwise recorded as `unavailable`.
6. **Landed with discrepancy (round-2 N1/N7).** When our own transaction is finalized (by status or entry proof) but the confirmed entry or the program's anchor hash disagrees with the intent, the attempt goes to `ANCHOR_MISMATCH` once and the operation is blocked; the blocked path never re-runs completion (`PUBLICATION_MAINTENANCE_REQUIRED`). Abandonment is refused (`PUBLICATION_FINALIZED_LANDING`: a successor would anchor the membership twice). The exit is `recordLandedDiscrepancy`: two people, reason, mandatory incident reference, audit row → terminal `LANDED_DISCREPANCY`, **no successor**, membership stays consumed and counts for later cursors; later registry work proceeds. No on-chain incident notice is opened by this code (incident reference is an external record).
7. **Abandonment** (`abandonForMaintenance`, no HTTP): only for a blocked operation or with an explicit `forceReason`; two people, reason, optional incident ref, audit + abandonment record, successor with the same membership via `superseded_by`, journals kept. Refused while a signed attempt may still land, when any landing of ours is proven, or when it cannot be ruled out. A SIGNED attempt whose transaction finalized with an error is recorded FAILED (via UNKNOWN).
8. **Maintenance identities are procedural, not authenticated**: caller-asserted strings normalized with NFKC, control/format (zero-width) characters removed, whitespace collapsed, compared case-insensitively; DB CHECK (`wf_publication_person_ok`) enforces trimmed, single-spaced, no control or zero-width bytes (NFKC itself only in the application, because `normalize()` needs a UTF8 server). Replaced by authenticated principals from ticket 07.
9. **Maintenance-required state**: `blocked_reason` set once (CHAIN_CONFLICT, ANCHOR_MISMATCH:*, ANCHOR_MISMATCH_UNATTRIBUTED:*, FAILED_ATTEMPT_LIMIT after 3 on-chain FAILED). Operator-key change → `PUBLICATION_SIGNER_MISMATCH` (exit: forced abandonment).
10. **Ledger day** from finalized block time; no new attempt within 300 s of UTC midnight.
11. **Unpublishable committed versions (round-2 N3)**: a version the mapping cannot represent yields `PUBLICATION_UNPUBLISHABLE_VERSION` with `{eventId, recordId, version, cause}`. **The registry's publication queue stops at that version** (a successor inherits it). No quarantine implemented; owner options in `docs/registry-workflow-contract.md` (two-signature exclusion with audit, or compensating version + exclusion).

## Database defence in depth (0013)

Triggers are defence in depth against accidental or partial writes, **not a security boundary**: a role able to write every table consistently can still forge a full history. Enforced: append-only incl. `BEFORE TRUNCATE` on all 0011/0013 publication tables; operations inserted only as OPEN/unblocked; membership inserted only into an OPEN operation created by the same transaction; lease check locks the operation row (`FOR UPDATE`) and requires current fence/owner/unexpired/OPEN on intent, attempt, event, anchor, abandonment and discrepancy inserts; intent hash and columns vs bytes; one live-or-anchored intent per (registry, sequence); contiguous attempts only after non-landable predecessors; event-sequence legality mirroring the TS map; signed bytes only after PREPARED; anchor must match stored intent and a FINALIZED attempt (proof kind, nullable slot only for LEDGER_ENTRY); abandonment requires block or force reason, current block reason and no landed/mismatched attempt; discrepancy requires an ANCHOR_MISMATCH attempt of a blocked operation; operation state machine (terminal FINALIZED / ABANDONED / LANDED_DISCREPANCY, monotonic fence and context slot, block never cleared, each terminal state needs its record).

**Required for the next slices (not done):** separate DB roles (worker, maintenance, read-only issuance, migration owner); issuance re-verifies the anchor on chain and resolves `slot` for LEDGER_ENTRY proofs; custody (ticket 16) must define recovery when read-back verification fails for reasons outside the publisher — key rotation of `idKey`/`fieldKeyMaster`, program or config migration, `PUBLICATION_PAYLOAD_MISMATCH` from corrupted storage: today those stop the operation with no exit (round-2 N4, not implemented by decision).

## Changed interface

- `src/workflow-publication.ts`: `PublicationError(code, detail?)`; claim ignores ABANDONED membership; exports `assertPublicationLease`, `lockRegistryPublication`, `journal`.
- `src/publication-intent.ts`: proto-safe CBOR, typed NFC errors.
- `src/publication-rpc.ts`: `PublicationChain`, `PublicationRpc` (context-slot reads).
- `src/publication-worker.ts`: `step`, `abandonForMaintenance`, `recordLandedDiscrepancy`, `maintenancePerson`; config `maxFailedAttempts`, `dayBoundaryGuardSeconds`; FINALIZED result carries `proof`.
- `src/registry-workflow.ts`: `assertPublishablePayload` (contract V1.1) at input and commit; `docs/registry-workflow-contract.md` V1.1 + queue-stop section.
- `db/migrations/0013_workflow_publication_chain.sql` (only ever applied to disposable databases).

## Commands and results (after round 2)

- `npm --prefix apps/demo-api run typecheck`: PASS.
- `npm --prefix apps/demo-api test`: 118/118 PASS (9 in `tests/publication-intent.test.ts`).
- `node --test --experimental-transform-types apps/demo-api/integration/workflow-publication-chain.test.ts`: 7/7 PASS; `workflow-publication.test.ts` + `registry-workflow.test.ts` + `workflow-access.test.ts`: 7/7 PASS. Real disposable PostgreSQL, no skips.
- The N5 regression test was checked to fail without the fix (worker proceeded to a second attempt's simulation) and pass with it.
- `workflow-publication-validator.test.ts` at 15:18 UTC: 1/1 PASS (≈123 s), live validator, real `PublicationRpc`, one send, stored anchor hash = program `last_anchor_hash`, second operation batch 2. Can fail within ±5 min of UTC midnight (day guard).
- Full `test:integration` not re-run after the revisions.

## Negative cases

Fake chain implements a subset of program rules (no ed25519 verification, roles, PDA or capacity checks; the validator test covers the real program). Covered: timeout-after-send; entry not visible → retry; crash after SIGNED → same bytes sent by another worker; stale fence (step and direct SQL); out-of-sequence event; fence decrease; TRUNCATE; concurrent steps → one BUSY; expired blockhash → attempt 2, one entry; lagging status node → `RPC_CONTEXT_STALE`; lagging account node after EXPIRED → `RPC_CONTEXT_STALE`, no attempt 2; pruned status → EXPIRED then ledger-entry proof FINALIZED (`slot` NULL, rationale recorded); abandonment without block → `MAINTENANCE_NOT_BLOCKED`, with force but landed → refused; our tx landed with wrong root → ANCHOR_MISMATCH, repeated steps give MAINTENANCE_REQUIRED (no loop), abandonment refused, zero-width self-approval and missing incident rejected, `LANDED_DISCREPANCY` recorded, no successor, later work proceeds; same for program anchor-hash disagreement; foreign anchor → CHAIN_CONFLICT → abandonment → successor publishes; paused registry; signing rejection / substituted bytes; corrupted intent; day boundary; failing journal insert; FAILED limit; unpublishable V1 float → typed error with event/record/version; membership insert after creation and non-OPEN operation insert rejected; failed SIGNED attempt at abandonment → UNKNOWN → FAILED.

## Migration / rollback implications

0013 alters 0011 objects (drops per-registry and per-event UNIQUE, replaced by partial index/triggers; extends lease-journal actions). No down-migration (would discard signed-bytes evidence, maintenance records and anchor linkage). Contract V1.1 is a subset of V1.

## Limitations and what is NOT verified

- Certificate issuance, disclosure policy, lifecycle hand-off (acceptance 4) — open.
- Native signer approval — adapter only. During a long signer wait the caller must renew the lease in parallel; if it lapses, the SIGNED write fails with `PUBLICATION_LEASE_LOST` and the next holder resumes the PREPARED reservation (or cancels it after expiry). No renewal loop exists.
- Maintenance identities are procedural strings (see 8).
- `LANDING_UNPROVEN` remains for matching entries with several candidate attempts in one segment; exit needs an archival RPC (maintenance refuses by design).
- `ANCHOR_MISMATCH_UNATTRIBUTED` (confirmed mismatch, no successful signature of ours visible) may, with pruned history, actually be our transaction; forced abandonment then risks a second anchor of the membership — owner decision needed (e.g. require archival RPC confirmation first).
- FIELDMAP/intent/cursor need Protocol/Verifier review; key custody undecided; single RPC endpoint; no metrics/alerting.

## Review findings / disposition (round 1)

| Finding | Disposition |
|---|---|
| MAJOR-1 lag/pruning, step race | Fixed (context slots, exact-slot height, landing search, serialization, CAS); residual N5 fixed in round 2. |
| MAJOR-2 stale ANCHOR_MISMATCH | Fixed (min context = landing, retry on absence, confirmed mismatch). |
| MAJOR-3 no exit | Abandonment (round 1) + landed-discrepancy procedure, block/force gating (round 2). |
| MAJOR-4 `__proto__` | Fixed + contract V1.1 + vector. |
| MAJOR-5 DB bypasses | Hardened as defence in depth (rounds 1–2); role separation deferred. |
| MINOR-1..5 | Fixed (reservation, chain-time day, bindings, FAILED limit, NFC/float). |
| Evidence claims 1–8 | Rewritten (EXPIRED is a judgement; fake is a subset; triggers are defence in depth; compared-field list; same-Builder rebuild; qualified "one attempt"/"no second transaction"/identity claims). |

## Review round 2 disposition

| Finding | Disposition |
|---|---|
| N1 MAJOR anchorHash loop | Fixed: ANCHOR_MISMATCH recorded once; blocked path never re-runs completion; terminal `LANDED_DISCREPANCY` via two-person `recordLandedDiscrepancy` with mandatory incident ref, no successor. Test covers merkleRoot and anchorHash cases. |
| N2 MAJOR LANDING_UNPROVEN liveness | Fixed: ledger-entry proof (all fields incl. manifestHash/operator, exactly one journaled attempt in the segment), rationale in FINALIZED event, anchor `proof=LEDGER_ENTRY`, `slot` NULL. Test: pruned status history. |
| N3 MAJOR unpublishable V1 | Typed `PUBLICATION_UNPUBLISHABLE_VERSION` with event/record/version; queue stop stated in contract and here; quarantine options listed; not implemented. Test. |
| N4 verify failure without exit | Recorded as custody requirement (ticket 16); not implemented. |
| N5 stale slot after EXPIRED | Fixed in step (max(slot, X)) and abandonment; regression test verified failing without the fix. |
| N6 abandon leaves UNKNOWN | Fixed (UNKNOWN → FAILED based on actual state). Test. |
| N7 own landed tx treated as foreign | Fixed: our successful signatures are checked first; abandonment refused for ANCHOR_MISMATCH/landed; test rewritten (discrepancy path instead of successor). |
| N8 insert/item/lock guards | Fixed: OPEN-only operation insert; membership only in the creating transaction into an OPEN operation; lease check locks the operation row. Tests for (a)(b). |
| N9 advisory lock | Switched to `pg_try_advisory_xact_lock` in a held transaction; failed ROLLBACK destroys the connection (`release(true)`); requirements documented (2 connections, idle-in-transaction timeout). |
| N10 identity normalization | NFKC, control/zero-width removal, whitespace collapse in TS; DB CHECK for control/zero-width/whitespace; documented as procedural until ticket 07. Unit test. |
| INFO force / lease renewal | Abandonment needs `blocked_reason` or `forceReason` (DB CHECK + guard); lease renewal during signer described above. |
| Evidence 1–7 | Corrected: LANDING_UNPROVEN narrowed and its exit described; discrepancy is terminal without successor (previously suggested abandonment after our own landed mismatch); abandonment refusals listed accurately; step-lock mechanism and pooling requirements; queue stop on unpublishable versions; identities procedural; LEDGER_ENTRY anchors lack slot. |

Reviewer: coordinator-run independent reviews (round 1: 5 MAJOR/5 MINOR/8 evidence; round 2: 3 MAJOR/7 MINOR/INFO/7 evidence); round-2 fixes await re-review.

## Next and handed-over contracts

Issuance must read `wf_publication_anchor` + stored intent, re-verify on chain, resolve `slot` for LEDGER_ENTRY proofs, rebuild proofs from stored leaves and apply disclosure policy; never issue for LANDED_DISCREPANCY or ABANDONED operations. `WorkflowPublisher.step` stays the only FINALIZED writer; `abandonForMaintenance` and `recordLandedDiscrepancy` are the only exits.

## ADR-0009 bounded continuation — 2026-10-01

Base commit: `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2`, shared dirty workspace retained. Environment: Node v24.10.0, PostgreSQL 17.10 (Homebrew), disposable clusters created by `isolatedPostgres`; synthetic records, signer, chain and archive only.

Inspected pre-existing uncommitted ADR-0009 worker/maintenance/migration implementation. Added `integration/publication-ambiguity.test.ts`. Fixed a reproduced SQL NULL bypass in 0017: a correctly hashed FOREIGN_PROVEN record with an absent `attempt.proof` previously passed the `NOT IN` check. The guard now explicitly rejects missing/null proofs. This changes the not-yet-deployed migration; no production migration was run.

Coordinator review also identified that `getFirstAvailableBlock` and `getSlot` do not prove gap-free transaction history. `ArchivalChain.historyFromSlot()` now permits null (unknown completeness). Generic `ArchivalRpc` returns null for coverage; missing transactions produce `UNRESOLVED:HISTORY_COMPLETENESS_UNKNOWN` and cannot authorize cancellation. Positive finalized transactions still support recovery/discrepancy, and finalized failed attempts remain evidence of failure. A provider-specific trusted complete-history adapter is required to prove absence; URL and ID alone are insufficient. This is intentionally a fail-closed operational limitation, not a claim that a production archive is configured.

Checks:

- Before the SQL fix, the new suite reproduced missing rejection of forged FOREIGN_PROVEN proof (2 passed / 1 failed).
- `node --test --experimental-transform-types apps/demo-api/integration/publication-ambiguity.test.ts apps/demo-api/integration/workflow-publication-chain.test.ts`: 10/10 PASS, zero skips (before the subsequent raw-RPC completeness hardening).
- The archival regression uses the real ArchivalRpc adapter with a synthetic fetch endpoint returning current tip, low first block and missing transaction while the fake chain actually contains our landing. It must stay INCONCLUSIVE, then a trusted synthetic archive identifies our landing correctly.

Additional negative cases: pruned own mismatched landing cannot be force-abandoned through worker or direct SQL; matching own landing finalizes from archive; mismatched own landing becomes LANDED_DISCREPANCY with no successor; live blockhash, missing coverage and lagging archive stay INCONCLUSIVE; cancellation requires two distinct permission-bearing synthetic sessions, exact evidence hash and newest check; one approval and superseded approvals do not unblock publication. Approved foreign cancellation creates one successor and an audit row without sending again during investigation. The test invokes the maintenance dispatcher with synthetic sessions, not a new end-to-end OIDC authentication test.

Remaining acceptance: certificates/disclosure/lifecycle, native signer, complete-history provider deployment/attestation, production custody and independent protocol review remain open. Execution stays in-review. Existing older notes about owner decision on forced ambiguity are superseded by accepted ADR-0009 and this tested fail-closed path; no production readiness is claimed.
