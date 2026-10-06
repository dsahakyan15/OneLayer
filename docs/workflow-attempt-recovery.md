# Durable workflow attempts

The English Registry workflow workspace prepares a durable receipt before sending a mutation. Credentials, payloads and idempotency keys are never persisted in browser storage. The ordinary workflow request-result table remains the immutable source of mutation outcomes.

## API

All routes require a current server session scoped to the deployment registry. Mutations require CSRF. The prepare request is `{path, body}`, where `path` is an exact draft create/edit/submit/approve/reject/commit path and `body` is that mutation's original JSON object.

| Route | Behavior |
| --- | --- |
| `POST /v2/admin/workflow/attempts` | Prepare or recover an outstanding receipt for the canonical path/body under this actor and registry. Returns `attemptId`, `idempotencyKey`, `state`, `draftId`, `action`, `recordId`. Never executes a mutation. |
| `GET /v2/admin/workflow/attempts` | List this actor's outstanding, currently authorized receipts. `PREPARED` means the server has no committed workflow result; it does not prove a request was never sent. `COMPLETED` means the immutable result exists. |
| `POST /v2/admin/workflow/attempts/:id/ack` | Acknowledge a completed receipt after the client validates a fresh read of the same draft UUID. The response and its replay key remain immutable. |
| `POST /v2/admin/workflow/attempts/:id/cancel` | Explicitly cancel an unconfirmed receipt. Shares the mutation's transaction lock; a committed result cannot be cancelled, and a cancelled key can never mutate later. |
| `GET /v2/admin/workflow/drafts?after=:uuid` | Up to 50 currently readable draft summaries, without payload. `nextCursor` is the last visible UUID when another visible row exists. Hidden UUIDs and hidden counts are never exposed. |

A failed prepare sends no mutation. After a lost prepare response, preparing the same canonical body recovers the same receipt. After a lost mutation response or a failed follow-up read, reload the pending list and open the returned draft. Opening a receipt does not send another mutation. If the receipt remains PREPARED, supply the original input to retry under its original key, or explicitly cancel it. Input is intentionally not duplicated in the receipt journal.

Acknowledgement ends that logical attempt. A deliberate new create with the same input afterwards receives a new key; the old key always replays its original response. This permits a new draft after rejecting or editing an earlier draft without weakening unknown-outcome retries. No automatic retry queue prepares new attempts after acknowledgement.

## Authorization and concurrency

Preparation checks both read and write resource scopes, current/base fields removed by replacements, and the actual draft/approval permission. Recovery rechecks stored field paths and the latest draft. Narrowing access hides the receipt. Hidden historical receipts are retained but do not charge the limit of 100 currently recoverable outstanding receipts, avoiding permanent quota lockout after a policy change.

Preparation and acknowledgement serialize by actor/registry. Mutations, cancellation, and publication maintenance sharing `wf_request` serialize by actor/registry/key. Prepared keys bind to the exact request commitment across these routes. Cancellation is permanent and fenced before mutation execution. The journal, acknowledgements and cancellations reject UPDATE/DELETE/TRUNCATE; the runtime role retains only SELECT/INSERT on these new tables.

Migration 0020 is additive. It contains no payload, password, cookie, CSRF token, signing key or recovery share. This journal covers workflow commands; publication workers have their separate durable queue and transaction reconciliation. A COMMITTED draft remains database workflow state, never proof of finalized publication or certificate suitability.

Draft discovery scans private rows in batches of 100, stops once it finds a visible page and its continuation, and refuses an oversized scan after 10,000 rows with `DRAFT_LIST_BUSY`. That refusal returns no partial rows or hidden cursor. Concurrent edits can change which drafts are visible between pages; opening a draft always checks its current read scope again.
