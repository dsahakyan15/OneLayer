# Registry Workflow V1 (synthetic backend contract)

Workflow tables and routes are isolated from legacy demo records. `POST /v2/admin/workflow/drafts` accepts `recordId`, `baseVersion`, `operation` (`upsert` or `tombstone`) and object `payload`. Tombstones require `{}` and preserve historical versions. Every mutation requires an `Idempotency-Key` scoped to registry and stable session username. Identical requests replay the result after current resource authorization; different content under a used key returns `IDEMPOTENCY_CONFLICT`.

`GET /v2/admin/workflow/drafts/:uuid` reads an authorized draft. POST actions `edit`, `submit`, `approve`, `reject`, `commit` take `expectedRevision`; all except edit also take exact `payloadHash` and `baseVersion`. Edit takes the new operation/payload, appends an immutable revision and resets approval. Submit requires DRAFT; independent approve/reject requires SUBMITTED; commit requires APPROVED. Every historical contributor, as well as the original creator, is prohibited from approval. A new edit after rejection or approval returns to DRAFT. Committed drafts cannot change.

The hash is SHA-256 over `ONELAYER:WORKFLOW:JSON:V1\n` followed by JSON with recursively sorted object keys, preserving array order, finite numbers only. Payload hash covers `{operation,payload}`. This protocol is distinct from Certificate Package canonicalization and does not change frozen certificate vectors. A row lock and expected revision protect draft changes; base-version compare-and-swap protects record publication. Immutable version, COMMIT audit and unique outbox event are written in the same PostgreSQL transaction. The outbox is append-only evidence; consumer delivery state belongs in ticket 09 tables.

## Signed source adapter

`ingestWorkflowSource(pool, trust, envelope)` is a trusted local adapter boundary, not a public HTTP ingestion route. `trust` pins registry ID, source ID, Ed25519 source key and a map of stable human IDs to public keys and draft/approve permissions. Provisioning this map and real upstream integrations remain external dependencies.

The event has `version:1`, registry/source IDs, positive safe-integer `cursor`, record ID, nonnegative safe-integer `baseVersion`, operation, payload, payload hash, creator and approver. All three detached signatures (source, creator, independent approver) sign `ONELAYER:WORKFLOW:SOURCE:V1\n` plus the same canonical event bytes. Signatures use unpadded base64url. An `authorized` boolean conveys no authority. Keys come exclusively from deployment-owned trust. Permission/key removal prevents subsequent ingestion and replay.

Cursor starts at 1 and increments by exactly one per source and registry. Gap/reordering returns `SOURCE_CURSOR_GAP` without advancing; the sender must supply missing events and retry. Identical signed event duplicates return the stored result; conflicting bytes at a used cursor return `SOURCE_EQUIVOCATION`. Physical `delete` is rejected; signed tombstone appends a new version. Cursor, deduplication evidence, version, audit and outbox commit atomically. Contiguity proves completeness only through the accepted cursor; it cannot prove the upstream has not withheld its tail. Production adapter must supply independently trusted high-watermark/health monitoring.

## Limits

Ticket 07 remains partial: stable human identity, permission refresh during in-flight transactions and production trust provisioning require its final integration and review. No desktop UI, source polling service, outbox delivery worker, chain publication or production source completeness claim is included here. Legacy demo writes do not become workflow-approved through coexistence with these tables.

Scope enforcement covers removed fields from the bound/current version for replacement and tombstone, including the current head check under a row lock at commit. Empty or dotted JSON object keys are rejected because the V1 authorization path grammar uses dot separators. Source creator and approver must use different Ed25519 public keys as well as different stable human IDs.

## Scoped committed-version reads

`GET /v2/admin/workflow/records/:recordId/versions/:version` accepts a positive integer version or `latest`. It requires a live session, `records.read` for the registry, and a single resource grant covering the record and every field in the requested historical payload. A denied or missing version returns the same 404 `RECORD_VERSION_NOT_FOUND`; denied/missing draft reads similarly return 404 `DRAFT_NOT_FOUND`. No aggregate count or approval/signature evidence is exposed. The response contains `recordId`, `version`, `payload`, `payloadHash`, `operation`, and `state:COMMITTED`. This is database workflow state, not a finalized anchor, Certificate Package, or proof of current suitability. Reading `latest` does not authorize older versions with different fields.

The workflow dispatcher snapshots request JSON before its first database wait so request hashing, scope checks and immutable revision insertion use the same bytes even if an in-process caller mutates its input.

## Contract revision V1.1 — publishable payload values (2026-09-24, ticket 09)

Versioned tightening of V1 input rules, enforced both on draft/source input (`payloadInput`) and again at commit (`appendWorkflowVersion` → `assertPublishablePayload`), so drafts stored under V1 are re-checked before they become versions:

- numbers must be safe integers; floats and integers outside ±(2^53−1) return `UNSUPPORTED_NUMBER`;
- an object key `__proto__` at any depth returns `RESERVED_FIELD_NAME` (JavaScript object handling can silently drop it from commitments);
- sibling keys that are equal after Unicode NFC normalization return `AMBIGUOUS_FIELD_PATH`, like empty or dotted keys.

Compatibility: the hash domains `ONELAYER:WORKFLOW:JSON:V1` and `ONELAYER:WORKFLOW:SOURCE:V1` and their canonical bytes are unchanged; V1.1 accepts a strict subset of V1 payloads, so every V1.1 payload hashes identically under V1. Payloads with floats, `__proto__` or NFC-colliding keys that V1 accepted can no longer be committed (open drafts fail at commit with the codes above) and already committed versions of that shape cannot be published by ticket 09 (the publication Builder rejects them). Only synthetic data exists under V1. Signed sources must stop emitting such values; a signed event carrying one is rejected before its cursor advances, so the source must re-sign a corrected event at the same cursor.

### Operational consequence for already committed V1 versions

Publication (ticket 09) processes ordered outbox events. Legacy versions that cannot be represented by FIELDMAP:V1 stop publication with `PUBLICATION_UNPUBLISHABLE_VERSION`. ADR-0009 and migration 0017 provide explicit exclusion without modifying the version or outbox history.

`POST /v2/admin/workflow/exclusions` requires `publication.maintenance`, record-wide read scope, an Idempotency-Key and `{recordId,version,payloadHash,correctedByVersion,correctedPayloadHash,reason}`. The correction must already exist on the same record, be a later publishable version (including tombstone), and match its hash. Publishable targets and intent-bound/anchored targets cannot be excluded. The proposal records the first authenticated approval. `POST /v2/admin/workflow/exclusions/:id/approve` binds `{payloadHash,correctedByVersion}` to the immutable proposal and records the second independent approval. Both people must be independent of all target-version authors; identities come from server sessions. Replays recheck permissions and resource scope.

Only two approvals make the decision effective. Fresh claims skip the event; an already claimed operation without intent is superseded with the remaining membership. Original membership, version, outbox, approvals and audit remain immutable. Read models expose `EXCLUDED_FROM_PUBLICATION`, `published:false`, `certificateEligible:false`, `current:false`. These are backend history/queue semantics; end-to-end Certificate Package issuance and verifier lifecycle integration remain ticket 09 work.
