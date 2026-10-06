# Verification result V2

`POST /v2/verify` accepts the same Certificate Package and `requiredCommitment`
(`finalized` only) as `/v1/verify`. Package, signature, Merkle and on-chain
protocol bytes are unchanged. The response has `resultVersion: 2` and HTTP 422
for INVALID, otherwise HTTP 200. HTTP success means a result was produced;
it does not mean a record is currently suitable.

The wire result separates:

| Field | Meaning |
| --- | --- |
| `status` | INVALID, DISPUTED, REVOKED, HISTORICAL or UNKNOWN |
| `proofs.status` / `anchorSlot` | VERIFIED historical inclusion, or NOT_ESTABLISHED |
| `registry.registryId` / `status` | Registry identity checked against policy and chain, or NOT_ESTABLISHED |
| `incidents.status` | CHECKED, STALE, UNAVAILABLE, INDEX_INCONSISTENT or NOT_CHECKED |
| `incidents.indexedThroughSlot` / `finalizedHeadSlot` / `lagSlots` | Observed incident watermark and finalized head; decimal strings |
| `lifecycle.status` / `code` / `reported` | UNKNOWN, or UNAUTHENTICATED advisory projection with its reported certificate state/version |
| `checkedAt` | Local verifier observation time, ISO timestamp; not a signed checkpoint |

There is deliberately no CURRENT value. An ACTIVE mutable projection with a
matching version still gives UNKNOWN. Null/error/mismatched IDs, a rollback
below the package version or a version outside u64 cannot establish currentness.
An advisory REVOKED or newer/replaced version can conservatively block use as
REVOKED/HISTORICAL, but remains explicitly UNAUTHENTICATED. A blocking incident
wins as DISPUTED. Invalid trust/signature/proofs/anchor cause INVALID and no
lifecycle lookup or disclosure; all disclosed values come from the proven package.

The exported `VerificationResultV2` type in `apps/verifier/src/verify-v2.ts` is the
runtime producer contract. All wire versions and slots are decimal strings.
The ordinary service-authenticated lifecycle transport proves the upstream's
service access control, not completeness or integrity of that mutable database.

Clients select V2 explicitly and show proof and current suitability separately.
Legacy V1 VERIFIED means historical proof only; a V1 response never becomes a
V2 current verdict. Unexpected versions/statuses must not produce a positive
currentness label. No automatic fallback to V1 on an unavailable V2 endpoint.

Remaining ticket 05 acceptance: an independently authenticated, complete and
fresh lifecycle source, connected to real issuance/revoke and rollback checks.
Production source trust provision and policy are still open; this increment
cannot claim them through a mutable database response or a fixture signature.
