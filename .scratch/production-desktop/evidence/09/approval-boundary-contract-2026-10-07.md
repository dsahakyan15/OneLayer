# Backend contract — authenticated approval receipts, publisher-boundary signing gate, pinned chain identity (H4/H5/M4)

Owner: backend implementation sub-agent r6 (this task).
Repo `/media/davit/DATA/projects/OneLayer`, branch `feat/pipeline-live-demo-20261006`,
HEAD `1317f28` + working changes. Draft PR #2. No commits, no devnet writes.
Consumers: launcher / `main.ts` owner (active), coordinator, reviewers.

This supersedes the approval-boundary claims of
`backend-attempt-approval-contract.md` (H3). The DTO names
(`approvedAttemptPlanHash`, `attemptPlanHash`, `PUBLICATION_*` codes) are unchanged;
the **internal** signing boundary is now unbypassable and the signer verifies an
independently issued, signed approval receipt.

---

## 1. What changed and why (review r3 H4/H5/M4)

- **H4:** `WorkflowPublisher.step()` defaulted to `allowNewWork: true` and
  `requirePlanApproval()` was a no-op without a hash, so a direct caller could
  reserve+sign+send with zero approval (PROBE-A). `allowNewWork` and the
  reserve+sign `newAttempt()` path are **removed**. `step()` now accepts only
  `{ approval: PublicationApprovalReceipt }`. Every new signature requires the
  receipt whose `attemptPlanHash` equals the exact reserved (PREPARED) attempt.
  Reconciliation of an already journaled signed attempt (SIGNED/SUBMITTED/
  UNKNOWN) still needs no approval and produces no new signature.
- **H5:** the signer's plan-hash recomputation was self-asserted (publisher
  supplied both sides). The signer now requires an Ed25519 **approval receipt**
  issued by a distinct approval key and verified against a **separately pinned**
  approval public key. The publisher only ever holds the verifier capability
  (public key); the issuer private key is loaded at the API boundary
  (`main.ts`) and is never passed to `WorkflowPublisher` or the renderer.
- **M4:** `PublisherConfig.cluster` is mandatory (runtime-enforced) and the
  connected RPC's `getGenesisHash` is compared against the pinned expected
  genesis hash before every reservation/signing. No `solana:local` default for
  an arbitrary URL. The signer policy requires an explicit cluster and pins the
  expected genesis hash.

## 2. Lab isolation limits (honest)

This is a **software lab issuer** in the same Node process as the API. It gives
object-level separation (the issuer key is never handed to the publisher or the
signer; the signer only holds the public key) and cryptographic separation
(forged/self-minted receipts fail signature verification). It is **not** crypto
isolation of one Node process: a process compromise can read both keys.
Production requires an HSM/KMS/provider approval issuer with the same receipt
contract (tickets 16/22). No claim of production custody is made here.

## 3. Receipt contract (`apps/demo-api/src/publication-approval.ts`)

```ts
interface PublicationApprovalClaims {
  version: 1;
  domain: "ONELAYER:WORKFLOW:PUBLICATION-APPROVAL:V1";
  receiptId: string;        // uuid v4 nonce, unique per issuance
  operationId: string;      // uuid of the leased publication operation
  intentHash: string;       // 64 hex, semantic intent
  attemptPlanHash: string;  // 64 hex, exact reserved attempt commitment
  cluster: string;          // deployment cluster, e.g. "solana:devnet"
  genesisHash: string;      // pinned chain identity
  actor: string;            // authenticated principal (session username)
  device: string;           // authenticated device (session.deviceId ?? sessionId)
  issuedAt: string;         // ISO-8601
  expiresAt: string;        // ISO-8601, issuedAt < expiresAt <= issuedAt + 10 min
}
interface PublicationApprovalReceipt { claims: PublicationApprovalClaims; signature: string /* base64 Ed25519 */ }
interface PublicationApprovalBinding { operationId: string; intentHash: string; attemptPlanHash: string }
interface PublicationApprovalService {
  readonly publicKey: string; // pinned issuer key (base58 Solana address)
  issue(binding: PublicationApprovalBinding, actor: string, device: string): PublicationApprovalReceipt;
}
```

Verification (publisher **and** signer, independently) rejects:
bad shape/domain/version; bad signature against the pinned public key; binding
mismatch (operation/intent/plan hash); cluster/genesis mismatch; missing/blank
actor/device; uuid nonce invalid; `now > expiresAt` (`..._EXPIRED`),
`issuedAt > now + 30 s` (`..._NOT_YET_VALID`), TTL > 10 min.
Error codes: `PUBLICATION_APPROVAL_INVALID`, `_SIGNATURE`, `_MISMATCH`,
`_IDENTITY`, `_EXPIRED`, `_NOT_YET_VALID`, `_CONSUMED`,
`_ACTOR_REQUIRED`, `_UNAVAILABLE`, `_KEY_UNAVAILABLE`.
An exact plan replay cannot sign a different lifetime/message: the receipt binds
the plan hash (which commits the message bytes, blockhash, lastValidBlockHeight,
fee, attempt/day/segment, cluster). A receipt already recorded on a SIGNED
attempt is refused (`PUBLICATION_APPROVAL_CONSUMED`).

## 4. Publisher boundary (`WorkflowPublisher`)

```ts
step(lease, options?: { approval?: PublicationApprovalReceipt }): Promise<PublicationStepResult>
```

- `step(lease)` with no receipt: reconciliation is allowed; any path that would
  mint a new signature throws `PUBLICATION_INTENT_APPROVAL_REQUIRED`.
- `step(lease, { approval })`: a new signature is produced only for the live
  PREPARED attempt whose `plan_hash` equals `approval.claims.attemptPlanHash`
  and whose operation/intent/cluster/genesis match the receipt. Reserved bytes
  are signed verbatim (no second blockhash fetch).
- `advance()` no longer reserves or signs. With no live attempt it always
  refuses (`..._APPROVAL_REQUIRED` without a receipt, `..._ATTEMPT_PLAN_MISMATCH`
  with a stale one). A fresh attempt is only ever reserved by `review()`.
- `newAttempt()` is deleted. `allowNewWork` is deleted. There is no
  maintenance/test method that signs without a receipt.
- `PublisherConfig` (runtime-enforced; TypeScript fields stay optional only so
  the current `main.ts` compiles until the launcher owner integrates):
  - `cluster: string` — mandatory; invalid/missing ⇒
    `PUBLICATION_IDENTITY_UNCONFIGURED` at construction.
  - `genesisHash?: string` — override; otherwise pinned from the known cluster
    (`solana:devnet`, `solana:testnet`, `solana:mainnet-beta`); `solana:local`
    and unknown labels require an explicit genesis or refuse.
  - `approvalVerifier?: { publicKey: string; cluster: string; genesisHash: string; now?: () => Date }`
    — normally built by `WorkflowPublicationRuntime` from the approval service.
    Missing ⇒ signing paths refuse `PUBLICATION_APPROVAL_UNCONFIGURED`.
- Chain identity is checked (`getGenesisHash`) before every `review`/`step`/
  `inspect`: mismatch ⇒ `PUBLICATION_CHAIN_IDENTITY_MISMATCH`, RPC failure ⇒
  `PUBLICATION_CHAIN_IDENTITY_UNAVAILABLE`; nothing is reserved or signed.

## 5. Runtime and HTTP DTO

`WorkflowPublicationRuntime` constructor gains an optional 5th argument:

```ts
new WorkflowPublicationRuntime(pool, chain, signer, config, approvals?: PublicationApprovalService)
```

`run` approval request gains `actor`/`device` (session-derived; never from the
body):

```ts
run(registryId, worker, {
  attemptPlanHash?: string;   // required for a new signature
  intentHash?: string;        // optional defence-in-depth
  actor?: string;             // required when attemptPlanHash is present
  device?: string;            // required when attemptPlanHash is present
}, operationId?)
```

The runtime inspects the reserved plan, then asks the approval service to mint
the receipt for exactly that `{operationId, intentHash, attemptPlanHash}` and
passes it to the publisher. `POST /v2/admin/workflow/publications/run` body is
**unchanged** (`{ operationId?, approvedAttemptPlanHash?, approvedIntentHash? }`);
the admin route adds `actor: session.username`, `device: session.deviceId ??
session.sessionId` after `publication.submit` + resource checks. A missing
approval service ⇒ 503 `PUBLICATION_APPROVAL_UNAVAILABLE`; missing actor/device
⇒ 409 `PUBLICATION_APPROVAL_ACTOR_REQUIRED`. Receipt verification failures are
409 with their `PUBLICATION_APPROVAL_*` code. Role/CSRF behaviour is unchanged
(HTTP test covers forbidden roles).

## 6. Signer policy (`LocalKeyPublicationSigner.create`)

```ts
{
  registryId, programId, configPda,
  cluster: string,             // REQUIRED; no optional cluster check
  genesisHash?: string,        // default pinned from cluster
  approvalPublicKey?: string,  // REQUIRED (base58); must differ from the operator key
  now?: () => Date,            // test clock seam
}
```

The signer refuses (before touching the key): missing receipt
(`PUBLICATION_SIGNER_APPROVAL_REQUIRED`), receipt verification failure
(`PUBLICATION_APPROVAL_*`), cluster mismatch (`PUBLICATION_SIGNER_SCOPE`),
missing approval key at construction
(`PUBLICATION_SIGNER_APPROVAL_KEY_REQUIRED`), unconfigured identity
(`PUBLICATION_SIGNER_IDENTITY_UNCONFIGURED`), and the existing scope/intent/
transaction/plan-recompute guards. A direct `signTransaction` with a
self-generated matching plan hash but no valid receipt is refused.

## 7. Deployment startup contract for the `main.ts` owner (required changes)

New env var, required together with the existing three when publication is
configured:

```
ONELAYER_PUBLICATION_APPROVAL_KEY_FILE=/absolute/path/inside/key-store/approval-issuer.json
```

Hardened key-store rules apply (same allow-list as the signer: private
directory, 0600-class, no symlinks, Solana CLI 64-byte keypair JSON). The key
**must differ** from the operator/chain key; `loadPublicationApproval` refuses a
reused key. It must not be the renderer key or journal material.

Integration (only the publication block of `main.ts` changes):

```ts
import { loadPublicationApproval } from "./publication-approval.ts";

if (publicationConfig !== undefined) {
  const approvals = await loadPublicationApproval(publicationConfig); // issuer + pinned public key
  const signer = await LocalKeyPublicationSigner.create(publicationConfig.signerKeyFile, {
    registryId: REGISTRY_ID, programId, configPda: configAddress,
    cluster: DEPLOYMENT_CLUSTER,
    genesisHash: process.env.ONELAYER_RPC_GENESIS_HASH, // optional override
    approvalPublicKey: approvals.publicKey,             // NEW: pinned, distinct
  });
  publication = {
    runtime: new WorkflowPublicationRuntime(pool, new PublicationRpc(rpcUrl, programId), signer, {
      registryId: REGISTRY_ID, programId: programId as Address, configPda: configAddress,
      operatorKeyId: publicationConfig.operatorKeyId, keys: publicationConfig.keys,
      cluster: DEPLOYMENT_CLUSTER, maxFeeLamports: MAX_PUBLISH_FEE_LAMPORTS,
      genesisHash: process.env.ONELAYER_RPC_GENESIS_HASH, // optional override
    }, approvals.service),                               // NEW: 5th argument
    keys: publicationConfig.keys,
    operatorKeyId: publicationConfig.operatorKeyId,
  };
}
```

`main.ts` now wires this itself (the coordinator transferred that region). The
launcher/deploy owner still owns `deploy/devnet-demo/native`, which must
provision the distinct approval key and pass the two new variables:

```bash
# in provision_publication_keys():
if [[ ! -s "$publication_approval_file" ]]; then
  NO_DNA=1 solana-keygen new --no-bip39-passphrase --silent --force -o "$publication_approval_file"
fi
chmod 600 "$publication_approval_file"
# in start_process demo-api env ...:
ONELAYER_PUBLICATION_APPROVAL_KEY_FILE="$publication_approval_file" \
ONELAYER_PUBLICATION_CLUSTER="solana:devnet" \
```

Until then, a live stack with only the three legacy publication variables
refuses startup (`PUBLICATION_CONFIG_INCOMPLETE`) — fail closed, never a
fallback.

## 8. Migrations and DB

No new migration. The signed event detail records `approvalReceiptId` /
`approvalReceiptHash`; `0024_publication_attempt_approval.sql` is unchanged and
`0025` (recovery-owned) is untouched. Historical migrations are immutable.

## 9. Caller inventory (must all explicitly review + approve)

| Caller | Change |
|---|---|
| `workflow-runtime.ts` (production) | mints via service, passes actor/device |
| `apps/monitor/tests/harness/builder.mts` | test-only: explicit `review()` + receipt before each new attempt |
| `integration/workflow-publication-*.test.ts`, `publication-ambiguity`, `workflow-version-exclusion` | `stepReviewed` helper: `review()` then `step({approval})`; expiry needs a second review |
| `tests/publication-signer.test.ts` | real receipt fixture signed by a pinned test issuer |
| `tests/publication-config.test.ts` | approval key env required/incomplete matrix |
| `/tmp/opencode/r3-unguarded-step-probe.test.ts` | ported into `integration/workflow-publication-approval-boundary.test.ts` with inverted expectations |
