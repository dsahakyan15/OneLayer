# Backend review r4 — independent READ-ONLY (round 4, post-r6)

Reviewer: independent read-only review sub-agent (model mimo-v2.6-pro).
Date: 2026-10-07. Repo `/media/davit/DATA/projects/OneLayer`, branch
`feat/pipeline-live-demo-20261006`, HEAD `bb227d5` + working changes (uncommitted).
Scope: backend publisher/runtime/signer approval boundary after DeepSeek r6 —
the r6 claims for H4 (no unguarded signing path), H5 (independently authenticated
approval receipt), M4 (pinned chain identity), consumed/reconcile/crash
semantics, body cannot mint actor/issuer authorization, unknown/public cluster
pin failures, startup fail-closed. No edits/staging/commits/resets; probes only
under `/tmp/opencode/`. No devnet writes (disposable PostgreSQL + FakeChain +
one local `solana-test-validator`).

## Concurrent-scope boundary (per coordinator)

Root owns the LOCAL validator launcher profile / namespace-isolated native+trust
and `apps/demo-api/scripts/local-demo.ts` (typecheck only; it imports
`ledgerDay` from `publication-worker.ts`, no publication edits). DeepSeek GUI
agent owns ONLY the `main.ts` `/v1/health` identity response (M6) and the
lab password/credential scoped principal/device bootstrap in
`admin-session.ts`/`postgres-session.ts`. **Nothing of that is counted as
evidence for, or attributed to, the publication receipt acceptance below.** The
guarded publication boundary was verified independently against the
publication-owned modules only. Root CI `fd6f3e2`/`bb227d5` (desktop/browser
PASS, umask fixture fix) touched no key policy.

## Tested source hashes (review binding; publication-owned)

```
4ce5fef0afbb…  apps/demo-api/src/publication-worker.ts
66be5ffe27a8…  apps/demo-api/src/publication-approval.ts
23520c58f26f…  apps/demo-api/src/publication-signer.ts
6c7013d17043…  apps/demo-api/src/publication-identity.ts
d1cec9212597…  apps/demo-api/src/publication-config.ts
adad2102a892…  apps/demo-api/src/publication-rpc.ts
6b9ac11952a0…  apps/demo-api/src/workflow-runtime.ts
78028dff3c03…  apps/demo-api/src/publication-intent.ts   (unchanged since r3)
```

---

## 0. Coordinator question first — does identity absence fail closed (lab cannot publish)?

**YES — fail closed at every layer; the lab cannot publish without explicit
verified identity. There is no fallback path.**

| Layer | Evidence (file:line) | Behaviour on identity absence |
|---|---|---|
| Startup config | `publication-config.ts:110-112` | no publication env ⇒ `undefined` (publication off); 3 legacy vars without `ONELAYER_PUBLICATION_CLUSTER` + `ONELAYER_PUBLICATION_APPROVAL_KEY_FILE` ⇒ throws `PUBLICATION_CONFIG_INCOMPLETE`, process exits (`tests/e2e/publication-startup.test.ts` 2/2 PASS executed) |
| HTTP surface | `admin.ts:3554` | no publication context ⇒ 503 `PUBLICATION_UNAVAILABLE` on every `…/publications*` route — the lab/desktop UI cannot review, run or publish |
| Publisher ctor | `publication-worker.ts:337-342` | missing/invalid `cluster` ⇒ `PUBLICATION_IDENTITY_UNCONFIGURED`; `solana:local`/unknown label without explicit `genesisHash` ⇒ `PUBLICATION_CHAIN_IDENTITY_UNCONFIGURED` (probe P-4) |
| Signer ctor | `publication-signer.ts:74-77` | no `approvalPublicKey` ⇒ `PUBLICATION_SIGNER_APPROVAL_KEY_REQUIRED`; approval key == operator key ⇒ `…_KEY_REUSED`; unverified cluster ⇒ `…_IDENTITY_UNCONFIGURED` (probe P-4) |
| Every review/step/inspect | `publication-worker.ts:703-713` (`checkChainIdentity`, called first in `stepLocked:665`, `review:1154`, `inspect:1219`) | live `getGenesisHash` vs pinned expected ⇒ mismatch `PUBLICATION_CHAIN_IDENTITY_MISMATCH`, RPC down `PUBLICATION_CHAIN_IDENTITY_UNAVAILABLE`; **nothing reserved or signed** (boundary test 4, probe P-4) |

Consequence for the launcher work: a LOCAL validator profile must export
`ONELAYER_PUBLICATION_CLUSTER` (e.g. `solana:local`) **and**
`ONELAYER_RPC_GENESIS_HASH=<that validator's genesis>` (contract
`backend-approval-boundary-contract.md` §7) plus the distinct approval key file,
or the stack either refuses startup or answers 503/409 — it will never publish
against an unpinned chain. `/v1/health`'s `cluster: "devnet"` fixture string
(`main.ts:539`, GUI-owned) is a display label and is **not** the publication
identity source; publication identity comes only from the env pin verified
against the connected node.

---

## 1. Method — actually executed (this run)

| # | Command / probe | Result |
|---|---|---|
| 1 | `npm --prefix apps/demo-api run typecheck` (twice, incl. after concurrent edits) | **PASS** (0 errors) |
| 2 | `npm --prefix apps/demo-api test` | **220/220 PASS** (matches author handoff) |
| 3 | `node --test integration/workflow-publication-approval-boundary.test.ts integration/workflow-publication-attempt-approval.test.ts` | **10/10 PASS** (H4/H5/M4 boundary + real-signer H4 + fee fail-closed + crash/restart) |
| 4 | `node --test integration/workflow-publication-chain.test.ts …-http …-approval …-certificate publication-ambiguity workflow-version-exclusion` | **19/19 PASS** |
| 5 | `node --test tests/e2e/publication-startup.test.ts` | **2/2 PASS** (configured runtime 401 not 503; partial config exits non-zero `PUBLICATION_CONFIG_INCOMPLETE`) |
| 6 | `ONELAYER_SBF_CACHE_DIR=/media/davit/DATA/.onelayer-agent-cache/20261007/sbf-cache node --test integration/workflow-publication-validator.test.ts` | **1/1 PASS** — real `solana-test-validator 3.1.10`, registry.so sha256 `db0c7203d771…` (matches r6 claim), `UNKNOWN → PENDING×10 → FINALIZED` |
| 7 | `/tmp/opencode/r4-approval-boundary-probe.test.ts` (independent, REAL `LocalKeyPublicationSigner` + hardened-store issuers + disposable PG + FakeChain + real `routeAdmin` HTTP) | **6/6 PASS** (re-run after concurrent edits: 6/6) |

Disposable PostgreSQL via `initdb` temp clusters; keys in `mkdtemp` homes
(Unix fs). No devnet writes; root's long-lived local validator on RPC 18899 was
not touched (my validator runs on random free ports).

---

## 2. Independent probes (my own, not the author's tests)

| Probe | Question | Outcome (file:line of refusal) |
|---|---|---|
| P-1 H4 | `step(lease)` / `step(lease,{allowNewWork:true})` with a live PREPARED reservation and the REAL signer; `newAttempt`/`stepInternalUnguarded` existence | Both refuse `PUBLICATION_INTENT_APPROVAL_REQUIRED` before any reservation (`publication-worker.ts:869-872`); 0 signatures, 0 sends, 0 rows before `review`; both methods absent on instance **and** `WorkflowPublisher.prototype`. Exact receipt signs exactly `review.messageBase64` once |
| P-2 H5 | Direct `LocalKeyPublicationSigner.signTransaction` (publisher bypassed) with: no receipt; attacker-key receipt; other-plan receipt; wrong-genesis receipt; expired; not-yet-valid; cluster swap; decodable byte-flip; undecodable flip; blank/tab/space principals; malformed hash | All refused before key use: `PUBLICATION_SIGNER_APPROVAL_REQUIRED` (`publication-signer.ts:105`), `PUBLICATION_APPROVAL_SIGNATURE` (`publication-approval.ts:216`), `_MISMATCH` (`:217-218`), `_IDENTITY` (`:220-221`), `_EXPIRED` (`:229`), `_NOT_YET_VALID` (`:228`), `PUBLICATION_SIGNER_SCOPE` (`publication-signer.ts:97`), plan recompute `PUBLICATION_SIGNER_APPROVAL_MISMATCH` (`:150-160`) on the decodable flip, `PUBLICATION_SIGNER_TRANSACTION_INVALID` (`:131`) on the raw flip; issuance refuses blank/control principals (`publication-approval.ts:160-164`) |
| P-3 body | Real `routeAdmin` HTTP run with body `{actor:"evil-body", device:"evil-device", approvalReceipt:{…}}` | 200 SUBMITTED; journal `approvalActor="operator-1"`, `approvalDevice="device-1"` (session-derived, `admin.ts:3592-3593`), `approvalReceiptId` a minted UUID. Body fields ignored — **body cannot mint actor/device/issuer authorization** |
| P-4 M4/startup | `expectedGenesisHash`/`assertClusterLabel` matrix; publisher/signer ctor refusals; `loadPublicationConfig` matrix | `solana:devnet` pins `EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG`; `solana:local`/`solana:mainnet` refuse without explicit genesis; explicit override honoured; evil/upper-case labels refuse; signer missing/reused approval key refuses; config: empty ⇒ `undefined`, legacy-3 ⇒ `PUBLICATION_CONFIG_INCOMPLETE`, same signer/approval file ⇒ `PUBLICATION_APPROVAL_KEY_REUSED`, bad cluster ⇒ `PUBLICATION_CLUSTER_INVALID` |
| P-5 replay | Two concurrent `step()` with the SAME receipt | Exactly **1** signature, **1** send, **1** `wf_publication_tx_signed` row, **1** SIGNED event carrying `approvalReceiptHash` (sha256-hex) + actor |
| P-6 surface | Issuer capability reachability from admin context | `runtime.approvals`/`#approvals` not reflectable; `publisher.issue` undefined — publisher holds only the verifier public key |

One probe expectation of mine was initially wrong (a raw byte flip fails
decoding → `TRANSACTION_INVALID`, not the recompute code); corrected to probe
both paths. No product defect.

---

## 3. r6 claim-by-claim verdict

| r6 claim | Verdict | Evidence |
|---|---|---|
| `allowNewWork`/reserve+sign `newAttempt()` removed; `step()` needs a receipt for every new signature; reconcile still approval-free and signature-free | **TRUE** | `publication-worker.ts:354-358` (only `options.approval`), `:1022-1046` (`advance` never reserves/signs, always refuses), `:931-942` (PREPARED → `requireApproval` → `signAndSend`; SIGNED → `sendStored` identical bytes); grep of `apps/demo-api/src` shows `step(` only in `workflow-runtime.ts:158/173`; P-1 |
| Publisher verifies issuer Ed25519 receipts only; issuer private key never reaches publisher | **TRUE** | `requireApproval` `:869-888` → `verifyPublicationApproval` (`publication-approval.ts:186-231`, signature `:213-216`); `approvalVerifier` carries public key only; P-6 |
| Runtime (`#approvals` private) mints only for the exact inspected reserved plan with session actor/device | **TRUE** | `workflow-runtime.ts:52` (ES private field), `:148-173` (inspect → bind `current.intentHash` + caller hash → `issue` → `step`); `admin.ts:3581-3595` body DTO unchanged; P-3 |
| LocalSigner pins distinct approval public key and verifies receipt before key use | **TRUE** | `publication-signer.ts:74-77` (required + distinct), `:105-119` (verify before `ed25519Sign` at `:133`); P-2 |
| Durable consumed-receipt journal | **TRUE (implemented; narrow reachability, see §5 I1)** | `signAndSend` `:1252-1257` + SIGNED event detail `:1287-1288`; boundary test forges the journal (immutable trigger disabled) to prove the guard; P-5 shows one-shot under replay |
| Live RPC genesis before review/step/inspect; explicit cluster/env + approval key at startup | **TRUE** | `checkChainIdentity` `:703-713` first in all three; `publication-config.ts:101-133`; `publication-identity.ts:13-46` (public pins verified against live networks; no `solana:local` default); startup e2e 2/2; P-4 |
| Same-Node lab issuer is object/crypto separation, NOT process isolation (production HSM/KMS = tickets 16/22) | **TRUE and honestly stated** | contract §2 + `publication-approval.ts` module header; **not treated as a defect** (lab scope) |

Receipt shape/domain/time/actor/device/hash/cluster/genesis checks are all
present in `verifyPublicationApproval` (`publication-approval.ts:190-230`):
version+domain `:194`, strict signature format `:195` (`BASE64` 86+`==`),
uuid nonce `:199`, hex64 hashes `:200-202`, genesis format `:204-207`,
actor/device pattern `:208-209` (no Cc/Cf), signature `:213-216`, binding
`operationId/intentHash/attemptPlanHash` `:217-218`, cluster/genesis `:220-221`,
TTL ≤ 10 min `:227`, not-yet-valid (+30 s skew) `:228`, expired `:229`.
Publisher and signer verify independently (`:875` and `publication-signer.ts:107`).

---

## 4. Prior findings — independent verdicts

| Finding | Status | Evidence |
|---|---|---|
| R3 H4 — `step()` default `allowNewWork=true` bypass (PROBE-A) | **FIXED** | deleted surface + inverted expectations in boundary test + P-1 |
| R3 H5 — signer self-asserted consistency only (PROBE-B) | **FIXED** | receipt verified against separately pinned key before key use; plan recompute retained as integrity guard (`publication-signer.ts:150-160`); P-2 |
| R3 M4 — self-labeled cluster (PROBE-C) | **FIXED** | mandatory cluster, pinned public genesis hashes, live `getGenesisHash` gate; P-4 |
| R2 H3 — semantic hash didn't bind blockhash/lvbh/fees | **FIXED, preserved** | `planHashFor` `:845-859` + `attemptPlanHash` commit message bytes + lifetime + fee; old-plan re-arm refused (attempt-approval 5/5) |
| R1 B1 fee-payer writability / B2 CI Agave / H1 `payload.*` / H2 23505 / M7 legacy scope | **FIXED, preserved** | covered by the executed 220 + 29 + 3 suites (0 fail) |

---

## 5. Remaining issues (none blocking the publication acceptance)

**I1 (INFO) — consumed-receipt guard is defence-in-depth with narrow reachability.**
A receipt binds `operationId+intentHash+attemptPlanHash`; `attemptPlanHash`
commits `attemptNo`, so a second attempt can never match an old receipt
(`publication-worker.ts:845-859`), and a SIGNED attempt never returns to
PREPARED. The `PUBLICATION_APPROVAL_CONSUMED` path (`:1252-1257`) is therefore
reachable mainly via journal replay/forge or a same-receipt race (P-5), where it
does its job. Not a defect; documented so nobody overestimates it.

**I2 (INFO) — publication `prepare` and `submit` are the same role.**
`admin-permissions.ts:19-20` gives `operator` both `publication.prepare` and
`publication.submit`, so the attempt-receipt actor who reviews can also submit.
The record pipeline's two-person rule (draft `operator` → approve
`registry_approver`) is intact and is the requirement's "different approver"
stage. No preparer≠submitter check exists at the publication layer — consistent
with the accepted contract (receipt binds the authenticated submitter), not a
regression. Flagged only so the coordinator can decide if a stricter rule is
wanted.

**I3 (INFO, cross-scope) — `/v1/health` `cluster: "devnet"` is a static fixture
label** (`main.ts:539`, GUI-owned M6 work in progress). The publication identity
is independently pinned and live-verified (§0), so publication safety does not
depend on it; but a launcher that trusts the health label for RPC wiring could
mis-wire a local validator. Suggest the GUI agent report the publication
cluster/genesis pin there too (their scope).

**I4 (OWNED ELSEWHERE, unchanged) — launcher/deploy env provisioning.**
`deploy/devnet-demo/native` must still provision the distinct approval key and
export `ONELAYER_PUBLICATION_APPROVAL_KEY_FILE` + `ONELAYER_PUBLICATION_CLUSTER`
(contract §7). Assigned to launcher r3. Until then the stack fails closed (§0) —
by design, not a backend gap.

**I5 (OWNED ELSEWHERE) — production approval custody (HSM/KMS/provider issuer,
tickets 16/22), real devnet namespace, IdP/ingress, signed release, shadow
pilot, recovery drill.** Lab limit stated honestly; no invented lab requirement.

No blocking/high/medium findings in the publisher/runtime/signer scope this
round.

---

## 6. Regressions

None. All executed suites green (220 unit + 29 publication/workflow integration
+ 3 http/certificate + 2 startup + 1 real-validator + 6 independent probes).
R1/R2/R3 fixes preserved. Concurrent root/GUI edits (`local-demo.ts`,
`admin-session`/`postgres-session` lab credential schema, `/v1/health` identity)
did not touch publication modules — hashes above re-bound and boundary + probes
re-run after their changes (5/5 and 6/6).

---

## 7. Verdicts

**Standards: PASS (publication scope).** Fail-closed identity at construction,
startup and every chain read; unbypassable receipt gate at publisher AND signer;
body cannot mint identity; durable consumed journal; immutable event log; no
legacy fake-current claims on this path (certificate suites green).

**Spec: ACCEPTED for the r6 claims** — "any new signature requires the exact
reviewed reserved plan, authorized by an independently signed receipt bound to
the authenticated actor/device and the verified chain identity" now holds at the
**publisher layer** (not just the runtime entry point): `advance` cannot sign,
`step` without a verified receipt cannot sign, the signer refuses before key
use. Acceptance is for the lab deployment model (same-process issuer, explicitly
not HSM isolation) and excludes the launcher/deploy env provisioning (I4).

---

## 8. Handoff — tested vs not claimed

**Executed:** typecheck ×2; unit 220/220; boundary+attempt-approval 10/10 (incl.
real-signer H4); chain/http/approval/certificate/ambiguity/version-exclusion
19/19; startup e2e 2/2; real validator 1/1 (`db0c7203…`, PENDING→FINALIZED);
independent probes 6/6 ×2 runs.

**Not claimed:** full `test:integration` as one invocation; durable-admin-http /
recovery / monitor / audit suites (other owners); desktop/GUI surfaces; deploy
provisioning (launcher r3); production gates 16/22-24; real devnet writes
(forbidden). No "all 24" claim.

**Bottom line:** r6 delivers what it claims. H4/H5/M4 are genuinely closed at
the publisher/signer boundary — independently proven with the real key signer
and real HTTP (P-1..P-6). Identity absence fails closed at every layer: **the
lab cannot publish until the launcher provisions the pinned cluster + genesis +
distinct approval key** (§0). Remaining work is external (launcher env, HSM
custody) plus two informational notes (I2, I3) for the coordinator.
