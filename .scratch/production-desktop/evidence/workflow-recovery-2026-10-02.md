# Workflow recovery continuation — 2026-10-02

The coordinator implements the backend receipt journal, scoped draft discovery and adversarial PostgreSQL/live OIDC coverage. DeepSeek v4.1 Flash with max reasoning implements the English recovery interface and independent backend/UI reviews. Existing dirty changes are preserved; no commit, deployment, key ceremony or production approval occurs.

Migration 0020 adds append-only attempts, acknowledgements and cancellation tombstones. Prepare stores an exact canonical request hash and field scope, not a payload or session credential. Unknown outcomes retain their server key across browser/API restarts. Completed attempts open their existing draft, without repeating the mutation; acknowledgement follows a validated same-UUID read. Cancel shares the original mutation mutex and permanently fences delayed requests. The same fence applies to publication maintenance sharing the `wf_request` namespace.

Scoped draft discovery removes the manual UUID hand-off gap for approvers. It returns 50 authorized summaries per page without payloads, hidden IDs or hidden counts, and only a visible UUID can become a continuation cursor. Oversized scans fail closed.

Independent backend review found a permanent quota lockout after authorization was narrowed: invisible receipts still occupied the pending limit. Fixed by charging only currently recoverable receipts, retaining hidden historical evidence. A PostgreSQL regression prepares 100 receipts, proves the limit, narrows access and proves a new authorized request succeeds. Added a request-hash index and cancellation immutability checks. Acknowledgement intentionally ends one logical attempt; an explicit new create can use the same input, while the original key continues to replay forever. See the [contract](../../../docs/workflow-attempt-recovery.md).

Validation recorded so far: API typecheck and 132 unit tests PASS; focused workflow/discovery/cancellation/quota tests 5/5 PASS; combined archival maintenance/version-exclusion/recovery tests 11/11 PASS. Live OIDC HTTP flow PASS, including receipt prepare/recover/ack, wrong-CSRF refusals and device revocation. Full integration and coordinated browser validation are still running; final outcomes will be appended below.

This completion concerns workflow operation recovery. Full-state checkpoints, isolated Recovery Controller, authenticated complete lifecycle, production signer/custody, signed desktop distribution and live operational acceptance remain separate unfinished implementation/provisioning gates. Local readiness checks do not close these gates.

## Final local validation

- Optimized web build PASS; coordinated production browser workflow/public-verification/publish suites **110/110 PASS** on desktop and mobile. Includes lost-201/reload recovery, stable preparation after reload, cancellation, draft discovery/pagination, mismatched receipt refusing all mutations, and malformed commit receipt recovering without fabricated evidence.
- Full serial API integration: **81 PASS / 1 FAIL / 0 SKIP, 82 cases**. Failure: service-principal API startup exceeded its unchanged 15-second deadline while independent builds/test work loaded the host. An isolated final rerun of that file plus the current receipt/discovery/quota suite **7/7 PASS** with no assertion relaxed. Both live local-validator tests passed in the broad run. Do not present the broad run as a clean 82/82 pass.
- Native migration/checksum suite **4/4 PASS** after the runtime-path and permission changes; old shared-volume migration invocation refuses before touching DB state. API typecheck/132 unit checks and live OIDC HTTP workflow PASS; archival-maintenance/version-exclusion/recovery focused suite **11/11 PASS**.
- Private runtime override added because the actual DATA/NTFS checkout reports repository PGDATA as mode 777. The local stack starts under `$HOME/.local/state/onelayer-devnet-demo/native`; root and PGDATA are actually mode 700. All three service endpoints answer 200, and the earlier repository cluster is preserved. No production/chain deployment occurs.
- Native GTK smoke maps a real English window; screenshot under `10/launcher-live-services-2026-10-02.png`. Health cards remain “Not checked” until the user requests a check, so the screenshot itself is not health proof; the recorded native status proves the three endpoint responses.
- Readiness suite **27/27 PASS**, including real mode 700/777 and symlink handling, PID 0/1, override PID lookup, regular-file refusal and foreign/live-marker port occupancy. Occupied ports intentionally fail *launch* preflight; use `native status` for a running stack. JSON refreshed for desktop scope and the already-running stack.

Independent DeepSeek max review findings were corrected: hidden-receipt quota lockout, cross-route consumption of prepared keys, indexed receipt lookup/keyset discovery, fabricated commit receipt display, mismatched receipt keys, misleading PID ownership and absent private-runtime enforcement. Test fixture now implements the complete browser-facing receipt/list contract; its in-memory state is synthetic and does not replace the real PostgreSQL persistence tests.

The actual native password-demo operator can sign in (201), but v2 workflow
preparation refuses it with 403 RESOURCE_FORBIDDEN: password identities carry
no scoped workflow resource policy. This is retained as a fail-closed boundary,
not worked around by granting global access or widening legacy authentication.
The full flow is proven by the separate live OIDC HTTP harness; using it in the
native runtime requires provisioning scoped OIDC identities. Running services
and green health responses do not imply all role workflows are provisioned.
