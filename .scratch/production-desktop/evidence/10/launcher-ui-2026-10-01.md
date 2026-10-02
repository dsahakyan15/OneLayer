# Ticket 07 continuation — scoped verifier reads

Date: 2026-10-01. Base commit: `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2`; shared dirty workspace, no commit/deployment. API and verifier workers: DeepSeek v4.1 Flash, max reasoning. Independent review complete for this increment.

## Bounded interface

The existing durable read actions are wired to the existing verifier GET surface:
`anchors.read` to `/v1/anchors/:sequence`, `incidents.read` to `/v1/incidents`,
and `certificates.read` to `/v1/certificates/:id/status` and `/lifecycle`.
This is an exact service-read allowlist, not a human session or export permission.
Package, metadata, QR, admin, mutation and arbitrary lookup paths are excluded.
Live credentials/action/registry scope are checked before resource lookup;
the certificate status query is restricted to the deployment registry.

Verifier HTTP adapters optionally load credentials from
`ONELAYER_LOOKUP_SERVICE_TOKEN_FILE` and `ONELAYER_INCIDENT_SERVICE_TOKEN_FILE`.
Configured invalid files refuse startup; there is no anonymous fallback.
Authenticated reads use validated HTTPS or loopback HTTP origins and refuse
redirects. Unset files preserve the demo's anonymous mode. No token reaches
the launcher UI, and no upstream body or token is included in adapter errors.

The coordinator found and requested a correction to an early gate placement:
the slot must cover the whole SQL/incident-refresh operation, not just auth.
The worker extracted the downstream dispatcher so release occurs in a final
`finally` after the operation. The final gate regressions pass, including mutation checks demonstrating premature release and leaked slots are detected.

## Verification

- API typecheck: PASS; unit tests: 124 PASS, zero failures.
- Service read HTTP: 2/2 PASS, real OIDC process and disposable PostgreSQL;
  concurrent blocked SQL keeps two slots occupied and a third read receives 429;
  error/aborted-client paths release admission. Duplicate registry selectors,
  wrong scopes, foreign resources, export isolation and cookie mixing are covered.
- Service principal HTTP: 2/2 PASS. Identity bundles: identity-revocation 4/4,
  OIDC HTTP 1/1, OIDC 19/19, service principal store 10/10 PASS.
- Verifier final typecheck: PASS; full suite: 67/67 PASS, zero skips; focused
  outbound-auth suite: 11/11 PASS. A FIFO token file without a writer is refused
  before startup can hang: nonblocking descriptor open plus regular-file fstat.
  Mutation restoring the old blocking open reproduces a 20-second startup
  timeout; the corrected startup refuses it in about 1.6 seconds. Composed e2e
  was also rerun by the verifier worker after this correction: PASS.
- Composed `tests/e2e/service-verifier-read.test.ts`: final rerun PASS (1),
  disposable PostgreSQL, real OIDC-mode API process, synthetic test IdP and real
  verifier adapters. Reads status/lifecycle/anchor metadata; foreign certificate
  ID maps to null, package export stays refused, anonymous OIDC lookup stays
  refused, revoke makes both adapters fail. Synthetic metadata only, no chain
  verification or real RPC calls in this test.
- Initial verifier run was 63/66: default port collision, a startup timeout
  under process load, and old anonymous-registry fixture compatibility. Ephemeral
  port and anonymous compatibility corrections plus serial rerun resolve them.
  Initial API test environment typecheck error was corrected. One API HTTP run
  exceeded its startup timeout under load; isolation rerun passed.

An authorized incidents HTTP success path still requires index RPC refresh and
was not exercised in this slice. Existing periodic refresh may call devnet in
long-lived processes. This report does not claim authenticated incident-index
completeness or a lifecycle verdict.

## Remaining acceptance

This slice is service-auth transport and scoped metadata reads. A mutable
lifecycle row does not prove completeness or current suitability. Native SSO,
signed environment profiles, trust/custody/issuance and full ticket 07 acceptance
remain open. Credentials are loaded at verifier startup; rotation requires
reconfiguring/restarting its credential holder. No production provisioning.

## Independent review — correction round

Reviewer: separate DeepSeek v4.1 Flash agent, max reasoning. No high/medium
finding in the completed implementation review. Three low-severity findings:

- F1: canonical anchor sequences above PostgreSQL int8 produced a database
  overflow/500 while verifier transport accepts u64. Correction in progress:
  invalid >u64 becomes controlled 400; valid u64 outside the current table's
  storage domain becomes 404 without a query. No schema or protocol narrowing.
- F2: a slow composed test could reach the API's existing 30-second periodic
  devnet refresh. Corrected only in the test: an imported temporary preload
  restricts child fetch to local IPv4 HTTP and refuses redirects, before the RPC
  adapter captures it. An explicit devnet refusal probe and startup marker prove
  the guard ran; the final guarded composed test passes (1/1). Production refresh
  behavior is unchanged; no external RPC dispatch is permitted by this test.
- F3: lifecycle adapter accepted mismatched resource identifiers from an upstream
  payload. Existing verdict code already rejects a wrong registry and does not
  use certificate ID, so no forged verdict was found. Adapter equality checks and
  mismatched-body tests are being added as defense in depth.

The FIFO correction was independently reproduced against the old code and
validated against the fixed code, including the focused 11/11 suite. Reviewer
also independently ran launcher transport (5/5) and native interaction (3/3).
Re-review of F1–F3 corrections is pending. Pre-existing malformed incident
`batchSequence` still returns 500; recorded as route-validation debt, not a
claimed incident-currentness fix.

## Independent review

Separate DeepSeek v4.1 Flash reviewer (max reasoning): no actionable findings
in the launcher increment. Independently checked fixed loopback transport,
absence of credentials/proxies/redirects, absolute deadline and response cap,
background updates and close-safe callbacks, installed module completeness and
smoke refusal without a display. Independently ran the transport tests (5/5)
and live GTK interaction tests (3/3). API/verifier low-severity correction-round
results are recorded in the ticket 07 evidence; they do not change the UI.
Desktop tests currently run locally; CI has no GTK/display job. This is an open
release gate, not a claim of production installation acceptance.
