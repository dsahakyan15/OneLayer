# Ticket 10 — desktop shell dependency handoff

Date: 2026-09-21. Baseline: `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2`,
existing dirty workspace preserved. Owner: desktop-agent.

Execution is blocked, not complete. ADR-0007 still requires comparative Tauri/Qt
spike acceptance, a supported OS decision, independent trusted signing review and
credential lifecycle validation. Existing GTK application is explicitly a
synthetic Linux runtime experiment; it does not choose the production platform.

Ticket02 now supplies a tested actual loopback transport with PKCE envelope guards
and disposable installed native smoke. See [13 tests and native evidence](../02/report.md).
There is no native authenticated backend session or server-permission navigation
in this experiment. The standalone authorization-code receiver cannot replace
backend `/v2/admin/oidc/start`, managed-device admission or durable session rules.

Remaining implementation/acceptance:

- Finish 02 comparison and choose supported OS/platform; build signed installer
  and environment profile, distinguish demo/staging/production.
- Integrate 07 backend identity contract with real test IdP/device admission;
  test native credential save/refresh/logout/revoke/locked store.
- Extract React client UI only after selecting renderer; permission navigation
  reflects server scope, direct action authorization remains backend-owned.
- Implement minimum native command surface, offline/loading/expired/error states,
  keyboard/scaling and operation-ID restart recovery.
- Run installed-app and adversarial callback/IPC/update tests against that actual
  application; the current synthetic transport tests are supporting evidence only.

No production secrets, signing/OS decisions, backend contract mutations or external
service calls were made. Review pending coordinator assessment.
