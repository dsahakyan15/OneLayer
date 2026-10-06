# Ticket 02 — executable Linux platform experiment

Date: 2026-09-20. Baseline: `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2`
with existing dirty workspace changes. Scope written by desktop-agent:
`apps/desktop/`, this evidence directory and ticket 02 only.

## Result

An actual installed native **synthetic GTK runtime harness** was launched in the
existing Linux display, mapped, captured, and closed automatically. Installation
used a newly created disposable prefix, including spaces in its path, and was
removed afterwards. No host package/menu installation was performed. Screenshot:
native-smoke.png (локальный артефакт: `native-smoke.png`; не включён в документационный PR), visually inspected after capture; all labels
and the close control are visible.

This is **not** a Tauri/Qt build and does not approve GTK as production stack.
Tauri/Qt development metadata/toolchains remain missing; ADR-0007 is unchanged.
No acceptance checkbox is marked complete: the requested full candidate platform
evaluation requires real IdP/signer/updater integration and comparative adversarial
tests. Ticket 01 dependencies and production OS decisions remain open.

## Environment and commands

- Linux Mint 22.1, Linux `6.8.0-106-generic`, x86_64.
- System `/usr/bin/python3`: 3.12.3; GTK 3.24.41; GI Secret 1 typelib available.
- System GI GTK display initialization returned `True`.
- `pkg-config --modversion gtk+-3.0 webkit2gtk-4.1`: metadata unavailable.
- `/usr/bin/python3 -m unittest discover -s apps/desktop/lab -v`: **7 PASS**.
- `/usr/bin/python3 apps/desktop/lab/smoke.py --screenshot .scratch/production-desktop/evidence/02/native-smoke.png`: **PASS** native window, existing-prefix overwrite refusal, unavailable credential-service write refusal, temporary install cleanup.
- `git diff --check`: **PASS**.

Installed `native.py` SHA-256:
`41a5d698768f2efa5d3a85a57e3194e1643c36fd7bff0c6e3df95f46f3dcede6`.
This is a source/runtime installer, not a bundled binary or signed release.

## Boundary and negative evidence

`BrowserLogin` generates PKCE S256, state and nonce in memory and validates a
single callback envelope. Tests reject foreign state/target, duplicate fields,
fragment, unexpected fields, expiry, replay and callbacks from another process
attempt. This does not exchange tokens, validate identity or implement a callback
HTTP listener. It is explicitly **not integrated** with server
`/v2/admin/oidc/start`; it must not replace that server identity model.

`ApprovalBroker` stores immutable test bytes and checks operation, subject,
device, expiry and adapter signature result before consuming the pending request.
Tests reject different bytes, subject, device, operation, invalid signature,
expired and repeated results. Signature verification uses a synthetic MAC
fixture; no wallet, HSM, browser signer, human review or durable replay protection
is claimed. Production requires the trusted signer adapter to bind the complete
server intent and independent semantic review. The GUI offers no fake login or
sign controls; it displays those integration blocks explicitly.

Native Secret Service adapter has no plaintext fallback or UI getter. A process
with a deliberately nonexistent session bus failed its write as expected. No
production token or key was used. Successful storage/lookup/logout and locked
keyring remain **unverified**. An initial isolated-bus experiment triggered Secret
Service auto-activation without returning promptly and was interrupted; it is
not counted as a passing credential test. The reproducible smoke instead uses a
nonexistent bus path, without service activation.

An initial native run exposed GI selecting Gdk 4 before GTK 3; explicit Gdk 3
version pin fixed it. Screenshot dimensions were corrected to the actual native
window geometry and the final screenshot inspected. These failures are resolved
for this harness only.

## Remaining gates and handoff

1. Install/pin approved Tauri and Qt development toolchains in an isolated lab,
   build both candidates and rerun equivalent threat-boundary tests. Production
   OS/support/patch ownership still needs an organization decision.
2. Integrate real test IdP via backend OIDC and managed-device admission; prove
   native credential lifecycle and no credential leakage into ordinary UI.
3. Supply an external signer/review adapter with actual signatures and server
   immutable intents; run D02–D04, including compromised ordinary UI.
4. Implement signed release/update fixtures and downgrade/interrupt tests D08.
5. Extract React client components without Next server routes. This harness adds
   no generic native shell, filesystem, HTTP proxy or credential-read commands;
   it cannot substitute for Tauri IPC/capability tests D01.

Review: pending independent coordinator/reviewer assessment. Execution is blocked
for full acceptance; independently executable lab work is implemented and tested.

## Continuation 2026-09-21 — real loopback callback transport

Baseline commit unchanged (`3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2`), dirty
workspace retained. Added `apps/desktop/lab/callback.py` and installed it with the
runtime harness. `LoopbackCallback` reserves an OS-selected port on `127.0.0.1`
before constructing PKCE authorization parameters. It validates exactly one Host,
origin-form callback path, state and parameter cardinality. Native caller can take
the authorization code once; close discards unread results and releases the port.
HTTP responses carry no secrets and disable caching/referrers; request logs are
suppressed. Each accepted connection has a two-second read timeout. The caller
controls listener lifetime; callback state expires after 120 seconds. This remains
a local transport experiment, not authenticated desktop login.

Fixed an envelope parser gap: `parse_qs` formerly dropped empty duplicate values,
allowing valid state/code followed by an empty duplicate. Blank values are now
preserved and duplicate cardinality is rejected. Regression cases included.

Commands/results:

- `/usr/bin/python3 -m unittest discover -s apps/desktop/lab -v`: **13 PASS**,
  including six actual TCP transport cases. Sandbox initially refused socket
  creation; approved escalation rerun passed. No skip converted to pass.
- `/usr/bin/python3 apps/desktop/lab/smoke.py --screenshot .scratch/production-desktop/evidence/02/native-smoke-2026-09-21.png`: **PASS**,
  GTK 3.24.41 installed native window, overwrite refusal, credential-service
  unavailable failure, cleanup. Sandbox could not access display; approved
  escalation rerun passed. Screenshot (локальный артефакт: `native-smoke-2026-09-21.png`; не включён в документационный PR) visually
  inspected, complete labels and close control visible. Native source SHA-256
  unchanged from earlier run.

Adverse TCP cases: competing bind, foreign and duplicate Host, foreign state,
duplicate state, absolute request target, foreign path, POST, replay, expiry,
callback from a previous attempt, no result after close, closed port. Code/body
and stderr checked for non-disclosure on success. No external network, IdP,
production credential or package-manager installation was used.

All earlier production gates remain open: candidate builds/comparison, approved
OS, real backend OIDC/device integration, credential success/locked lifecycle,
external signer/review and signed updates. Ticket 10 is explicitly blocked by 02
and 07; this code does not assert their acceptance. Independent review pending.
