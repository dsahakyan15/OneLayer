# Local readiness preflight sidecar — 2026-10-02

Base commit: `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2` (HEAD; no commit was
created). Working tree: preserved as found — 377 porcelain entries observed with
these additions in place; `apps/desktop/` and `.scratch/production-desktop/` are
untracked in this checkout, so all new files appear as untracked paths and do not
change that count. No commit, reset, chmod, package install, or process
start/stop was performed.

## Added files

- `apps/desktop/readiness.py` (new): read-only local readiness CLI with English
  output, `--json`, `--scope all|stack|desktop` and a `--repo-root` override.
  The repository root is derived from the script location
  (`Path(__file__).resolve().parents[2]`), so any working directory works,
  including paths with spaces.
- `apps/desktop/test_readiness.py` (new): 21 stdlib unittest tests. All system
  access goes through a fake `Probe`; two subprocess tests cover a spaced cwd and
  a spaced script path.
- `apps/desktop/README.md` (appended): "Local readiness preflight" section.
- this evidence file.

## What it checks

Stack scope (for `deploy/devnet-demo/native start`): Node.js >= 22.7 that accepts
`--experimental-transform-types`, npm, curl, sha256sum, bash >= 4, `solana-keygen`
(used by `deploy/devnet-demo/scripts/initialize-runtime`), PostgreSQL >= 17
discovered exactly like `native` does (Homebrew `postgresql@17`, then PATH; a
distro-only install is reported with a PATH remediation because `native` would
not see it), the four dependency markers (`apps/demo-api/node_modules/pg`,
`apps/verifier/node_modules/@solana/kit`, `apps/mvp-web/node_modules/next`,
`packages/onchain-client/node_modules/@solana/kit`), `db/migrations/*.sql`,
`db/fixtures/devnet-demo.sql`, an executable `deploy/devnet-demo/native`,
writability of `deploy/devnet-demo` and `/dev/shm`, and the point-in-time
loopback state of 8080/8090/8091. A port that is free passes; a port held by this
demo's own live PID file is informational; a port held by anything else fails
with a stop-and-retry remediation.

Desktop scope (for `apps/desktop/launcher`): `/usr/bin/python3` >= 3.10,
importability of PyGObject plus GTK 3.0 and Secret 1 typelibs under
`/usr/bin/python3`, `DISPLAY`/`WAYLAND_DISPLAY`, and the session bus (warning
only).

Exit codes: 0 = required local prerequisites present, 1 = a required local
prerequisite is missing, 2 = usage error.

Not done by the command: no network requests, no package installation, no
process start/stop, no environment values printed, no secret contents read. The
only files read outside the repository layout are PID files (process ids);
`/dev/shm/onelayer-devnet-demo` is tested for existence only. Production/external
gates are emitted with status `external` and are never evaluated or marked as
passed: devnet RPC reachability, production signer (KMS/HSM), IdP/SSO and device
enrollment, managed signed install/SBOM, signed updates/rollback, the 60-day
shadow pilot, and independent audit/pentest plus a recovery drill on real data. A
green run is local launch readiness only, not production readiness and not
liveness under traffic (see issue 20 readiness-vs-liveness).

## Verification (commands and actual outcomes)

1. `/usr/bin/python3 -m unittest discover -s apps/desktop -p 'test_readiness.py' -v`
   → `Ran 21 tests ... OK`. Coverage: healthy host ready, JSON schema, human
   note, external gates never carrying a pass status, missing and old Node.js,
   Node.js rejecting `--experimental-transform-types`, missing dependency marker
   remediation, PostgreSQL distro-layout remediation, PostgreSQL via Homebrew
   prefix, foreign port holder (exit 1) versus demo-owned port (informational,
   exit 0), scope isolation in both directions, missing display, secret-path
   access surface, environment-value suppression, spaced-cwd and
   spaced-script-path subprocess runs.
2. `/usr/bin/python3 apps/desktop/readiness.py` → exit 0. Observed: Node.js
   24.10.0, npm 11.6.1, curl, sha256sum, solana-keygen, bash 5.2.21, PostgreSQL
   17.10 via Homebrew `postgresql@17`, all four dependency markers present, 19
   migrations, fixture present, launcher executable, runtime dirs writable, ports
   8080/8090/8091 free, `/usr/bin/python3` 3.12.3, GTK 3.0 and Secret 1
   importable, DISPLAY set. Summary: 22 ok, 0 warnings, 3 informational, 0
   missing required → "Local readiness: READY for the selected scope."
3. `/usr/bin/python3 apps/desktop/readiness.py --json --scope stack` → exit 0;
   schema `onelayer.desktop.local-readiness.v1`; `local_ready: true`; required 19,
   failed 0.
4. Foreign port holder: a temporary stdlib socket listener on 127.0.0.1:8090 (no
   project process touched, closed immediately after) → exit 1, `ports.8090`
   `fail`, remediation "Stop the process listening on 127.0.0.1:8090 ...".
   Confirms the nonzero exit and actionable text.
5. Missing layout: `--repo-root /tmp/onelayer-missing-root-check` → exit 1 with
   failures for the four dependency markers, migrations, fixture, native
   launcher and runtime dir (plus 8090, which was still held by the socket from
   step 4 because both probes ran concurrently).
6. Regression: `/usr/bin/python3 -m unittest discover -s apps/desktop/lab` →
   `Ran 27 tests ... OK` (the GTK/lab suite is unchanged).
7. `/usr/bin/python3 -m py_compile apps/desktop/readiness.py` → OK.

## Limits and review

- The CLI checks presence and shape of prerequisites only; it does not run the
  stack, build the web app, or verify application verdicts. Each port check is a
  single loopback TCP connect and does not identify the foreign holder.
- Some checks deliberately mirror `deploy/devnet-demo/native` discovery rules. If
  that launcher changes its prerequisites, this preflight must be updated; that
  coupling is the main maintenance risk.
- Self-review of the final diff: all file access is routed through the injectable
  `Probe`; secret paths never appear in the probe surface (asserted by a test);
  external gates are asserted never to carry a local pass status; exit codes are
  asserted in tests and observed live. An earlier test-helper draft omitted
  `--repo-root`, which made fixture runs resolve the real repository; the helper
  was fixed before the final green run, so the suite and outputs above are the
  post-fix observations.
- Independent review and CI wiring are not part of this increment, and no smoke
  run of the installed launcher was repeated here.

Coordinator review: the port check proves occupancy and a live PID marker, not process/socket ownership. Its English message now states that limit explicitly. Description now says no external network requests, since loopback TCP port probes do occur. The 21 focused tests pass after these copy corrections. A fresh JSON report is stored alongside this file.

Final review hardening: reject PID 0/1, and an occupied port now fails launch preflight even when a PID marker is live. The marker cannot prove which process owns the listener; use `native status` for an already-running stack. Added the bogus-PID regression and changed the live-marker expectation to fail closed. Focused suite now 22/22 PASS.

Final environment correction: the initial presence-only preflight missed the
repository runtime's NTFS mode 777. The CLI now checks private directory type,
owner and mode and honors `ONELAYER_NATIVE_STATE_DIR`. Native startup/migration
also reject unsafe state without chmod-ing the old cluster. The actual stack
was started successfully in a separate mode-700 state directory outside DATA;
all three endpoints answer 200. The old cluster remains intact. Focused tests
are now 27/27 PASS. The refreshed primary JSON uses desktop scope; the second
JSON records stack scope while its ports are already occupied and intentionally
reports not ready for another launch. Use the native status evidence for the
already-running services.
