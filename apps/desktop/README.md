# Desktop platform lab

## Actual usability — 2026-10-02

Normal startup has no connection configuration or sign-in, and authenticated summaries do not open role workspaces. The synthetic session adapter is a test harness. The full English application remains unfinished. See [implementation status](../../docs/implementation-status-2026-10-02.md) and [personal usage-pipeline review](../../.scratch/production-desktop/evidence/launcher-usage-pipeline-review-2026-10-02.md). Tests described below validate bounded lab behavior, not full installed-app acceptance.

This is an executable **synthetic Linux platform harness**, not the production
desktop application. Tauri 2 + React is the primary candidate under ADR-0007;
Qt remains a fallback. Their development toolchains are absent in the current lab. System Python GI
and GTK 3 runtime allow measuring an actual installed native window without
installing system packages or selecting a third production stack.

Run on a Linux desktop with `/usr/bin/python3`, PyGObject, GTK 3 and libsecret
typelibs:

```sh
/usr/bin/python3 -m unittest discover -s apps/desktop/lab -v
/usr/bin/python3 apps/desktop/lab/smoke.py --screenshot /tmp/onelayer-lab.png
```

The smoke creates a fresh temporary prefix, copies the application, executes its
launcher (including a path with spaces), captures **only its own window**, closes
it, checks installer overwrite refusal and unavailable credential-service failure,
and removes the installation. It does not install desktop menu entries or change
the host package manager. This is a source/runtime installation, not a bundled,
signed production executable. It requires a live display; unavailable display is
failure, never a skipped pass.

`lab/broker.py` exercises PKCE authorization request construction and single-use
callback-envelope validation, immutable signing payload binding, and a Linux
Secret Service write/delete adapter. Login results are authorization **codes**,
not authenticated sessions. `lab/callback.py` now provides a real IPv4 loopback
HTTP listener with an ephemeral port reserved before authorization URL creation,
strict Host validation, single-use native result handoff, and no callback secrets
in HTTP responses/access logs. Callers own its lifetime using a context manager.
There is no external-browser/native SSO or real signer adapter yet. Separately,
`lab/session.py` exercises the backend-owned OIDC exchange against a synthetic
loopback test IdP. The GUI exposes its login/refresh/logout controls only when
both `--lab-backend` and `--lab-issuer` are explicitly supplied. It receives only
a sanitized username/role summary, not cookies or CSRF material.
The synthetic signature test uses a MAC fixture, not a claimed wallet signature.
Credential store failure raises; there is no plaintext fallback or UI token getter.
Successful/locked-keyring lifecycle is still untested.

The standalone PKCE experiment in `broker.py` is **not integrated** with the server
OIDC flow. The separate session transport exercises `/v2/admin/oidc/start` and its
callback as a synthetic HTTP user-agent; it is not native browser SSO.
Product integration must preserve
the backend identity/session model. In-memory expiry/replay guards here do not
replace durable backend operation states or server authorization. A trusted
adapter must verify external signatures over the complete server intent and
bind identity, device, operation, action and expiration. External human review
must show actual signing parameters independently of the ordinary UI.

For React migration, extract client components and replace Next routing and
same-origin transport with explicit authenticated backend operations. Next server
routes/proxy stay on the server. No generic native HTTP/shell/filesystem command
or credential-read command is implemented by this harness. Tauri capabilities,
malicious-renderer testing, signed update/rollback and both candidate builds remain
separate open spike gates, documented in ticket 02 evidence.

## Launcher UI — first increment

Open the Linux demo launcher with:

```sh
./apps/desktop/launcher
```

The launcher presents an overview, a connection page and availability cards for
the local data service, verifier and web workspace. Services initially show
"Not checked". "Check connection" performs an explicit background check;
loading, available, offline and error states are shown independently per service.
Availability means a response was observed at the last check, not a signed-in
session or a verification verdict. The profile remains visibly Demo.

The probes use fixed IPv4 loopback endpoints (`8090`, `8080`, `8091`), carry no
cookies/service tokens, disable environment proxies and refuse redirects. The
launcher does not automatically start processes, migrate the application database,
open external URLs, or provision accounts. Smoke runs do not probe the running
application stack. Installed native smoke and synthetic IdP/session tests remain
the verification paths above; the full production installer/SSO/signer gates are
still open.

The product interface is English (user decision 2026-10-01). Registry contents
and usernames remain data and are not translated. CI runs these GTK tests and
the installed launcher smoke under a virtual display; local target-desktop
acceptance remains separate from that CI runtime.
## Local readiness preflight

`apps/desktop/readiness.py` is a read-only preflight for this machine. It checks
the commands, runtimes, dependencies and repository files that the native demo
stack (`deploy/devnet-demo/native start`) and the GTK launcher
(`apps/desktop/launcher`) need, and prints one actionable line per check:

```sh
/usr/bin/python3 apps/desktop/readiness.py
/usr/bin/python3 apps/desktop/readiness.py --json
/usr/bin/python3 apps/desktop/readiness.py --scope stack
```

Exit code 0 means every required local prerequisite for the selected scope is
present; 1 means at least one is missing and the report names the remediation;
2 is a usage error. `--json` emits the same report for scripts (schema
`onelayer.desktop.local-readiness.v1`). The repository root is derived from the
script's own location, so any working directory works, including paths with
spaces; `--repo-root` overrides the detection.

Scopes are explicit: `--scope stack` covers the demo stack, `--scope desktop`
covers the GTK harness, and the default `all` covers both. Checks include
Node.js 22.7+ with `--experimental-transform-types`, npm, curl, sha256sum, bash,
PostgreSQL 17 discovered the same way `native` discovers it (Homebrew
`postgresql@17` or PATH), the four `node_modules` dependency markers, migration
and fixture files, runtime-directory write access, loopback ports
8080/8090/8091 (a port already served by this demo's own recorded pid is
informational, not a failure), and for the desktop scope `/usr/bin/python3`,
the GTK 3/Secret typelibs, `DISPLAY`/`WAYLAND_DISPLAY` and a session bus.

The preflight installs nothing, starts or stops nothing, performs no network
requests, and never reads secret values: it only tests whether
`/dev/shm/onelayer-devnet-demo` exists and reads PID files, never token,
credential, key or database-URL contents. Environment values are not printed.

Production/external gates (devnet RPC reachability, a real signer, IdP/SSO,
managed and signed install/updates, the 60-day shadow pilot, independent audit
and a recovery drill on real data) are listed as `external` and are never
evaluated or marked as passed. A green run is local launch readiness, not
production readiness.

Run the focused tests with:

```sh
/usr/bin/python3 -m unittest discover -s apps/desktop -p 'test_readiness.py' -v
```

For a DATA/NTFS checkout, select a private native runtime before starting the
stack or running its preflight:

```bash
export ONELAYER_NATIVE_STATE_DIR="$HOME/.local/state/onelayer-devnet-demo/native"
/usr/bin/python3 apps/desktop/readiness.py --scope stack
./deploy/devnet-demo/native start
./apps/desktop/launcher
```

The environment setting also selects the PID markers inspected by preflight.
Occupied ports fail launch preflight even when their PID marker is alive;
`native status` is the check for a running stack. A previous repository-local
database is preserved and must be migrated explicitly if it is to be reused.

## Live-demo seed, tamper and opt-in live smoke (B4/B5)

Three deploy-side entry points drive the live-demo scenario outside the GTK
walk. All of them live in `deploy/devnet-demo/scripts/` and print machine
readable reports; key material is read only through the A1 key store and never
printed.

```bash
# readiness assessment (read-only) + opt-in idempotent preparation + fallback
./deploy/devnet-demo/scripts/live-demo-seed --help
./deploy/devnet-demo/scripts/live-demo-seed                 # assessment only
./deploy/devnet-demo/scripts/live-demo-seed --prepare       # chain preparation
./deploy/devnet-demo/scripts/live-demo-seed --prepare --approve-fallback

# accepted A3 tamper CLI (args and exit codes verbatim; --out must be a new file)
./deploy/devnet-demo/scripts/live-demo-tamper --in package.json --out tampered.json --mode area

# opt-in live GTK smoke: real widgets against the real local services
ONELAYER_LIVE_DEVNET_SMOKE=1 ./deploy/devnet-demo/scripts/live-demo-smoke
```

`live-demo-seed` preparation covers registry init, operator role, bounded
rent/fee funding and the day's ledger segment, and is idempotent: a satisfied
step is never executed twice. Without `--prepare` nothing is sent. A missing
governance authority (the current devnet's permanently lost key) fails with
`GOVERNANCE_KEY_UNAVAILABLE` **before any chain mutation**; nothing is
substituted, no program is deployed and an initialized registry is never
mutated. `--approve-fallback` publishes one real finalized certificate with
selective disclosure (`status` + `areaSquareMeters`) through the demo-api
publication flow; a previous finalized fallback is reused only after it
re-verifies, and artifacts are fresh private files under
`~/.local/state/onelayer-devnet-demo/seed/` (0700 tree). Exit codes: 0 ready or
prepared · 2 refused request · 3 refused environment or authority · 4 report
produced but not ready.

`live-demo-smoke` does nothing without `ONELAYER_LIVE_DEVNET_SMOKE=1` (no
network, no chain). With the flag it preflights loopback health plus the
readiness probe and drives the ordinary launcher pages with real
`Gtk.Button.clicked()` callbacks and the real file-chooser seams against
`mode="live"` services — never fixture success. Three consecutive runs are
requested and the JSON report states exactly how many completed: a missing
governance authority reports `BLOCKED` with `"0/3"`, never a pass or a green
skip. Screenshots and a public-ID log are kept only for runs that succeeded,
in `~/.local/state/onelayer-devnet-demo/evidence/live-smoke/` (0700). Exit 0
only for `PASS` (3/3) or the documented `DISABLED` opt-out; every other
outcome exits 3.

Tests for these scripts are hermetic (fake RPC and fake HTTP, no live chain):

```bash
node --test --experimental-transform-types deploy/devnet-demo/scripts/*.test.ts
/usr/bin/python3 -m unittest discover -s deploy/devnet-demo/scripts -p 'test_live_demo_smoke_gate.py'
```

### Installed prefix and the source-root binding

`lab/install.py` installs a disposable prefix that carries the Python modules
plus one generated `live_demo_source_root.py` binding: a single bounded,
non-secret absolute path to the trusted source tree whose Node helpers (A1
signer, operator-address helper, A4 QR decoder) the installed launcher runs.
No key material and no repository content is copied into the prefix, and the
path is validated (absolute, length-bounded, helper files present) before any
helper executes. The installed launcher is therefore **source-root dependent**:
the tree named in the binding must stay in place. This is a source/runtime
installation of the lab harness, not a bundled, signed production installer;
production install/update gates remain open.
