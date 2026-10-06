#!/usr/bin/python3
"""Local readiness preflight for the OneLayer desktop workbench.

Checks this machine for the commands, runtimes, dependencies and repository
files that `deploy/devnet-demo/native start` and `apps/desktop/launcher` need.
The command is read-only: it installs nothing, starts or stops nothing, makes
no external network requests, and never reads secret values. Synthetic runtime material
lives under /dev/shm/onelayer-devnet-demo; this check only tests whether that
directory exists and never looks inside it.

Required local prerequisites are separated from production/external gates.
External gates are listed for orientation, never evaluated and never marked as
passed. Exit code 0 means the required local prerequisites for the selected
scope are present; it is not a production-readiness claim.

Usage:
    /usr/bin/python3 apps/desktop/readiness.py
    /usr/bin/python3 apps/desktop/readiness.py --json
    /usr/bin/python3 apps/desktop/readiness.py --scope stack

Exit codes: 0 = required local prerequisites present, 1 = a required local
prerequisite is missing, 2 = usage error.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path

SCHEMA = "onelayer.desktop.local-readiness.v1"
SCRIPT_LABEL = "apps/desktop/readiness.py"
LOOPBACK_HOST = "127.0.0.1"
SYNTHETIC_RUNTIME_DIR = Path("/dev/shm/onelayer-devnet-demo")
DEMO_PORTS = ((8080, "verifier"), (8090, "demo-api"), (8091, "mvp-web"))
POSTGRES_BINARIES = ("pg_ctl", "initdb", "psql", "createdb", "pg_isready")
MIN_NODE = (22, 7)
MIN_BASH = (4, 0)
MIN_POSTGRES_MAJOR = 17
MIN_PYTHON = (3, 10)
GTK_PROBE = (
    "import gi;"
    "gi.require_version('Gtk','3.0');"
    "from gi.repository import Gtk;"
    "gi.require_version('Secret','1');"
    "from gi.repository import Secret"
)
NODE_DEPENDENCIES = (
    ("deps.demo-api", "apps/demo-api", "node_modules/pg", "apps/demo-api"),
    ("deps.verifier", "apps/verifier", "node_modules/@solana/kit", "apps/verifier"),
    ("deps.mvp-web", "apps/mvp-web", "node_modules/next", "apps/mvp-web"),
    ("deps.onchain-client", "packages/onchain-client", "node_modules/@solana/kit", "packages/onchain-client"),
)
EXTERNAL_GATES = (
    {
        "id": "gate.devnet-rpc",
        "title": "Solana devnet RPC reachability and rate limits",
        "detail": "This preflight makes no external network requests. The running stack and live smoke checks observe devnet availability.",
        "reference": "deploy/devnet-demo/README.md",
    },
    {
        "id": "gate.signer",
        "title": "Production signer (KMS/HSM or external signer)",
        "detail": "Requires a real organization decision and independent review; the demo uses a synthetic software key in tmpfs.",
        "reference": "docs/application-pipeline-ru.md",
    },
    {
        "id": "gate.identity",
        "title": "Production IdP/SSO and device enrollment",
        "detail": "Requires a real IdP, managed devices and private network/VPN ingress acceptance.",
        "reference": "docs/adr/0007-desktop-application-and-role-scoped-access.md",
    },
    {
        "id": "gate.installer",
        "title": "Managed install, signed bundle, SBOM/provenance",
        "detail": "The GTK lab is a source/runtime installation, not a bundled signed production executable.",
        "reference": ".scratch/production-desktop/evidence/02/preflight.md",
    },
    {
        "id": "gate.updates",
        "title": "Signed updates and rollback policy",
        "detail": "Signed updater and rollback acceptance remain open spike gates.",
        "reference": "docs/application-pipeline-ru.md",
    },
    {
        "id": "gate.pilot",
        "title": "60-day shadow pilot",
        "detail": "Long-running operational evidence on the target organization; not a local machine check.",
        "reference": ".scratch/production-desktop/index.md",
    },
    {
        "id": "gate.audit",
        "title": "Independent audit/pentest and recovery drill on real data",
        "detail": "Requires external reviewers and real restored data; cannot be satisfied by this or any local command.",
        "reference": "docs/agents/implementation-runbook.md",
    },
)
NOTE = (
    "Local build/launch readiness only. This command only probes local loopback ports, installs nothing, "
    "starts nothing and never reads secret values. Production readiness is not claimed: the external "
    "gates listed below are not evaluated here and must not be reported as passed."
)

_VERSION = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def parse_version(text: str | None):
    """Return (major, minor[, patch]) from the first version-looking token."""
    if not text:
        return None
    match = _VERSION.search(text)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups() if part is not None)


def version_text(version) -> str:
    return ".".join(str(part) for part in version)


class Probe:
    """System interface. Tests replace it with a fake so checks stay hermetic."""

    def which(self, name: str):
        return shutil.which(name)

    def run(self, argv, timeout: float = 10.0):
        try:
            completed = subprocess.run(
                [str(item) for item in argv],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return None, str(error)
        return completed.returncode, (completed.stdout or "") + (completed.stderr or "")

    def is_dir(self, path) -> bool:
        return Path(path).is_dir()

    def is_symlink(self, path) -> bool:
        return Path(path).is_symlink()

    def is_file(self, path) -> bool:
        return Path(path).is_file()

    def is_executable(self, path) -> bool:
        return Path(path).is_file() and os.access(path, os.X_OK)

    def private_directory(self, path) -> bool:
        try:
            info = Path(path).lstat()
            return stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0
        except OSError:
            return False

    def is_writable(self, path) -> bool:
        return Path(path).is_dir() and os.access(path, os.W_OK)

    def glob(self, pattern: str):
        return sorted(Path(item) for item in glob.glob(str(pattern)))

    def port_open(self, port: int) -> bool:
        try:
            with socket.create_connection((LOOPBACK_HOST, port), timeout=0.5):
                return True
        except OSError:
            return False

    def pid_alive(self, pid: int) -> bool:
        if pid <= 1:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        return True

    def read_pid(self, path):
        # PID files hold a process id, not a secret. Nothing else is read.
        try:
            raw = Path(path).read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return None
        return int(raw) if raw.isdigit() and int(raw) > 1 else None

    def getenv(self, name: str):
        return os.environ.get(name)


def repo_root_from(script_path) -> Path:
    """Repository root derived from this file's location (spaces are fine)."""
    return Path(script_path).resolve().parents[2]


def default_repo_root() -> Path:
    return repo_root_from(Path(__file__))


def result(check_id, group, title, severity, status, detail, remediation=None):
    return {
        "id": check_id,
        "group": group,
        "title": title,
        "severity": severity,
        "status": status,
        "detail": detail,
        "remediation": remediation,
    }


def required(check_id, group, title, detail, remediation=None):
    return result(check_id, group, title, "required", "fail", detail, remediation)


def passed(check_id, group, title, detail):
    return result(check_id, group, title, "required", "pass", detail)


def advisory(check_id, group, title, detail, status="warn", remediation=None):
    return result(check_id, group, title, "advisory", status, detail, remediation)


def _command_check(name, label, remediation, probe):
    path = probe.which(name)
    if path is None:
        return required(f"runtime.{name}", "stack", label, f"{name} was not found in PATH.", remediation)
    return None


def _command_version_check(check_id, name, label, minimum, remediation, probe, group="stack"):
    path = probe.which(name)
    if path is None:
        return required(check_id, group, label, f"{name} was not found in PATH.", remediation)
    code, output = probe.run([path, "--version"])
    version = parse_version(output) if code == 0 else None
    if version is None:
        return required(
            check_id,
            group,
            label,
            f"{name} was found at {path} but did not report a usable version.",
            f"Repair the {name} installation or select a working binary in PATH.",
        )
    if version < minimum:
        return required(
            check_id,
            group,
            label,
            f"{name} {version_text(version)} is older than the required {version_text(minimum)}.",
            remediation,
        )
    return passed(check_id, group, label, f"{name} {version_text(version)} found at {path}.")


def stack_checks(repo_root: Path, probe: Probe):
    checks = []

    node_path = probe.which("node")
    if node_path is None:
        checks.append(required(
            "runtime.node", "stack", "Node.js",
            "node was not found in PATH; deploy/devnet-demo/native requires it.",
            "Install Node.js 22.7 or newer, then re-run this preflight.",
        ))
    else:
        code, output = probe.run([node_path, "--version"])
        version = parse_version(output) if code == 0 else None
        transform_code, transform_output = probe.run([node_path, "--experimental-transform-types", "--version"])
        if version is None:
            checks.append(required(
                "runtime.node", "stack", "Node.js",
                f"node was found at {node_path} but did not report a usable version.",
                "Repair the Node.js installation or select a working node in PATH.",
            ))
        elif version < MIN_NODE:
            checks.append(required(
                "runtime.node", "stack", "Node.js",
                f"Node.js {version_text(version)} is older than the required 22.7.",
                "Install Node.js 22.7 or newer; the services run with --experimental-transform-types.",
            ))
        elif transform_code != 0:
            checks.append(required(
                "runtime.node", "stack", "Node.js",
                f"Node.js {version_text(version)} rejects --experimental-transform-types.",
                "Install a Node.js build that accepts --experimental-transform-types (22.7+).",
            ))
        else:
            checks.append(passed(
                "runtime.node", "stack", "Node.js",
                f"Node.js {version_text(version)} at {node_path} accepts --experimental-transform-types.",
            ))

    checks.append(_command_version_check(
        "runtime.npm", "npm", "npm", (10, 0),
        "Install npm (bundled with Node.js 22.7+).", probe,
    ))
    for name, label, remediation in (
        ("curl", "curl", "Install curl; native start checks service health with it."),
        ("sha256sum", "sha256sum", "Install coreutils; native start verifies migration digests with sha256sum."),
        ("solana-keygen", "Solana CLI (solana-keygen)",
         "Install the Solana CLI, or run only the desktop GTK launcher with --scope desktop. "
         "deploy/devnet-demo/scripts/initialize-runtime creates the synthetic devnet payer keypair with solana-keygen."),
    ):
        missing = _command_check(name, label, remediation, probe)
        if missing is not None:
            checks.append(missing)
        else:
            checks.append(passed(f"runtime.{name}", "stack", label, f"{label} found at {probe.which(name)}."))

    bash_version_path = probe.which("bash")
    if bash_version_path is None:
        checks.append(required(
            "runtime.bash", "stack", "Bash",
            "bash was not found in PATH; deploy/devnet-demo/native uses #!/usr/bin/env bash.",
            "Install bash 4 or newer.",
        ))
    else:
        code, output = probe.run([bash_version_path, "--version"])
        version = parse_version(output) if code == 0 else None
        if version is None or version < MIN_BASH:
            checks.append(required(
                "runtime.bash", "stack", "Bash",
                f"bash at {bash_version_path} did not report a version >= 4.",
                "Install bash 4 or newer.",
            ))
        else:
            checks.append(passed("runtime.bash", "stack", "Bash", f"bash {version_text(version)} found at {bash_version_path}."))

    checks.append(_postgres_check(probe))

    for check_id, relative, marker, package in NODE_DEPENDENCIES:
        directory = repo_root / relative
        if probe.is_dir(directory / marker):
            checks.append(passed(check_id, "stack", f"{package} dependencies", f"{relative}/{marker} is present."))
        else:
            checks.append(required(
                check_id, "stack", f"{package} dependencies",
                f"{relative}/{marker} is missing.",
                f"npm --prefix {relative} ci",
            ))

    migrations = probe.glob(str(repo_root / "db" / "migrations" / "*.sql"))
    if migrations:
        checks.append(passed(
            "files.migrations", "stack", "Database migrations",
            f"db/migrations contains {len(migrations)} SQL migration file(s).",
        ))
    else:
        checks.append(required(
            "files.migrations", "stack", "Database migrations",
            "db/migrations contains no *.sql files.",
            "Restore the repository checkout; native start applies db/migrations.",
        ))

    fixture = repo_root / "db" / "fixtures" / "devnet-demo.sql"
    if probe.is_file(fixture):
        checks.append(passed("files.fixture", "stack", "Synthetic demo fixture", "db/fixtures/devnet-demo.sql is present."))
    else:
        checks.append(required(
            "files.fixture", "stack", "Synthetic demo fixture",
            "db/fixtures/devnet-demo.sql is missing; native start records the ONELAYER_SYNTHETIC_DEVNET_DEMO_V1 fixture marker.",
            "Restore the repository checkout.",
        ))

    native = repo_root / "deploy" / "devnet-demo" / "native"
    if probe.is_file(native) and probe.is_executable(native):
        checks.append(passed("files.native-launcher", "stack", "Native demo launcher", "deploy/devnet-demo/native is present and executable."))
    elif probe.is_file(native):
        checks.append(required(
            "files.native-launcher", "stack", "Native demo launcher",
            "deploy/devnet-demo/native exists but is not executable.",
            "chmod +x deploy/devnet-demo/native",
        ))
    else:
        checks.append(required(
            "files.native-launcher", "stack", "Native demo launcher",
            "deploy/devnet-demo/native is missing.",
            "Restore the repository checkout.",
        ))

    demo_dir = repo_root / "deploy" / "devnet-demo"
    if probe.is_writable(demo_dir):
        checks.append(passed(
            "files.runtime-dir", "stack", "Runtime state directory",
            "deploy/devnet-demo is writable for PostgreSQL data, logs and pid files.",
        ))
    else:
        checks.append(required(
            "files.runtime-dir", "stack", "Runtime state directory",
            "deploy/devnet-demo is not writable; native start writes .runtime/native there.",
            "Fix ownership or permissions on deploy/devnet-demo.",
        ))

    if probe.is_writable(Path("/dev/shm")):
        checks.append(passed(
            "files.tmpfs", "stack", "tmpfs runtime",
            "/dev/shm is writable; synthetic keys and demo credentials are created there (contents are never read here).",
        ))
    else:
        checks.append(required(
            "files.tmpfs", "stack", "tmpfs runtime",
            "/dev/shm is missing or not writable; initialize-runtime creates /dev/shm/onelayer-devnet-demo there.",
            "Ensure /dev/shm is mounted and writable.",
        ))

    if probe.is_dir(SYNTHETIC_RUNTIME_DIR):
        checks.append(advisory(
            "state.synthetic-runtime", "stack", "Synthetic runtime state",
            "/dev/shm/onelayer-devnet-demo is present; initialize-runtime reuses existing files. Contents are not read by this check.",
            status="info",
        ))
    else:
        checks.append(advisory(
            "state.synthetic-runtime", "stack", "Synthetic runtime state",
            "/dev/shm/onelayer-devnet-demo is absent; native start creates it in tmpfs.",
            status="info",
        ))

    if probe.is_dir(repo_root / "apps" / "mvp-web" / ".next"):
        checks.append(advisory(
            "build.mvp-web", "stack", "Next.js build output",
            "apps/mvp-web/.next is present; native start rebuilds it before launch.",
            status="info",
        ))
    else:
        checks.append(advisory(
            "build.mvp-web", "stack", "Next.js build output",
            "apps/mvp-web/.next is absent; native start runs npm --prefix apps/mvp-web run build.",
            status="info",
        ))

    override = probe.getenv("ONELAYER_NATIVE_STATE_DIR")
    native_root = Path(override) if override else demo_dir / ".runtime" / "native"
    if not native_root.is_absolute():
        checks.append(required("files.native-state", "stack", "Private native state", "The state directory must be absolute.", "Set ONELAYER_NATIVE_STATE_DIR to an absolute path on a filesystem supporting private Unix permissions."))
    elif probe.is_file(native_root) or probe.is_symlink(native_root):
        checks.append(required("files.native-state", "stack", "Private native state", "The selected state path is a file or symlink, not an owned private directory.", "Choose a private directory for ONELAYER_NATIVE_STATE_DIR."))
    elif probe.is_dir(native_root) and not probe.private_directory(native_root):
        checks.append(required("files.native-state", "stack", "Private native state", "The state directory is not a private directory owned by this user. PostgreSQL and private runtime files cannot use this directory safely.", "Set ONELAYER_NATIVE_STATE_DIR=$HOME/.local/state/onelayer-devnet-demo/native on a Unix filesystem; preserve or explicitly migrate the existing database before switching."))
    else:
        checks.append(advisory("files.native-state", "stack", "Private native state", "An absent directory is created with umask 077; existing private state is retained. Filesystem permission support is verified during startup.", status="info"))
    pids_dir = native_root / "pids"
    for port, service in DEMO_PORTS:
        check_id = f"ports.{port}"
        if not probe.port_open(port):
            checks.append(passed(check_id, "stack", f"Loopback port {port}", f"127.0.0.1:{port} is free for {service}."))
            continue
        pid = probe.read_pid(pids_dir / f"{service}.pid")
        if pid is not None and probe.pid_alive(pid):
            checks.append(required(
                check_id, "stack", f"Loopback port {port}",
                f"127.0.0.1:{port} is occupied and the {service} PID marker is live (pid {pid}); socket ownership is not verified.",
                "Check deploy/devnet-demo/native status; stop the demo or the foreign listener before checking launch readiness again.",
            ))
        else:
            checks.append(required(
                check_id, "stack", f"Loopback port {port}",
                f"127.0.0.1:{port} is in use by another process, so native start will refuse to launch {service}.",
                f"Stop the process listening on 127.0.0.1:{port} (check deploy/devnet-demo/native status), then re-run this preflight.",
            ))

    return checks


def _postgres_check(probe: Probe):
    pg_bin = None
    source = None
    brew = probe.which("brew")
    if brew is not None:
        code, output = probe.run([brew, "--prefix", "postgresql@17"])
        prefix = output.strip() if code == 0 else ""
        if prefix and probe.is_executable(Path(prefix) / "bin" / "pg_ctl"):
            pg_bin = Path(prefix) / "bin"
            source = "Homebrew postgresql@17"
    if pg_bin is None:
        pg_ctl = probe.which("pg_ctl")
        if pg_ctl is not None:
            pg_bin = Path(pg_ctl).parent
            source = "PATH"
    if pg_bin is None:
        distro = probe.glob("/usr/lib/postgresql/*/bin/pg_ctl")
        if distro:
            remediation = (
                f"PostgreSQL is installed at {distro[0].parent} but deploy/devnet-demo/native discovers it only "
                "via Homebrew postgresql@17 or PATH; add that directory to PATH for the launch shell."
            )
        else:
            remediation = "Install PostgreSQL 17 or newer (for example brew install postgresql@17) so pg_ctl is in PATH."
        return required("runtime.postgres", "stack", "PostgreSQL", "PostgreSQL 17+ was not found via Homebrew postgresql@17 or PATH.", remediation)

    missing = [name for name in POSTGRES_BINARIES if not probe.is_executable(pg_bin / name)]
    if missing:
        return required(
            "runtime.postgres", "stack", "PostgreSQL",
            f"PostgreSQL at {pg_bin} (via {source}) is missing: {', '.join(missing)}.",
            "Repair the PostgreSQL 17 installation so all server and client binaries are present.",
        )
    code, output = probe.run([str(pg_bin / "pg_ctl"), "--version"])
    version = parse_version(output) if code == 0 else None
    if version is None:
        return required(
            "runtime.postgres", "stack", "PostgreSQL",
            f"pg_ctl at {pg_bin} did not report a usable version.",
            "Repair the PostgreSQL 17 installation.",
        )
    if version[0] < MIN_POSTGRES_MAJOR:
        return required(
            "runtime.postgres", "stack", "PostgreSQL",
            f"PostgreSQL {version_text(version)} found via {source}; version 17 or newer is required.",
            "Install PostgreSQL 17 or newer (for example brew install postgresql@17).",
        )
    return passed(
        "runtime.postgres", "stack", "PostgreSQL",
        f"PostgreSQL {version_text(version)} found via {source} at {pg_bin}.",
    )


def desktop_checks(repo_root: Path, probe: Probe):
    checks = []
    python = Path("/usr/bin/python3")
    python_ok = False
    if probe.is_file(python) and probe.is_executable(python):
        code, output = probe.run([str(python), "--version"])
        version = parse_version(output) if code == 0 else None
        if version is None:
            checks.append(required(
                "desktop.python", "desktop", "System Python 3",
                "/usr/bin/python3 did not report a usable version.",
                "Repair the system python3 installation.",
            ))
        elif version < MIN_PYTHON:
            checks.append(required(
                "desktop.python", "desktop", "System Python 3",
                f"/usr/bin/python3 is Python {version_text(version)}; 3.10 or newer is required.",
                "Install a newer system python3.",
            ))
        else:
            python_ok = True
            checks.append(passed(
                "desktop.python", "desktop", "System Python 3",
                f"/usr/bin/python3 is Python {version_text(version)}.",
            ))
    else:
        checks.append(required(
            "desktop.python", "desktop", "System Python 3",
            "/usr/bin/python3 is missing or not executable; apps/desktop/launcher execs it.",
            "Install python3.",
        ))

    if python_ok:
        code, output = probe.run([str(python), "-c", GTK_PROBE], timeout=30.0)
        if code == 0:
            checks.append(passed(
                "desktop.gtk", "desktop", "GTK 3 and Secret typelibs",
                "PyGObject, GTK 3.0 and Secret 1 typelibs are importable by /usr/bin/python3.",
            ))
        else:
            first_line = next((line.strip() for line in (output or "").splitlines() if line.strip()), "no error output")
            checks.append(required(
                "desktop.gtk", "desktop", "GTK 3 and Secret typelibs",
                f"The import check failed: {first_line}",
                "Install python3-gi, gir1.2-gtk-3.0 and gir1.2-secret-1 (the packages installed by the desktop job in .github/workflows/ci.yml).",
            ))
    else:
        checks.append(required(
            "desktop.gtk", "desktop", "GTK 3 and Secret typelibs",
            "Cannot probe GTK/Secret typelibs because /usr/bin/python3 is missing or did not report a usable Python 3 version.",
            "Install python3 and python3-gi first.",
        ))

    display = probe.getenv("DISPLAY") or ""
    wayland = probe.getenv("WAYLAND_DISPLAY") or ""
    if display or wayland:
        variable = "DISPLAY" if display else "WAYLAND_DISPLAY"
        checks.append(passed(
            "desktop.display", "desktop", "Display",
            f"A display is available via {variable} (value not printed).",
        ))
    else:
        checks.append(required(
            "desktop.display", "desktop", "Display",
            "Neither DISPLAY nor WAYLAND_DISPLAY is set; the GTK launcher cannot open a window here.",
            "Run inside a desktop session, or use the CI pattern: dbus-run-session -- xvfb-run -a --server-args=\"-screen 0 1280x900x24\" /usr/bin/python3 apps/desktop/lab/smoke.py",
        ))

    if probe.getenv("DBUS_SESSION_BUS_ADDRESS"):
        checks.append(advisory(
            "desktop.dbus", "desktop", "Session bus",
            "DBUS_SESSION_BUS_ADDRESS is set; credential-service paths can be exercised.",
            status="info",
        ))
    else:
        checks.append(advisory(
            "desktop.dbus", "desktop", "Session bus",
            "DBUS_SESSION_BUS_ADDRESS is not set; interactive GTK launch may work, but Secret Service and GTK tests need a session bus.",
            remediation="Wrap the command in dbus-run-session, as the desktop CI job does.",
        ))

    return checks


def build_report(repo_root: Path, scope, probe: Probe):
    checks = []
    if "stack" in scope:
        checks.extend(stack_checks(repo_root, probe))
    if "desktop" in scope:
        checks.extend(desktop_checks(repo_root, probe))
    failed_required = [item for item in checks if item["severity"] == "required" and item["status"] == "fail"]
    summary = {
        "checks": len(checks),
        "required": sum(1 for item in checks if item["severity"] == "required"),
        "failed_required": len(failed_required),
        "passed": sum(1 for item in checks if item["status"] == "pass"),
        "warnings": sum(1 for item in checks if item["status"] == "warn"),
        "informational": sum(1 for item in checks if item["status"] == "info"),
    }
    return {
        "schema": SCHEMA,
        "tool": SCRIPT_LABEL,
        "repository": str(repo_root),
        "scope": list(scope),
        "local_ready": not failed_required,
        "summary": summary,
        "checks": checks,
        "external_gates": [dict(gate, status="external") for gate in EXTERNAL_GATES],
        "note": NOTE,
    }


_STATUS_LABELS = {"pass": "ok", "fail": "fail", "warn": "warn", "info": "info"}


def render_human(report) -> str:
    lines = [
        "OneLayer desktop local readiness preflight",
        f"Repository: {report['repository']}",
        f"Scope: {', '.join(report['scope'])}",
        "",
    ]
    for group in ("stack", "desktop"):
        group_checks = [item for item in report["checks"] if item["group"] == group]
        if not group_checks:
            continue
        lines.append(f"{group}:")
        for item in group_checks:
            lines.append(f"  [{_STATUS_LABELS[item['status']]}] {item['id']}: {item['detail']}")
            if item["remediation"]:
                lines.append(f"        remediation: {item['remediation']}")
        lines.append("")
    summary = report["summary"]
    lines.append(
        f"Summary: {summary['passed']} ok, {summary['warnings']} warning(s), "
        f"{summary['informational']} informational, {summary['failed_required']} missing required."
    )
    lines.append("Local readiness: READY for the selected scope." if report["local_ready"] else "Local readiness: NOT READY (missing required local prerequisites; exit 1).")
    lines.append("")
    lines.append(report["note"])
    lines.append("External gates not evaluated by this command:")
    for gate in report["external_gates"]:
        lines.append(f"  - {gate['title']} ({gate['reference']})")
    return "\n".join(lines)


def main(argv=None, probe=None) -> int:
    parser = argparse.ArgumentParser(
        prog=SCRIPT_LABEL,
        description="Check required local commands, runtimes, dependencies and repository files for the "
                    "OneLayer desktop workbench. Read-only: no installs, no network, no secret reads.",
    )
    parser.add_argument("--json", action="store_true", help="Print the report as JSON.")
    parser.add_argument(
        "--scope", choices=("all", "stack", "desktop"), default="all",
        help="Check the demo stack, the desktop GTK harness, or both (default: all).",
    )
    parser.add_argument(
        "--repo-root", type=Path,
        help="Override the repository root (default: derived from this script's location, so any working directory works).",
    )
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve() if args.repo_root else default_repo_root()
    scope = ("stack", "desktop") if args.scope == "all" else (args.scope,)
    report = build_report(repo_root, scope, probe or Probe())
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=False))
    else:
        print(render_human(report))
    return 0 if report["local_ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
