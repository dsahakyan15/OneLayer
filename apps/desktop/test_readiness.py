#!/usr/bin/python3
"""Focused stdlib tests for apps/desktop/readiness.py.

The tests replace the preflight's system interface (Probe) with a fake, so no
project command runs and no real secret is touched. One subprocess test proves
that the real CLI derives the repository root from its own location even when
the working directory and the script path contain spaces.
"""
import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import readiness  # noqa: E402  (path is prepared above)


REPO = Path("/repo")
NODE = "/usr/bin/node"
NPM = "/usr/bin/npm"
CURL = "/usr/bin/curl"
SHA256SUM = "/usr/bin/sha256sum"
KEYGEN = "/opt/solana/bin/solana-keygen"
BASH = "/usr/bin/bash"
PG_BIN = Path("/pg/bin")
PG_CTL = str(PG_BIN / "pg_ctl")
PYTHON = "/usr/bin/python3"

SECRET_PATHS = (
    "/dev/shm/onelayer-devnet-demo/internal-token",
    "/dev/shm/onelayer-devnet-demo/issuer-secret",
    "/dev/shm/onelayer-devnet-demo/admin-credentials.json",
    "/dev/shm/onelayer-devnet-demo/test-payer.json",
    "/dev/shm/onelayer-devnet-demo/program-buffer-keypair.json",
    "/repo/deploy/devnet-demo/.runtime/native/database-url",
)


class FakeProbe:
    """In-memory stand-in for readiness.Probe; records every path it is asked about."""

    def __init__(self, *, commands=None, files=(), dirs=(), execs=(), outputs=None, ports=(),
                 pids=None, alive=(), env=None, writable=(), globs=None, fail_runs=()):
        self.commands = dict(commands or {})
        self.files = {str(item) for item in files}
        self.dirs = {str(item) for item in dirs}
        self.execs = {str(item) for item in execs}
        self.outputs = {tuple(str(part) for part in key): value for key, value in (outputs or {}).items()}
        self.ports = set(ports)
        self.pids = {str(key): value for key, value in (pids or {}).items()}
        self.alive = set(alive)
        self.env = dict(env or {})
        self.writable = {str(item) for item in writable}
        self.globs = {str(key): [str(item) for item in value] for key, value in (globs or {}).items()}
        self.fail_runs = {tuple(str(part) for part in key) for key in fail_runs}
        self.seen_paths = []
        self.runs = []
        self.env_reads = []

    def _record(self, path):
        text = str(path)
        self.seen_paths.append(text)
        return text

    def which(self, name):
        return self.commands.get(name)

    def run(self, argv, timeout=10.0):
        key = tuple(str(part) for part in argv)
        self.runs.append(key)
        if key in self.fail_runs:
            return 1, ""
        return 0, self.outputs.get(key, "")

    def is_dir(self, path):
        return self._record(path) in self.dirs

    def is_file(self, path):
        text = self._record(path)
        return text in self.files or text in self.execs

    def is_executable(self, path):
        return self._record(path) in self.execs

    def is_writable(self, path):
        return self._record(path) in self.writable

    def glob(self, pattern):
        text = self._record(pattern)
        return [Path(item) for item in self.globs.get(text, [])]

    def port_open(self, port):
        return port in self.ports

    def is_symlink(self, path):
        return str(path) in getattr(self, "symlinks", set())

    def private_directory(self, path):
        return str(path) not in getattr(self, "nonprivate", set())

    def pid_alive(self, pid):
        return pid in self.alive

    def read_pid(self, path):
        return self.pids.get(self._record(path))

    def getenv(self, name):
        self.env_reads.append(name)
        return self.env.get(name)


def healthy_probe():
    """A fake host where every required prerequisite is present."""
    outputs = {
        (NODE, "--version"): "v24.10.0\n",
        (NODE, "--experimental-transform-types", "--version"): "v24.10.0\n",
        (NPM, "--version"): "11.6.1\n",
        (BASH, "--version"): "GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)\n",
        (PG_CTL, "--version"): "pg_ctl (PostgreSQL) 17.10 (Homebrew)\n",
        (PYTHON, "--version"): "Python 3.12.3\n",
        (PYTHON, "-c", readiness.GTK_PROBE): "",
    }
    return FakeProbe(
        commands={
            "node": NODE, "npm": NPM, "curl": CURL, "sha256sum": SHA256SUM,
            "solana-keygen": KEYGEN, "pg_ctl": PG_CTL, "bash": BASH,
        },
        files=(REPO / "db" / "fixtures" / "devnet-demo.sql",),
        execs=(REPO / "deploy" / "devnet-demo" / "native", PYTHON, *(PG_BIN / name for name in readiness.POSTGRES_BINARIES)),
        outputs=outputs,
        dirs=(
            "/dev/shm", REPO / "deploy" / "devnet-demo", REPO / "apps" / "mvp-web" / ".next",
            REPO / "apps" / "demo-api" / "node_modules" / "pg",
            REPO / "apps" / "verifier" / "node_modules" / "@solana" / "kit",
            REPO / "apps" / "mvp-web" / "node_modules" / "next",
            REPO / "packages" / "onchain-client" / "node_modules" / "@solana" / "kit",
        ),
        globs={str(REPO / "db" / "migrations" / "*.sql"): [REPO / "db" / "migrations" / "0001_init.sql"]},
        writable=("/dev/shm", REPO / "deploy" / "devnet-demo"),
        env={"DISPLAY": ":0", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"},
    )


def run_main(argv, probe):
    argv = list(argv)
    if "--repo-root" not in argv:
        argv += ["--repo-root", str(REPO)]
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = readiness.main(argv, probe=probe)
    return code, buffer.getvalue()


class RepoRootTests(unittest.TestCase):
    def test_repo_root_derived_from_script_location_with_spaces(self):
        script = Path("/tmp/One Layer/check out/apps/desktop/test_readiness.py")
        self.assertEqual(readiness.repo_root_from(script), Path("/tmp/One Layer/check out"))

    def test_repo_root_of_this_checkout(self):
        expected = Path(__file__).resolve().parents[2]
        self.assertEqual(readiness.default_repo_root(), expected)


class HealthyHostTests(unittest.TestCase):
    def test_healthy_host_with_both_scopes_is_ready(self):
        report = readiness.build_report(REPO, ("stack", "desktop"), healthy_probe())
        self.assertTrue(report["local_ready"])
        self.assertEqual(report["summary"]["failed_required"], 0)
        self.assertEqual([item for item in report["checks"] if item["status"] == "fail"], [])
        self.assertGreaterEqual(report["summary"]["passed"], 18)

    def test_json_report_schema_and_exit_zero(self):
        code, output = run_main(["--json", "--scope", "all"], healthy_probe())
        self.assertEqual(code, 0)
        report = json.loads(output)
        self.assertEqual(report["schema"], readiness.SCHEMA)
        self.assertEqual(report["tool"], "apps/desktop/readiness.py")
        self.assertEqual(report["repository"], str(REPO))
        self.assertTrue(report["local_ready"])

    def test_human_output_states_local_readiness_and_open_gates(self):
        code, output = run_main(["--scope", "stack"], healthy_probe())
        self.assertEqual(code, 0)
        self.assertIn("Local readiness: READY", output)
        self.assertIn("Production readiness is not claimed", output)
        self.assertIn("External gates not evaluated by this command", output)

    def test_external_gates_are_listed_but_never_evaluated_as_pass(self):
        report = readiness.build_report(REPO, ("stack", "desktop"), healthy_probe())
        self.assertTrue(report["external_gates"])
        for gate in report["external_gates"]:
            self.assertEqual(gate["status"], "external")
        local_statuses = {item["status"] for item in report["checks"]}
        self.assertNotIn("external", local_statuses)


class MissingPrerequisiteTests(unittest.TestCase):
    def test_missing_node_fails_with_remediation(self):
        probe = healthy_probe()
        del probe.commands["node"]
        code, output = run_main(["--json", "--scope", "stack"], probe)
        self.assertEqual(code, 1)
        report = json.loads(output)
        self.assertFalse(report["local_ready"])
        check = next(item for item in report["checks"] if item["id"] == "runtime.node")
        self.assertEqual(check["status"], "fail")
        self.assertEqual(check["severity"], "required")
        self.assertTrue(check["remediation"])

    def test_old_node_version_fails(self):
        probe = healthy_probe()
        probe.outputs[(NODE, "--version")] = "v20.11.0\n"
        code, _ = run_main(["--json", "--scope", "stack"], probe)
        self.assertEqual(code, 1)

    def test_node_without_transform_types_fails(self):
        probe = healthy_probe()
        probe.fail_runs.add((NODE, "--experimental-transform-types", "--version"))
        code, output = run_main(["--json", "--scope", "stack"], probe)
        self.assertEqual(code, 1)
        report = json.loads(output)
        check = next(item for item in report["checks"] if item["id"] == "runtime.node")
        self.assertIn("experimental-transform-types", check["detail"])

    def test_missing_npm_dependencies_report_npm_ci_remediation(self):
        probe = healthy_probe()
        probe.dirs.discard(str(REPO / "apps" / "verifier" / "node_modules" / "@solana" / "kit"))
        code, output = run_main(["--json", "--scope", "stack"], probe)
        self.assertEqual(code, 1)
        report = json.loads(output)
        check = next(item for item in report["checks"] if item["id"] == "deps.verifier")
        self.assertEqual(check["remediation"], "npm --prefix apps/verifier ci")

    def test_postgres_from_distro_layout_reports_path_remediation(self):
        probe = healthy_probe()
        del probe.commands["pg_ctl"]
        distro_ctl = "/usr/lib/postgresql/17/bin/pg_ctl"
        probe.globs["/usr/lib/postgresql/*/bin/pg_ctl"] = [distro_ctl]
        code, output = run_main(["--json", "--scope", "stack"], probe)
        self.assertEqual(code, 1)
        report = json.loads(output)
        check = next(item for item in report["checks"] if item["id"] == "runtime.postgres")
        self.assertIn("/usr/lib/postgresql/17/bin", check["remediation"])

    def test_postgres_found_through_brew_prefix(self):
        probe = healthy_probe()
        del probe.commands["pg_ctl"]
        brew = "/opt/homebrew/bin/brew"
        brew_prefix = "/opt/homebrew/opt/postgresql@17"
        probe.commands["brew"] = brew
        probe.outputs[(brew, "--prefix", "postgresql@17")] = brew_prefix + "\n"
        probe.execs.update(str(Path(brew_prefix) / "bin" / name) for name in readiness.POSTGRES_BINARIES)
        probe.outputs[(str(Path(brew_prefix) / "bin" / "pg_ctl"), "--version")] = "pg_ctl (PostgreSQL) 17.10\n"
        report = readiness.build_report(REPO, ("stack",), probe)
        self.assertTrue(report["local_ready"])
        check = next(item for item in report["checks"] if item["id"] == "runtime.postgres")
        self.assertIn("Homebrew postgresql@17", check["detail"])

    def test_port_held_by_another_process_fails(self):
        probe = healthy_probe()
        probe.ports = {8090}
        code, output = run_main(["--json", "--scope", "stack"], probe)
        self.assertEqual(code, 1)
        report = json.loads(output)
        check = next(item for item in report["checks"] if item["id"] == "ports.8090")
        self.assertEqual(check["status"], "fail")

    def test_live_pid_marker_cannot_prove_listener_ownership(self):
        probe = healthy_probe()
        probe.ports = {8090}
        probe.pids[str(REPO / "deploy" / "devnet-demo" / ".runtime" / "native" / "pids" / "demo-api.pid")] = 4242
        probe.alive = {4242}
        code, output = run_main(["--json", "--scope", "stack"], probe)
        self.assertEqual(code, 1)
        report = json.loads(output)
        check = next(item for item in report["checks"] if item["id"] == "ports.8090")
        self.assertEqual(check["status"], "fail")
        self.assertIn("pid 4242", check["detail"])

    def test_pid_zero_or_init_is_never_a_live_demo_marker(self):
        probe = readiness.Probe()
        self.assertFalse(probe.pid_alive(0))
        self.assertFalse(probe.pid_alive(1))

    def test_nonprivate_runtime_requires_a_unix_state_directory(self):
        probe = healthy_probe()
        root = REPO / "deploy" / "devnet-demo" / ".runtime" / "native"
        probe.dirs.add(str(root))
        probe.nonprivate = {str(root)}
        report = readiness.build_report(REPO, ("stack",), probe)
        self.assertFalse(report["local_ready"])
        check = next(c for c in report["checks"] if c["id"] == "files.native-state")
        self.assertEqual(check["status"], "fail")
        self.assertIn("ONELAYER_NATIVE_STATE_DIR", check["remediation"])
        probe.env["ONELAYER_NATIVE_STATE_DIR"] = "/private/state"
        self.assertTrue(readiness.build_report(REPO, ("stack",), probe)["local_ready"])

    def test_real_private_directory_rejects_shared_mode_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            root.mkdir(mode=0o700)
            probe = readiness.Probe()
            self.assertTrue(probe.private_directory(root))
            root.chmod(0o777)
            self.assertFalse(probe.private_directory(root))
            root.chmod(0o700)
            link = Path(directory) / "link"
            link.symlink_to(root, target_is_directory=True)
            self.assertFalse(probe.private_directory(link))

    def test_override_selects_its_own_pid_markers(self):
        probe = healthy_probe()
        probe.env["ONELAYER_NATIVE_STATE_DIR"] = "/private/state"
        probe.ports = {8090}
        probe.pids["/private/state/pids/demo-api.pid"] = 4242
        probe.alive = {4242}
        report = readiness.build_report(REPO, ("stack",), probe)
        check = next(c for c in report["checks"] if c["id"] == "ports.8090")
        self.assertEqual(check["status"], "fail")
        self.assertIn("pid 4242", check["detail"])

    def test_state_override_cannot_name_a_regular_file(self):
        probe = healthy_probe()
        probe.env["ONELAYER_NATIVE_STATE_DIR"] = "/private/not-directory"
        probe.files.add("/private/not-directory")
        report = readiness.build_report(REPO, ("stack",), probe)
        self.assertFalse(report["local_ready"])
        check = next(c for c in report["checks"] if c["id"] == "files.native-state")
        self.assertEqual(check["status"], "fail")

    def test_dangling_state_symlink_is_not_reported_as_absent(self):
        probe = healthy_probe()
        probe.env["ONELAYER_NATIVE_STATE_DIR"] = "/private/link"
        probe.symlinks = {"/private/link"}
        report = readiness.build_report(REPO, ("stack",), probe)
        self.assertFalse(report["local_ready"])
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "dangling"
            link.symlink_to(Path(directory) / "missing")
            self.assertTrue(readiness.Probe().is_symlink(link))

class ScopeTests(unittest.TestCase):
    def test_stack_scope_ignores_missing_desktop_prerequisites(self):
        probe = healthy_probe()
        probe.execs.discard(PYTHON)
        probe.env.pop("DISPLAY")
        code, output = run_main(["--json", "--scope", "stack"], probe)
        self.assertEqual(code, 0)
        report = json.loads(output)
        self.assertTrue(all(item["group"] == "stack" for item in report["checks"]))
        code, _ = run_main(["--json", "--scope", "all"], probe)
        self.assertEqual(code, 1)

    def test_desktop_scope_skips_stack_checks(self):
        probe = healthy_probe()
        del probe.commands["node"]
        code, output = run_main(["--json", "--scope", "desktop"], probe)
        self.assertEqual(code, 0)
        report = json.loads(output)
        self.assertTrue(all(item["group"] == "desktop" for item in report["checks"]))

    def test_missing_display_fails_for_desktop_scope(self):
        probe = healthy_probe()
        probe.env.pop("DISPLAY")
        code, output = run_main(["--json", "--scope", "desktop"], probe)
        self.assertEqual(code, 1)
        report = json.loads(output)
        check = next(item for item in report["checks"] if item["id"] == "desktop.display")
        self.assertEqual(check["status"], "fail")


class SecretSurfaceTests(unittest.TestCase):
    def test_probe_surface_never_includes_secret_files(self):
        probe = healthy_probe()
        probe.dirs.add("/dev/shm/onelayer-devnet-demo")
        for path in SECRET_PATHS:
            probe.files.add(path)  # pretend they exist; readiness must not look at them
        code, output = run_main(["--json", "--scope", "all"], probe)
        self.assertEqual(code, 0)
        for path in SECRET_PATHS:
            self.assertNotIn(path, probe.seen_paths)
        for argv in probe.runs:
            joined = " ".join(argv)
            for path in SECRET_PATHS:
                self.assertNotIn(path, joined)
        self.assertNotIn("SUPERSECRET", output)
        self.assertNotIn("issuer-secret", output)
        self.assertNotIn("admin-credentials", output)

    def test_environment_values_are_never_printed(self):
        probe = healthy_probe()
        probe.env["DISPLAY"] = ":0.0-with-private-host"
        code, output = run_main(["--json", "--scope", "desktop"], probe)
        self.assertEqual(code, 0)
        self.assertNotIn("private-host", output)
        self.assertIn("DISPLAY", output)


class RealCliTests(unittest.TestCase):
    """Subprocess checks for script-location-based paths and valid JSON."""

    def test_cli_from_spaced_cwd_keeps_script_location_root(self):
        script = Path(__file__).resolve().parent / "readiness.py"
        expected_root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(prefix="One Layer ") as tmp:
            completed = subprocess.run(
                [sys.executable, str(script), "--json", "--scope", "stack"],
                cwd=tmp, capture_output=True, text=True, timeout=180,
            )
        self.assertIn(completed.returncode, (0, 1))
        report = json.loads(completed.stdout)
        self.assertEqual(report["repository"], str(expected_root))

    def test_cli_from_spaced_script_path_reports_that_root(self):
        script = Path(__file__).resolve().parent / "readiness.py"
        with tempfile.TemporaryDirectory(prefix="One Layer ") as tmp:
            root = Path(tmp) / "check out"
            target = root / "apps" / "desktop" / "readiness.py"
            target.parent.mkdir(parents=True)
            shutil.copyfile(script, target)
            completed = subprocess.run(
                [sys.executable, str(target), "--json", "--scope", "stack"],
                cwd=tmp, capture_output=True, text=True, timeout=180,
            )
        self.assertEqual(completed.returncode, 1)
        report = json.loads(completed.stdout)
        self.assertEqual(report["repository"], str(root))
        self.assertFalse(report["local_ready"])


if __name__ == "__main__":
    unittest.main()
