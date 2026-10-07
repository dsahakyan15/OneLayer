"""Contract tests for the shared helper runtime (B2 revision).

``run_bounded`` is the single subprocess path for every Node helper: no shell,
bounded stdin, and stdout/stderr capped *while* the process runs so a runaway
helper is killed instead of buffered. ``source_root_binding`` is the installer's
one-path binding to the trusted source tree — validated (absolute, bounded,
helpers present) before it is ever used.
"""
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from live_demo_runtime import (  # noqa: E402
    MAX_OUTPUT_BYTES,
    MAX_SOURCE_ROOT_CHARS,
    OUTPUT_TOO_LARGE,
    TIMEOUT,
    UNAVAILABLE,
    BoundedRunError,
    discover_source_root,
    expected_helper_paths,
    run_bounded,
    source_root_binding,
)

LAB_DIR = Path(__file__).resolve().parent
REPO_ROOT = LAB_DIR.parents[2]
NODE = "node"


@unittest.skipUnless(subprocess.run([NODE, "--version"], capture_output=True).returncode == 0,
                     "node is required for the bounded-run checks")
class RunBoundedTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="onelayer-live-demo-runtime-"))
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def _script(self, name, source):
        path = self.root / name
        path.write_text(source)
        return path

    def test_returns_the_exit_code_and_both_streams(self):
        script = self._script("both.mjs", """
process.stdout.write("out");
process.stderr.write("err");
process.exit(7);
""")
        code, out, err = run_bounded([NODE, str(script)], timeout=10)
        self.assertEqual(code, 7)
        self.assertEqual(out, b"out")
        self.assertEqual(err, b"err")

    def test_stdin_is_delivered_and_bounded_by_the_caller(self):
        script = self._script("echo.mjs", """
process.stdin.on("data", () => {});
process.stdin.on("end", () => process.stdout.write("done"));
""")
        code, out, _ = run_bounded([NODE, str(script)], input_bytes=b"{}", timeout=10)
        self.assertEqual((code, out), (0, b"done"))

    def test_output_above_the_cap_is_refused_and_the_process_is_killed(self):
        script = self._script("flood.mjs", 'process.stdout.write("x".repeat(5000000));\n')
        started = time.monotonic()
        with self.assertRaises(BoundedRunError) as caught:
            run_bounded([NODE, str(script)], timeout=30, max_output=1024)
        self.assertEqual(caught.exception.code, OUTPUT_TOO_LARGE)
        self.assertLess(time.monotonic() - started, 10)

    def test_timeout_kills_a_runaway_process(self):
        script = self._script("hang.mjs", "setTimeout(() => {}, 60000);\n")
        started = time.monotonic()
        with self.assertRaises(BoundedRunError) as caught:
            run_bounded([NODE, str(script)], timeout=0.4)
        self.assertEqual(caught.exception.code, TIMEOUT)
        self.assertLess(time.monotonic() - started, 5)

    def test_missing_binary_is_unavailable(self):
        with self.assertRaises(BoundedRunError) as caught:
            run_bounded([str(self.root / "does-not-exist")], timeout=2)
        self.assertEqual(caught.exception.code, UNAVAILABLE)

    def test_default_cap_is_the_module_bound(self):
        self.assertEqual(MAX_OUTPUT_BYTES, 64 * 1024)


class SourceRootBindingTests(unittest.TestCase):
    """The binding is data: validated hard before any helper runs."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="onelayer-live-demo-binding-"))
        self.addCleanup(self._cleanup)
        self.spaced = self.root / "source root with spaces"
        for path in expected_helper_paths(self.spaced):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("// helper stand-in\n")
        self.spaced_helper_count = len(expected_helper_paths(self.spaced))

    def _cleanup(self):
        import shutil
        sys.modules.pop("live_demo_source_root", None)
        if str(self.root) in sys.path:
            sys.path.remove(str(self.root))
        shutil.rmtree(self.root, ignore_errors=True)

    def _bind(self, value: str | Path):
        (self.root / "live_demo_source_root.py").write_text(
            f"SOURCE_REPO_ROOT = {str(value)!r}\n")
        sys.modules.pop("live_demo_source_root", None)
        if str(self.root) not in sys.path:
            sys.path.insert(0, str(self.root))
        return source_root_binding()

    def test_source_checkout_root_is_inferred_from_this_file(self):
        root = discover_source_root()
        self.assertEqual(root, REPO_ROOT)
        for helper in expected_helper_paths(root):
            self.assertTrue(helper.is_file(), helper)

    def test_spaced_binding_path_is_accepted(self):
        bound = self._bind(self.spaced)
        self.assertEqual(bound, self.spaced)
        self.assertEqual(len(expected_helper_paths(bound)), self.spaced_helper_count)

    def test_relative_and_oversized_and_empty_values_are_refused(self):
        self.assertIsNone(self._bind("relative/path"))
        self.assertIsNone(self._bind("x" * (MAX_SOURCE_ROOT_CHARS + 1)))
        (self.root / "live_demo_source_root.py").write_text("SOURCE_REPO_ROOT = ''\n")
        sys.modules.pop("live_demo_source_root", None)
        self.assertIsNone(source_root_binding())

    def test_binding_without_the_expected_helpers_is_refused(self):
        incomplete = self.root / "incomplete"
        incomplete.mkdir()
        (incomplete / "apps").mkdir()
        self.assertIsNone(self._bind(incomplete))

    def test_non_string_values_are_refused(self):
        (self.root / "live_demo_source_root.py").write_text("SOURCE_REPO_ROOT = 42\n")
        sys.modules.pop("live_demo_source_root", None)
        if str(self.root) not in sys.path:
            sys.path.insert(0, str(self.root))
        self.assertIsNone(source_root_binding())

    def test_binding_module_is_absent_in_the_source_checkout(self):
        # The source checkout runs from inference; no binding module is shipped.
        self.assertFalse((LAB_DIR / "live_demo_source_root.py").exists())


if __name__ == "__main__":
    unittest.main()
