"""Contract tests for the local signer / address adapter (B2).

The adapter is the only desktop-side touchpoint for key material, so these
checks pin its subprocess contract: shell-free argv, request on stdin, strict
single-object output, code-only failures and no key bytes on any channel.

Two layers:
* a recording runner exercises the mapping logic deterministically;
* real subprocesses (Node + stub helper, Node + the real A1 key-store helper)
  exercise the transport. The real helper is initialized under a throwaway
  ``HOME`` — never the developer's key store.
"""
import base64
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from live_demo_signer import (  # noqa: E402
    ADDRESS_OUTPUT_INVALID,
    ADDRESS_UNAVAILABLE,
    OperatorSigner,
    SIGNER_FAILED,
    SIGNER_OUTPUT_INVALID,
    SIGNER_OUTPUT_TOO_LARGE,
    SIGNER_REQUEST_INVALID,
    SIGNER_TIMEOUT,
    SIGNER_UNAVAILABLE,
    SignerError,
    default_key_file,
)

LAB_DIR = Path(__file__).resolve().parent
REPO_ROOT = LAB_DIR.parents[2]
NODE = "node"

REQUEST = {
    "approved": True,
    "intentId": "11111111-2222-3333-4444-555555555555",
    "cluster": "solana:devnet",
    "intentHash": "dd" * 32,
    "transactionBase64": base64.b64encode(b"\x01" * 64).decode(),
    "instructionData": base64.b64encode(bytes(range(178))).decode(),
    "intent": {},
}


class RecordingRunner:
    """Test double for the subprocess runner: records argv and stdin."""

    def __init__(self, *, code=0, stdout=b"", stderr=b""):
        self.code = code
        self.stdout = stdout
        self.stderr = stderr
        self.calls = []

    def __call__(self, argv, *, input_bytes, timeout, env=None):
        self.calls.append({"argv": list(argv), "input": input_bytes, "timeout": timeout, "env": env})
        return self.code, self.stdout, self.stderr


def _signer(runner, **kwargs):
    return OperatorSigner(repo_root=REPO_ROOT, runner=runner, **kwargs)


class SignRequestContractTests(unittest.TestCase):
    def test_sign_happy_path_returns_only_the_signed_transaction(self):
        runner = RecordingRunner(stdout=b'{"signedTransactionBase64":"QUJD"}\n')
        signed = _signer(runner).sign(REQUEST)
        self.assertEqual(signed, "QUJD")
        call = runner.calls[0]
        self.assertIn("live-demo-sign.ts", call["argv"][-1])
        self.assertTrue(call["argv"][0].endswith("node"))
        self.assertEqual(call["argv"][1:4], [
            "--experimental-transform-types",
            "--disable-warning=ExperimentalWarning",
            call["argv"][3],
        ])
        self.assertEqual(json.loads(call["input"]), REQUEST)

    def test_request_travels_on_stdin_and_never_in_argv(self):
        runner = RecordingRunner(stdout=b'{"signedTransactionBase64":"QUJD"}')
        _signer(runner).sign(REQUEST)
        joined = " ".join(runner.calls[0]["argv"])
        self.assertNotIn("intentHash", joined)
        self.assertNotIn(REQUEST["intentHash"], joined)

    def test_unapproved_request_is_refused_before_any_process(self):
        runner = RecordingRunner(stdout=b"{}")
        signer = _signer(runner)
        for request in ({}, dict(REQUEST, approved=False), dict(REQUEST, approved="true")):
            with self.subTest(request=request), self.assertRaises(SignerError) as caught:
                signer.sign(request)
            self.assertEqual(caught.exception.code, SIGNER_REQUEST_INVALID)
        self.assertEqual(runner.calls, [])

    def test_non_mapping_request_is_refused(self):
        runner = RecordingRunner(stdout=b"{}")
        with self.assertRaises(SignerError) as caught:
            _signer(runner).sign(["not", "a", "mapping"])
        self.assertEqual(caught.exception.code, SIGNER_REQUEST_INVALID)
        self.assertEqual(runner.calls, [])

    def test_helper_failure_codes_are_reported_verbatim(self):
        for stderr, expected in (
            (b'{"error":{"code":"KEYFILE_REJECTED"}}\n', "KEYFILE_REJECTED"),
            (b'{"error":{"code":"OPERATOR_MISMATCH"}}\n', "OPERATOR_MISMATCH"),
            (b'{"error":{"code":"APPROVAL_REQUIRED"}}\n', "APPROVAL_REQUIRED"),
            (b'{"error":{"code":"SOMETHING_ELSE"}}\n', "SOMETHING_ELSE"),
        ):
            runner = RecordingRunner(code=3, stderr=stderr)
            with self.subTest(stderr=stderr), self.assertRaises(SignerError) as caught:
                _signer(runner).sign(REQUEST)
            self.assertEqual(caught.exception.code, expected)

    def test_failure_without_a_code_falls_back_and_never_echoes_stderr(self):
        runner = RecordingRunner(code=1, stderr=b"private-canary-secret")
        with self.assertRaises(SignerError) as caught:
            _signer(runner).sign(REQUEST)
        self.assertEqual(caught.exception.code, SIGNER_FAILED)
        self.assertNotIn("private-canary", str(caught.exception))
        self.assertNotIn("private-canary", repr(caught.exception.args))

    def test_malformed_success_output_is_refused(self):
        for stdout in (b"", b"not json", b"[]", b'{"other":1}', b'{"signedTransactionBase64":""}',
                       b'{"signedTransactionBase64":123}'):
            runner = RecordingRunner(stdout=stdout)
            with self.subTest(stdout=stdout), self.assertRaises(SignerError) as caught:
                _signer(runner).sign(REQUEST)
            self.assertEqual(caught.exception.code, SIGNER_OUTPUT_INVALID)

    def test_oversized_output_is_refused(self):
        huge = b'{"signedTransactionBase64":"' + b"A" * 200000 + b'"}'
        runner = RecordingRunner(stdout=huge)
        with self.assertRaises(SignerError) as caught:
            _signer(runner).sign(REQUEST)
        self.assertEqual(caught.exception.code, SIGNER_OUTPUT_TOO_LARGE)

    def test_timeout_is_its_own_code(self):
        def runner(argv, *, input_bytes, timeout, env=None):
            raise SignerError(SIGNER_TIMEOUT)

        with self.assertRaises(SignerError) as caught:
            _signer(runner).sign(REQUEST)
        self.assertEqual(caught.exception.code, SIGNER_TIMEOUT)

    def test_missing_helper_script_is_unavailable(self):
        signer = OperatorSigner(
            repo_root=REPO_ROOT,
            signer_script=REPO_ROOT / "apps" / "demo-api" / "scripts" / "does-not-exist.ts",
            runner=RecordingRunner(stdout=b"{}"),
        )
        with self.assertRaises(SignerError) as caught:
            signer.sign(REQUEST)
        self.assertEqual(caught.exception.code, SIGNER_UNAVAILABLE)


class AddressContractTests(unittest.TestCase):
    def test_operator_address_reports_only_public_identity(self):
        runner = RecordingRunner(
            stdout=b'{"address":"4Y4pGizJm5CL789jRKYx5jeQLJ58eBBmf5UzGRFChikn",'
                   b'"path":"/x/demo-operator.json","created":false}\n')
        result = _signer(runner).operator_address()
        self.assertEqual(result.address, "4Y4pGizJm5CL789jRKYx5jeQLJ58eBBmf5UzGRFChikn")
        self.assertEqual(result.path, "/x/demo-operator.json")
        self.assertFalse(result.created)

    def test_ensure_flag_is_forwarded(self):
        runner = RecordingRunner(stdout=b'{"address":"A","path":"/x","created":true}')
        result = _signer(runner).operator_address(ensure=True)
        self.assertTrue(result.created)
        self.assertIn("--ensure", runner.calls[0]["argv"])

    def test_key_file_option_is_forwarded_only_as_a_path(self):
        runner = RecordingRunner(stdout=b'{"signedTransactionBase64":"QUJD"}')
        signer = OperatorSigner(repo_root=REPO_ROOT, runner=runner, key_file="/dev/shm/private-dir/key.json")
        signer.sign(REQUEST)
        argv = runner.calls[0]["argv"]
        self.assertIn("--key-file", argv)
        self.assertIn("/dev/shm/private-dir/key.json", argv)
        self.assertNotIn("QUJD", " ".join(argv))

    def test_address_failures_are_code_only(self):
        for code, stdout, stderr, expected in (
            (3, b"", b'{"error":{"code":"KEYFILE_UNREADABLE"}}', "KEYFILE_UNREADABLE"),
            (3, b"", b"junk", ADDRESS_UNAVAILABLE),
            (0, b"{}", b"", ADDRESS_OUTPUT_INVALID),
            (0, b'{"address":"x"*200,"path":"/x"}', b"", ADDRESS_OUTPUT_INVALID),
        ):
            runner = RecordingRunner(code=code, stdout=stdout, stderr=stderr)
            with self.subTest(stderr=stderr, stdout=stdout), self.assertRaises(SignerError) as caught:
                _signer(runner).operator_address()
            self.assertEqual(caught.exception.code, expected)

    def test_default_key_file_is_the_persistent_store(self):
        self.assertTrue(default_key_file().endswith(
            ".local/state/onelayer-devnet-demo/keys/demo-operator.json"))


@unittest.skipUnless(subprocess.run([NODE, "--version"], capture_output=True).returncode == 0,
                     "node is required for the real helper checks")
class RealSubprocessTests(unittest.TestCase):
    """Real processes: stub helpers for transport, real key-store helper for identity."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="onelayer-live-demo-signer-"))
        self.addCleanup(self._cleanup_home)
        self.env = dict(os.environ, HOME=str(self.home))
        self.stub_dir = Path(tempfile.mkdtemp(prefix="onelayer-live-demo-stub-"))
        self.addCleanup(self._cleanup_stubs)

    def _cleanup_home(self):
        import shutil
        for root, _dirs, files in os.walk(self.home, topdown=False):
            for name in files:
                Path(root, name).chmod(0o600)
        shutil.rmtree(self.home, ignore_errors=True)

    def _cleanup_stubs(self):
        import shutil
        shutil.rmtree(self.stub_dir, ignore_errors=True)

    def _stub(self, name, source):
        path = self.stub_dir / name
        path.write_text(source)
        return path

    def test_real_subprocess_signs_with_no_shell_and_stdin_request(self):
        stub = self._stub("sign.mjs", """
process.stdin.on("data", () => {});
process.stdin.on("end", () => {
  process.stdout.write(JSON.stringify({ signedTransactionBase64: "QUJD" }) + "\\n");
});
""")
        signer = OperatorSigner(repo_root=REPO_ROOT, signer_script=stub, env=self.env, node=NODE)
        self.assertEqual(signer.sign(REQUEST), "QUJD")

    def test_real_subprocess_failure_is_code_only(self):
        stub = self._stub("fail.mjs", """
process.stderr.write(JSON.stringify({ error: { code: "KEYFILE_REJECTED" } }) + "\\n");
process.exit(3);
""")
        signer = OperatorSigner(repo_root=REPO_ROOT, signer_script=stub, env=self.env, node=NODE)
        with self.assertRaises(SignerError) as caught:
            signer.sign(REQUEST)
        self.assertEqual(caught.exception.code, "KEYFILE_REJECTED")

    def test_real_address_helper_ensures_and_then_reads_without_key_material(self):
        signer = OperatorSigner(repo_root=REPO_ROOT, env=self.env, node=NODE)
        created = signer.operator_address(ensure=True)
        self.assertTrue(created.created)
        self.assertTrue(created.path.endswith("demo-operator.json"))
        looked_up = signer.operator_address()
        self.assertEqual(looked_up.address, created.address)
        self.assertFalse(looked_up.created)
        key_path = Path(created.path)
        self.assertTrue(key_path.is_file())
        mode = stat.S_IMODE(key_path.stat().st_mode)
        self.assertEqual(mode & 0o077, 0)
        # The key file is the Solana CLI 64-byte layout, and nothing outside
        # {address, path, created} ever leaves the helper.
        key_bytes = json.loads(key_path.read_text())
        self.assertEqual(len(key_bytes), 64)
        self.assertEqual(set(vars(created)), {"address", "path", "created"})

    def test_real_address_helper_never_creates_a_key_without_ensure(self):
        signer = OperatorSigner(repo_root=REPO_ROOT, env=self.env, node=NODE)
        with self.assertRaises(SignerError) as caught:
            signer.operator_address()
        self.assertIn(caught.exception.code, ("KEYFILE_UNREADABLE", "KEYFILE_REJECTED"))
        self.assertFalse((self.home / ".local").exists())

    def test_oversized_helper_output_is_streamed_and_capped(self):
        stub = self._stub("flood.mjs", 'process.stdout.write("x".repeat(300000));\n')
        signer = OperatorSigner(repo_root=REPO_ROOT, signer_script=stub, env=self.env, node=NODE)
        started = time.monotonic()
        with self.assertRaises(SignerError) as caught:
            signer.sign(REQUEST)
        self.assertEqual(caught.exception.code, SIGNER_OUTPUT_TOO_LARGE)
        # Streamed capping: the flood is cut off and killed, not buffered whole.
        self.assertLess(time.monotonic() - started, 10)

    def test_a_runaway_helper_is_killed_on_timeout(self):
        stub = self._stub("hang.mjs", "setTimeout(() => {}, 60000);\n")
        signer = OperatorSigner(
            repo_root=REPO_ROOT, signer_script=stub, env=self.env, node=NODE, timeout=0.5)
        started = time.monotonic()
        with self.assertRaises(SignerError) as caught:
            signer.sign(REQUEST)
        self.assertEqual(caught.exception.code, SIGNER_TIMEOUT)
        self.assertLess(time.monotonic() - started, 5)


if __name__ == "__main__":
    unittest.main()
