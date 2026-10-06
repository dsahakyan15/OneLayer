"""Contract tests for the QR image adapter (B2).

The real decoder lives in A4 (``apps/mvp-web/scripts/live-demo-qr-decode.mjs``).
Until that lands, these tests pin the *adapter* contract with a stub helper and
never claim the real decoder is validated: payload parsing, PNG pre-checks,
positional/``--input`` tolerance and code-only failures.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from live_demo_qr import (  # noqa: E402
    QR_DECODER_UNAVAILABLE,
    QR_IMAGE_INVALID,
    QR_PAYLOAD_MALFORMED,
    QR_UNREADABLE,
    QrDecoderError,
    QrImageDecoder,
)

LAB_DIR = Path(__file__).resolve().parent
REPO_ROOT = LAB_DIR.parents[2]
NODE = "node"
GOOD_URL = "http://127.0.0.1:8090/c/" + "ab" * 16 + "?h=" + "A" * 43

_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


class RecordingRunner:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def __call__(self, argv, *, input_bytes, timeout, env=None):
        self.calls.append({"argv": list(argv), "input": input_bytes, "timeout": timeout, "env": env})
        return self.outcomes.pop(0) if self.outcomes else (1, b"", b"")


def _png_file(directory: Path, name: str = "qr.png", data: bytes = _PNG) -> Path:
    path = directory / name
    path.write_bytes(data)
    return path


class QrAdapterTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="onelayer-live-demo-qr-"))
        self.addCleanup(self._cleanup)
        self.helper = self.root / "live-demo-qr-decode.mjs"
        self.helper.write_text("// stub helper for adapter tests\n")

    def _cleanup(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def _decoder(self, runner):
        return QrImageDecoder(repo_root=REPO_ROOT, helper=self.helper, runner=runner, node=NODE)

    def test_bare_url_output_is_accepted(self):
        runner = RecordingRunner([(0, (GOOD_URL + "\n").encode(), b"")])
        image = _png_file(self.root)
        self.assertEqual(self._decoder(runner).decode(image), GOOD_URL)
        self.assertEqual(runner.calls[0]["argv"][-1], str(image))
        self.assertEqual(runner.calls[0]["input"], b"")

    def test_json_url_output_is_accepted(self):
        runner = RecordingRunner([(0, json.dumps({"url": GOOD_URL}).encode(), b"")])
        self.assertEqual(self._decoder(runner).decode(_png_file(self.root)), GOOD_URL)

    def test_positional_usage_failure_falls_back_to_input_flag(self):
        runner = RecordingRunner([
            (2, b"", b"usage"),
            (0, (GOOD_URL + "\n").encode(), b""),
        ])
        image = _png_file(self.root)
        self.assertEqual(self._decoder(runner).decode(image), GOOD_URL)
        self.assertEqual(len(runner.calls), 2)
        self.assertEqual(runner.calls[1]["argv"][-2], "--input")
        self.assertEqual(runner.calls[1]["argv"][-1], str(image))

    def test_undecodable_image_reports_unreadable(self):
        runner = RecordingRunner([(3, b"", b""), (3, b"", b"")])
        with self.assertRaises(QrDecoderError) as caught:
            self._decoder(runner).decode(_png_file(self.root))
        self.assertEqual(caught.exception.code, QR_UNREADABLE)
        self.assertEqual(str(caught.exception), QR_UNREADABLE)

    def test_no_qr_and_input_refusals_are_unreadable_not_unavailable(self):
        # A4: 3 = refused input/image, 4 = no usable QR — both mean the image
        # is unreadable; only a missing/broken helper is "unavailable". (This
        # supersedes the older note that mapped exit 4 to QR_DECODER_UNAVAILABLE.)
        for code in (3, 4):
            runner = RecordingRunner([(code, b"", b""), (code, b"", b"")])
            with self.subTest(code=code), self.assertRaises(QrDecoderError) as caught:
                self._decoder(runner).decode(_png_file(self.root))
            self.assertEqual(caught.exception.code, QR_UNREADABLE)
        for code in (1, 2):
            runner = RecordingRunner([(code, b"", b""), (code, b"", b"")])
            with self.subTest(code=code), self.assertRaises(QrDecoderError) as caught:
                self._decoder(runner).decode(_png_file(self.root))
            self.assertEqual(caught.exception.code, QR_DECODER_UNAVAILABLE)

    def test_missing_helper_is_unavailable(self):
        decoder = QrImageDecoder(
            repo_root=REPO_ROOT,
            helper=self.root / "does-not-exist.mjs",
            runner=RecordingRunner([]),
            node=NODE,
        )
        with self.assertRaises(QrDecoderError) as caught:
            decoder.decode(_png_file(self.root))
        self.assertEqual(caught.exception.code, QR_DECODER_UNAVAILABLE)
        self.assertFalse(decoder.available)

    def test_non_loopback_payload_is_refused(self):
        for payload in (
            "https://evil.example/c/aa?h=" + "A" * 43,
            "http://127.0.0.1:8090/admin",
            "http://127.0.0.1:8090/c/zz?h=" + "A" * 43,
            "file:///etc/passwd",
        ):
            runner = RecordingRunner([(0, (payload + "\n").encode(), b"")])
            with self.subTest(payload=payload), self.assertRaises(QrDecoderError) as caught:
                self._decoder(runner).decode(_png_file(self.root))
            self.assertEqual(caught.exception.code, QR_PAYLOAD_MALFORMED)

    def test_empty_helper_output_is_an_unreadable_image(self):
        runner = RecordingRunner([(0, b"", b"")])
        with self.assertRaises(QrDecoderError) as caught:
            self._decoder(runner).decode(_png_file(self.root))
        self.assertEqual(caught.exception.code, QR_UNREADABLE)

    def test_json_output_without_a_url_is_refused(self):
        runner = RecordingRunner([(0, json.dumps({"path": GOOD_URL}).encode(), b"")])
        with self.assertRaises(QrDecoderError) as caught:
            self._decoder(runner).decode(_png_file(self.root))
        self.assertEqual(caught.exception.code, QR_PAYLOAD_MALFORMED)

    def test_png_prechecks_run_before_the_helper(self):
        runner = RecordingRunner([])
        decoder = self._decoder(runner)
        cases = [
            _png_file(self.root, "not-png.png", b"hello world, not a png"),
            _png_file(self.root, "empty.png", b""),
            self.root / "missing.png",
        ]
        for path in cases:
            with self.subTest(path=path), self.assertRaises(QrDecoderError) as caught:
                decoder.decode(path)
            self.assertEqual(caught.exception.code, QR_IMAGE_INVALID)
        self.assertEqual(runner.calls, [])

    def test_symlinked_image_is_refused(self):
        image = _png_file(self.root)
        link = self.root / "link.png"
        link.symlink_to(image)
        with self.assertRaises(QrDecoderError) as caught:
            self._decoder(RecordingRunner([])).decode(link)
        self.assertEqual(caught.exception.code, QR_IMAGE_INVALID)

    def test_helper_failure_codes_do_not_leak_helper_output(self):
        runner = RecordingRunner([(1, b"", b"private-canary-detail")])
        with self.assertRaises(QrDecoderError) as caught:
            self._decoder(runner).decode(_png_file(self.root))
        self.assertEqual(caught.exception.code, QR_DECODER_UNAVAILABLE)
        self.assertNotIn("private-canary", str(caught.exception))


@unittest.skipUnless(subprocess.run([NODE, "--version"], capture_output=True).returncode == 0,
                     "node is required for the real subprocess check")
class RealSubprocessTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="onelayer-live-demo-qr-"))
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def test_real_a4_helper_decodes_a_generated_qr_png(self):
        """End-to-end against the real A4 decoder (not a double)."""
        helper = REPO_ROOT / "apps" / "mvp-web" / "scripts" / "live-demo-qr-decode.mjs"
        if not helper.is_file():
            self.skipTest("A4 QR helper is not present in this checkout")
        generator = self.root / "gen.mjs"
        generator.write_text(
            "import { createRequire } from 'node:module';\n"
            "import { writeFileSync } from 'node:fs';\n"
            f"const require = createRequire({json.dumps(str(helper))});\n"
            "const QRCode = require('qrcode');\n"
            "const [out, payload] = process.argv.slice(2);\n"
            "const buf = await QRCode.toBuffer(payload, "
            "{ type: 'png', errorCorrectionLevel: 'M', margin: 2, width: 256 });\n"
            "writeFileSync(out, buf);\n"
        )
        image = self.root / "real-qr.png"
        subprocess.run(
            [NODE, str(generator), str(image), GOOD_URL],
            check=True, capture_output=True, cwd=str(REPO_ROOT),
        )
        self.assertTrue(image.read_bytes().startswith(b"\x89PNG"))
        decoder = QrImageDecoder(repo_root=REPO_ROOT, node=NODE)
        self.assertTrue(decoder.available)
        self.assertEqual(decoder.decode(image), GOOD_URL)

    def test_stub_helper_runs_without_a_shell(self):
        helper = self.root / "stub.mjs"
        helper.write_text(
            "import { readFileSync } from 'node:fs';\n"
            "const path = process.argv[2] === '--input' ? process.argv[3] : process.argv[2];\n"
            "readFileSync(path);\n"
            f"process.stdout.write({json.dumps(GOOD_URL)} + '\\n');\n"
        )
        image = self.root / "qr.png"
        image.write_bytes(_PNG)
        decoder = QrImageDecoder(repo_root=REPO_ROOT, helper=helper, node=NODE)
        self.assertTrue(decoder.available)
        self.assertEqual(decoder.decode(image), GOOD_URL)

    def test_oversized_helper_output_is_streamed_and_capped(self):
        helper = self.root / "flood.mjs"
        helper.write_text('process.stdout.write("x".repeat(300000));\n')
        image = _png_file(self.root)
        decoder = QrImageDecoder(repo_root=REPO_ROOT, helper=helper, node=NODE)
        started = time.monotonic()
        with self.assertRaises(QrDecoderError) as caught:
            decoder.decode(image)
        self.assertEqual(caught.exception.code, QR_UNREADABLE)
        self.assertLess(time.monotonic() - started, 10)

    def test_a_runaway_helper_is_killed_on_timeout(self):
        helper = self.root / "hang.mjs"
        helper.write_text("setTimeout(() => {}, 60000);\n")
        image = _png_file(self.root)
        decoder = QrImageDecoder(repo_root=REPO_ROOT, helper=helper, node=NODE, timeout=0.5)
        started = time.monotonic()
        with self.assertRaises(QrDecoderError) as caught:
            decoder.decode(image)
        self.assertEqual(caught.exception.code, QR_UNREADABLE)
        self.assertLess(time.monotonic() - started, 5)


if __name__ == "__main__":
    unittest.main()
