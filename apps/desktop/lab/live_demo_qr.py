"""QR image adapter for the live-demo launcher (B2).

Thin adapter over the anticipated A4 helper
``apps/mvp-web/scripts/live-demo-qr-decode.mjs``. The desktop never decodes QR
images itself and never fetches the decoded URL: this module turns a local PNG
into the *payload string* and hands it to :mod:`live_demo_api`, which parses the
loopback URL and retrieves the package from the demo API.

Helper CLI contract (A4, ``apps/mvp-web/scripts/live-demo-qr-decode.mjs``):

.. code-block:: text

    node apps/mvp-web/scripts/live-demo-qr-decode.mjs <png-path>

    stdout: the payload text (the loopback certificate URL) plus a newline
    stderr (failure): {"error":{"code":"..."}}
    exit 0 decoded · 2 refused request · 3 refused input/image · 4 no usable QR

The helper only *decodes* — it never fetches the URL and never runs a command.
This adapter leads with the positional form (A4's spelling) and tolerates a
``--input <png-path>`` alternative and a ``{"url": ...}`` output shape so a
respin of the helper cannot break the launcher. A missing helper is simply
"unavailable" and the Verify page says so honestly.

Security: the input path is an ordinary file the operator picked in a native
chooser; only its size and PNG signature are inspected here. The decoded value
is accepted only if it is the exact loopback ``/c/<id>?h=<hash>`` shape that
:func:`live_demo_api.parse_qr_payload` allows. No network access happens in
this module.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from live_demo_api import MAX_QR_IMAGE_BYTES, parse_qr_payload
from live_demo_runtime import (
    OUTPUT_TOO_LARGE,
    TIMEOUT,
    UNAVAILABLE,
    BoundedRunError,
    discover_source_root,
    run_bounded,
)
from live_demo_session import LiveDemoError

__all__ = [
    "QrDecoderError",
    "QrImageDecoder",
    "QR_DECODER_UNAVAILABLE",
    "QR_IMAGE_INVALID",
    "QR_UNREADABLE",
]

QR_DECODER_UNAVAILABLE = "QR_DECODER_UNAVAILABLE"
QR_UNREADABLE = "QR_UNREADABLE"
QR_IMAGE_INVALID = "QR_IMAGE_INVALID"
QR_PAYLOAD_MALFORMED = "QR_PAYLOAD_MALFORMED"

MAX_OUTPUT_BYTES = 16 * 1024
DEFAULT_TIMEOUT_SECONDS = 15.0
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class QrDecoderError(LiveDemoError):
    """QR image decoding failed. ``detail`` is a bare code."""

    def __init__(self, code: str, detail: str | None = None):
        super().__init__("error", detail or code)
        self.code = code

    def __str__(self) -> str:
        return self.code


Runner = Callable[..., tuple[int, bytes, bytes]]


def _default_runner(
    argv: Sequence[str],
    *,
    input_bytes: bytes,
    timeout: float,
    env: Mapping[str, str] | None = None,
) -> tuple[int, bytes, bytes]:
    try:
        return run_bounded(
            list(argv),
            input_bytes=input_bytes,
            timeout=timeout,
            env=env,
            max_output=MAX_OUTPUT_BYTES,
        )
    except BoundedRunError as error:
        if error.code == UNAVAILABLE:
            raise QrDecoderError(QR_DECODER_UNAVAILABLE) from None
        # timeout and oversized output both mean "this image is unreadable".
        assert error.code in (TIMEOUT, OUTPUT_TOO_LARGE)
        raise QrDecoderError(QR_UNREADABLE) from None


class QrImageDecoder:
    """Runs the QR decode helper as an isolated, shell-free subprocess."""

    def __init__(
        self,
        *,
        repo_root: Path | str | None = None,
        helper: Path | str | None = None,
        node: str | None = None,
        runner: Runner | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        env: Mapping[str, str] | None = None,
    ):
        root = Path(repo_root) if repo_root is not None else discover_source_root()
        self._helper = Path(helper) if helper is not None else (
            root / "apps" / "mvp-web" / "scripts" / "live-demo-qr-decode.mjs"
        )
        self._node = node or shutil.which("node") or "node"
        self._runner: Runner = runner or _default_runner
        self._timeout = timeout
        self._env = dict(env) if env is not None else None

    @property
    def available(self) -> bool:
        """True when the A4 helper script is present."""
        return self._helper.is_file()

    @property
    def helper_path(self) -> str:
        return str(self._helper)

    def decode(self, image: Path | str) -> str:
        """Decode one local QR image to its loopback payload URL."""
        path = Path(image)
        data = self._read_png(path)
        if not self._helper.is_file():
            raise QrDecoderError(QR_DECODER_UNAVAILABLE)
        payload = self._invoke(path)
        text = payload.strip()
        if text.startswith("{"):
            text = self._url_from_json(text)
        if not text:
            raise QrDecoderError(QR_UNREADABLE)
        try:
            parse_qr_payload(text)
        except LiveDemoError:
            raise QrDecoderError(QR_PAYLOAD_MALFORMED) from None
        return text

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _read_png(path: Path) -> bytes:
        try:
            if path.is_symlink() or not path.is_file():
                raise QrDecoderError(QR_IMAGE_INVALID)
            size = path.stat().st_size
            if size < len(_PNG_SIGNATURE) or size > MAX_QR_IMAGE_BYTES:
                raise QrDecoderError(QR_IMAGE_INVALID)
            data = path.read_bytes()
        except QrDecoderError:
            raise
        except OSError:
            # An unreadable or raced file is an invalid image, reported as a
            # code — never the raw OS error text.
            raise QrDecoderError(QR_IMAGE_INVALID) from None
        if not data.startswith(_PNG_SIGNATURE):
            raise QrDecoderError(QR_IMAGE_INVALID)
        return data

    def _invoke(self, path: Path) -> str:
        """Try positional first, then ``--input``; accept URL or {"url": ...}."""
        attempts = (
            [self._node, str(self._helper), str(path)],
            [self._node, str(self._helper), "--input", str(path)],
        )
        last_code = 1
        for argv in attempts:
            code, stdout, _stderr = self._runner(
                argv, input_bytes=b"", timeout=self._timeout, env=self._env
            )
            last_code = code
            if code == 0:
                return stdout.decode("utf-8", "replace")
            if code != 2:
                break
        raise QrDecoderError(_failure_code(last_code))

    @staticmethod
    def _url_from_json(text: str) -> str:
        try:
            parsed: Any = json.loads(text)
        except (ValueError, RecursionError):
            raise QrDecoderError(QR_PAYLOAD_MALFORMED) from None
        if isinstance(parsed, dict):
            value = parsed.get("url")
            if isinstance(value, str):
                return value.strip()
        raise QrDecoderError(QR_PAYLOAD_MALFORMED)


def _failure_code(code: int) -> str:
    # A4: 3 = refused input/image, 4 = no usable QR — both mean "unreadable".
    if code in (3, 4):
        return QR_UNREADABLE
    return QR_DECODER_UNAVAILABLE
