"""Local signing adapter for the live-demo launcher (B2).

This module is the *only* place the desktop talks to Node for key material, and
it talks to two small helpers instead of touching key files itself:

* ``apps/demo-api/scripts/live-demo-sign.ts`` (A1) — signs one **approved**
  publish request read from stdin and prints only
  ``{"signedTransactionBase64": ...}``.
* ``apps/desktop/lab/live-demo-operator-address.ts`` (B2) — prints only the
  operator's **public** address from the same A1 persistent key store.

Security contract
-----------------
* Key bytes never enter Python, the UI, argv, environment, logs or git. The key
  path may appear in argv (that is A1's own CLI contract); key *contents* do not.
* Subprocesses run with ``shell=False`` and an argv allow-list. Nothing is ever
  interpolated into a command string.
* stdin carries the request JSON (bounded); stdout/stderr are streamed and
  size-capped *while the helper runs* and parsed strictly. Helper errors are
  reported as code-only values.
* The request is signed only when it carries the explicit ``approved`` marker;
  the launcher sets it only after the operator pressed Approve.
* The key file defaults to the persistent store
  (``~/.local/state/onelayer-devnet-demo/keys/demo-operator.json``) and is
  enforced by the A1 key-store allow-list; this wrapper never widens it.

The key store is development-time synthetic devnet key custody. Production
secret custody is explicitly out of scope.
"""
from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

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
    "OperatorAddress",
    "OperatorSigner",
    "SignerError",
    "default_key_file",
]

MAX_REQUEST_BYTES = 256 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 20.0
ADDRESS_TIMEOUT_SECONDS = 10.0

# Code-only failures; nothing from the key or the request is ever echoed.
SIGNER_UNAVAILABLE = "SIGNER_UNAVAILABLE"
SIGNER_TIMEOUT = "SIGNER_TIMEOUT"
SIGNER_FAILED = "SIGNER_FAILED"
SIGNER_OUTPUT_INVALID = "SIGNER_OUTPUT_INVALID"
SIGNER_OUTPUT_TOO_LARGE = "SIGNER_OUTPUT_TOO_LARGE"
SIGNER_REQUEST_INVALID = "SIGNER_REQUEST_INVALID"
ADDRESS_UNAVAILABLE = "ADDRESS_UNAVAILABLE"
ADDRESS_OUTPUT_INVALID = "ADDRESS_OUTPUT_INVALID"

_CODE_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{0,62}$")


class SignerError(LiveDemoError):
    """A local signing or address lookup failed. ``detail`` is a bare code."""

    def __init__(self, code: str, detail: str | None = None):
        super().__init__("error", detail or code)
        self.code = code

    def __str__(self) -> str:  # never carry helper stderr into messages
        return self.code


@dataclass(frozen=True)
class OperatorAddress:
    """Public identity of the demo operator. No key material of any kind."""

    address: str
    path: str
    created: bool


def default_key_file() -> str:
    """The A1 persistent-store default (``…/keys/demo-operator.json``)."""
    home = os.environ.get("HOME") or str(Path.home())
    return str(Path(home) / ".local" / "state" / "onelayer-devnet-demo" / "keys" / "demo-operator.json")


Runner = Callable[..., tuple[int, bytes, bytes]]


def _default_runner(
    argv: Sequence[str],
    *,
    input_bytes: bytes,
    timeout: float,
    env: Mapping[str, str] | None = None,
) -> tuple[int, bytes, bytes]:
    """Run one helper process with no shell and streamed, size-capped output."""
    try:
        return run_bounded(
            list(argv),
            input_bytes=input_bytes,
            timeout=timeout,
            env=env,
            max_output=MAX_OUTPUT_BYTES,
        )
    except BoundedRunError as error:
        if error.code == TIMEOUT:
            raise SignerError(SIGNER_TIMEOUT) from None
        if error.code == OUTPUT_TOO_LARGE:
            raise SignerError(SIGNER_OUTPUT_TOO_LARGE) from None
        assert error.code == UNAVAILABLE
        raise SignerError(SIGNER_UNAVAILABLE) from None


class OperatorSigner:
    """Runs the local Node signer / address helpers as isolated subprocesses."""

    def __init__(
        self,
        *,
        repo_root: Path | str | None = None,
        key_file: Path | str | None = None,
        node: str | None = None,
        signer_script: Path | str | None = None,
        address_script: Path | str | None = None,
        runner: Runner | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        address_timeout: float = ADDRESS_TIMEOUT_SECONDS,
        env: Mapping[str, str] | None = None,
    ):
        root = Path(repo_root) if repo_root is not None else _discover_repo_root()
        self._root = root
        self._signer_script = Path(signer_script) if signer_script is not None else (
            root / "apps" / "demo-api" / "scripts" / "live-demo-sign.ts"
        )
        self._address_script = Path(address_script) if address_script is not None else (
            root / "apps" / "desktop" / "lab" / "live-demo-operator-address.ts"
        )
        self._key_file = Path(key_file) if key_file is not None else None
        self._node = node or shutil.which("node") or "node"
        self._runner: Runner = runner or _default_runner
        self._timeout = timeout
        self._address_timeout = address_timeout
        self._env = dict(env) if env is not None else None

    # -- properties --------------------------------------------------------

    @property
    def key_file(self) -> str:
        """Key path or the A1 default. The contents are never read here."""
        return str(self._key_file) if self._key_file is not None else default_key_file()

    @property
    def signer_script(self) -> str:
        return str(self._signer_script)

    # -- public operations -------------------------------------------------

    def operator_address(self, *, ensure: bool = False) -> OperatorAddress:
        """Return the operator's public address (never any key bytes).

        ``ensure=True`` initializes the persistent store idempotently (no
        overwrite) and is meant for seeding and tests; the default is a
        read-only lookup that fails closed when the key is missing.
        """
        argv = self._node_argv(self._address_script)
        if self._key_file is not None:
            argv += ["--key-file", str(self._key_file)]
        if ensure:
            argv.append("--ensure")
        code, stdout, stderr = self._runner(
            argv, input_bytes=b"", timeout=self._address_timeout, env=self._env
        )
        payload = _parse_single_json_object(stdout, stderr, code, ADDRESS_OUTPUT_INVALID)
        if code != 0:
            raise SignerError(_failure_code(payload, stderr, code, ADDRESS_UNAVAILABLE))
        address = payload.get("address")
        path = payload.get("path")
        if not isinstance(address, str) or not address or len(address) > 64:
            raise SignerError(ADDRESS_OUTPUT_INVALID)
        if not isinstance(path, str) or not path or len(path) > 1024:
            raise SignerError(ADDRESS_OUTPUT_INVALID)
        return OperatorAddress(address=address, path=path, created=payload.get("created") is True)

    def sign(self, request: Mapping[str, Any]) -> str:
        """Sign one approved request; returns only ``signedTransactionBase64``."""
        if not isinstance(request, Mapping):
            raise SignerError(SIGNER_REQUEST_INVALID)
        if request.get("approved") is not True:
            # Defense in depth: the launcher marks approval only after the
            # explicit Approve action, and A1 refuses anything else too.
            raise SignerError(SIGNER_REQUEST_INVALID)
        try:
            body = json.dumps(dict(request), separators=(",", ":"), sort_keys=False).encode("utf-8")
        except (TypeError, ValueError):
            raise SignerError(SIGNER_REQUEST_INVALID) from None
        if not body or len(body) > MAX_REQUEST_BYTES:
            raise SignerError(SIGNER_REQUEST_INVALID)
        argv = self._node_argv(self._signer_script)
        if self._key_file is not None:
            argv += ["--key-file", str(self._key_file)]
        code, stdout, stderr = self._runner(
            argv, input_bytes=body, timeout=self._timeout, env=self._env
        )
        payload = _parse_single_json_object(stdout, stderr, code, SIGNER_OUTPUT_INVALID)
        if code != 0:
            raise SignerError(_failure_code(payload, stderr, code, SIGNER_FAILED))
        signed = payload.get("signedTransactionBase64")
        if not isinstance(signed, str) or not signed or len(signed) > 8192:
            raise SignerError(SIGNER_OUTPUT_INVALID)
        return signed

    # -- internals ---------------------------------------------------------

    def _node_argv(self, script: Path) -> list[str]:
        if not script.is_file():
            raise SignerError(SIGNER_UNAVAILABLE)
        return [
            self._node,
            "--experimental-transform-types",
            "--disable-warning=ExperimentalWarning",
            str(script),
        ]


def _discover_repo_root() -> Path:
    """Repository root for the helpers: source checkout, else install binding.

    The source checkout is inferred from this file's own path. An installed
    prefix carries no helpers, so the installer writes a bounded non-secret
    ``live_demo_source_root.py`` binding to the trusted source tree; it is used
    only after its expected helper paths validate. See
    :func:`live_demo_runtime.discover_source_root`.
    """
    return discover_source_root()


def _parse_single_json_object(
    stdout: bytes, stderr: bytes, code: int, invalid_code: str
) -> dict[str, Any]:
    """Parse the helper's single JSON object; never echo raw output.

    Success output must be exactly one JSON object. Failure output is only
    mined for a bare error code: anything unparseable yields ``{}`` so the
    caller falls back to its own code instead of inventing detail.
    """
    raw = stdout.strip() if code == 0 else stderr.strip()
    if not raw:
        return {}
    if len(raw) > MAX_OUTPUT_BYTES:
        if code == 0:
            raise SignerError(SIGNER_OUTPUT_TOO_LARGE)
        return {}
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        if code == 0:
            raise SignerError(invalid_code) from None
        return {}
    except RecursionError:
        if code == 0:
            raise SignerError(invalid_code) from None
        return {}
    if not isinstance(parsed, dict):
        if code == 0:
            raise SignerError(invalid_code)
        return {}
    return parsed


def _failure_code(
    payload: Mapping[str, Any], stderr: bytes, code: int, fallback: str
) -> str:
    """Map a helper failure to a bare code; nothing else is ever reported."""
    del stderr  # never inspected: raw helper output is not a code source
    error = payload.get("error")
    if isinstance(error, dict):
        reported = error.get("code")
        if isinstance(reported, str) and _CODE_TOKEN.match(reported):
            return reported
    return fallback
