"""Loopback-only live-demo admin session for the legacy password demo API.

This is the transport half of the live demo «Поддельная выписка перед
ипотекой». It talks to the *existing* demo-api over IPv4 loopback and keeps the
server-issued session cookie and CSRF token in memory only.

Credential handling
-------------------
The operator password is read from the private runtime credential file written
by ``deploy/devnet-demo/scripts/initialize-runtime`` (tmpfs
``/dev/shm/onelayer-devnet-demo/admin-credentials.json``, a JSON object mapping
demo role name to password). It is never:

* accepted from a caller (``sign_in`` takes no password),
* returned by any method or included in :class:`SessionSummary`,
* placed in argv, environment, request URLs or log output,
* rendered by the UI.

Errors are sanitized: only a short UI-safe ``state`` token and, for API
refusals, the server's constrained ``code`` are exposed. Raw response bodies and
credential-file contents never reach ``str(error)``.

Network rules (ADR-0006 loopback boundary)
------------------------------------------
* endpoints are fixed IPv4 loopback origins; nothing else may be contacted,
* environment proxies are disabled and redirects are never followed,
* request and response bodies are size-bounded and time-bounded,
* the HTTP layer never opens a URL it did not build from a fixed origin plus a
  validated request path.
"""
from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

RUNTIME_DIR = Path("/dev/shm/onelayer-devnet-demo")
DEFAULT_CREDENTIAL_PATH = RUNTIME_DIR / "admin-credentials.json"
DEFAULT_PRIVATE_ROOT = Path("/dev/shm")

SESSION_COOKIE = "onelayer_admin_session"

DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_RESPONSE_BYTES = 65536
DEFAULT_MAX_REQUEST_BYTES = 262144

_OPERATOR_ROLE = "operator"
_MIN_PASSWORD_LENGTH = 16
_CODE_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
_IDEMPOTENCY_ALPHABET = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
)
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class LiveDemoError(Exception):
    """Sanitized failure. ``state`` is a short UI-safe token, never a secret."""

    def __init__(self, state: str, detail: str | None = None):
        super().__init__(state if detail is None else f"{state}: {detail}")
        self.state = state
        self.detail = detail


class CredentialError(LiveDemoError):
    """The private credential file is missing, unsafe or malformed."""


class TransportError(LiveDemoError):
    """The loopback service could not be reached or violated the transport rules."""


class ProtocolError(LiveDemoError):
    """A loopback service answered with something this client cannot accept."""


class ApiRefusal(LiveDemoError):
    """The API refused the request; ``code``/``status`` come from the server.

    ``payload`` is at most a sanitized, bounded echo of a publish-intent
    refusal body (see :func:`sanitized_refusal_echo`) so a failed simulation can
    still be reviewed. It is never part of the exception message or repr, and
    raw error, session or login bodies are never retained.
    """

    def __init__(
        self,
        status: int,
        code: str | None,
        state: str = "error",
        payload: Any = None,
    ):
        super().__init__(state, code)
        self.status = status
        self.code = code
        self.payload = payload


@dataclass(frozen=True)
class SessionSummary:
    """Everything the UI may show after sign-in. Never carries a secret."""

    username: str
    role: str
    permissions: tuple[str, ...]
    registry_ids: tuple[str, ...]
    deployment_registry_id: str
    expires_at: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "role": self.role,
            "permissions": list(self.permissions),
            "registryIds": list(self.registry_ids),
            "deploymentRegistryId": self.deployment_registry_id,
            "expiresAt": self.expires_at,
        }


@dataclass(frozen=True)
class ApiResponse:
    """Bounded, parsed response envelope for the API adapters."""

    status: int
    payload: Any
    code: str | None


@dataclass(frozen=True)
class RawResponse:
    """Bounded raw response envelope for binary endpoints."""

    status: int
    content_type: str
    body: bytes


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def loopback_origin(value: str) -> str:
    """Accept only ``http://127.0.0.1:<port>`` — no path, query, user or host alias."""
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or not parsed.port
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Only explicit synthetic IPv4 loopback origins are allowed")
    return value


def build_loopback_url(origin: str, path: str) -> str:
    """Join a validated loopback origin with an origin-relative request path.

    The result is re-parsed and re-checked so a crafted path can never leave the
    pinned origin (no ``//host``, no scheme, no credentials, no fragment).
    """
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise ProtocolError("error", "request path must be origin-relative")
    if "\\" in path or "://" in path or "\r" in path or "\n" in path or "@" in path:
        raise ProtocolError("error", "request path is malformed")
    if len(path) > 2048:
        raise ProtocolError("error", "request path is too long")
    url = origin + path
    parsed = urlsplit(url)
    expected = urlsplit(origin)
    if (parsed.scheme, parsed.netloc, parsed.fragment) != (expected.scheme, expected.netloc, ""):
        raise ProtocolError("error", "request left the loopback origin")
    if parsed.username or parsed.password:
        raise ProtocolError("error", "request left the loopback origin")
    return url


def sanitized_code(value: Any) -> str | None:
    """Keep only a constrained server error code; anything else becomes None."""
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    if set(value) - _CODE_ALPHABET:
        return None
    return value


# --------------------------------------------------------------------------
# Refusal echo: a bounded, sanitized copy of a publish-intent refusal body.
#
# The only refusal contract that carries a reviewable body is the failed
# publish simulation (HTTP 422 with the intent envelope). Everything else —
# login, session, generic errors — is dropped entirely, and even for the
# publish echo nothing secret-shaped is ever retained.
# --------------------------------------------------------------------------

_REFUSAL_ECHO_STATUS = 422
_REFUSAL_ECHO_KEYS = frozenset(
    {
        "intentId",
        "state",
        "batchSequence",
        "intentHash",
        "review",
        "recentBlockhash",
        "lastValidBlockHeight",
        "expiresAt",
        "transactionSignature",
        "anchorSlot",
        "certificateId",
        "failureCode",
        "replayed",
    }
)
_ECHO_FORBIDDEN_KEY_PARTS = (
    "password",
    "passphrase",
    "secret",
    "token",
    "csrf",
    "cookie",
    "seed",
    "session",
    "authorization",
    "privatekey",
    "keyfile",
    "logs",
)
_ECHO_MAX_DEPTH = 8
_ECHO_MAX_STRING = 4096
_ECHO_MAX_ITEMS = 256
_ECHO_MAX_KEYS = 64

_DROP = object()


def _echo_key_visible(name: Any) -> bool:
    if not isinstance(name, str) or not name or len(name) > 64:
        return False
    lowered = name.lower()
    return not any(part in lowered for part in _ECHO_FORBIDDEN_KEY_PARTS)


def _echo_value(value: Any, depth: int) -> Any:
    """Return a faithful bounded copy of ``value``, or :data:`_DROP`.

    A single unrepresentable value fails the whole echo rather than silently
    presenting a partial review to the operator.
    """
    if depth > _ECHO_MAX_DEPTH:
        return _DROP
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if value == value and value not in (float("inf"), float("-inf")) else _DROP
    if isinstance(value, str):
        return value if len(value) <= _ECHO_MAX_STRING else _DROP
    if isinstance(value, list):
        if len(value) > _ECHO_MAX_ITEMS:
            return _DROP
        items = []
        for item in value:
            cleaned = _echo_value(item, depth + 1)
            if cleaned is _DROP:
                return _DROP
            items.append(cleaned)
        return items
    if isinstance(value, dict):
        if len(value) > _ECHO_MAX_KEYS:
            return _DROP
        cleaned_map: dict[str, Any] = {}
        for name, item in value.items():
            if not _echo_key_visible(name):
                continue
            cleaned = _echo_value(item, depth + 1)
            if cleaned is _DROP:
                return _DROP
            cleaned_map[name] = cleaned
        return cleaned_map
    return _DROP


def sanitized_refusal_echo(status: Any, payload: Any) -> dict[str, Any] | None:
    """Bounded echo of a publish-intent refusal body; ``None`` for everything else.

    Only the 422 publish-intent refusal (the failed-simulation contract) may
    echo anything. The echo is restricted to the typed intent envelope keys, so
    free-form error text, simulation logs and any secret-shaped key are dropped;
    an unrepresentable envelope value drops the entire echo.
    """
    if status != _REFUSAL_ECHO_STATUS or not isinstance(payload, dict):
        return None
    kept: dict[str, Any] = {}
    for name, value in payload.items():
        if name not in _REFUSAL_ECHO_KEYS:
            continue
        cleaned = _echo_value(value, 1)
        if cleaned is _DROP:
            return None
        kept[name] = cleaned
    return kept or None


def _is_private_directory(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(info.st_mode)
        and not path.is_symlink()
        and info.st_uid == os.getuid()
        and info.st_mode & 0o077 == 0
    )


def _is_regular_file(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and not path.is_symlink()


def load_operator_password(
    credential_path: Path | str = DEFAULT_CREDENTIAL_PATH,
    *,
    private_root: Path | str | None = None,
) -> str:
    """Read the demo operator password out of the private runtime file.

    The file must be a regular file (never a symlink) whose resolved location
    lives under ``private_root`` (``/dev/shm`` by default), inside a directory
    owned by this user with no group/other permission bits. The returned string
    must be kept out of argv, environment, logs and UI; prefer passing it to
    :meth:`AdminSession.sign_in` directly rather than storing it.
    """
    root = Path(private_root) if private_root is not None else DEFAULT_PRIVATE_ROOT
    try:
        root_resolved = root.resolve(strict=True)
    except OSError:
        raise CredentialError("credentials", "runtime directory is unavailable") from None

    path = Path(credential_path)
    if not path.is_absolute():
        raise CredentialError("credentials", "credential path must be absolute")
    if not _is_regular_file(path):
        raise CredentialError("credentials", "credential file is missing or not a regular file")
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise CredentialError("credentials", "credential file is unavailable") from None
    if resolved != path or root_resolved not in resolved.parents:
        raise CredentialError("credentials", "credential file is outside the private runtime directory")
    if not _is_private_directory(resolved.parent):
        raise CredentialError("credentials", "credential directory is not private")

    try:
        raw = resolved.read_bytes()
    except OSError:
        raise CredentialError("credentials", "credential file is unreadable") from None
    if len(raw) > 8192:
        raise CredentialError("credentials", "credential file is too large")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise CredentialError("credentials", "credential file is not valid JSON") from None
    except RecursionError:
        raise CredentialError("credentials", "credential file is not valid JSON") from None
    if not isinstance(parsed, dict):
        raise CredentialError("credentials", "credential file must be a JSON object")

    password = parsed.get(_OPERATOR_ROLE)
    if not isinstance(password, str) or len(password) < _MIN_PASSWORD_LENGTH:
        raise CredentialError("credentials", "operator credential is missing or too short")
    if any(character < " " or character == "\x7f" for character in password):
        raise CredentialError("credentials", "operator credential is not printable")
    return password


class LoopbackHttp:
    """Bounded, proxy-free, redirect-free HTTP against one pinned loopback origin."""

    def __init__(
        self,
        origin: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
    ):
        self._origin = loopback_origin(origin)
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes
        self._max_request_bytes = max_request_bytes
        self._cookies = http.cookiejar.CookieJar()
        self._opener = build_opener(ProxyHandler({}), _NoRedirect(), HTTPCookieProcessor(self._cookies))

    @property
    def origin(self) -> str:
        return self._origin

    @property
    def cookie_jar(self) -> http.cookiejar.CookieJar:
        return self._cookies

    def clear_cookies(self) -> None:
        self._cookies.clear()

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> RawResponse:
        if method not in ("GET", "HEAD", "POST", "DELETE", "PUT", "PATCH"):
            raise ProtocolError("error", "unsupported request method")
        if body is not None and len(body) > self._max_request_bytes:
            raise ProtocolError("error", "request body is too large")
        url = build_loopback_url(self._origin, path)
        request = Request(url, data=body, method=method, headers=dict(headers or {}))
        try:
            response = self._opener.open(request, timeout=self._timeout)
        except HTTPError as error:
            response = error
        except (URLError, TimeoutError, OSError):
            raise TransportError("offline") from None
        with response:
            raw = response.read(self._max_response_bytes + 1)
            if len(raw) > self._max_response_bytes:
                raise ProtocolError("error", "response body is too large")
            status = int(getattr(response, "status", 0) or 0)
            if status in _REDIRECT_STATUSES:
                # A redirect would leave the pinned loopback origin.
                raise TransportError("offline", "redirect refused")
            content_type = response.headers.get("content-type", "") or ""
            return RawResponse(status=status, content_type=content_type, body=raw)


def decode_json_body(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ProtocolError("error", "response is not JSON") from None
    except RecursionError:
        raise ProtocolError("error", "response is too deeply nested") from None


class AdminSession:
    """Cookie/CSRF session against one loopback demo-api origin.

    Only :meth:`request_json` and :meth:`request_bytes` are meant for the API
    adapters; the UI should go through :mod:`live_demo_api`, which never
    exposes the CSRF token.
    """

    def __init__(
        self,
        origin: str,
        *,
        credential_path: Path | str = DEFAULT_CREDENTIAL_PATH,
        private_root: Path | str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
    ):
        self._http = LoopbackHttp(
            origin,
            timeout=timeout,
            max_response_bytes=max_response_bytes,
            max_request_bytes=max_request_bytes,
        )
        self._credential_path = Path(credential_path)
        self._private_root = private_root
        self._max_response_bytes = max_response_bytes
        self._max_request_bytes = max_request_bytes
        self._csrf: str | None = None
        self._summary: SessionSummary | None = None

    # -- state -------------------------------------------------------------

    @property
    def origin(self) -> str:
        return self._http.origin

    @property
    def summary(self) -> SessionSummary | None:
        return self._summary

    @property
    def signed_in(self) -> bool:
        return self._summary is not None

    @property
    def csrf_token(self) -> str | None:
        """Server CSRF token. For the API adapters only — never display it."""
        return self._csrf

    # -- transport ---------------------------------------------------------

    def _headers(self, method: str, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = dict(extra or {})
        if method not in ("GET", "HEAD") and self._csrf is not None:
            headers.setdefault("x-onelayer-csrf", self._csrf)
        return headers

    def request_bytes(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> RawResponse:
        return self._http.request(method, path, body=body, headers=self._headers(method, headers))

    def request_json(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        idempotency_key: str | None = None,
    ) -> ApiResponse:
        """Send one API request. Refusals raise :class:`ApiRefusal`."""
        body = None
        headers: dict[str, str] = {}
        if json_body is not None:
            body = json.dumps(json_body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            headers["content-type"] = "application/json; charset=utf-8"
        if idempotency_key is not None:
            if (
                not isinstance(idempotency_key, str)
                or not 16 <= len(idempotency_key) <= 64
                or set(idempotency_key) - _IDEMPOTENCY_ALPHABET
            ):
                raise ProtocolError("error", "idempotency key is malformed")
            headers["idempotency-key"] = idempotency_key
        response = self.request_bytes(method, path, body=body, headers=headers)
        payload = decode_json_body(response.body)
        code = sanitized_code(payload.get("code")) if isinstance(payload, dict) else None
        if response.status >= 400:
            state = "expired" if response.status == 401 else "error"
            raise ApiRefusal(
                response.status,
                code,
                state,
                sanitized_refusal_echo(response.status, payload),
            )
        return ApiResponse(status=response.status, payload=payload, code=code)

    # -- session lifecycle -------------------------------------------------

    def sign_in(self) -> SessionSummary:
        """Sign in as the demo operator using the private credential file."""
        password = load_operator_password(self._credential_path, private_root=self._private_root)
        self.clear()
        try:
            response = self._http.request(
                "POST",
                "/v1/admin/session",
                body=json.dumps(
                    {"username": _OPERATOR_ROLE, "password": password},
                    separators=(",", ":"),
                ).encode("utf-8"),
                headers={"content-type": "application/json; charset=utf-8"},
            )
        finally:
            del password
        payload = decode_json_body(response.body)
        if response.status == 401:
            self.clear()
            raise ApiRefusal(401, "INVALID_CREDENTIALS", "error")
        if response.status != 201:
            self.clear()
            raise ApiRefusal(response.status, sanitized_code(payload.get("code")) if isinstance(payload, dict) else None, "error")
        return self._adopt(payload)

    def refresh(self) -> SessionSummary:
        response = self.request_bytes("GET", "/v1/admin/session")
        payload = decode_json_body(response.body)
        if response.status == 401:
            self.clear()
            raise ApiRefusal(401, "SESSION_REQUIRED", "expired")
        if response.status != 200:
            self.clear()
            raise ApiRefusal(response.status, None, "error")
        return self._adopt(payload)

    def sign_out(self) -> None:
        try:
            if self._summary is not None:
                self.request_bytes("DELETE", "/v1/admin/session")
        except LiveDemoError:
            pass
        finally:
            self.clear()

    def clear(self) -> None:
        self._http.clear_cookies()
        self._csrf = None
        self._summary = None

    def _adopt(self, payload: Any) -> SessionSummary:
        if not isinstance(payload, dict):
            self.clear()
            raise ProtocolError("error", "session response is malformed")
        username = payload.get("username")
        role = payload.get("role")
        csrf = payload.get("csrfToken")
        if not all(isinstance(value, str) and value for value in (username, role, csrf)):
            self.clear()
            raise ProtocolError("error", "session response is malformed")
        permissions = payload.get("permissions")
        registry_ids = payload.get("registryIds")
        if not isinstance(permissions, list) or not isinstance(registry_ids, list):
            self.clear()
            raise ProtocolError("error", "session response is malformed")
        if any(not isinstance(item, str) for item in permissions + registry_ids):
            self.clear()
            raise ProtocolError("error", "session response is malformed")
        deployment = payload.get("deploymentRegistryId")
        expires_at = payload.get("expiresAt")
        self._csrf = csrf
        self._summary = SessionSummary(
            username=username,
            role=role,
            permissions=tuple(permissions),
            registry_ids=tuple(registry_ids),
            deployment_registry_id=deployment if isinstance(deployment, str) else "",
            expires_at=expires_at if isinstance(expires_at, str) else None,
        )
        return self._summary


def decode_base64url(value: str, *, label: str = "value") -> bytes:
    if not isinstance(value, str) or not value or len(value) > 1 << 20:
        raise ProtocolError("error", f"{label} is malformed")
    if not value or any(character not in
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
                        for character in value):
        raise ProtocolError("error", f"{label} is not unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError):
        raise ProtocolError("error", f"{label} is not base64url") from None
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ProtocolError("error", f"{label} is not canonical base64url")
    return raw


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
