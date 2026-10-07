"""Synthetic platform experiments, deliberately not a production identity client."""
import base64
import hashlib
import hmac
import math
import secrets
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlsplit


class Rejected(ValueError):
    pass


def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class BrowserLogin:
    """One in-memory attempt; caller owns socket and token exchange/validation.

    This ONLY validates the callback envelope. It never authenticates an identity.
    Server OIDC integration must replace this experiment before product use.
    """

    def __init__(self, authorization_endpoint, client_id, port, clock=time.monotonic):
        endpoint = urlsplit(authorization_endpoint)
        if (endpoint.scheme != "https" or not endpoint.hostname or endpoint.username
                or endpoint.password or endpoint.query or endpoint.fragment):
            raise Rejected("untrusted authorization endpoint")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise Rejected("invalid loopback port")
        self.redirect_uri = f"http://127.0.0.1:{port}/callback"
        self.state = secrets.token_urlsafe(32)
        self.nonce = secrets.token_urlsafe(32)
        self.verifier = secrets.token_urlsafe(48)
        self._clock = clock
        self._expires = clock() + 120
        self._used = False
        self.url = authorization_endpoint + "?" + urlencode({
            "client_id": client_id, "redirect_uri": self.redirect_uri,
            "response_type": "code", "scope": "openid", "state": self.state,
            "nonce": self.nonce, "code_challenge_method": "S256",
            "code_challenge": _b64(hashlib.sha256(self.verifier.encode()).digest()),
        })

    def consume(self, callback_url):
        if self._used or self._clock() >= self._expires:
            raise Rejected("expired or consumed callback")
        actual, expected = urlsplit(callback_url), urlsplit(self.redirect_uri)
        if (actual.scheme, actual.netloc, actual.path) != (expected.scheme, expected.netloc, expected.path) or actual.fragment:
            raise Rejected("unexpected callback target")
        try:
            params = parse_qs(actual.query, strict_parsing=True, max_num_fields=4, keep_blank_values=True)
        except ValueError as error:
            raise Rejected("malformed callback") from error
        if set(params) != {"state", "code"} or any(len(values) != 1 for values in params.values()):
            raise Rejected("unexpected callback parameters")
        if not hmac.compare_digest(params["state"][0], self.state):
            raise Rejected("state mismatch")
        code = params["code"][0]
        if not code or len(code) > 4096:
            raise Rejected("invalid authorization code")
        self._used = True
        return code


@dataclass(frozen=True)
class ApprovalIntent:
    operation_id: str
    subject: str
    device: str
    action: str
    payload: bytes
    expires_at: float


class ApprovalBroker:
    """Binds an external approval result to immutable bytes from a trusted source.

    verify_signature is a mandatory trusted adapter, not a renderer callback.
    Independent human review and durable server replay protection are still required.
    """

    def __init__(self, verify_signature, clock=time.monotonic):
        self._verify = verify_signature
        self._clock = clock
        self._pending = {}
        self._seen = set()

    def register(self, intent):
        if (not isinstance(intent.payload, bytes) or not intent.payload
                or len(intent.payload) > 65536 or not intent.operation_id
                or not intent.subject or not intent.device or not intent.action
                or not math.isfinite(intent.expires_at) or intent.expires_at <= self._clock()):
            raise Rejected("invalid intent")
        if intent.operation_id in self._seen:
            raise Rejected("duplicate operation")
        self._seen.add(intent.operation_id)
        self._pending[intent.operation_id] = intent

    def accept(self, operation_id, subject, device, payload, signature):
        intent = self._pending.get(operation_id)
        if intent is None or self._clock() >= intent.expires_at:
            raise Rejected("unknown, expired or consumed operation")
        if (subject, device) != (intent.subject, intent.device) or not hmac.compare_digest(payload, intent.payload):
            raise Rejected("approval binding mismatch")
        if not self._verify(intent, signature):
            raise Rejected("invalid external signature")
        del self._pending[operation_id]
        return {"operation_id": operation_id, "status": "verified-lab-result"}


class NativeCredentialStore:
    """Linux Secret Service adapter. No plaintext fallback or UI getter."""

    def __init__(self):
        import gi
        gi.require_version("Secret", "1")
        from gi.repository import Secret
        self._secret = Secret
        self._schema = Secret.Schema.new("org.onelayer.DesktopLab", Secret.SchemaFlags.NONE,
                                         {"session": Secret.SchemaAttributeType.STRING})

    def save(self, session_id, token):
        if not self._secret.password_store_sync(self._schema, {"session": session_id},
                self._secret.COLLECTION_SESSION, "OneLayer synthetic lab session", token, None):
            raise Rejected("credential store refused write")

    def clear(self, session_id):
        self._secret.password_clear_sync(self._schema, {"session": session_id}, None)
