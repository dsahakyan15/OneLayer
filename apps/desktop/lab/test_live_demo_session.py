#!/usr/bin/python3
"""Focused stdlib tests for apps/desktop/lab/live_demo_session.py.

Every test drives a real ``http.server`` on IPv4 loopback; no project service is
started, no real credential file is read, and no secret is printed. The
credential fixture is a private temporary directory mirroring
``/dev/shm/onelayer-devnet-demo``.
"""
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import live_demo_session  # noqa: E402  (path is prepared above)
from live_demo_session import (  # noqa: E402
    AdminSession,
    ApiRefusal,
    CredentialError,
    LoopbackHttp,
    ProtocolError,
    SessionSummary,
    TransportError,
    build_loopback_url,
    decode_base64url,
    encode_base64url,
    load_operator_password,
    loopback_origin,
    sanitized_code,
    sanitized_refusal_echo,
)

SECRET = "synthetic-operator-password-0123456789abcdef"
CSRF = "csrf-token-value-0123456789abcdef"
SESSION_ID = "session-token-value-0123456789abcdef"


class LoopbackOriginTests(unittest.TestCase):
    def test_accepts_only_explicit_ipv4_loopback_origin(self):
        self.assertEqual(loopback_origin("http://127.0.0.1:8090"), "http://127.0.0.1:8090")

    def test_rejects_off_loopback_and_aliased_origins(self):
        for origin in (
            "https://example.com",
            "http://localhost:1234",
            "http://127.0.0.1",
            "http://127.0.0.1:1234/",
            "http://127.0.0.1:1234?x",
            "http://127.0.0.1:1234#x",
            "http://user@127.0.0.1:1234",
            "http://user:pass@127.0.0.1:1234",
            "http://127.0.0.2:1234",
            "http://[::1]:1234",
            "http://2130706433:1234",
            "",
        ):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                loopback_origin(origin)

    def test_build_loopback_url_rejects_path_escapes(self):
        origin = "http://127.0.0.1:8090"
        for path in (
            "//evil.example.com/x",
            "/\\evil.example.com/x",
            "/http://evil.example.com/x",
            "/v1/x?q=1#frag",
            "/v1/\r\nHost: evil",
            "/v1/user@example.com",
            "",
            "v1/x",
        ):
            with self.subTest(path=path), self.assertRaises(ProtocolError):
                build_loopback_url(origin, path)

    def test_build_loopback_url_joins_origin_relative_paths(self):
        self.assertEqual(
            build_loopback_url("http://127.0.0.1:8090", "/v1/admin/session"),
            "http://127.0.0.1:8090/v1/admin/session",
        )

    def test_build_loopback_url_rejects_oversized_paths(self):
        with self.assertRaises(ProtocolError):
            build_loopback_url("http://127.0.0.1:8090", "/v1/" + "a" * 3000)


class SanitizedCodeTests(unittest.TestCase):
    def test_keeps_constrained_codes_only(self):
        self.assertEqual(sanitized_code("QR_HASH_MISMATCH"), "QR_HASH_MISMATCH")
        for value in ("lowercase", "has space", "a" * 65, 5, None, "", "a-b"):
            with self.subTest(value=value):
                self.assertIsNone(sanitized_code(value))


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="onelayer-live-demo-creds-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.private = self.root / "onelayer-devnet-demo"
        os.mkdir(self.private, 0o700)
        os.chmod(self.private, 0o700)
        self.credential = self.private / "admin-credentials.json"
        self.write_credentials({"operator": SECRET, "auditor": "x" * 16})

    def write_credentials(self, payload, mode=0o644):
        self.credential.write_text(json.dumps(payload))
        os.chmod(self.credential, mode)

    def test_reads_operator_password_from_private_file(self):
        self.assertEqual(
            load_operator_password(self.credential, private_root=self.root), SECRET
        )

    def test_accepts_the_realistic_chmod_644_inside_a_private_directory(self):
        self.write_credentials({"operator": SECRET, "auditor": "x" * 16}, mode=0o644)
        self.assertEqual(
            load_operator_password(self.credential, private_root=self.root), SECRET
        )

    def test_missing_file_is_a_credential_error(self):
        self.credential.unlink()
        with self.assertRaises(CredentialError):
            load_operator_password(self.credential, private_root=self.root)

    def test_symlinked_credential_file_is_refused(self):
        target = self.root / "elsewhere.json"
        target.write_text(json.dumps({"operator": SECRET}))
        self.credential.unlink()
        self.credential.symlink_to(target)
        with self.assertRaises(CredentialError):
            load_operator_password(self.credential, private_root=self.root)

    def test_shared_credential_directory_is_refused(self):
        os.chmod(self.private, 0o755)
        with self.assertRaises(CredentialError):
            load_operator_password(self.credential, private_root=self.root)

    def test_credential_file_outside_private_root_is_refused(self):
        outside = self.root / "outside.json"
        outside.write_text(json.dumps({"operator": SECRET}))
        os.chmod(self.root, 0o700)
        with self.assertRaises(CredentialError):
            load_operator_password(outside, private_root=self.private)

    def test_relative_path_is_refused(self):
        with self.assertRaises(CredentialError):
            load_operator_password("admin-credentials.json", private_root=self.root)

    def test_malformed_documents_are_refused(self):
        for payload in ("not json", "[]", '{"auditor":"x"}', '{"operator":"short"}',
                        '{"operator":"' + "a" * 20 + '\n"}', '{"operator":"abc\x00def' + "x" * 16 + '"}'):
            with self.subTest(payload=payload):
                self.credential.write_text(payload)
                os.chmod(self.credential, 0o644)
                with self.assertRaises(CredentialError):
                    load_operator_password(self.credential, private_root=self.root)

    def test_deeply_nested_credential_json_is_refused_not_crashed(self):
        # 4 000 nesting levels fit under the 8 KiB file cap; deep documents must
        # fail as a credential error and never escape as a crash.
        self.credential.write_text("[" * 4000 + "]" * 4000)
        os.chmod(self.credential, 0o644)
        with self.assertRaises(CredentialError):
            load_operator_password(self.credential, private_root=self.root)

    def test_oversized_credential_file_is_refused(self):
        self.credential.write_text("x" * 9000)
        os.chmod(self.credential, 0o644)
        with self.assertRaises(CredentialError):
            load_operator_password(self.credential, private_root=self.root)

    def test_failures_never_echo_the_credential(self):
        self.write_credentials({"operator": SECRET})
        os.chmod(self.private, 0o755)
        with self.assertRaises(CredentialError) as raised:
            load_operator_password(self.credential, private_root=self.root)
        self.assertNotIn(SECRET, str(raised.exception))
        self.assertNotIn(SECRET, repr(raised.exception.args))

    def test_directory_credential_is_not_a_regular_file(self):
        self.credential.unlink()
        os.mkdir(self.credential)
        with self.assertRaises(CredentialError):
            load_operator_password(self.credential, private_root=self.root)


class Base64Tests(unittest.TestCase):
    def test_roundtrip_is_unpadded_base64url(self):
        raw = bytes(range(32))
        encoded = encode_base64url(raw)
        self.assertNotIn("=", encoded)
        self.assertEqual(decode_base64url(encoded), raw)

    def test_non_canonical_and_padded_values_are_refused(self):
        for value in ("abc=", "ab+/cd", "", "a" * 100 + "!", 5):
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                decode_base64url(value)


class ServerFixture(unittest.TestCase):
    """A loopback http.server that records requests and replays a script."""

    def server(self, handle):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                handle(self)

            def do_POST(self):
                handle(self)

            def do_DELETE(self):
                handle(self)

            def do_PUT(self):
                handle(self)

            def log_message(self, *_args):
                pass

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        def cleanup():
            httpd.shutdown()
            httpd.server_close()
            thread.join()

        self.addCleanup(cleanup)
        fixture.last_request = None
        return f"http://127.0.0.1:{httpd.server_port}"

    @staticmethod
    def reply(request, status, body=None, headers=None, raw=None):
        request.send_response(status)
        for name, value in (headers or {}).items():
            request.send_header(name, value)
        payload = raw if raw is not None else (b"" if body is None else json.dumps(body).encode())
        if raw is None and body is not None:
            request.send_header("content-type", "application/json")
        request.send_header("content-length", str(len(payload)))
        request.end_headers()
        request.wfile.write(payload)

    @staticmethod
    def record(request, sink):
        length = int(request.headers.get("content-length") or 0)
        sink.append(
            {
                "method": request.command,
                "path": request.path,
                "headers": {key.lower(): value for key, value in request.headers.items()},
                "body": request.rfile.read(length) if length else b"",
            }
        )

    def credentials_dir(self):
        root = Path(tempfile.mkdtemp(prefix="onelayer-live-demo-session-"))
        self.addCleanup(shutil.rmtree, root, True)
        private = root / "onelayer-devnet-demo"
        os.mkdir(private, 0o700)
        os.chmod(private, 0o700)
        (private / "admin-credentials.json").write_text(
            json.dumps({"operator": SECRET, "auditor": "x" * 16, "chief_admin": "y" * 16})
        )
        os.chmod(private / "admin-credentials.json", 0o644)
        return root, private / "admin-credentials.json"

    def session(self, origin, credential, **kwargs):
        root = credential.parent.parent
        return AdminSession(origin, credential_path=credential, private_root=root, **kwargs)


class SignInTests(ServerFixture):
    def test_sign_in_uses_file_password_and_never_returns_it(self):
        seen = []

        def handle(request):
            self.record(request, seen)
            self.reply(
                request,
                201,
                {
                    "role": "operator",
                    "username": "operator",
                    "csrfToken": CSRF,
                    "expiresAt": "2026-10-02T12:00:00Z",
                    "permissions": ["records.draft"],
                    "registryIds": ["gov.registry.land"],
                    "deploymentRegistryId": "gov.registry.land",
                },
                {"set-cookie": f"onelayer_admin_session={SESSION_ID}; HttpOnly; Path=/"},
            )

        origin = self.server(handle)
        _root, credential = self.credentials_dir()
        client = self.session(origin, credential)
        summary = client.sign_in()

        self.assertIsInstance(summary, SessionSummary)
        self.assertEqual(summary.username, "operator")
        self.assertEqual(summary.role, "operator")
        self.assertEqual(summary.deployment_registry_id, "gov.registry.land")
        self.assertEqual(summary.permissions, ("records.draft",))
        self.assertEqual(len(seen), 1)
        sent = json.loads(seen[0]["body"])
        self.assertEqual(sent["username"], "operator")
        self.assertEqual(sent["password"], SECRET)
        self.assertNotIn("password", summary.as_dict())
        self.assertNotIn(SECRET, json.dumps(summary.as_dict()))
        self.assertNotIn(SECRET, repr(summary))
        self.assertEqual(client.csrf_token, CSRF)

    def test_sign_in_sends_no_cookie_and_no_csrf_header(self):
        seen = []

        def handle(request):
            self.record(request, seen)
            self.reply(
                request,
                201,
                {
                    "role": "operator",
                    "username": "operator",
                    "csrfToken": CSRF,
                    "permissions": [],
                    "registryIds": [],
                    "deploymentRegistryId": "gov.registry.land",
                },
                {"set-cookie": f"onelayer_admin_session={SESSION_ID}; HttpOnly; Path=/"},
            )

        origin = self.server(handle)
        _root, credential = self.credentials_dir()
        self.session(origin, credential).sign_in()
        self.assertNotIn("cookie", seen[0]["headers"])
        self.assertNotIn("x-onelayer-csrf", seen[0]["headers"])

    def test_invalid_credentials_map_to_a_sanitized_refusal(self):
        def handle(request):
            self.reply(request, 401, {"code": "INVALID_CREDENTIALS"})

        origin = self.server(handle)
        _root, credential = self.credentials_dir()
        with self.assertRaises(ApiRefusal) as raised:
            self.session(origin, credential).sign_in()
        self.assertEqual(raised.exception.status, 401)
        self.assertEqual(raised.exception.code, "INVALID_CREDENTIALS")
        self.assertEqual(raised.exception.state, "error")
        self.assertNotIn(SECRET, str(raised.exception))

    def test_missing_credential_file_never_reaches_the_network(self):
        seen = []

        def handle(request):
            self.record(request, seen)
            self.reply(request, 201, {})

        origin = self.server(handle)
        root = Path(tempfile.mkdtemp(prefix="onelayer-live-demo-empty-"))
        self.addCleanup(shutil.rmtree, root, True)
        private = root / "onelayer-devnet-demo"
        os.mkdir(private, 0o700)
        with self.assertRaises(CredentialError):
            AdminSession(
                origin,
                credential_path=private / "admin-credentials.json",
                private_root=root,
            ).sign_in()
        self.assertEqual(seen, [])

    def test_redirect_is_never_followed(self):
        seen = []

        def handle(request):
            self.record(request, seen)
            self.reply(
                request,
                302,
                {"code": "MOVED"},
                {"location": "http://127.0.0.1:1/stolen"},
            )

        origin = self.server(handle)
        _root, credential = self.credentials_dir()
        with self.assertRaises(TransportError):
            self.session(origin, credential).sign_in()
        self.assertEqual(len(seen), 1)

    def test_oversized_response_is_rejected(self):
        def handle(request):
            self.reply(request, 200, raw=b"x" * 200000)

        origin = self.server(handle)
        _root, credential = self.credentials_dir()
        with self.assertRaises(ProtocolError):
            self.session(origin, credential, max_response_bytes=1024).sign_in()

    def test_non_json_response_is_rejected(self):
        def handle(request):
            self.reply(request, 201, raw=b"<html>no</html>")

        origin = self.server(handle)
        _root, credential = self.credentials_dir()
        with self.assertRaises(ProtocolError):
            self.session(origin, credential).sign_in()

    def test_malformed_session_body_is_rejected(self):
        for body in ({"role": "operator"}, {"username": "operator", "role": "operator"},
                     {"username": "operator", "role": "operator", "csrfToken": CSRF,
                      "permissions": "not-a-list", "registryIds": []}):
            def handle(request, body=body):
                self.reply(request, 201, body)

            with self.subTest(body=body):
                origin = self.server(handle)
                _root, credential = self.credentials_dir()
                client = self.session(origin, credential)
                with self.assertRaises(ProtocolError):
                    client.sign_in()
                self.assertIsNone(client.summary)
                self.assertIsNone(client.csrf_token)


class CsrfAndCookieTests(ServerFixture):
    def signed_in_client(self, origin):
        _root, credential = self.credentials_dir()
        return self.session(origin, credential)

    def test_mutation_carries_csrf_and_session_cookie(self):
        seen = []

        def handle(request):
            self.record(request, seen)
            if request.command == "POST" and request.path == "/v1/admin/session":
                self.reply(
                    request,
                    201,
                    {
                        "role": "operator",
                        "username": "operator",
                        "csrfToken": CSRF,
                        "permissions": [],
                        "registryIds": [],
                        "deploymentRegistryId": "gov.registry.land",
                    },
                    {"set-cookie": f"onelayer_admin_session={SESSION_ID}; HttpOnly; Path=/"},
                )
                return
            self.reply(request, 200, {"ok": True})

        origin = self.server(handle)
        client = self.signed_in_client(origin)
        client.sign_in()
        client.request_json("POST", "/v1/admin/records", json_body={"a": 1})
        request = seen[-1]
        self.assertEqual(request["headers"].get("x-onelayer-csrf"), CSRF)
        self.assertIn(f"onelayer_admin_session={SESSION_ID}", request["headers"].get("cookie", ""))

    def test_read_request_does_not_carry_csrf(self):
        seen = []

        def handle(request):
            self.record(request, seen)
            if request.command == "POST":
                self.reply(
                    request,
                    201,
                    {
                        "role": "operator",
                        "username": "operator",
                        "csrfToken": CSRF,
                        "permissions": [],
                        "registryIds": [],
                        "deploymentRegistryId": "gov.registry.land",
                    },
                    {"set-cookie": f"onelayer_admin_session={SESSION_ID}; HttpOnly; Path=/"},
                )
            else:
                self.reply(request, 200, {"ok": True})

        origin = self.server(handle)
        client = self.signed_in_client(origin)
        client.sign_in()
        client.request_json("GET", "/v1/admin/records")
        self.assertNotIn("x-onelayer-csrf", seen[-1]["headers"])

    def test_sign_out_sends_delete_and_clears_state(self):
        seen = []

        def handle(request):
            self.record(request, seen)
            if request.command == "POST":
                self.reply(
                    request,
                    201,
                    {
                        "role": "operator",
                        "username": "operator",
                        "csrfToken": CSRF,
                        "permissions": [],
                        "registryIds": [],
                        "deploymentRegistryId": "gov.registry.land",
                    },
                    {"set-cookie": f"onelayer_admin_session={SESSION_ID}; HttpOnly; Path=/"},
                )
            else:
                self.reply(request, 204)

        origin = self.server(handle)
        client = self.signed_in_client(origin)
        client.sign_in()
        client.sign_out()
        self.assertIsNone(client.summary)
        self.assertIsNone(client.csrf_token)
        self.assertEqual(seen[-1]["method"], "DELETE")

    def test_clear_wipes_cookie_jar_and_csrf(self):
        seen = []

        def handle(request):
            self.record(request, seen)
            self.reply(
                request,
                201,
                {
                    "role": "operator",
                    "username": "operator",
                    "csrfToken": CSRF,
                    "permissions": [],
                    "registryIds": [],
                    "deploymentRegistryId": "gov.registry.land",
                },
                {"set-cookie": f"onelayer_admin_session={SESSION_ID}; HttpOnly; Path=/"},
            )

        origin = self.server(handle)
        client = self.signed_in_client(origin)
        client.sign_in()
        client.clear()
        self.assertIsNone(client.csrf_token)
        self.assertIsNone(client.summary)
        self.assertEqual(list(client._http.cookie_jar), [])


class RequestShapeTests(ServerFixture):
    def client(self, seen=None, status=200, body=None):
        def handle(request):
            if seen is not None:
                self.record(request, seen)
            self.reply(request, status, body if body is not None else {"ok": True})

        origin = self.server(handle)
        _root, credential = self.credentials_dir()
        return self.session(origin, credential)

    def test_idempotency_key_is_sent_and_validated(self):
        seen = []
        client = self.client(seen=seen)
        client.request_json(
            "POST", "/v1/admin/publish-intents", json_body={"a": 1}, idempotency_key="A" * 16
        )
        self.assertEqual(seen[-1]["headers"].get("idempotency-key"), "A" * 16)
        for key in ("short", "A" * 65, "has space", 5):
            with self.subTest(key=key), self.assertRaises(ProtocolError):
                client.request_json("POST", "/x", json_body={"a": 1}, idempotency_key=key)

    def test_oversized_request_body_is_rejected_locally(self):
        seen = []
        client = self.client(seen=seen)
        with self.assertRaises(ProtocolError):
            client.request_bytes(
                "POST", "/x", body=b"a" * 300000, headers={"content-type": "application/json"}
            )
        self.assertEqual(seen, [])

    def test_api_refusal_carries_only_the_sanitized_code(self):
        client = self.client(status=422, body={"code": "QR_HASH_MISMATCH", "detail": "secret-path"})
        with self.assertRaises(ApiRefusal) as raised:
            client.request_json("GET", "/v1/certificates/aa/package")
        self.assertEqual(raised.exception.status, 422)
        self.assertEqual(raised.exception.code, "QR_HASH_MISMATCH")
        self.assertNotIn("secret-path", str(raised.exception))
        self.assertNotIn("secret-path", repr(raised.exception))
        self.assertIsNone(raised.exception.payload)

    def test_unsanitizable_code_becomes_none(self):
        client = self.client(status=400, body={"code": "weird code!"})
        with self.assertRaises(ApiRefusal) as raised:
            client.request_json("GET", "/x")
        self.assertIsNone(raised.exception.code)

    def test_expired_status_is_reported_as_expired(self):
        client = self.client(status=401, body={"code": "SESSION_REQUIRED"})
        with self.assertRaises(ApiRefusal) as raised:
            client.request_json("GET", "/x")
        self.assertEqual(raised.exception.state, "expired")

    def test_request_bytes_returns_bounded_raw_body(self):
        seen = []

        def handle(request):
            self.record(request, seen)
            self.reply(request, 200, raw=b"\x89PNG\r\n\x1a\n" + b"0" * 32)

        origin = self.server(handle)
        _root, credential = self.credentials_dir()
        client = self.session(origin, credential)
        response = client.request_bytes("GET", "/v1/qr/aa.png")
        self.assertEqual(response.status, 200)
        self.assertTrue(response.body.startswith(b"\x89PNG"))


class RefusalEchoTests(ServerFixture):
    """The retained refusal payload is bounded, typed and never secret-bearing (M2)."""

    PUBLISH_BODY = {
        "intentId": "11111111-2222-3333-4444-555555555555",
        "state": "SIMULATION_FAILED",
        "batchSequence": "2",
        "intentHash": "dd" * 32,
        "review": {
            "registryId": "gov.registry.land",
            "simulation": {"ok": False, "error": "synthetic simulation failure"},
            "accounts": [{"address": "4Y4pGizJm5CL789jRKYx5jeQLJ58eBBmf5UzGRFChikn", "role": "signer"}],
        },
        "recentBlockhash": "9" * 43,
        "lastValidBlockHeight": "123456",
        "failureCode": "SIMULATION_FAILED",
    }

    def echo(self, body):
        return sanitized_refusal_echo(422, body)

    def test_publish_envelope_is_kept_and_free_form_keys_are_dropped(self):
        body = dict(self.PUBLISH_BODY)
        body["simulationLogs"] = ["Program log: super-secret-rpc-log"]
        body["code"] = "SIMULATION_FAILED"
        body["message"] = "free-form server text"
        body["detail"] = "secret-path"
        body["csrfToken"] = CSRF
        body["password"] = SECRET
        echoed = self.echo(body)
        self.assertIsInstance(echoed, dict)
        self.assertEqual(echoed["state"], "SIMULATION_FAILED")
        self.assertIn("review", echoed)
        for forbidden in ("simulationLogs", "code", "message", "detail", "csrfToken", "password"):
            self.assertNotIn(forbidden, echoed)
        rendered = json.dumps(echoed)
        self.assertNotIn("super-secret-rpc-log", rendered)
        self.assertNotIn("secret-path", rendered)
        self.assertNotIn(SECRET, rendered)
        self.assertNotIn(CSRF, rendered)

    def test_secret_shaped_nested_keys_are_dropped(self):
        body = dict(self.PUBLISH_BODY)
        body["review"] = dict(
            body["review"], csrfToken=CSRF, issuerSecret="do-not-retain", sessionId=SESSION_ID
        )
        echoed = self.echo(body)
        rendered = json.dumps(echoed)
        self.assertNotIn("csrfToken", echoed["review"])
        self.assertNotIn("issuerSecret", echoed["review"])
        self.assertNotIn("sessionId", echoed["review"])
        self.assertNotIn("do-not-retain", rendered)
        self.assertNotIn(CSRF, rendered)
        self.assertIn("simulation", echoed["review"])

    def test_unrepresentable_values_drop_the_whole_echo(self):
        body = dict(self.PUBLISH_BODY)
        body["review"] = dict(body["review"], note="x" * 5000)
        self.assertIsNone(self.echo(body))
        self.assertIsNone(self.echo({"review": {"deep": [[[[[[[[[[1]]]]]]]]]]}}))
        self.assertIsNone(self.echo({"review": {"flag": float("nan")}}))
        self.assertIsNone(self.echo({"review": {"bytes": b"\x01"}}))

    def test_only_the_publish_422_echoes_anything(self):
        self.assertIsNone(sanitized_refusal_echo(401, dict(self.PUBLISH_BODY)))
        self.assertIsNone(sanitized_refusal_echo(409, dict(self.PUBLISH_BODY)))
        self.assertIsNone(sanitized_refusal_echo(500, dict(self.PUBLISH_BODY)))
        self.assertIsNone(sanitized_refusal_echo(422, {"code": "QR_HASH_MISMATCH"}))
        self.assertIsNone(sanitized_refusal_echo(422, "not a dict"))
        self.assertIsNone(sanitized_refusal_echo(422, None))

    def test_refusal_carries_the_echo_but_never_in_str_or_repr(self):
        body = dict(self.PUBLISH_BODY)
        body["simulationLogs"] = ["super-secret-rpc-log"]
        seen = []

        def handle(request):
            self.record(request, seen)
            self.reply(request, 422, body)

        origin = self.server(handle)
        _root, credential = self.credentials_dir()
        client = self.session(origin, credential)
        with self.assertRaises(ApiRefusal) as raised:
            client.request_json("POST", "/v1/admin/publish-intents", json_body={"a": 1})
        error = raised.exception
        self.assertIsInstance(error.payload, dict)
        self.assertEqual(error.payload["state"], "SIMULATION_FAILED")
        self.assertNotIn("simulationLogs", error.payload)
        self.assertNotIn("super-secret-rpc-log", json.dumps(error.payload))
        self.assertNotIn("super-secret-rpc-log", str(error))
        self.assertNotIn("super-secret-rpc-log", repr(error))
        self.assertNotIn("super-secret-rpc-log", repr(error.args))
        self.assertNotIn(SECRET, json.dumps(error.payload))

    def test_login_and_session_failures_never_echo_bodies(self):
        def handle(request):
            self.reply(request, 401, {"code": "INVALID_CREDENTIALS", "csrfToken": CSRF})

        origin = self.server(handle)
        _root, credential = self.credentials_dir()
        client = self.session(origin, credential)
        with self.assertRaises(ApiRefusal) as raised:
            client.request_json("GET", "/v1/admin/session")
        self.assertIsNone(raised.exception.payload)
        self.assertNotIn(CSRF, repr(raised.exception))

    def test_deeply_nested_response_json_is_refused_not_crashed(self):
        def handle(request):
            self.reply(
                request,
                200,
                raw=('{"a":' * 20000 + "1" + "}" * 20000).encode(),
            )

        origin = self.server(handle)
        _root, credential = self.credentials_dir()
        client = self.session(origin, credential, max_response_bytes=1 << 20)
        with self.assertRaises(ProtocolError):
            client.request_json("GET", "/v1/admin/records")


class TransportRulesTests(ServerFixture):
    def test_environment_proxy_is_ignored(self):
        seen = []

        def handle(request):
            self.record(request, seen)
            self.reply(request, 200, {"ok": True})

        origin = self.server(handle)
        os.environ["http_proxy"] = "http://127.0.0.1:9"
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:9"
        self.addCleanup(os.environ.pop, "http_proxy", None)
        self.addCleanup(os.environ.pop, "HTTP_PROXY", None)
        http = LoopbackHttp(origin, max_response_bytes=4096)
        response = http.request("GET", "/v1/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["path"], "/v1/health")

    def test_off_loopback_origin_is_rejected_at_construction(self):
        for origin in ("http://example.com:8090", "https://127.0.0.1:8090", "http://127.0.0.1:8090/"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                LoopbackHttp(origin)

    def test_unknown_method_is_rejected(self):
        origin = self.server(lambda request: self.reply(request, 200, {"ok": True}))
        http = LoopbackHttp(origin)
        with self.assertRaises(ProtocolError):
            http.request("TRACE", "/x")

    def test_connection_refusal_is_offline(self):
        http = LoopbackHttp("http://127.0.0.1:1", timeout=0.4)
        with self.assertRaises(TransportError):
            http.request("GET", "/v1/health")


if __name__ == "__main__":
    unittest.main()
