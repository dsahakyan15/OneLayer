import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from session import LabSession, SessionFailure


class SessionTransportTests(unittest.TestCase):
    def server(self, handle):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                handle(self)

            def do_POST(self):
                handle(self)

            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join()
        self.addCleanup(cleanup)
        return f"http://127.0.0.1:{server.server_port}"

    def reply(self, request, status, body=None, headers=None):
        request.send_response(status)
        for name, value in (headers or {}).items():
            request.send_header(name, value)
        request.end_headers()
        request.wfile.write(json.dumps(body).encode())

    def test_only_synthetic_loopback_origins(self):
        for origin in ("https://example.com", "http://localhost:1234", "http://127.0.0.1:1234/",
                       "http://127.0.0.1:1234?x", "http://user@127.0.0.1:1234", "http://127.0.0.1"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                LabSession(origin, "http://127.0.0.1:2345")

    def test_issuer_never_receives_backend_cookies_and_callback_redirect_is_pinned(self):
        received = []
        def issuer_request(request):
            received.append(request.headers.get("cookie"))
            self.reply(request, 302, headers={"location": "http://127.0.0.1:1/stolen"})
        issuer = self.server(issuer_request)
        backend = self.server(lambda request: self.reply(request, 200,
            {"authorizationUrl": issuer + "/authorize?state=synthetic"},
            {"set-cookie": "backend_canary=secret; HttpOnly; Path=/"}))
        client = LabSession(backend, issuer)
        with self.assertRaises(SessionFailure):
            client.login()
        self.assertEqual(received, [None])
        self.assertEqual(list(client._cookies), [])

    def test_backend_redirect_is_not_followed(self):
        received = []
        foreign = self.server(lambda request: (received.append(True), self.reply(request, 200)))
        backend = self.server(lambda request: self.reply(request, 302, headers={"location": foreign + "/steal"}))
        client = LabSession(backend, foreign)
        with self.assertRaises(SessionFailure):
            client.login()
        self.assertEqual(received, [])

    def test_foreign_authorization_url_not_requested(self):
        received = []
        foreign = self.server(lambda request: (received.append(True), self.reply(request, 200)))
        backend = self.server(lambda request: self.reply(request, 200, {"authorizationUrl": foreign + "/authorize"}))
        client = LabSession(backend, "http://127.0.0.1:1")
        with self.assertRaises(SessionFailure):
            client.login()
        self.assertEqual(received, [])

    def test_summary_does_not_expose_session_secrets(self):
        backend = self.server(lambda request: self.reply(request, 200,
            {"username": "synthetic", "role": "auditor", "csrfToken": "secret-canary", "refreshToken": "never-display"}))
        client = LabSession(backend, "http://127.0.0.1:1")
        self.assertEqual(client.refresh(), {"username": "synthetic", "role": "auditor"})

    def test_oversized_response_fails_closed(self):
        backend = self.server(lambda request: self.reply(request, 200, "x" * 65536))
        client = LabSession(backend, "http://127.0.0.1:1")
        with self.assertRaises(SessionFailure):
            client.refresh()


if __name__ == "__main__":
    unittest.main()
