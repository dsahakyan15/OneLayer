import json
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from launcher_state import _probe, probe_services


class LauncherStateTests(unittest.TestCase):
    def server(self, handle):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
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

    def reply(self, request, status=200, body=b'{"status":"ok"}', headers=None):
        request.send_response(status)
        for name, value in (headers or {}).items():
            request.send_header(name, value)
        request.send_header("content-length", str(len(body)))
        request.end_headers()
        request.wfile.write(body)

    def test_health_and_web_responses_are_distinguished(self):
        origin = self.server(lambda request: self.reply(request, body=b"<html>workspace</html>"))
        self.assertEqual(_probe(origin, False)["state"], "available")
        self.assertEqual(_probe(origin, True)["state"], "error")
        for body in (b'{"status":"ok"}', b'{"status":"down"}', b"[]", b"x" * 4097):
            with self.subTest(body=body[:30]):
                origin = self.server(lambda request, body=body: self.reply(request, body=body))
                expected = "available" if body == b'{"status":"ok"}' else "error"
                self.assertEqual(_probe(origin, True)["state"], expected)

    def test_redirects_are_not_followed_and_no_credentials_are_sent(self):
        seen = []
        redirected = []
        target = self.server(lambda request: (redirected.append(True), self.reply(request)))

        def handle(request):
            seen.append((request.headers.get("Authorization"), request.headers.get("Cookie")))
            self.reply(request, 302, headers={"Location": target + "/other"})

        origin = self.server(handle)
        self.assertEqual(_probe(origin, True), {"state": "error", "detail": "HTTP 302"})
        self.assertEqual(seen, [(None, None)])
        self.assertEqual(redirected, [])

    def test_refusal_and_server_failure_do_not_echo_response_details(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
            # A reserved but non-listening port deterministically refuses a connection.
            result = _probe(origin, True)
        self.assertEqual(result["state"], "offline")
        origin = self.server(lambda request: self.reply(request, 503, b"private-canary"))
        result = _probe(origin, True)
        self.assertEqual(result, {"state": "error", "detail": "HTTP 503"})
        self.assertNotIn("private-canary", json.dumps(result))

    def test_each_service_has_an_independent_observation(self):
        endpoints = (
            ("api", self.server(lambda request: self.reply(request)), True),
            ("verifier", self.server(lambda request: self.reply(request, 503)), True),
            ("web", self.server(lambda request: self.reply(request, body=b"workspace")), False),
        )
        with patch("launcher_state._ENDPOINTS", endpoints):
            result = probe_services()
        self.assertEqual({key: value["state"] for key, value in result.items()},
                         {"api": "available", "verifier": "error", "web": "available"})

    def test_slow_stream_cannot_extend_the_probe_deadline(self):
        def handle(request):
            body = b'{"status":"ok"}'
            request.send_response(200)
            request.send_header("content-length", str(len(body)))
            request.end_headers()
            try:
                for byte in body:
                    request.wfile.write(bytes([byte]))
                    request.wfile.flush()
                    time.sleep(0.05)
            except OSError:
                pass

        origin = self.server(handle)
        started = time.monotonic()
        with patch("launcher_state._TIMEOUT", 0.15):
            result = _probe(origin, True)
        self.assertNotEqual(result["state"], "available")
        self.assertLess(time.monotonic() - started, 0.6)


if __name__ == "__main__":
    unittest.main()
