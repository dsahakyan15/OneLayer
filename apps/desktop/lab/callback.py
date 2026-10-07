"""Loopback transport for synthetic PKCE experiments; no token exchange or login."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from queue import Empty, Queue
from threading import Thread

from broker import BrowserLogin, Rejected


class LoopbackCallback:
    """Reserve an ephemeral IPv4 port before producing the authorization URL.

    Native caller takes the code once. Neither responses nor access logs contain
    callback data. The caller must close this bounded-lifetime experiment.
    """

    def __init__(self, authorization_endpoint, client_id, clock=None):
        owner = self
        self._codes = Queue(maxsize=1)
        self._closed = False

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                self.request.settimeout(2)
                super().setup()

            def log_message(self, *args):
                pass

            def do_GET(self):
                hosts = self.headers.get_all("Host", [])
                expected_host = f"127.0.0.1:{owner._server.server_port}"
                # Origin-form only; reject DNS rebinding/duplicate Host and bodies.
                if (hosts != [expected_host] or not self.path.startswith("/callback?")
                        or len(self.path) > 8192 or self.headers.get("Content-Length")
                        or self.headers.get("Transfer-Encoding")):
                    self.respond(400)
                    return
                try:
                    code = owner.login.consume("http://" + expected_host + self.path)
                except (Rejected, ValueError):
                    self.respond(400)
                    return
                owner._codes.put_nowait(code)
                self.respond(200)

            def do_POST(self):
                self.respond(405)

            def respond(self, status):
                body = b"Callback received. Return to the application." if status == 200 else b"Callback rejected."
                self.send_response(status)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        try:
            options = {} if clock is None else {"clock": clock}
            self.login = BrowserLogin(authorization_endpoint, client_id, self._server.server_port, **options)
        except Exception:
            self._server.server_close()
            raise
        self._thread = Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()

    def take_code(self, timeout=0):
        if self._closed:
            raise Rejected("callback listener closed")
        try:
            return self._codes.get(timeout=timeout)
        except Empty as error:
            raise Rejected("no callback result") from error

    def close(self):
        if not self._closed:
            self._server.shutdown()
            self._server.server_close()
            self._thread.join()
            self._closed = True
            while not self._codes.empty():
                self._codes.get_nowait()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
