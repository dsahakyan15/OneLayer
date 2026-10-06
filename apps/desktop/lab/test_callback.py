import contextlib
import http.client
import io
import socket
import unittest
from urllib.parse import urlencode, urlsplit

from broker import Rejected
from callback import LoopbackCallback


class CallbackTransportTests(unittest.TestCase):
    def setUp(self):
        self.now = 100
        self.receiver = LoopbackCallback("https://identity.example.invalid/authorize", "lab", lambda: self.now)
        self.addCleanup(self.receiver.close)
        self.port = urlsplit(self.receiver.login.redirect_uri).port
        self.path = "/callback?" + urlencode({"state": self.receiver.login.state, "code": "synthetic-secret-code"})

    def request(self, path=None, host=None, method="GET"):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request(method, path or self.path, headers={"Host": host or f"127.0.0.1:{self.port}"})
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    def test_real_socket_reserved_single_use_and_no_secret_output(self):
        with socket.socket() as competing:
            with self.assertRaises(OSError):
                competing.bind(("127.0.0.1", self.port))
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            status, body, headers = self.request()
        self.assertEqual(status, 200)
        self.assertNotIn(b"synthetic-secret-code", body)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(self.receiver.take_code(), "synthetic-secret-code")
        self.assertEqual(self.request()[0], 400)
        with self.assertRaises(Rejected):
            self.receiver.take_code()

    def test_foreign_host_state_absolute_target_method_and_duplicates(self):
        attempts = [dict(host="attacker.invalid"), dict(path=self.path.replace(self.receiver.login.state, "foreign")),
                    dict(path=self.path + "&state=duplicate"), dict(path="http://127.0.0.1:" + str(self.port) + self.path),
                    dict(path="/wrong"), dict(method="POST")]
        for attempt in attempts:
            with self.subTest(attempt=attempt):
                self.assertIn(self.request(**attempt)[0], (400, 405))
                with self.assertRaises(Rejected):
                    self.receiver.take_code()
        self.assertEqual(self.request()[0], 200)

    def test_duplicate_host_rejected(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=3) as connection:
            connection.sendall((f"GET {self.path} HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nHost: attacker.invalid\r\n\r\n").encode())
            self.assertIn(b"400", connection.recv(4096).split(b"\r\n")[0])
        with self.assertRaises(Rejected):
            self.receiver.take_code()

    def test_expiry_and_close_discard_result(self):
        self.now = 220
        self.assertEqual(self.request()[0], 400)
        self.receiver.close()
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", self.port), timeout=1)
        with self.assertRaises(Rejected):
            self.receiver.take_code()

    def test_close_discards_unread_code(self):
        self.assertEqual(self.request()[0], 200)
        self.receiver.close()
        with self.assertRaises(Rejected):
            self.receiver.take_code()

    def test_new_attempt_rejects_old_state(self):
        with LoopbackCallback("https://identity.example.invalid/authorize", "lab") as another:
            connection = http.client.HTTPConnection("127.0.0.1", urlsplit(another.login.redirect_uri).port, timeout=3)
            try:
                connection.request("GET", self.path)
                response = connection.getresponse()
                self.assertEqual(response.status, 400)
                response.read()
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
