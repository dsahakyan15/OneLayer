import hashlib
import hmac
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit

from broker import ApprovalBroker, ApprovalIntent, BrowserLogin, Rejected


class LoginTests(unittest.TestCase):
    def setUp(self):
        self.now = 100
        self.login = BrowserLogin("https://identity.example.invalid/authorize", "lab", 41999, lambda: self.now)

    def callback(self, **changes):
        values = {"state": self.login.state, "code": "synthetic-code"}
        values.update(changes)
        return self.login.redirect_uri + "?" + urlencode(values)

    def test_pkce_and_single_use(self):
        query = parse_qs(urlsplit(self.login.url).query)
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertNotIn(self.login.verifier, self.login.url)
        self.assertEqual(self.login.consume(self.callback()), "synthetic-code")
        with self.assertRaises(Rejected):
            self.login.consume(self.callback())

    def test_rejects_wrong_state_duplicate_fields_and_callback_origins(self):
        for callback in (self.callback(state="foreign"), self.callback() + "&state=foreign", self.callback() + "&state=", self.callback() + "&code=",
                         self.callback().replace("127.0.0.1", "localhost"),
                         self.callback().replace("/callback", "/other"),
                         self.callback() + "#fragment", self.callback(error="denied")):
            with self.subTest(callback=callback), self.assertRaises(Rejected):
                self.login.consume(callback)
        self.assertEqual(self.login.consume(self.callback()), "synthetic-code")

    def test_expiry_and_process_restart(self):
        other = BrowserLogin("https://identity.example.invalid/authorize", "lab", 41999)
        with self.assertRaises(Rejected):
            other.consume(self.callback())
        self.now = 220
        with self.assertRaises(Rejected):
            self.login.consume(self.callback())

    def test_rejects_untrusted_endpoint(self):
        for endpoint in ("http://identity.invalid", "https://user@identity.invalid", "https://identity.invalid?a=b"):
            with self.subTest(endpoint=endpoint), self.assertRaises(Rejected):
                BrowserLogin(endpoint, "lab", 41999)


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.now = 100
        # Synthetic MAC adapter only; does not claim hardware or external signing.
        self.key = b"synthetic-lab-only"
        self.broker = ApprovalBroker(lambda intent, signature: hmac.compare_digest(
            hmac.digest(self.key, intent.payload, hashlib.sha256), signature), lambda: self.now)
        self.intent = ApprovalIntent("op-1", "alice", "device-1", "lab-only", b"exact bytes A", 120)
        self.signature = hmac.digest(self.key, self.intent.payload, hashlib.sha256)
        self.broker.register(self.intent)

    def accept(self, **changes):
        values = dict(operation_id="op-1", subject="alice", device="device-1",
                      payload=self.intent.payload, signature=self.signature)
        values.update(changes)
        return self.broker.accept(**values)

    def test_exact_bytes_and_one_shot(self):
        self.assertEqual(self.accept()["operation_id"], "op-1")
        with self.assertRaises(Rejected):
            self.accept()
        with self.assertRaises(Rejected):
            self.broker.register(self.intent)

    def test_tamper_subject_device_signature_operation_and_bytes(self):
        for changes in ({"subject": "bob"}, {"device": "device-2"}, {"payload": b"exact bytes B"},
                        {"signature": b"invalid"}, {"operation_id": "op-2"}):
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                self.accept(**changes)
        self.accept()

    def test_expired(self):
        self.now = 120
        with self.assertRaises(Rejected):
            self.accept()


if __name__ == "__main__":
    unittest.main()
