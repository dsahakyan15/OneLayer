#!/usr/bin/python3
"""Focused stdlib tests for apps/desktop/lab/live_demo_api.py.

The suite is hermetic: a real ``http.server`` stands in for the legacy demo-api
and verifier, and the frozen ``spec/vectors/certificate.json`` golden bytes
prove that the pure-Python package hasher matches the canonical CertificatePackageV1
contract. No chain is touched, no key is read, and no secret is printed.

Two properties are asserted explicitly because getting them wrong would be a
security regression:

* the package hash is a real ``sha256`` of the canonical signed body, not a
  comparison of two attacker-controlled strings;
* an ``INVALID`` verification never discloses fields, and
  ``VERIFIED_NO_INCIDENT_CHECK`` is never promoted to ``VERIFIED``.
"""
import base64
import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import live_demo_api  # noqa: E402  (path is prepared above)
from live_demo_api import (  # noqa: E402
    CanonicalPackageHasher,
    CertificateMetadata,
    DeferredPackageHashVerifier,
    HashVerdict,
    IssuedCertificate,
    LiveDemoApi,
    LiveDemoProfile,
    PackageFormatError,
    PackageHashResult,
    ProtocolError,
    PublishPlan,
    PublishReview,
    RecordVersion,
    VerificationReport,
    certificate_body_cbor,
    certificate_hash_hex,
    configured_registry_id,
    decode_certificate_package,
    normalize_verification_result,
    parse_qr_payload,
    qr_hash_to_hex,
    validate_explorer_url,
)
from live_demo_session import AdminSession, ApiRefusal  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
SPEC_VECTORS = REPO_ROOT / "spec" / "vectors" / "certificate.json"

SECRET = "synthetic-operator-password-0123456789abcdef"
CSRF = "csrf-token-value-0123456789abcdef"
SESSION_ID = "session-token-value-0123456789abcdef"
OPERATOR = "4Y4pGizJm5CL789jRKYx5jeQLJ58eBBmf5UzGRFChikn"
SIGNATURE = "w" * 88
CERT_ID = "01010101010101010101010101010101"
INTENT_ID = "11111111-2222-3333-4444-555555555555"
INTENT_HASH = "dd" * 32
PROGRAM_ID = "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo"
CONFIG_PDA = "BPgSTnDHop1NhMrksBWJtZV2zqVmUM1iusEuUXocCnFU"

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(raw: bytes) -> str:
    """Real base58 (32-byte key material) so fixtures pass any address check."""
    number = int.from_bytes(raw, "big")
    out = ""
    while number:
        number, remainder = divmod(number, 58)
        out = _B58_ALPHABET[remainder] + out
    padding = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * padding + (out or "1")


ROLE_PDA = b58(bytes([1] * 32))
SEGMENT_PDA = b58(bytes([2] * 32))
RECENT_BLOCKHASH = b58(bytes([3] * 32))
INSTRUCTION_DATA = base64.b64encode(bytes(range(178))).decode()
TRANSACTION_BASE64 = base64.b64encode(b"\x01" * 64).decode()


# --------------------------------------------------------------------------
# synthetic CertificatePackageV1 fixture builder
# --------------------------------------------------------------------------


def _c_int(value):
    return live_demo_api._cbor_int(value)


def _c_text(value):
    return live_demo_api._cbor_text(value)


def _c_bytes(value):
    return live_demo_api._cbor_bytes(value)


def _c_map(pairs):
    return live_demo_api._cbor_map(pairs)


def _c_array(items):
    return live_demo_api._cbor_array(items)


def build_package(
    *,
    disclosed=None,
    disclosure_mode="SELECTIVE_FIELDS",
    certificate_id=None,
    issuer_secret=b"k" * 32,
    tamper=None,
    field_proof_paths=None,
):
    """Return (package_bytes, expected_hash_hex) for a synthetic certificate."""
    disclosed = dict(disclosed if disclosed is not None else
                     {"areaSquareMeters": "1250.50", "status": "ACTIVE"})
    certificate_id = bytes.fromhex(certificate_id or CERT_ID)
    salts = {path: hashlib.sha256(b"salt:" + path.encode()).digest() for path in disclosed}
    field_proofs = []
    proof_paths = sorted(disclosed) if field_proof_paths is None else list(field_proof_paths)
    if disclosure_mode == "SELECTIVE_FIELDS" or field_proof_paths is not None:
        for index, path in enumerate(proof_paths):
            field_proofs.append(
                _c_map(
                    (
                        ("path", _c_text(path)),
                        ("leafIndex", _c_int(index)),
                        ("siblings", _c_array(())),
                    )
                )
            )
    anchor = _c_map(
        (
            ("batchSequence", _c_int(7)),
            ("registryVersion", _c_int(3)),
            ("merkleRoot", _c_bytes(b"m" * 32)),
            ("manifestHash", _c_bytes(b"h" * 32)),
            ("solanaProgramId", _c_bytes(b"p" * 32)),
            ("segmentIndex", _c_int(2)),
            ("segmentPda", _c_bytes(b"s" * 32)),
            ("transactionSignature", _c_bytes(b"t" * 64)),
            ("anchorSlot", _c_int(412267854)),
            ("commitmentRequired", _c_text("finalized")),
        )
    )
    batch_proof = _c_map(
        (
            ("treeAlgorithm", _c_text("RFC6962_SHA256_V1")),
            ("leafIndex", _c_int(0)),
            ("leafHash", _c_bytes(b"l" * 32)),
            ("siblings", _c_array(())),
            ("expectedRoot", _c_bytes(b"r" * 32)),
        )
    )
    issuer = _c_map(
        (
            ("keyId", _c_text("pilot-issuer-1")),
            ("publicKey", _c_bytes(issuer_secret)),
            ("signatureAlgorithm", _c_text("Ed25519")),
        )
    )
    entries = [
        ("format", _c_text("ONELAYER_CERTIFICATE")),
        ("version", _c_int(1)),
        ("certificateId", _c_bytes(certificate_id)),
        ("registryId", _c_text("gov.registry.land")),
        ("issuedAt", _c_text("2026-10-02T10:00:00Z")),
        ("recordIdCommitment", _c_bytes(b"c" * 32)),
        ("recordVersion", _c_int(2)),
        ("schemaVersion", _c_int(1)),
        ("disclosureMode", _c_text(disclosure_mode)),
        ("disclosedFields", _c_map((path, _c_text(value)) for path, value in disclosed.items())),
        ("fieldSalts", _c_map((path, _c_bytes(salt)) for path, salt in salts.items())),
        ("fieldRoot", _c_bytes(b"f" * 32)),
        ("fieldProofs", _c_array(field_proofs)),
        ("batchProof", batch_proof),
        ("anchor", anchor),
        ("issuer", issuer),
        ("issuerSignature", _c_bytes(b"z" * 64)),
    ]
    package = live_demo_api._encode(_c_map(entries))
    digest = None
    try:
        digest = certificate_hash_hex(decode_certificate_package(package))
    except PackageFormatError:
        # Intentionally malformed fixtures carry no trustworthy digest.
        digest = None
    if tamper == "area":
        tampered = dict(disclosed)
        tampered["areaSquareMeters"] = "9999.99"
        return build_package(
            disclosed=tampered,
            disclosure_mode=disclosure_mode,
            certificate_id=certificate_id.hex(),
            issuer_secret=issuer_secret,
            field_proof_paths=field_proof_paths,
        )
    return package, digest


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# --------------------------------------------------------------------------
# frozen spec vectors — the hash must match the canonical implementation.
# --------------------------------------------------------------------------


class GoldenVectorTests(unittest.TestCase):
    def setUp(self):
        if not SPEC_VECTORS.is_file():
            self.skipTest("spec/vectors/certificate.json is absent")
        self.vectors = json.loads(SPEC_VECTORS.read_text())["vectors"]

    def test_canonical_body_cbor_matches_the_frozen_spec(self):
        for vector in self.vectors:
            expected = vector["expected"]
            package = bytes.fromhex(expected["certificate_package_cbor"])
            with self.subTest(vector=vector["id"]):
                body = decode_certificate_package(package)
                self.assertEqual(
                    certificate_body_cbor(body), bytes.fromhex(expected["certificate_body_cbor"])
                )

    def test_certificate_hash_matches_the_frozen_spec(self):
        for vector in self.vectors:
            expected = vector["expected"]
            package = bytes.fromhex(expected["certificate_package_cbor"])
            with self.subTest(vector=vector["id"]):
                body = decode_certificate_package(package)
                self.assertEqual(certificate_hash_hex(body), expected["certificate_hash"])

    def test_hasher_reports_match_against_the_frozen_hash(self):
        hasher = CanonicalPackageHasher()
        for vector in self.vectors:
            expected = vector["expected"]
            package = bytes.fromhex(expected["certificate_package_cbor"])
            with self.subTest(vector=vector["id"]):
                result = hasher.verify(package, expected["certificate_hash"])
                self.assertEqual(result.verdict, HashVerdict.MATCH)
                self.assertTrue(result.matched)
                self.assertTrue(result.validated)

    def test_hasher_rejects_a_wrong_expected_hash(self):
        hasher = CanonicalPackageHasher()
        package = bytes.fromhex(self.vectors[0]["expected"]["certificate_package_cbor"])
        wrong = "0" * 64
        result = hasher.verify(package, wrong)
        self.assertEqual(result.verdict, HashVerdict.MISMATCH)
        self.assertFalse(result.matched)
        self.assertNotEqual(result.computed_hash_hex, wrong)


class HashIsRealTests(unittest.TestCase):
    """The hash check must hash the canonical body, not compare two strings."""

    def test_tampered_body_changes_the_hash(self):
        original, original_hash = build_package()
        tampered, tampered_hash = build_package(tamper="area")
        self.assertNotEqual(original, tampered)
        self.assertNotEqual(original_hash, tampered_hash)

    def test_a_self_declared_hash_cannot_hide_a_tampered_body(self):
        tampered, tampered_hash = build_package(tamper="area")
        # An attacker relabels the tampered package with the ORIGINAL hash.
        _, original_hash = build_package()
        result = CanonicalPackageHasher().verify(tampered, original_hash, expected_source="qr")
        self.assertEqual(result.verdict, HashVerdict.MISMATCH)
        self.assertFalse(result.validated)
        self.assertEqual(result.computed_hash_hex, tampered_hash)

    def test_changing_only_the_expected_hash_is_a_mismatch(self):
        package, digest = build_package()
        result = CanonicalPackageHasher().verify(package, "1" * 64)
        self.assertEqual(result.verdict, HashVerdict.MISMATCH)
        self.assertEqual(result.computed_hash_hex, digest)

    def test_no_expected_hash_is_deferred_not_a_match(self):
        package, digest = build_package()
        result = CanonicalPackageHasher().verify(package, None)
        self.assertEqual(result.verdict, HashVerdict.DEFERRED)
        self.assertFalse(result.matched)
        self.assertFalse(result.validated)
        self.assertEqual(result.computed_hash_hex, digest)

    def test_unparseable_package_is_never_a_match(self):
        for blob in (b"", b"\xff\xff", b"not cbor at all", b"\xa1" * 4):
            with self.subTest(blob=blob):
                result = CanonicalPackageHasher().verify(blob, "0" * 64)
                self.assertEqual(result.verdict, HashVerdict.UNPARSEABLE)
                self.assertFalse(result.matched)

    def test_truncated_package_is_unparseable(self):
        package, digest = build_package()
        result = CanonicalPackageHasher().verify(package[:-3], digest)
        self.assertEqual(result.verdict, HashVerdict.UNPARSEABLE)

    def test_deferred_verifier_never_reports_match(self):
        package, digest = build_package()
        verifier = DeferredPackageHashVerifier()
        for expected in (digest, None, "0" * 64):
            with self.subTest(expected=expected):
                result = verifier.verify(package, expected)
                self.assertEqual(result.verdict, HashVerdict.DEFERRED)
                self.assertFalse(result.matched)
                self.assertFalse(result.validated)

    def test_package_hash_result_serializes_without_secrets(self):
        result = CanonicalPackageHasher().verify(build_package()[0], "0" * 64)
        serialized = json.dumps(result.as_dict())
        self.assertIn("verdict", serialized)
        self.assertNotIn(SECRET, serialized)


class PackageFormatTests(unittest.TestCase):
    def test_full_record_requires_no_field_proofs(self):
        package, _ = build_package(disclosure_mode="FULL_RECORD", disclosed={"status": "ACTIVE"})
        body = decode_certificate_package(package)
        self.assertEqual(body.disclosure_mode, "FULL_RECORD")

    def test_selective_fields_requires_matching_proof_paths(self):
        package, _ = build_package(
            disclosed={"areaSquareMeters": "1250.50", "status": "ACTIVE"},
            field_proof_paths=["status"],
        )
        with self.assertRaises(PackageFormatError):
            decode_certificate_package(package)

    def test_full_record_rejects_any_field_proof(self):
        package, _ = build_package(
            disclosure_mode="FULL_RECORD",
            disclosed={"status": "ACTIVE"},
            field_proof_paths=["status"],
        )
        with self.assertRaises(PackageFormatError):
            decode_certificate_package(package)

    def test_empty_disclosure_is_rejected(self):
        package, _ = build_package(disclosed={}, disclosure_mode="FULL_RECORD")
        with self.assertRaises(PackageFormatError):
            decode_certificate_package(package)

    def test_trailing_bytes_are_rejected(self):
        package, _ = build_package()
        with self.assertRaises(PackageFormatError):
            decode_certificate_package(package + b"\x00")

    def test_truncated_package_is_rejected(self):
        package, _ = build_package()
        with self.assertRaises(PackageFormatError):
            decode_certificate_package(package[:-1])

    def test_non_shortest_integer_is_rejected(self):
        package, _ = build_package()
        # `0x18 0x00` is a non-shortest encoding of integer 0.
        patched = package.replace(_head_int(0), b"\x18\x00", 1)
        if patched == package:
            self.skipTest("fixture has no single-byte integer to rewrite")
        with self.assertRaises(PackageFormatError):
            decode_certificate_package(patched)

    def test_unknown_top_level_key_is_rejected(self):
        entries = _c_map(
            (
                ("format", _c_text("ONELAYER_CERTIFICATE")),
                ("surprise", _c_text("x")),
            )
        )
        with self.assertRaises(PackageFormatError):
            decode_certificate_package(live_demo_api._encode(entries))

    def test_non_canonical_map_order_is_rejected(self):
        package, _ = build_package()
        decoded = live_demo_api.decode_canonical(package)
        pairs = tuple(decoded.value)
        # `_encode` sorts map keys, so to produce non-canonical bytes the
        # entries must be concatenated by hand in reverse key order.
        encoded_pairs = [
            (live_demo_api._encode(_c_text(key)), live_demo_api._encode(value))
            for key, value in pairs
        ]
        encoded_pairs.sort(key=lambda item: item[0])
        reversed_bytes = (
            live_demo_api._head(5, len(encoded_pairs))
            + b"".join(k + v for k, v in reversed(encoded_pairs))
        )
        self.assertNotEqual(reversed_bytes, package)
        with self.assertRaises(PackageFormatError):
            decode_certificate_package(reversed_bytes)


def _head_int(value):
    return live_demo_api._head(0, value)


class NormalizationTests(unittest.TestCase):
    def test_invalid_status_clears_disclosed_fields(self):
        payload = {
            "status": "INVALID",
            "code": "CERT_SIGNATURE_INVALID",
            "certificateId": CERT_ID,
            "disclosureMode": "SELECTIVE_FIELDS",
            "disclosedFields": {"areaSquareMeters": "1250.50"},
        }
        report = normalize_verification_result(payload)
        self.assertEqual(report.status, "INVALID")
        self.assertEqual(report.disclosed_fields, {})
        self.assertIsNone(report.disclosure_mode)
        self.assertEqual(report.as_dict()["disclosedFields"], {})

    def test_unknown_status_is_invalid_and_discloses_nothing(self):
        payload = {
            "status": "TOTALLY_MADE_UP",
            "certificateId": CERT_ID,
            "disclosedFields": {"status": "ACTIVE"},
            "disclosureMode": "FULL_RECORD",
        }
        report = normalize_verification_result(payload)
        self.assertEqual(report.status, "INVALID")
        self.assertEqual(report.code, "VERIFICATION_STATUS_UNKNOWN")
        self.assertEqual(report.disclosed_fields, {})

    def test_verifier_unknown_lifecycle_stays_unknown_not_verified(self):
        # The /v2 verifier's deliberate answer (backend contract §4): no
        # complete authenticated lifecycle source exists. It must never be
        # displayed as verified or current, and must stay distinct from INVALID.
        payload = {
            "status": "UNKNOWN",
            "certificateId": CERT_ID,
            "lifecycle": {"status": "UNAUTHENTICATED"},
            "disclosureMode": "SELECTIVE_FIELDS",
            "disclosedFields": {"status": "ACTIVE"},
        }
        report = normalize_verification_result(payload)
        self.assertEqual(report.status, "UNKNOWN")
        self.assertFalse(report.is_verified)

    def test_revoked_is_never_current(self):
        payload = {"status": "REVOKED", "certificateId": CERT_ID}
        report = normalize_verification_result(payload)
        self.assertEqual(report.status, "REVOKED")
        self.assertFalse(report.is_verified)

    def test_verified_no_incident_check_is_never_promoted(self):
        payload = {
            "status": "VERIFIED_NO_INCIDENT_CHECK",
            "certificateId": CERT_ID,
            "disclosureMode": "SELECTIVE_FIELDS",
            "disclosedFields": {"status": "ACTIVE"},
        }
        report = normalize_verification_result(payload)
        self.assertEqual(report.status, "VERIFIED_NO_INCIDENT_CHECK")
        self.assertNotEqual(report.status, "VERIFIED")
        self.assertFalse(report.is_verified)

    def test_verifier_can_never_inject_an_explorer_link(self):
        payload = {
            "status": "VERIFIED",
            "certificateId": CERT_ID,
            "disclosedFields": {"status": "ACTIVE"},
            "explorerUrl": "https://evil.example.com/tx/abc",
        }
        report = normalize_verification_result(payload)
        self.assertIsNone(report.explorer_url)

    def test_non_object_response_becomes_invalid(self):
        report = normalize_verification_result(["not", "a", "dict"])
        self.assertEqual(report.status, "INVALID")
        self.assertEqual(report.disclosed_fields, {})

    def test_verified_status_keeps_disclosed_fields(self):
        payload = {
            "status": "VERIFIED",
            "certificateId": CERT_ID,
            "disclosureMode": "SELECTIVE_FIELDS",
            "disclosedFields": {"status": "ACTIVE", "areaSquareMeters": "1250.50"},
            "warnings": ["ok", 5],
        }
        report = normalize_verification_result(payload)
        self.assertEqual(report.status, "VERIFIED")
        self.assertEqual(dict(report.disclosed_fields), {"status": "ACTIVE", "areaSquareMeters": "1250.50"})
        self.assertEqual(report.warnings, ("ok",))

    def test_superseded_and_disputed_are_distinct_from_verified(self):
        for status in ("SUPERSEDED", "DISPUTED", "VERIFIED_HISTORICAL"):
            with self.subTest(status=status):
                report = normalize_verification_result({"status": status, "certificateId": CERT_ID})
                self.assertEqual(report.status, status)
                self.assertNotEqual(report.status, "VERIFIED")


class UrlTests(unittest.TestCase):
    def test_explorer_url_accepts_only_the_devnet_transaction_shape(self):
        good = "https://explorer.solana.com/tx/" + SIGNATURE + "?cluster=devnet"
        self.assertEqual(validate_explorer_url(good), good)

    def test_explorer_url_rejects_everything_else(self):
        for value in (
            None,
            5,
            "http://explorer.solana.com/tx/" + SIGNATURE + "?cluster=devnet",
            "https://evil.example.com/tx/" + SIGNATURE + "?cluster=devnet",
            "https://explorer.solana.com/tx/" + SIGNATURE + "?cluster=mainnet",
            "https://explorer.solana.com/tx/" + SIGNATURE + "?cluster=devnet&x=1",
            "https://explorer.solana.com/tx/short?cluster=devnet",
            "https://explorer.solana.com@" + "/tx/" + SIGNATURE + "?cluster=devnet",
            "javascript:alert(1)",
            "https://explorer.solana.com/tx/" + SIGNATURE + "?cluster=devnet#x",
        ):
            with self.subTest(value=value):
                self.assertIsNone(validate_explorer_url(value))

    def test_qr_payload_requires_a_loopback_url(self):
        good = f"http://127.0.0.1:8091/c/{CERT_ID}?h=" + "A" * 43
        cert_id, qr_hash = parse_qr_payload(good)
        self.assertEqual(cert_id, CERT_ID)
        self.assertEqual(qr_hash, "A" * 43)

    def test_qr_payload_rejects_off_loopback_and_aliased_hosts(self):
        for value in (
            "https://127.0.0.1:8091/c/" + CERT_ID + "?h=" + "A" * 43,
            "http://localhost:8091/c/" + CERT_ID + "?h=" + "A" * 43,
            "http://evil.example.com/c/" + CERT_ID + "?h=" + "A" * 43,
            "http://127.0.0.1/c/" + CERT_ID + "?h=" + "A" * 43,
            "http://127.0.0.1:8091/c/" + CERT_ID,
            "http://127.0.0.1:8091/c/" + CERT_ID + "?h=short",
            "http://127.0.0.1:8091/c/" + CERT_ID + "?h=" + "A" * 43 + "&x=1",
            "http://127.0.0.1:8091/other/" + CERT_ID + "?h=" + "A" * 43,
            "not a url",
            "",
        ):
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                parse_qr_payload(value)

    def test_qr_hash_decodes_to_the_same_hex_as_demo_api(self):
        digest = bytes(range(32))
        encoded = b64url(digest)
        self.assertEqual(qr_hash_to_hex(encoded), digest.hex())
        self.assertIsNone(qr_hash_to_hex("A" * 42))
        self.assertIsNone(qr_hash_to_hex("!!!!"))
        self.assertIsNone(qr_hash_to_hex(None))


class ProfileTests(unittest.TestCase):
    def test_local_profile_uses_the_fixed_demo_ports(self):
        profile = LiveDemoProfile.local()
        self.assertEqual(profile.demo_api_origin, "http://127.0.0.1:8090")
        self.assertEqual(profile.verifier_origin, "http://127.0.0.1:8080")
        self.assertEqual(profile.registry_id, "gov.registry.land")
        self.assertEqual(set(profile.services), {"demo-api", "verifier"})

    def test_off_loopback_endpoints_are_refused(self):
        for kwargs in (
            {"demo_api_origin": "http://example.com:8090", "verifier_origin": "http://127.0.0.1:8080"},
            {"demo_api_origin": "http://127.0.0.1:8090", "verifier_origin": "https://127.0.0.1:8080"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                LiveDemoProfile(**kwargs)

    def test_foreign_registry_is_refused(self):
        # ADR-0010: an explicitly configured isolated namespace is legitimate
        # (same deployed program, new config PDA). Only malformed ids refuse.
        with self.assertRaises(ValueError):
            LiveDemoProfile(
                demo_api_origin="http://127.0.0.1:8090",
                verifier_origin="http://127.0.0.1:8080",
                registry_id="not a registry id",
            )
        with self.assertRaises(ValueError):
            LiveDemoProfile(
                demo_api_origin="http://127.0.0.1:8090",
                verifier_origin="http://127.0.0.1:8080",
                registry_id="",
            )

    def test_isolated_namespace_is_accepted_and_labeled(self):
        profile = LiveDemoProfile(
            demo_api_origin="http://127.0.0.1:8090",
            verifier_origin="http://127.0.0.1:8080",
            registry_id="demo.synthetic.onelayer",
        )
        self.assertEqual(profile.registry_id, "demo.synthetic.onelayer")
        self.assertFalse(profile.is_legacy_registry)
        self.assertIn("Synthetic", profile.namespace_label)
        self.assertIn("Not the production registry", profile.namespace_detail)

    def test_legacy_namespace_is_the_default_and_is_labeled(self):
        profile = LiveDemoProfile(
            demo_api_origin="http://127.0.0.1:8090",
            verifier_origin="http://127.0.0.1:8080",
        )
        self.assertEqual(profile.registry_id, "gov.registry.land")
        self.assertTrue(profile.is_legacy_registry)
        self.assertIn("Legacy", profile.namespace_label)

    def test_configured_registry_id_reads_env_explicitly(self):
        self.assertEqual(configured_registry_id({}), "gov.registry.land")
        self.assertEqual(
            configured_registry_id({"ONELAYER_REGISTRY_ID": "demo.synthetic.onelayer"}),
            "demo.synthetic.onelayer",
        )
        with self.assertRaises(ValueError):
            configured_registry_id({"ONELAYER_REGISTRY_ID": "bad id!"})


# --------------------------------------------------------------------------
# hermetic legacy API adapters
# --------------------------------------------------------------------------


class ApiFixture(unittest.TestCase):
    """One loopback process speaking the legacy demo-api + verifier protocols."""

    def setUp(self):
        self.requests = []
        self.routes = {}
        self.verifier_routes = {}
        self.demo_origin = self._serve(self.routes, self.requests)
        self.verifier_origin = self._serve(self.verifier_routes, self.requests)
        self.profile = LiveDemoProfile(
            demo_api_origin=self.demo_origin,
            verifier_origin=self.verifier_origin,
        )
        self.root = Path(tempfile.mkdtemp(prefix="onelayer-live-demo-api-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        private = self.root / "onelayer-devnet-demo"
        os.mkdir(private, 0o700)
        os.chmod(private, 0o700)
        self.credential = private / "admin-credentials.json"
        self.credential.write_text(json.dumps({"operator": SECRET, "auditor": "x" * 16}))
        os.chmod(self.credential, 0o644)
        self.session = AdminSession(
            self.demo_origin, credential_path=self.credential, private_root=self.root
        )
        self.api = LiveDemoApi(self.profile, self.session)

    def _serve(self, routes, sink):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                fixture._dispatch(self, routes, sink)

            def do_POST(self):
                fixture._dispatch(self, routes, sink)

            def do_DELETE(self):
                fixture._dispatch(self, routes, sink)

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
        return f"http://127.0.0.1:{httpd.server_port}"

    def _dispatch(self, request, routes, sink):
        length = int(request.headers.get("content-length") or 0)
        sink.append(
            {
                "method": request.command,
                "path": request.path,
                "headers": {key.lower(): value for key, value in request.headers.items()},
                "body": request.rfile.read(length) if length else b"",
            }
        )
        key = (request.command, request.path.split("?")[0])
        handler = routes.get(key) or routes.get((request.command, "*"))
        if handler is None:
            request.send_response(404)
            request.send_header("content-type", "application/json")
            payload = json.dumps({"code": "NOT_FOUND"}).encode()
            request.send_header("content-length", str(len(payload)))
            request.end_headers()
            request.wfile.write(payload)
            return
        status, body, headers = handler(request)
        raw = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode()
        request.send_response(status)
        for name, value in (headers or {}).items():
            request.send_header(name, value)
        if not isinstance(body, (bytes, bytearray)):
            request.send_header("content-type", "application/json")
        request.send_header("content-length", str(len(raw)))
        request.end_headers()
        request.wfile.write(raw)

    def sign_in(self):
        self.routes[("POST", "/v1/admin/session")] = lambda request: (
            201,
            {
                "role": "operator",
                "username": "operator",
                "csrfToken": CSRF,
                "expiresAt": "2026-10-02T12:00:00Z",
                "permissions": [
                    "records.draft",
                    "publication.prepare",
                    "publication.submit",
                    "certificates.issue",
                    "certificates.read",
                ],
                "registryIds": ["gov.registry.land"],
                "deploymentRegistryId": "gov.registry.land",
            },
            {"set-cookie": f"onelayer_admin_session={SESSION_ID}; HttpOnly; Path=/"},
        )
        return self.api.sign_in()

    def last(self, method, path_suffix):
        matches = [
            item for item in self.requests
            if item["method"] == method and item["path"].split("?")[0].endswith(path_suffix)
        ]
        self.assertTrue(matches, f"no {method} request ending in {path_suffix}")
        return matches[-1]

    def install_verifier(self, status, payload):
        def handle(_request):
            return (200 if status != "INVALID" else 422), payload, None

        self.verifier_routes[("POST", "/v1/verify")] = handle


class RecordAdapterTests(ApiFixture):
    def test_create_record_version_posts_status_cadastral_and_area(self):
        self.sign_in()
        self.routes[("POST", "/v1/admin/records")] = lambda request: (
            201,
            {
                "internalRecordId": "SYNTHETIC-42",
                "recordVersion": "1",
                "status": "ACTIVE",
                "origin": "ADMIN_UI",
            },
            None,
        )
        version = self.api.create_record_version(
            "SYNTHETIC-42",
            status="ACTIVE",
            cadastral_number="01-004-0123-045",
            area_square_meters="1250.50",
        )
        self.assertIsInstance(version, RecordVersion)
        self.assertEqual(version.record_version, "1")
        sent = json.loads(self.last("POST", "/v1/admin/records")["body"])
        self.assertEqual(sent["internalRecordId"], "SYNTHETIC-42")
        self.assertEqual(sent["status"], "ACTIVE")
        self.assertEqual(
            sent["fields"],
            {
                "status": "ACTIVE",
                "cadastralNumber": "01-004-0123-045",
                "areaSquareMeters": "1250.50",
            },
        )
        self.assertNotIn(SECRET, json.dumps(sent))

    def test_second_version_of_the_same_record_is_a_new_version(self):
        self.sign_in()
        payloads = iter(
            [
                {"internalRecordId": "SYNTHETIC-7", "recordVersion": "1", "status": "ACTIVE", "origin": "ADMIN_UI"},
                {"internalRecordId": "SYNTHETIC-7", "recordVersion": "2", "status": "DISPUTED", "origin": "ADMIN_UI"},
            ]
        )

        def handle(_request):
            return 201, next(payloads), None

        self.routes[("POST", "/v1/admin/records")] = handle
        first = self.api.create_record_version(
            "SYNTHETIC-7", status="ACTIVE", cadastral_number="A-1", area_square_meters="10.00"
        )
        second = self.api.create_record_version(
            "SYNTHETIC-7", status="DISPUTED", cadastral_number="A-1", area_square_meters="20.00"
        )
        self.assertEqual((first.record_version, second.record_version), ("1", "2"))

    def test_invalid_status_and_area_are_rejected_before_any_request(self):
        self.sign_in()
        before = len(self.requests)
        for kwargs in (
            {"status": "NOT_A_STATUS", "cadastral_number": "A", "area_square_meters": "1.00"},
            {"status": "ACTIVE", "cadastral_number": "A", "area_square_meters": "1.0"},
            {"status": "ACTIVE", "cadastral_number": "A", "area_square_meters": "1.000"},
            {"status": "ACTIVE", "cadastral_number": "A", "area_square_meters": "x"},
            {"status": "ACTIVE", "cadastral_number": "", "area_square_meters": "1.00"},
            {"status": "ACTIVE", "cadastral_number": "A", "area_square_meters": "1.00",
             "extra_fields": {"bad path": "x"}},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ProtocolError):
                self.api.create_record_version("SYNTHETIC-1", **kwargs)
        self.assertEqual(len(self.requests), before)

    def test_list_records_is_bounded_and_typed(self):
        self.sign_in()
        self.routes[("GET", "/v1/admin/records")] = lambda request: (
            200,
            {
                "schemaId": "land-registry-v1",
                "records": [
                    {
                        "internalRecordId": "SYNTHETIC-1",
                        "recordVersion": "3",
                        "status": "ACTIVE",
                        "origin": "ADMIN_UI",
                        "fields": [
                            {"path": "cadastralNumber", "type": "text", "value": "A-1"},
                            {"path": "status", "type": "text", "value": "ACTIVE"},
                        ],
                    }
                ],
            },
            None,
        )
        records = self.api.list_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].record_version, "3")
        self.assertEqual(
            dict(records[0].fields),
            {"cadastralNumber": "A-1", "status": "ACTIVE"},
        )

    def test_list_records_rejects_the_wrong_fields_shape(self):
        self.sign_in()
        for fields in (
            {"cadastralNumber": "A-1"},
            [{"value": "A-1"}],
            [{"path": "bad path", "value": "x"}],
            [{"path": "ok", "value": {"nested": 1}}],
            [{"path": "dup", "value": "a"}, {"path": "dup", "value": "b"}],
            "fields",
        ):
            with self.subTest(fields=fields):
                self.routes[("GET", "/v1/admin/records")] = lambda request: (
                    200,
                    {
                        "schemaId": "land-registry-v1",
                        "records": [
                            {
                                "internalRecordId": "SYNTHETIC-1",
                                "recordVersion": "1",
                                "status": "ACTIVE",
                                "origin": "ADMIN_UI",
                                "fields": fields,
                            }
                        ],
                    },
                    None,
                )
                with self.assertRaises(ProtocolError):
                    self.api.list_records()


class PublishAdapterTests(ApiFixture):
    def review(self, state="SIMULATED", **overrides):
        """The real demo-api intent envelope (intentResponse + batchReview).

        Shaped exactly like apps/demo-api/src/admin.ts produces it: accounts are
        ``{address, role}`` objects, counts and indexes are numbers, decimal ids
        are strings, and the review carries the signer-facing fields.
        """
        payload = {
            "intentId": INTENT_ID,
            "state": state,
            "batchSequence": "2",
            "intentHash": INTENT_HASH,
            "review": {
                "registryId": "gov.registry.land",
                "batchSequence": "2",
                "registryVersion": "3",
                "cursorStart": "10",
                "cursorEnd": "13",
                "leafCount": 3,
                "merkleRoot": "aa" * 32,
                "manifestHash": "bb" * 32,
                "previousAnchorHash": "cc" * 32,
                "createdAt": "2026-10-02T10:00:00Z",
                "cluster": "solana:devnet",
                "programId": PROGRAM_ID,
                "configPda": CONFIG_PDA,
                "rolePda": ROLE_PDA,
                "segmentPda": SEGMENT_PDA,
                "segmentIndex": 2,
                "dayUtc": 20261006,
                "feePayer": OPERATOR,
                "accounts": [
                    {"address": OPERATOR, "role": "signer-writable"},
                    {"address": CONFIG_PDA, "role": "readonly"},
                    {"address": ROLE_PDA, "role": "readonly"},
                    {"address": SEGMENT_PDA, "role": "writable"},
                ],
                "instructionData": INSTRUCTION_DATA,
                "transactionBase64": TRANSACTION_BASE64,
                "simulation": {"ok": True, "error": None, "unitsConsumed": 1200},
                "records": [
                    {
                        "internalRecordId": "SYNTHETIC-1",
                        "recordVersion": "1",
                        "recordIdCommitment": "ee" * 32,
                        "fieldRoot": "ff" * 32,
                        "recordCommitment": "ab" * 32,
                        "batchLeafHash": "cd" * 32,
                        "leafIndex": 0,
                        "disclosedFields": {
                            "status": "ACTIVE",
                            "areaSquareMeters": "1250.50",
                        },
                    }
                ],
            },
            "recentBlockhash": RECENT_BLOCKHASH,
            "lastValidBlockHeight": "123456",
            "expiresAt": "2026-10-02T10:01:30Z",
            "transactionSignature": None,
            "anchorSlot": None,
            "certificateId": None,
            "failureCode": None,
            "simulationLogs": ["Program log: synthetic demo batch"],
            "replayed": False,
        }
        payload.update(overrides)
        return payload

    def test_prepare_publish_sends_idempotency_key_and_returns_the_plan(self):
        self.sign_in()
        self.routes[("POST", "/v1/admin/publish-intents")] = lambda request: (
            201,
            self.review(),
            None,
        )
        review = self.api.prepare_publish(OPERATOR, idempotency_key="demo-live-intent-0001")
        self.assertIsInstance(review, PublishReview)
        self.assertIsInstance(review.plan, PublishPlan)
        self.assertEqual(review.plan.cluster, "solana:devnet")
        self.assertEqual(review.plan.fee_payer, OPERATOR)
        self.assertEqual(review.plan.merkle_root, "aa" * 32)
        self.assertTrue(review.plan.simulation_ok)
        self.assertEqual(review.plan.units_consumed, 1200)
        self.assertEqual(review.state, "SIMULATED")
        request = self.last("POST", "/v1/admin/publish-intents")
        self.assertEqual(request["headers"].get("idempotency-key"), "demo-live-intent-0001")
        self.assertEqual(json.loads(request["body"]), {"operator": OPERATOR, "cluster": "solana:devnet"})
        self.assertNotIn(SECRET, json.dumps(review.as_dict()))

    def test_prepare_publish_rejects_foreign_cluster_and_bad_keys(self):
        self.sign_in()
        before = len(self.requests)
        for operator, kwargs in (
            (OPERATOR, {"idempotency_key": "demo-live-intent-0001", "cluster": "solana:mainnet"}),
            (OPERATOR, {"idempotency_key": "short"}),
            ("not-a-pubkey", {"idempotency_key": "demo-live-intent-0001"}),
        ):
            with self.subTest(operator=operator, kwargs=kwargs), self.assertRaises(ProtocolError):
                self.api.prepare_publish(operator, **kwargs)
        self.assertEqual(len(self.requests), before)

    def test_signature_submission_forwards_the_signed_wire_transaction(self):
        self.sign_in()
        signed = base64.b64encode(b"\x01" * 64).decode()
        self.routes[("POST", f"/v1/admin/publish-intents/{INTENT_ID}/signature")] = lambda request: (
            200,
            self.review(state="SUBMITTED", transactionSignature=SIGNATURE),
            None,
        )
        review = self.api.submit_signature(INTENT_ID, signed)
        self.assertEqual(review.state, "SUBMITTED")
        self.assertEqual(review.transaction_signature, SIGNATURE)
        request = self.last("POST", "/signature")
        self.assertEqual(json.loads(request["body"]), {"signedTransactionBase64": signed})

    def test_signature_submission_rejects_malformed_payloads(self):
        self.sign_in()
        before = len(self.requests)
        for value in ("", "!!!!", "a" * 9000, None, 5):
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                self.api.submit_signature(INTENT_ID, value)
        self.assertEqual(len(self.requests), before)

    def test_reconciliation_reports_finalized(self):
        self.sign_in()
        self.routes[("POST", f"/v1/admin/publish-intents/{INTENT_ID}/reconciliation")] = lambda request: (
            200,
            self.review(state="FINALIZED", transactionSignature=SIGNATURE, anchorSlot="412267854"),
            None,
        )
        review = self.api.reconcile(INTENT_ID)
        self.assertEqual(review.state, "FINALIZED")
        self.assertEqual(review.anchor_slot, "412267854")

    def test_certificate_issuance_returns_explorer_url_and_disclosure(self):
        self.sign_in()
        self.routes[("POST", f"/v1/admin/publish-intents/{INTENT_ID}/certificate")] = lambda request: (
            201,
            {
                "intentId": INTENT_ID,
                "state": "ISSUED",
                "certificateId": CERT_ID,
                "certificateHash": "ab" * 32,
                "qrUrl": f"http://127.0.0.1:8091/c/{CERT_ID}?h=" + "A" * 43,
                "transactionSignature": SIGNATURE,
                "anchorSlot": "412267854",
                "explorerUrl": f"https://explorer.solana.com/tx/{SIGNATURE}?cluster=devnet",
                "disclosureMode": "SELECTIVE_FIELDS",
                "disclosedPaths": ["status", "areaSquareMeters"],
                "fieldCount": 2,
            },
            None,
        )
        issued = self.api.issue_certificate(
            INTENT_ID, "SYNTHETIC-1", disclosed_paths=["status", "areaSquareMeters"]
        )
        self.assertIsInstance(issued, IssuedCertificate)
        self.assertEqual(issued.disclosure_mode, "SELECTIVE_FIELDS")
        self.assertEqual(issued.disclosed_paths, ("status", "areaSquareMeters"))
        self.assertEqual(issued.field_count, 2)
        self.assertEqual(
            issued.explorer_url, f"https://explorer.solana.com/tx/{SIGNATURE}?cluster=devnet"
        )
        request = self.last("POST", "/certificate")
        self.assertEqual(
            json.loads(request["body"]),
            {"internalRecordId": "SYNTHETIC-1", "disclosedPaths": ["status", "areaSquareMeters"]},
        )

    def test_certificate_issuance_rejects_invalid_disclosure_paths(self):
        self.sign_in()
        before = len(self.requests)
        for paths in ([], ["bad path"], ["status", "status"], ["ok", ""]):
            with self.subTest(paths=paths), self.assertRaises(ProtocolError):
                self.api.issue_certificate(INTENT_ID, "SYNTHETIC-1", disclosed_paths=paths)
        self.assertEqual(len(self.requests), before)

    def test_server_refusal_surfaces_the_sanitized_code(self):
        self.sign_in()
        self.routes[("POST", f"/v1/admin/publish-intents/{INTENT_ID}/certificate")] = lambda request: (
            409,
            {"code": "ANCHOR_NOT_FINALIZED"},
            None,
        )
        with self.assertRaises(ApiRefusal) as raised:
            self.api.issue_certificate(INTENT_ID, "SYNTHETIC-1")
        self.assertEqual(raised.exception.status, 409)
        self.assertEqual(raised.exception.code, "ANCHOR_NOT_FINALIZED")

    # -- typed review contract (H2/M1) -----------------------------------

    def test_plan_retains_every_signer_field_with_correct_types(self):
        self.sign_in()
        self.routes[("POST", "/v1/admin/publish-intents")] = lambda request: (201, self.review(), None)
        review = self.api.prepare_publish(OPERATOR, idempotency_key="demo-live-intent-0001")
        plan = review.plan
        self.assertEqual(review.intent_hash, INTENT_HASH)
        self.assertEqual(plan.instruction_data, INSTRUCTION_DATA)
        self.assertEqual((plan.cursor_start, plan.cursor_end), ("10", "13"))
        self.assertEqual(plan.registry_id, "gov.registry.land")
        self.assertEqual(plan.batch_sequence, "2")
        self.assertEqual(plan.registry_version, "3")
        self.assertIsInstance(plan.leaf_count, int)
        self.assertEqual(plan.leaf_count, 3)
        self.assertIsInstance(plan.segment_index, int)
        self.assertEqual(plan.segment_index, 2)
        self.assertIsInstance(plan.day_utc, int)
        self.assertEqual(plan.day_utc, 20261006)
        self.assertIsInstance(plan.units_consumed, int)
        for name in ("batch_sequence", "registry_version", "cursor_start", "cursor_end"):
            self.assertIsInstance(getattr(plan, name), str)

    def test_day_utc_is_the_real_yyyy_mm_dd_ledger_day(self):
        """The ledger day is `utc_day`'s YYYYMMDD, from the parser to the signer.

        Compatibility: earlier fixtures used ordinal day numbers (20231) that
        this parser used to accept but the registry program would reject with
        `WrongLedgerDay`. The canonical contract is a real UTC calendar day, so
        the fixtures moved to 20261006 and only calendar days are accepted.
        """
        self.sign_in()

        def review_with(day):
            body = self.review()
            body["review"]["dayUtc"] = day
            return lambda request: (201, body, None)

        for day in (20261006, 19700101, 20240229, 20261231, 99991231):
            with self.subTest(day=day):
                self.routes[("POST", "/v1/admin/publish-intents")] = review_with(day)
                review = self.api.prepare_publish(OPERATOR, idempotency_key="demo-live-intent-0001")
                self.assertEqual(review.plan.day_utc, day)
                self.assertEqual(review.signer_request_fields()["intent"]["dayUtc"], day)

        for day in (20231, 20665, 100_000, 19700100, 99991232, 20261301, 20260230, 21000229):
            with self.subTest(day=day):
                self.routes[("POST", "/v1/admin/publish-intents")] = review_with(day)
                with self.assertRaises(ProtocolError):
                    self.api.prepare_publish(OPERATOR, idempotency_key="demo-live-intent-0001")

    def test_accounts_review_objects_are_typed(self):
        self.sign_in()
        self.routes[("POST", "/v1/admin/publish-intents")] = lambda request: (201, self.review(), None)
        review = self.api.prepare_publish(OPERATOR, idempotency_key="demo-live-intent-0001")
        accounts = review.plan.accounts
        self.assertEqual(len(accounts), 4)
        self.assertEqual(accounts[0].address, OPERATOR)
        self.assertEqual(accounts[0].role, "signer-writable")
        self.assertEqual(accounts[3].role, "writable")
        self.assertEqual(
            review.plan.as_dict()["accounts"][0],
            {"address": OPERATOR, "role": "signer-writable"},
        )

    def test_bare_account_addresses_keep_the_validated_string_fallback(self):
        self.sign_in()
        body = self.review()
        body["review"]["accounts"] = [OPERATOR, CONFIG_PDA]
        self.routes[("POST", "/v1/admin/publish-intents")] = lambda request: (201, body, None)
        review = self.api.prepare_publish(OPERATOR, idempotency_key="demo-live-intent-0001")
        self.assertEqual(
            [account.role for account in review.plan.accounts],
            ["unspecified", "unspecified"],
        )
        self.assertEqual(review.plan.accounts[1].address, CONFIG_PDA)

    def test_malformed_accounts_fail_closed(self):
        self.sign_in()
        for accounts in (
            [],
            ["not-a-pubkey"],
            [{"address": OPERATOR, "role": "admin"}],
            [{"address": OPERATOR}],
            [{"role": "signer"}],
            [{"address": OPERATOR, "role": "signer", "extra": 1}],
            OPERATOR,
            [{"address": OPERATOR, "role": "signer"}, None],
        ):
            with self.subTest(accounts=accounts):
                body = self.review()
                body["review"]["accounts"] = accounts
                self.routes[("POST", "/v1/admin/publish-intents")] = lambda request: (201, body, None)
                with self.assertRaises(ProtocolError):
                    self.api.prepare_publish(OPERATOR, idempotency_key="demo-live-intent-0001")

    def test_signer_request_fields_is_the_exact_a1_contract(self):
        self.sign_in()
        self.routes[("POST", "/v1/admin/publish-intents")] = lambda request: (201, self.review(), None)
        review = self.api.prepare_publish(OPERATOR, idempotency_key="demo-live-intent-0001")
        request = review.signer_request_fields()
        self.assertIs(request["approved"], False)
        self.assertEqual(
            set(request),
            {
                "approved",
                "intentId",
                "cluster",
                "intentHash",
                "transactionBase64",
                "instructionData",
                "intent",
            },
        )
        self.assertNotIn("messageBase64", request)
        intent = request["intent"]
        self.assertEqual(
            set(intent),
            {
                "registryId",
                "batchSequence",
                "registryVersion",
                "cursorStart",
                "cursorEnd",
                "leafCount",
                "merkleRootHex",
                "manifestHashHex",
                "previousAnchorHashHex",
                "programId",
                "configPda",
                "rolePda",
                "segmentPda",
                "segmentIndex",
                "dayUtc",
                "feePayer",
                "recentBlockhash",
                "lastValidBlockHeight",
            },
        )
        self.assertEqual(request["intentHash"], INTENT_HASH)
        self.assertEqual(request["instructionData"], INSTRUCTION_DATA)
        self.assertEqual(request["transactionBase64"], TRANSACTION_BASE64)
        self.assertEqual(request["intentId"], INTENT_ID)
        self.assertEqual(request["cluster"], "solana:devnet")
        self.assertEqual(intent["merkleRootHex"], "aa" * 32)
        self.assertEqual(intent["manifestHashHex"], "bb" * 32)
        self.assertEqual(intent["previousAnchorHashHex"], "cc" * 32)
        self.assertEqual(intent["feePayer"], OPERATOR)
        self.assertEqual(intent["programId"], PROGRAM_ID)
        self.assertIsInstance(intent["leafCount"], int)
        self.assertIsInstance(intent["segmentIndex"], int)
        self.assertIsInstance(intent["dayUtc"], int)
        self.assertEqual(intent["leafCount"], 3)
        self.assertEqual(intent["segmentIndex"], 2)
        self.assertEqual(intent["dayUtc"], 20261006)
        for key in ("batchSequence", "registryVersion", "cursorStart", "cursorEnd", "lastValidBlockHeight"):
            self.assertIsInstance(intent[key], str)
        self.assertEqual(intent["lastValidBlockHeight"], "123456")
        self.assertEqual(intent["recentBlockhash"], RECENT_BLOCKHASH)
        json.dumps(request)

    def test_signer_request_fields_requires_the_explicit_approval_marker(self):
        self.sign_in()
        self.routes[("POST", "/v1/admin/publish-intents")] = lambda request: (201, self.review(), None)
        review = self.api.prepare_publish(OPERATOR, idempotency_key="demo-live-intent-0001")
        self.assertIs(review.signer_request_fields()["approved"], False)
        self.assertIs(review.signer_request_fields(approved=False)["approved"], False)
        self.assertIs(review.signer_request_fields(approved=True)["approved"], True)
        with self.assertRaises(ProtocolError):
            review.signer_request_fields(approved="yes")
        with self.assertRaises(ProtocolError):
            review.signer_request_fields(approved=1)

    # -- simulation failure (M2) -----------------------------------------

    def simulation_failed_body(self):
        body = self.review(state="SIMULATION_FAILED")
        body["review"] = dict(
            body["review"],
            simulation={"ok": False, "error": "synthetic simulation failure", "unitsConsumed": 0},
        )
        return body

    def test_simulation_failed_review_is_preserved_but_not_approvable(self):
        self.sign_in()
        self.routes[("POST", "/v1/admin/publish-intents")] = lambda request: (
            422, self.simulation_failed_body(), None,
        )
        review = self.api.prepare_publish(OPERATOR, idempotency_key="demo-live-intent-0001")
        self.assertEqual(review.state, "SIMULATION_FAILED")
        self.assertFalse(review.plan.simulation_ok)
        self.assertEqual(review.plan.simulation_error, "synthetic simulation failure")
        self.assertEqual(review.plan.units_consumed, 0)
        self.assertFalse(review.can_approve)
        with self.assertRaises(ProtocolError):
            review.signer_request_fields()
        with self.assertRaises(ProtocolError):
            review.signer_request_fields(approved=True)

    def test_refusal_echo_drops_logs_and_secret_shaped_keys(self):
        self.sign_in()
        body = self.simulation_failed_body()
        body["simulationLogs"] = ["Program log: synthetic", "super-secret-rpc-log"]
        body["review"]["csrfToken"] = CSRF
        body["review"]["issuerSecret"] = "do-not-retain"
        self.routes[("POST", "/v1/admin/publish-intents")] = lambda request: (422, body, None)
        with self.assertRaises(ApiRefusal) as raised:
            self.session.request_json(
                "POST",
                "/v1/admin/publish-intents",
                json_body={"operator": OPERATOR, "cluster": "solana:devnet"},
                idempotency_key="demo-live-intent-0001",
            )
        error = raised.exception
        self.assertIsInstance(error.payload, dict)
        echoed = json.dumps(error.payload)
        self.assertNotIn("simulationLogs", error.payload)
        self.assertNotIn("super-secret-rpc-log", echoed)
        self.assertNotIn("do-not-retain", echoed)
        self.assertNotIn("csrfToken", echoed)
        self.assertNotIn(SECRET, echoed)
        self.assertNotIn(CSRF, echoed)
        self.assertNotIn("simulationLogs", repr(error))
        self.assertNotIn("super-secret-rpc-log", repr(error))
        self.assertNotIn("super-secret-rpc-log", str(error))
        self.assertEqual(error.payload["state"], "SIMULATION_FAILED")

    def test_422_without_a_review_stays_an_api_refusal(self):
        self.sign_in()
        self.routes[("POST", "/v1/admin/publish-intents")] = lambda request: (
            422, {"code": "SIMULATION_FAILED"}, None,
        )
        with self.assertRaises(ApiRefusal) as raised:
            self.api.prepare_publish(OPERATOR, idempotency_key="demo-live-intent-0001")
        self.assertEqual(raised.exception.code, "SIMULATION_FAILED")

    # -- fail-closed review parsing --------------------------------------

    def test_unknown_or_malformed_core_review_fails_closed(self):
        self.sign_in()
        broken = []

        def with_review(label, mutate):
            body = self.review()
            mutate(body)
            broken.append((label, body))

        def drop_review_key(key):
            def mutate(body):
                body["review"].pop(key, None)
            return mutate

        def set_review(key, value):
            def mutate(body):
                body["review"][key] = value
            return mutate

        def set_simulation(key, value):
            def mutate(body):
                body["review"]["simulation"][key] = value
            return mutate

        with_review("no intentHash", lambda body: body.pop("intentHash"))
        with_review("no recentBlockhash", lambda body: body.pop("recentBlockhash"))
        with_review("no lastValidBlockHeight", lambda body: body.pop("lastValidBlockHeight"))
        with_review("no instructionData", drop_review_key("instructionData"))
        with_review("no cursorStart", drop_review_key("cursorStart"))
        with_review("no cursorEnd", drop_review_key("cursorEnd"))
        with_review("no registryId", drop_review_key("registryId"))
        with_review("no simulation", drop_review_key("simulation"))
        with_review("no accounts", drop_review_key("accounts"))
        with_review("leafCount as string", set_review("leafCount", "3"))
        with_review("leafCount zero", set_review("leafCount", 0))
        with_review("segmentIndex as string", set_review("segmentIndex", "2"))
        with_review("segmentIndex out of range", set_review("segmentIndex", 9))
        with_review("dayUtc as string", set_review("dayUtc", "20261006"))
        with_review("dayUtc ordinal legacy fixture", set_review("dayUtc", 20231))
        with_review("dayUtc before the epoch day", set_review("dayUtc", 19700100))
        with_review("dayUtc out of range", set_review("dayUtc", 100_000))
        with_review("dayUtc over YYYYMMDD", set_review("dayUtc", 99991232))
        with_review("dayUtc impossible month", set_review("dayUtc", 20261301))
        with_review("dayUtc impossible date", set_review("dayUtc", 20260230))
        with_review("unitsConsumed as string", set_simulation("unitsConsumed", "1200"))
        with_review("simulation.ok as string", set_review("simulation", {"ok": "true"}))
        with_review("merkleRoot not hex", set_review("merkleRoot", "zz" * 32))
        with_review("instructionData wrong size", set_review("instructionData", "AAAA"))
        with_review("registryId not the demo registry", set_review("registryId", "other.registry"))
        with_review("cluster mainnet", set_review("cluster", "solana:mainnet"))
        with_review("cursorStart leading zeros", set_review("cursorStart", "007"))
        with_review("cursorStart over 20 digits", set_review("cursorStart", "1" * 21))

        for label, body in broken:
            with self.subTest(label=label):
                self.routes[("POST", "/v1/admin/publish-intents")] = lambda request: (201, body, None)
                with self.assertRaises(ProtocolError):
                    self.api.prepare_publish(OPERATOR, idempotency_key="demo-live-intent-0001")

    def test_inconsistent_top_level_batch_sequence_fails_closed(self):
        self.sign_in()
        body = self.review()
        body["batchSequence"] = "3"
        self.routes[("POST", "/v1/admin/publish-intents")] = lambda request: (201, body, None)
        with self.assertRaises(ProtocolError):
            self.api.prepare_publish(OPERATOR, idempotency_key="demo-live-intent-0001")


class CertificateAdapterTests(ApiFixture):
    def package_document(self, *, tamper=False):
        package, digest = build_package(tamper="area" if tamper else None)
        return package, digest, {
            "package_base64url": b64url(package),
            "certificateHash": digest,
            "qrUrl": f"http://127.0.0.1:8091/c/{CERT_ID}?h=" + b64url(bytes.fromhex(digest)),
        }

    def test_package_fetch_pins_the_qr_hash_and_verifies_it(self):
        self.sign_in()
        package, digest, document = self.package_document()
        self.routes[("GET", f"/v1/certificates/{CERT_ID}/package")] = lambda request: (
            200, document, None,
        )
        fetched = self.api.get_certificate_package(CERT_ID, qr_hash=b64url(bytes.fromhex(digest)))
        self.assertEqual(fetched.package_bytes, package)
        self.assertEqual(fetched.hash_result.verdict, HashVerdict.MATCH)
        self.assertTrue(fetched.hash_result.validated)
        self.assertEqual(fetched.hash_result.expected_source, "qr")
        self.assertIn("?h=", self.last("GET", "/package")["path"])

    def test_package_fetch_reports_qr_hash_mismatch_from_the_server(self):
        self.sign_in()
        self.routes[("GET", f"/v1/certificates/{CERT_ID}/package")] = lambda request: (
            422, {"code": "QR_HASH_MISMATCH"}, None,
        )
        with self.assertRaises(ApiRefusal) as raised:
            self.api.get_certificate_package(CERT_ID, qr_hash="A" * 43)
        self.assertEqual(raised.exception.code, "QR_HASH_MISMATCH")

    def test_metadata_is_typed_and_explorer_url_is_validated(self):
        self.sign_in()
        self.routes[("GET", f"/v1/certificates/{CERT_ID}/metadata")] = lambda request: (
            200,
            {
                "certificateId": CERT_ID,
                "registryId": "gov.registry.land",
                "cluster": "solana:devnet",
                "status": "ACTIVE",
                "issuedAt": "2026-10-02T10:00:00Z",
                "recordVersion": "2",
                "certificateHash": "ab" * 32,
                "qrUrl": f"http://127.0.0.1:8091/c/{CERT_ID}?h=" + "A" * 43,
                "disclosureMode": "SELECTIVE_FIELDS",
                "disclosedPaths": ["status", "areaSquareMeters"],
                "batchSequence": "2",
                "anchorSlot": "412267854",
                "transactionSignature": SIGNATURE,
                "merkleRoot": "aa" * 32,
                "manifestHash": "bb" * 32,
                "explorerUrl": f"https://explorer.solana.com/tx/{SIGNATURE}?cluster=devnet",
            },
            None,
        )
        metadata = self.api.get_certificate_metadata(CERT_ID)
        self.assertIsInstance(metadata, CertificateMetadata)
        self.assertEqual(metadata.explorer_url, f"https://explorer.solana.com/tx/{SIGNATURE}?cluster=devnet")
        self.assertEqual(metadata.disclosed_paths, ("status", "areaSquareMeters"))

    def test_metadata_drops_an_off_loopback_explorer_link(self):
        self.sign_in()
        self.routes[("GET", f"/v1/certificates/{CERT_ID}/metadata")] = lambda request: (
            200,
            {
                "certificateId": CERT_ID,
                "registryId": "gov.registry.land",
                "cluster": "solana:devnet",
                "status": "ACTIVE",
                "issuedAt": "2026-10-02T10:00:00Z",
                "recordVersion": "2",
                "certificateHash": "ab" * 32,
                "qrUrl": f"http://127.0.0.1:8091/c/{CERT_ID}?h=" + "A" * 43,
                "disclosureMode": "FULL_RECORD",
                "disclosedPaths": ["status"],
                "batchSequence": "2",
                "anchorSlot": "412267854",
                "transactionSignature": SIGNATURE,
                "merkleRoot": "aa" * 32,
                "manifestHash": "bb" * 32,
                "explorerUrl": "javascript:alert(1)",
            },
            None,
        )
        self.assertIsNone(self.api.get_certificate_metadata(CERT_ID).explorer_url)

    def test_qr_image_is_validated_as_png(self):
        self.sign_in()
        self.routes[("GET", f"/v1/qr/{CERT_ID}.png")] = lambda request: (
            200, b"\x89PNG\r\n\x1a\n" + b"0" * 64, {"content-type": "image/png"},
        )
        image = self.api.get_qr_image(CERT_ID, fmt="png")
        self.assertTrue(image.startswith(b"\x89PNG"))
        with self.assertRaises(ProtocolError):
            self.api.get_qr_image(CERT_ID, fmt="gif")

    def test_lifecycle_carries_the_profile_registry_id(self):
        self.sign_in()
        self.routes[("GET", f"/v1/certificates/{CERT_ID}/lifecycle")] = lambda request: (
            200,
            {"registryId": "gov.registry.land", "currentRecordVersion": "3",
             "certificateStatus": "SUPERSEDED"},
            None,
        )
        lifecycle = self.api.get_certificate_lifecycle(CERT_ID)
        self.assertEqual(lifecycle["certificateStatus"], "SUPERSEDED")
        self.assertIn("registryId=gov.registry.land", self.last("GET", "/lifecycle")["path"])


class VerifyFlowTests(ApiFixture):
    def test_healthy_package_verifies_and_exposes_only_disclosed_fields(self):
        self.sign_in()
        package, digest = build_package()
        self.install_verifier(
            "VERIFIED",
            {
                "status": "VERIFIED",
                "certificateId": CERT_ID,
                "batchSequence": "2",
                "solanaSlot": "412267854",
                "disclosureMode": "SELECTIVE_FIELDS",
                "disclosedFields": {"status": "ACTIVE", "areaSquareMeters": "1250.50"},
                "warnings": [],
            },
        )
        self.routes[("GET", f"/v1/certificates/{CERT_ID}/metadata")] = lambda request: (
            200,
            {"certificateId": CERT_ID, "explorerUrl": f"https://explorer.solana.com/tx/{SIGNATURE}?cluster=devnet"},
            None,
        )
        report = self.api.verify_package(package, expected_hash_hex=digest)
        self.assertEqual(report.status, "VERIFIED")
        self.assertTrue(report.is_verified)
        self.assertEqual(
            dict(report.disclosed_fields), {"status": "ACTIVE", "areaSquareMeters": "1250.50"}
        )
        self.assertEqual(report.explorer_url, f"https://explorer.solana.com/tx/{SIGNATURE}?cluster=devnet")
        self.assertEqual(report.package_hash.verdict, HashVerdict.MATCH)

    def test_tampered_area_package_fails_the_hash_check_without_the_verifier(self):
        self.sign_in()
        original, original_hash = build_package()
        tampered, tampered_hash = build_package(tamper="area")
        self.assertNotEqual(original_hash, tampered_hash)
        called = []
        self.verifier_routes[("POST", "/v1/verify")] = lambda request: (
            called.append(True) or (200, {"status": "VERIFIED"}, None)
        )
        report = self.api.verify_package(tampered, expected_hash_hex=original_hash)
        self.assertEqual(report.status, "INVALID")
        self.assertEqual(report.code, "QR_HASH_MISMATCH")
        self.assertEqual(report.disclosed_fields, {})
        self.assertEqual(report.package_hash.verdict, HashVerdict.MISMATCH)
        self.assertEqual(report.package_hash.computed_hash_hex, tampered_hash)
        self.assertEqual(called, [])

    def test_relabelled_tamper_is_still_detected(self):
        self.sign_in()
        tampered, tampered_hash = build_package(tamper="area")
        self.verifier_routes[("POST", "/v1/verify")] = lambda request: (
            200, {"status": "VERIFIED", "certificateId": CERT_ID,
                  "disclosedFields": {"areaSquareMeters": "9999.99"}}, None,
        )
        # The attacker also updates the "official" hash to match the tampering.
        report = self.api.verify_package(tampered, expected_hash_hex=tampered_hash)
        # Local hash check passes (it matches), so the verifier decides.
        self.assertEqual(report.package_hash.verdict, HashVerdict.MATCH)

    def test_invalid_verifier_verdict_clears_disclosed_fields(self):
        self.sign_in()
        package, digest = build_package()
        self.install_verifier(
            "INVALID",
            {
                "status": "INVALID",
                "code": "CERT_SIGNATURE_INVALID",
                "certificateId": CERT_ID,
                "batchSequence": "2",
                "disclosureMode": "SELECTIVE_FIELDS",
                "disclosedFields": {"areaSquareMeters": "1250.50"},
                "warnings": [],
            },
        )
        report = self.api.verify_package(package, expected_hash_hex=digest)
        self.assertEqual(report.status, "INVALID")
        self.assertEqual(report.code, "CERT_SIGNATURE_INVALID")
        self.assertEqual(report.disclosed_fields, {})
        self.assertIsNone(report.disclosure_mode)
        self.assertNotIn("areaSquareMeters", json.dumps(report.as_dict()["disclosedFields"]))

    def test_verified_no_incident_check_is_not_promoted(self):
        self.sign_in()
        package, digest = build_package()
        self.install_verifier(
            "VERIFIED_NO_INCIDENT_CHECK",
            {
                "status": "VERIFIED_NO_INCIDENT_CHECK",
                "certificateId": CERT_ID,
                "batchSequence": "2",
                "disclosureMode": "SELECTIVE_FIELDS",
                "disclosedFields": {"status": "ACTIVE"},
                "warnings": ["incident index unavailable"],
            },
        )
        report = self.api.verify_package(package, expected_hash_hex=digest)
        self.assertEqual(report.status, "VERIFIED_NO_INCIDENT_CHECK")
        self.assertFalse(report.is_verified)

    def test_unparseable_package_never_reaches_the_verifier(self):
        self.sign_in()
        called = []
        self.verifier_routes[("POST", "/v1/verify")] = lambda request: (
            called.append(True) or (200, {"status": "VERIFIED"}, None)
        )
        report = self.api.verify_package(b"not a package", expected_hash_hex="0" * 64)
        self.assertEqual(report.status, "INVALID")
        self.assertEqual(report.code, "CERTIFICATE_FORMAT_INVALID")
        self.assertEqual(called, [])

    def test_deferred_hash_verifier_fails_closed_on_a_qr_pinned_hash(self):
        package, digest = build_package()
        session = AdminSession(
            self.demo_origin, credential_path=self.credential, private_root=self.root
        )
        api = LiveDemoApi(self.profile, session, hash_verifier=DeferredPackageHashVerifier())
        called = []
        self.verifier_routes[("POST", "/v1/verify")] = lambda request: (
            called.append(True) or (200, {"status": "VERIFIED"}, None)
        )
        report = api.verify_package(package, expected_hash_hex=digest, expected_source="qr")
        self.assertEqual(report.status, "INVALID")
        self.assertEqual(report.code, "HASH_VERIFICATION_DEFERRED")
        self.assertFalse(report.package_hash.validated)
        self.assertEqual(called, [])

    def test_verify_package_file_accepts_a_json_document(self):
        self.sign_in()
        package, digest = build_package()
        document = {
            "package_base64url": b64url(package),
            "certificateHash": digest,
            "qrUrl": f"http://127.0.0.1:8091/c/{CERT_ID}?h={b64url(bytes.fromhex(digest))}",
        }
        path = self.root / "certificate-package.json"
        path.write_text(json.dumps(document))
        self.install_verifier(
            "VERIFIED",
            {"status": "VERIFIED", "certificateId": CERT_ID,
             "disclosedFields": {"status": "ACTIVE"}, "disclosureMode": "SELECTIVE_FIELDS"},
        )
        report = self.api.verify_package_file(path)
        self.assertEqual(report.status, "VERIFIED")
        self.assertEqual(report.package_hash.expected_source, "document")

    def test_verify_package_file_detects_a_tampered_body(self):
        self.sign_in()
        _original, original_hash = build_package()
        tampered, _tampered_hash = build_package(tamper="area")
        document = {
            "package_base64url": b64url(tampered),
            "certificateHash": original_hash,
        }
        path = self.root / "tampered.json"
        path.write_text(json.dumps(document))
        report = self.api.verify_package_file(path)
        self.assertEqual(report.status, "INVALID")
        self.assertEqual(report.code, "QR_HASH_MISMATCH")
        self.assertEqual(report.disclosed_fields, {})

    def test_verify_qr_payload_fetches_the_package_and_verifies(self):
        self.sign_in()
        package, digest = build_package()
        document = {
            "package_base64url": b64url(package),
            "certificateHash": digest,
            "qrUrl": f"http://127.0.0.1:8091/c/{CERT_ID}?h={b64url(bytes.fromhex(digest))}",
        }
        self.routes[("GET", f"/v1/certificates/{CERT_ID}/package")] = lambda request: (
            200, document, None,
        )
        self.install_verifier(
            "VERIFIED",
            {"status": "VERIFIED", "certificateId": CERT_ID,
             "disclosedFields": {"status": "ACTIVE", "areaSquareMeters": "1250.50"},
             "disclosureMode": "SELECTIVE_FIELDS"},
        )
        qr_payload = f"http://127.0.0.1:8091/c/{CERT_ID}?h={b64url(bytes.fromhex(digest))}"
        report = self.api.verify_qr_payload(qr_payload)
        self.assertEqual(report.status, "VERIFIED")
        self.assertEqual(report.certificate_id, CERT_ID)
        self.assertEqual(report.package_hash.expected_source, "qr")

    def test_verify_qr_payload_maps_a_server_side_hash_mismatch(self):
        self.sign_in()
        self.routes[("GET", f"/v1/certificates/{CERT_ID}/package")] = lambda request: (
            422, {"code": "QR_HASH_MISMATCH"}, None,
        )
        qr_payload = f"http://127.0.0.1:8091/c/{CERT_ID}?h=" + "A" * 43
        report = self.api.verify_qr_payload(qr_payload)
        self.assertEqual(report.status, "INVALID")
        self.assertEqual(report.code, "QR_HASH_MISMATCH")
        self.assertEqual(report.disclosed_fields, {})

    def test_off_loopback_qr_payload_is_refused(self):
        self.sign_in()
        with self.assertRaises(ProtocolError):
            self.api.verify_qr_payload("https://evil.example.com/c/" + CERT_ID + "?h=" + "A" * 43)

    def test_verifier_origin_cannot_be_off_loopback(self):
        with self.assertRaises(ValueError):
            LiveDemoProfile(
                demo_api_origin=self.demo_origin,
                verifier_origin="http://example.com:8080",
            )


class AdversarialInputTests(ApiFixture):
    """Crash-proofing and path-integrity regression tests (H1/L1/L2)."""

    def test_deeply_nested_cbor_never_crashes_the_verify_flow(self):
        self.sign_in()
        called = []
        self.verifier_routes[("POST", "/v1/verify")] = lambda request: (
            called.append(True) or (200, {"status": "VERIFIED"}, None)
        )
        blob = b"\x81" * 1500 + b"\x00"
        with self.assertRaises(PackageFormatError):
            decode_certificate_package(blob)
        self.assertEqual(CanonicalPackageHasher().verify(blob, "0" * 64).verdict, "UNPARSEABLE")
        report = self.api.verify_package(blob, expected_hash_hex="0" * 64)
        self.assertEqual(report.status, "INVALID")
        self.assertEqual(report.code, "CERTIFICATE_FORMAT_INVALID")
        self.assertEqual(called, [])
        report = self.api.verify_package(blob)
        self.assertEqual(report.status, "INVALID")
        self.assertEqual(report.code, "CERTIFICATE_FORMAT_INVALID")

    def test_deeply_nested_json_package_file_is_refused_not_crashed(self):
        self.sign_in()
        path = self.root / "deep.json"
        # 20 000 levels: past the interpreter's JSON nesting limit, still far
        # under MAX_PACKAGE_BYTES.
        path.write_text('{"a":' * 20000 + "1" + "}" * 20000)
        with self.assertRaises(ProtocolError):
            self.api.verify_package_file(path)

    def test_deeply_nested_verifier_response_is_refused_not_crashed(self):
        self.sign_in()
        package, digest = build_package()
        self.verifier_routes[("POST", "/v1/verify")] = lambda request: (
            200, ('{"a":' * 20000 + "1" + "}" * 20000).encode(), None,
        )
        report = self.api.verify_package(package, expected_hash_hex=digest)
        self.assertEqual(report.status, "INVALID")
        self.assertEqual(report.code, "VERIFIER_RESPONSE_INVALID")
        self.assertEqual(report.disclosed_fields, {})

    def test_verifier_certificate_id_cannot_redirect_the_metadata_path(self):
        self.sign_in()
        package, digest = build_package()
        self.install_verifier(
            "VERIFIED",
            {
                "status": "VERIFIED",
                "certificateId": "../../v1/admin/session",
                "disclosureMode": "SELECTIVE_FIELDS",
                "disclosedFields": {"status": "ACTIVE"},
                "warnings": [],
            },
        )
        report = self.api.verify_package(package, expected_hash_hex=digest)
        self.assertIsNone(report.explorer_url)
        self.assertEqual(report.certificate_id, "")
        for item in self.requests:
            self.assertNotIn("../../", item["path"])
            self.assertNotIn("/metadata", item["path"])

    def test_non_canonical_certificate_id_from_the_verifier_is_not_reported(self):
        self.sign_in()
        package, digest = build_package()
        self.install_verifier(
            "VERIFIED",
            {
                "status": "VERIFIED",
                "certificateId": "not-a-certificate-id",
                "disclosedFields": {"status": "ACTIVE"},
                "disclosureMode": "SELECTIVE_FIELDS",
            },
        )
        report = self.api.verify_package(package, expected_hash_hex=digest)
        self.assertEqual(report.certificate_id, "")
        self.assertIsNone(report.explorer_url)

    def test_valid_certificate_id_still_reaches_the_metadata_lookup(self):
        self.sign_in()
        package, digest = build_package()
        self.install_verifier(
            "VERIFIED",
            {
                "status": "VERIFIED",
                "certificateId": CERT_ID,
                "disclosedFields": {"status": "ACTIVE"},
                "disclosureMode": "SELECTIVE_FIELDS",
            },
        )
        self.routes[("GET", f"/v1/certificates/{CERT_ID}/metadata")] = lambda request: (
            200,
            {"explorerUrl": f"https://explorer.solana.com/tx/{SIGNATURE}?cluster=devnet"},
            None,
        )
        report = self.api.verify_package(package, expected_hash_hex=digest)
        self.assertEqual(report.certificate_id, CERT_ID)
        self.assertEqual(
            report.explorer_url, f"https://explorer.solana.com/tx/{SIGNATURE}?cluster=devnet"
        )
        self.assertTrue(
            any(item["path"].endswith(f"/certificates/{CERT_ID}/metadata") for item in self.requests)
        )


class SecretSurfaceTests(ApiFixture):
    def test_no_summary_or_report_carries_the_password(self):
        self.sign_in()
        self.routes[("GET", "/v1/admin/records")] = lambda request: (
            200,
            {"schemaId": "land-registry-v1",
             "records": [{"internalRecordId": "SYNTHETIC-1", "recordVersion": "1",
                          "status": "ACTIVE", "origin": "ADMIN_UI", "fields": []}]},
            None,
        )
        self.install_verifier(
            "VERIFIED",
            {"status": "VERIFIED", "certificateId": CERT_ID,
             "disclosedFields": {"status": "ACTIVE"}, "disclosureMode": "SELECTIVE_FIELDS"},
        )
        package, digest = build_package()
        surfaces = [
            json.dumps(self.api.session_summary.as_dict()),
            json.dumps(self.api.list_records()[0].as_dict()),
            json.dumps(self.api.verify_package(package, expected_hash_hex=digest).as_dict()),
        ]
        for surface in surfaces:
            self.assertNotIn(SECRET, surface)
            self.assertNotIn(CSRF, surface)
            self.assertNotIn(SESSION_ID, surface)

    def test_session_summary_has_no_credential_keys(self):
        summary = self.sign_in()
        self.assertNotIn("password", summary.as_dict())
        self.assertNotIn("csrfToken", summary.as_dict())
        self.assertNotIn("csrf", json.dumps(summary.as_dict()).lower())


if __name__ == "__main__":
    unittest.main()
