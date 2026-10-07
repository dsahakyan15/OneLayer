"""TEST-ONLY fixture backends for the live-demo launcher (B3).

Never imported by the production launcher path. The screenshot harness and the
flow tests use it to drive the *real* GTK pages and the *real* B1 API/session
client against loopback servers that speak the legacy demo-api / verifier
protocols with synthetic answers. Anything rendered from this module is labeled
**FIXTURE DATA — not live devnet** by the view.

What is real here: the HTTP transport (cookies, CSRF, loopback pinning), the
B1 typed parsing (strict fail-closed review/record/certificate shapes), the
canonical package hash, the controller state machine and the GTK widgets.
What is synthetic: the server answers, the issuer HMAC (a fixture stand-in for
Ed25519), the anchor slots and the signer/QR subprocesses (test doubles).

The real devnet scenario is blocked on the lost governance key
(``4Y4pGizJm5CL789jRKYx5jeQLJ58eBBmf5UzGRFChikn``); nothing in this module
claims otherwise.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping

import live_demo_api
from live_demo_api import (
    certificate_body_cbor,
    certificate_hash_hex,
    decode_certificate_package,
)

__all__ = [
    "FakeQrDecoder",
    "package_signature",
    "FakeSigner",
    "FixtureStack",
    "build_fixture_package",
    "fixture_account",
    "package_document",
    "tamper_document_area",
    "write_credential_file",
]

FIXTURE_ISSUER_SECRET = b"fixture-issuer-secret-not-a-real-key"
FIXTURE_OPERATOR = "4Y4pGizJm5CL789jRKYx5jeQLJ58eBBmf5UzGRFChikn"
FIXTURE_PROGRAM = "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo"
FIXTURE_CONFIG_PDA = "BPgSTnDHop1NhMrksBWJtZV2zqVmUM1iusEuUXocCnFU"
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58(raw: bytes) -> str:
    """Real base58 so every fixture address passes the address checks."""
    number = int.from_bytes(raw, "big")
    out = ""
    while number:
        number, remainder = divmod(number, 58)
        out = _B58_ALPHABET[remainder] + out
    padding = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * padding + (out or "1")


FIXTURE_ROLE_PDA = _b58(bytes([1] * 32))
FIXTURE_SEGMENT_PDA = _b58(bytes([2] * 32))
FIXTURE_BLOCKHASH = _b58(bytes([3] * 32))
FIXTURE_SIGNATURE = "w" * 88
FIXTURE_INTENT_ID = "11111111-2222-3333-4444-555555555555"
FIXTURE_INTENT_HASH = "dd" * 32
FIXTURE_CERT_ID = "01010101010101010101010101010101"
FIXTURE_CREDENTIAL_SECRET = "fixture-operator-password-0123456789abcdef"
# A well-formed 32-byte QR hash that is deliberately *not* the certificate's.
FIXTURE_OTHER_QR_HASH = base64.urlsafe_b64encode(bytes([1] * 32)).rstrip(b"=").decode("ascii")


def _c_int(value: int):
    return live_demo_api._cbor_int(value)


def _c_text(value: str):
    return live_demo_api._cbor_text(value)


def _c_bytes(value: bytes):
    return live_demo_api._cbor_bytes(value)


def _c_map(pairs):
    return live_demo_api._cbor_map(pairs)


def _c_array(items):
    return live_demo_api._cbor_array(items)


def fixture_issuer_signature(signed_body_cbor: bytes) -> bytes:
    """Fixture stand-in for the issuer's Ed25519 signature (64 bytes).

    Covers the canonical *signed body* — exactly the bytes a real issuer signs
    (``certificateBodyCbor``, everything except ``issuerSignature``). A body
    edit therefore breaks this check just like a broken Ed25519 signature.
    """
    return hmac.new(FIXTURE_ISSUER_SECRET, signed_body_cbor, hashlib.sha512).digest()


def build_fixture_package(
    *,
    disclosed: Mapping[str, str],
    certificate_id: str = FIXTURE_CERT_ID,
    record_version: int = 2,
    disclosure_mode: str = "SELECTIVE_FIELDS",
    issuer_signature: bytes | None = None,
    record_id_commitment: bytes = b"c" * 32,
) -> tuple[bytes, str, str]:
    """Return ``(package_bytes, certificate_hash_hex, qr_hash_base64url)``.

    ``issuer_signature`` may be overridden to reproduce a package that keeps the
    *original* signature after its body was edited (the tamper scenarios).
    """
    fields = dict(disclosed)
    salts = {path: hashlib.sha256(b"salt:" + path.encode()).digest() for path in fields}
    field_proofs = [
        _c_map(
            (
                ("path", _c_text(path)),
                ("leafIndex", _c_int(index)),
                ("siblings", _c_array(())),
            )
        )
        for index, path in enumerate(sorted(fields))
    ]
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
            ("keyId", _c_text("fixture-issuer-1")),
            ("publicKey", _c_bytes(b"k" * 32)),
            ("signatureAlgorithm", _c_text("Ed25519")),
        )
    )
    signature = issuer_signature if issuer_signature is not None else b"\x00" * 64
    entries = [
        ("format", _c_text("ONELAYER_CERTIFICATE")),
        ("version", _c_int(1)),
        ("certificateId", _c_bytes(bytes.fromhex(certificate_id))),
        ("registryId", _c_text("gov.registry.land")),
        ("issuedAt", _c_text("2026-10-06T10:00:00Z")),
        ("recordIdCommitment", _c_bytes(record_id_commitment)),
        ("recordVersion", _c_int(record_version)),
        ("schemaVersion", _c_int(1)),
        ("disclosureMode", _c_text(disclosure_mode)),
        ("disclosedFields", _c_map((path, _c_text(value)) for path, value in sorted(fields.items()))),
        ("fieldSalts", _c_map((path, _c_bytes(salt)) for path, salt in sorted(salts.items()))),
        ("fieldRoot", _c_bytes(b"f" * 32)),
        ("fieldProofs", _c_array(field_proofs)),
        ("batchProof", batch_proof),
        ("anchor", anchor),
        ("issuer", issuer),
        ("issuerSignature", _c_bytes(signature)),
    ]
    body = live_demo_api._encode(_c_map(entries))
    if issuer_signature is None:
        # Sign the canonical signed body (the same bytes the hash covers).
        signature = fixture_issuer_signature(certificate_body_cbor(decode_certificate_package(body)))
        entries[-1] = ("issuerSignature", _c_bytes(signature))
        body = live_demo_api._encode(_c_map(entries))
    digest = certificate_hash_hex(decode_certificate_package(body))
    qr_hash = base64.urlsafe_b64encode(bytes.fromhex(digest)).rstrip(b"=").decode("ascii")
    return body, digest, qr_hash


def fixture_account(address: str, role: str) -> dict[str, str]:
    return {"address": address, "role": role}


def package_signature(package: bytes) -> bytes:
    """The package's ``issuerSignature`` value (the body hash excludes it)."""
    value = live_demo_api.decode_canonical(package)
    if value.kind != "map":
        raise ValueError("fixture package is not a canonical map")
    for key, entry in value.value:
        if key == "issuerSignature" and entry.kind == "bytes":
            return bytes(entry.value)
    raise ValueError("fixture package has no issuerSignature")


class FixtureStack:
    """One loopback demo-api + verifier pair with synthetic state."""

    def __init__(self, *, issuer_secret: bytes = FIXTURE_ISSUER_SECRET):
        del issuer_secret  # the fixture HMAC key is a module constant
        self.requests: list[dict[str, Any]] = []
        self.records: dict[str, list[dict[str, Any]]] = {}
        self.record_fields: dict[str, dict[str, Any]] = {}
        self.intents: dict[str, dict[str, Any]] = {}
        self.certificates: dict[str, dict[str, Any]] = {}
        self.record_certificates: dict[str, list[str]] = {}
        self.qr_hash_mismatch: set[str] = set()
        self.fail_simulation = False
        self.force_status: str | None = None
        self._intent_counter = 0
        self._certificate_counter = 0
        self.demo_origin = self._serve(self._demo_dispatch)
        self.verifier_origin = self._serve(self._verifier_dispatch)

    # -- lifecycle --------------------------------------------------------

    def _serve(self, dispatch: Callable[..., None]) -> str:
        stack = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                dispatch(self)

            def do_POST(self):
                dispatch(self)

            def do_DELETE(self):
                dispatch(self)

            def log_message(self, *_args):
                pass

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self._servers = getattr(self, "_servers", [])
        self._servers.append((httpd, thread))
        return f"http://127.0.0.1:{httpd.server_port}"

    def close(self) -> None:
        for httpd, thread in getattr(self, "_servers", []):
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)

    # -- helpers ----------------------------------------------------------

    def _record_request(self, request: BaseHTTPRequestHandler) -> bytes:
        length = int(request.headers.get("content-length") or 0)
        body = request.rfile.read(length) if length else b""
        self.requests.append(
            {
                "method": request.command,
                "path": request.path,
                "headers": {key.lower(): value for key, value in request.headers.items()},
                "body": body,
            }
        )
        return body

    def _reply(self, request: BaseHTTPRequestHandler, status: int, payload: Any, *, raw: bytes | None = None) -> None:
        data = raw if raw is not None else json.dumps(payload).encode("utf-8")
        request.send_response(status)
        request.send_header("content-type", "application/json" if raw is None else "application/octet-stream")
        request.send_header("content-length", str(len(data)))
        request.end_headers()
        request.wfile.write(data)

    # -- demo-api protocol ------------------------------------------------

    def _demo_dispatch(self, request: BaseHTTPRequestHandler) -> None:
        body = self._record_request(request)
        path = request.path.split("?")[0]
        query = request.path.split("?")[1] if "?" in request.path else ""
        method = request.command
        if (method, path) == ("POST", "/v1/admin/session"):
            self._reply(request, 201, {
                "role": "operator",
                "username": "operator",
                "csrfToken": "fixture-csrf-token-0123456789abcdef",
                "expiresAt": "2026-10-06T12:00:00Z",
                "permissions": [
                    "records.draft", "publication.prepare", "publication.submit",
                    "certificates.issue", "certificates.read",
                ],
                "registryIds": ["gov.registry.land"],
                "deploymentRegistryId": "gov.registry.land",
            })
            return
        if (method, path) == ("DELETE", "/v1/admin/session"):
            request.send_response(204)
            request.send_header("content-length", "0")
            request.end_headers()
            return
        if (method, path) == ("GET", "/v1/admin/session"):
            self._reply(request, 200, {
                "role": "operator", "username": "operator",
                "csrfToken": "fixture-csrf-token-0123456789abcdef",
                "expiresAt": "2026-10-06T12:00:00Z",
                "permissions": ["records.draft", "publication.prepare", "publication.submit",
                                "certificates.issue", "certificates.read"],
                "registryIds": ["gov.registry.land"],
                "deploymentRegistryId": "gov.registry.land",
            })
            return
        if (method, path) == ("POST", "/v1/admin/records"):
            self._create_record(request, body)
            return
        if (method, path) == ("GET", "/v1/admin/records"):
            self._reply(request, 200, {
                "schemaId": "land-registry-v1",
                "records": [
                    {
                        "internalRecordId": record_id,
                        "recordVersion": str(versions[-1]["recordVersion"]),
                        "status": self.record_fields[record_id].get("status", "ACTIVE"),
                        "origin": "ADMIN_UI",
                        "fields": [
                            {"path": key, "type": _field_type(key), "value": value}
                            for key, value in self.record_fields[record_id].items()
                        ],
                    }
                    for record_id, versions in self.records.items()
                ],
            })
            return
        if (method, path) == ("POST", "/v1/admin/publish-intents"):
            self._prepare_intent(request, body)
            return
        if method == "GET" and path.startswith("/v1/admin/publish-intents/"):
            intent_id = path.rsplit("/", 1)[1]
            intent = self.intents.get(intent_id)
            if intent is None:
                self._reply(request, 404, {"code": "NOT_FOUND"})
                return
            self._reply(request, 200, intent)
            return
        if method == "POST" and path.endswith("/signature"):
            intent_id = path.split("/")[-2]
            intent = self.intents.get(intent_id)
            if intent is None:
                self._reply(request, 404, {"code": "NOT_FOUND"})
                return
            payload = json.loads(body.decode("utf-8")) if body else {}
            signed = payload.get("signedTransactionBase64")
            if not isinstance(signed, str) or not signed:
                self._reply(request, 422, {"code": "REQUEST_INVALID"})
                return
            intent["state"] = "SUBMITTED"
            intent["transactionSignature"] = FIXTURE_SIGNATURE
            self._reply(request, 200, intent)
            return
        if method == "POST" and path.endswith("/reconciliation"):
            intent_id = path.split("/")[-2]
            intent = self.intents.get(intent_id)
            if intent is None:
                self._reply(request, 404, {"code": "NOT_FOUND"})
                return
            intent["state"] = "FINALIZED"
            intent["anchorSlot"] = "412267854"
            self._reply(request, 200, intent)
            return
        if method == "POST" and path.endswith("/certificate"):
            self._issue_certificate(request, body, path)
            return
        if method == "GET" and path.startswith("/v1/certificates/") and path.endswith("/package"):
            self._serve_package(request, path, query)
            return
        if method == "GET" and path.startswith("/v1/certificates/") and path.endswith("/metadata"):
            self._serve_metadata(request, path)
            return
        if method == "GET" and path.startswith("/v1/qr/"):
            self._serve_qr(request, path)
            return
        self._reply(request, 404, {"code": "NOT_FOUND"})

    def _create_record(self, request: BaseHTTPRequestHandler, body: bytes) -> None:
        payload = json.loads(body.decode("utf-8")) if body else {}
        record_id = payload.get("internalRecordId")
        fields = payload.get("fields")
        if not isinstance(record_id, str) or not isinstance(fields, dict):
            self._reply(request, 422, {"code": "REQUEST_INVALID"})
            return
        versions = self.records.setdefault(record_id, [])
        version = len(versions) + 1
        versions.append({"recordVersion": version})
        self.record_fields[record_id] = dict(fields)
        self._reply(request, 201, {
            "internalRecordId": record_id,
            "recordVersion": str(version),
            "status": str(fields.get("status", "ACTIVE")),
            "origin": "ADMIN_UI",
        })

    def _prepare_intent(self, request: BaseHTTPRequestHandler, body: bytes) -> None:
        payload = json.loads(body.decode("utf-8")) if body else {}
        operator = payload.get("operator")
        self._intent_counter += 1
        intent_id = f"{self._intent_counter:08x}-2222-3333-4444-555555555555"
        intent = _review_envelope(
            intent_id=intent_id,
            intent_hash=hashlib.sha256(intent_id.encode("ascii")).hexdigest(),
            state="SIMULATED",
            operator=operator if isinstance(operator, str) else FIXTURE_OPERATOR,
        )
        if self.fail_simulation:
            # demo-api's failed-simulation contract: 422 with the full review.
            intent["state"] = "SIMULATION_FAILED"
            intent["review"]["simulation"] = {
                "ok": False, "error": "LEDGER_SEGMENT_MISSING", "unitsConsumed": 0}
            self.intents[intent_id] = intent
            self._reply(request, 422, intent)
            return
        self.intents[intent_id] = intent
        self._reply(request, 201, intent)

    def _issue_certificate(self, request: BaseHTTPRequestHandler, body: bytes, path: str) -> None:
        payload = json.loads(body.decode("utf-8")) if body else {}
        intent_id = path.split("/")[-2]
        intent = self.intents.get(intent_id)
        record_id = payload.get("internalRecordId")
        if intent is None or intent.get("state") != "FINALIZED" or not isinstance(record_id, str):
            self._reply(request, 409, {"code": "NOT_FINALIZED"})
            return
        disclosed_paths = payload.get("disclosedPaths") or ["status", "areaSquareMeters"]
        fields = self.record_fields.get(record_id, {})
        disclosed = {
            path: str(fields[path])
            for path in disclosed_paths
            if path in fields
        }
        self._certificate_counter += 1
        certificate_id = f"{self._certificate_counter:032x}"
        record_version = len(self.records.get(record_id, [{"recordVersion": 1}]))
        package, digest, qr_hash = build_fixture_package(
            disclosed=disclosed,
            certificate_id=certificate_id,
            record_version=record_version,
            record_id_commitment=hashlib.sha256(record_id.encode("utf-8")).digest(),
        )
        for previous in self.record_certificates.get(record_id, []):
            self.certificates[previous]["lifecycle"] = "SUPERSEDED"
        self.record_certificates.setdefault(record_id, []).append(certificate_id)
        self.certificates[certificate_id] = {
            "certificateId": certificate_id,
            "recordId": record_id,
            "recordVersion": record_version,
            "package": package,
            "certificateHash": digest,
            "qrHash": qr_hash,
            "disclosureMode": "SELECTIVE_FIELDS" if payload.get("disclosedPaths") else "FULL_RECORD",
            "disclosedPaths": list(disclosed_paths),
            "disclosed": disclosed,
            "lifecycle": "CURRENT",
        }
        intent["state"] = "ISSUED"
        intent["certificateId"] = certificate_id
        self._reply(request, 201, {
            "intentId": intent_id,
            "state": "ISSUED",
            "certificateId": certificate_id,
            "certificateHash": digest,
            "qrUrl": self.qr_url(certificate_id, qr_hash),
            "transactionSignature": FIXTURE_SIGNATURE,
            "anchorSlot": "412267854",
            "explorerUrl": f"https://explorer.solana.com/tx/{FIXTURE_SIGNATURE}?cluster=devnet",
            "disclosureMode": "SELECTIVE_FIELDS" if payload.get("disclosedPaths") else "FULL_RECORD",
            "disclosedPaths": list(disclosed_paths),
            "fieldCount": len(disclosed_paths),
        })

    def qr_url(self, certificate_id: str, qr_hash: str) -> str:
        return f"http://127.0.0.1:8091/c/{certificate_id}?h={qr_hash}"

    def _serve_package(self, request: BaseHTTPRequestHandler, path: str, query: str) -> None:
        certificate_id = path.split("/")[-2]
        certificate = self.certificates.get(certificate_id)
        if certificate is None:
            self._reply(request, 404, {"code": "NOT_FOUND"})
            return
        carried = None
        for part in query.split("&"):
            if part.startswith("h="):
                carried = part[2:]
        if carried is not None and carried != certificate["qrHash"]:
            # demo-api's QR hash pinning: a wrong ?h= is a 422 mismatch.
            self._reply(request, 422, {"code": "QR_HASH_MISMATCH"})
            return
        self._reply(request, 200, {
            "package_base64url": base64.urlsafe_b64encode(certificate["package"]).rstrip(b"=").decode("ascii"),
            "certificateHash": certificate["certificateHash"],
            "qrUrl": self.qr_url(certificate_id, certificate["qrHash"]),
        })

    def _serve_metadata(self, request: BaseHTTPRequestHandler, path: str) -> None:
        certificate_id = path.split("/")[-2]
        certificate = self.certificates.get(certificate_id)
        if certificate is None:
            self._reply(request, 404, {"code": "NOT_FOUND"})
            return
        self._reply(request, 200, {
            "certificateId": certificate_id,
            "registryId": "gov.registry.land",
            "cluster": "solana:devnet",
            "status": certificate["lifecycle"],
            "issuedAt": "2026-10-06T10:00:00Z",
            "recordVersion": str(certificate["recordVersion"]),
            "certificateHash": certificate["certificateHash"],
            "qrUrl": self.qr_url(certificate_id, certificate["qrHash"]),
            "disclosureMode": certificate["disclosureMode"],
            "disclosedPaths": certificate["disclosedPaths"],
            "batchSequence": "2",
            "anchorSlot": "412267854",
            "transactionSignature": FIXTURE_SIGNATURE,
            "merkleRoot": "aa" * 32,
            "manifestHash": "bb" * 32,
            "explorerUrl": f"https://explorer.solana.com/tx/{FIXTURE_SIGNATURE}?cluster=devnet",
        })

    def _serve_qr(self, request: BaseHTTPRequestHandler, path: str) -> None:
        certificate_id = path.rsplit("/", 1)[1].split(".")[0]
        certificate = self.certificates.get(certificate_id)
        if certificate is None:
            self._reply(request, 404, {"code": "NOT_FOUND"})
            return
        self._reply(request, 200, None, raw=_tiny_png())

    # -- verifier protocol ------------------------------------------------

    @staticmethod
    def _v2_envelope(body: dict[str, Any]) -> dict[str, Any]:
        """Wrap a fixture verdict in the strict ``/v2/verify`` wire shape.

        The desktop refuses anything without ``resultVersion: 2`` and reads the
        nested proofs/registry/incidents/lifecycle. Nested values are honest
        defaults so the overall ``status`` (what the UI chip renders) stays the
        fixture's intended verdict.
        """
        status = body.get("status")
        out: dict[str, Any] = {
            "resultVersion": 2,
            "proofs": {"status": "NOT_ESTABLISHED" if status == "INVALID" else "VERIFIED", "anchorSlot": "412267854"},
            "registry": {"registryId": "gov.registry.land", "status": "NOT_ESTABLISHED" if status == "INVALID" else "CHECKED"},
            "incidents": {"status": "NOT_CHECKED"},
            "lifecycle": {"status": "UNKNOWN", "code": "LIFECYCLE_UNAVAILABLE"},
        }
        out.update(body)
        return out

    def _verifier_dispatch(self, request: BaseHTTPRequestHandler) -> None:
        body = self._record_request(request)
        if request.command != "POST" or request.path != "/v2/verify":
            self._reply(request, 404, {"code": "NOT_FOUND"})
            return
        payload = json.loads(body.decode("utf-8")) if body else {}
        encoded = payload.get("certificatePackage")
        if not isinstance(encoded, str):
            self._reply(request, 422, self._v2_envelope({"status": "INVALID", "code": "CERTIFICATE_FORMAT_INVALID"}))
            return
        try:
            package = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
            self._reply(request, 422, self._v2_envelope({"status": "INVALID", "code": "CERTIFICATE_FORMAT_INVALID"}))
            return
        report = self._v2_envelope(self._verdict(package))
        status = 200 if report["status"] != "INVALID" else 422
        self._reply(request, status, report)

    def _verdict(self, package: bytes) -> dict[str, Any]:
        if self.force_status is not None:
            return {
                "status": self.force_status,
                "code": None,
                "certificateId": FIXTURE_CERT_ID,
                "batchSequence": "2",
                "solanaSlot": "412267854",
                "recordVersion": "1",
                "currentRecordVersion": "1",
                "certificateLifecycle": "CURRENT",
                "incidentIndexStatus": "skipped",
                "warnings": ["fixture verdict override"],
                "disclosureMode": "SELECTIVE_FIELDS",
                "disclosedFields": {"status": "ACTIVE"},
            }
        try:
            decoded = decode_certificate_package(package)
        except Exception:  # noqa: BLE001 - any decode failure is a format error
            return {"status": "INVALID", "code": "CERTIFICATE_FORMAT_INVALID", "certificateId": ""}
        certificate_id = decoded.certificate_id.hex()
        try:
            expected = certificate_hash_hex(decoded)
        except Exception:  # noqa: BLE001
            return {"status": "INVALID", "code": "CERTIFICATE_FORMAT_INVALID", "certificateId": certificate_id}
        stored = self.certificates.get(certificate_id)
        signature = package_signature(package)
        # Fixture issuer check over the canonical signed body. A tampered body
        # keeps the old signature and fails here exactly like Ed25519 would.
        if signature != fixture_issuer_signature(certificate_body_cbor(decoded)):
            # Body tampered but the old signature kept: a real verifier would
            # report CERT_SIGNATURE_INVALID for the same reason.
            return {
                "status": "INVALID",
                "code": "CERT_SIGNATURE_INVALID",
                "certificateId": certificate_id,
                "disclosedFields": {},
            }
        if stored is None:
            return {
                "status": "INVALID",
                "code": "CERTIFICATE_UNKNOWN",
                "certificateId": certificate_id,
                "disclosedFields": {},
            }
        if stored["certificateHash"] != expected:
            return {
                "status": "INVALID",
                "code": "CERT_SIGNATURE_INVALID",
                "certificateId": certificate_id,
                "disclosedFields": {},
            }
        lifecycle = stored["lifecycle"]
        status = "SUPERSEDED" if lifecycle == "SUPERSEDED" else "VERIFIED"
        return {
            "status": status,
            "code": None,
            "certificateId": certificate_id,
            "batchSequence": "2",
            "solanaSlot": "412267854",
            "recordVersion": str(stored["recordVersion"]),
            "currentRecordVersion": str(stored["recordVersion"]),
            "certificateLifecycle": lifecycle,
            "incidentIndexStatus": "ok",
            "warnings": [],
            "disclosureMode": stored["disclosureMode"],
            "disclosedFields": dict(stored["disclosed"]),
        }


def _field_type(path: str) -> str:
    if path in ("areaSquareMeters",):
        return "decimal"
    if path == "encumbered":
        return "bool"
    return "text"


def _review_envelope(*, intent_id: str, intent_hash: str, state: str, operator: str) -> dict[str, Any]:
    """The real demo-api intent envelope (intentResponse + batchReview)."""
    return {
        "intentId": intent_id,
        "state": state,
        "batchSequence": "2",
        "intentHash": intent_hash,
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
            "createdAt": "2026-10-06T10:00:00Z",
            "cluster": "solana:devnet",
            "programId": FIXTURE_PROGRAM,
            "configPda": FIXTURE_CONFIG_PDA,
            "rolePda": FIXTURE_ROLE_PDA,
            "segmentPda": FIXTURE_SEGMENT_PDA,
            "segmentIndex": 2,
            # Ledger day is the UTC calendar day YYYYMMDD (utc_day/ledgerDay);
            # the pre-contract ordinal 20231 is refused by the review parser.
            "dayUtc": 20261006,
            "feePayer": operator,
            "accounts": [
                {"address": operator, "role": "signer-writable"},
                {"address": FIXTURE_CONFIG_PDA, "role": "readonly"},
                {"address": FIXTURE_ROLE_PDA, "role": "readonly"},
                {"address": FIXTURE_SEGMENT_PDA, "role": "writable"},
            ],
            "instructionData": base64.b64encode(bytes(range(178))).decode(),
            "transactionBase64": base64.b64encode(b"\x01" * 64).decode(),
            "simulation": {"ok": True, "error": None, "unitsConsumed": 1200},
            "records": [],
        },
        "recentBlockhash": FIXTURE_BLOCKHASH,
        "lastValidBlockHeight": "123456",
        "expiresAt": "2026-10-06T10:01:30Z",
        "transactionSignature": None,
        "anchorSlot": None,
        "certificateId": None,
        "failureCode": None,
        "simulationLogs": ["Program log: fixture demo batch"],
        "replayed": False,
    }


def _tiny_png() -> bytes:
    """A minimal valid 1x1 PNG (the QR payload is a test-double concern)."""
    import struct
    import zlib

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(
            ">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    header = b"\x89PNG\r\n\x1a\n"
    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    raw = zlib.compress(b"\x00\xff\x00\x00")
    idat = chunk(b"IDAT", raw)
    return header + ihdr + idat + chunk(b"IEND", b"")


class FakeSigner:
    """Test double for the A1 Node signer: records requests, never signs keys."""

    def __init__(self, *, address: str = FIXTURE_OPERATOR, fail: bool = False):
        self.address = address
        self.fail = fail
        self.requests: list[dict[str, Any]] = []
        self.calls = 0

    def operator_address(self, *, ensure: bool = False):
        from live_demo_signer import OperatorAddress

        return OperatorAddress(address=self.address, path="/fixture/keys/demo-operator.json", created=False)

    def sign(self, request: Mapping[str, Any]) -> str:
        self.calls += 1
        self.requests.append(dict(request))
        if self.fail:
            from live_demo_signer import SignerError

            raise SignerError("SIGNER_FAILED")
        digest = hashlib.sha256(json.dumps(dict(request), sort_keys=True).encode("utf-8")).digest()
        return base64.b64encode(digest * 2).decode("ascii")


class FakeQrDecoder:
    """Test double for the A4 QR helper: maps a PNG path to a fixture QR URL."""

    def __init__(self, payloads: Mapping[str, str] | None = None, *, default: str | None = None):
        self.payloads = dict(payloads or {})
        self.default = default
        self.calls: list[str] = []

    @property
    def available(self) -> bool:
        return True

    def decode(self, image: Path | str) -> str:
        key = str(image)
        self.calls.append(key)
        if key in self.payloads:
            return self.payloads[key]
        if self.default is not None:
            return self.default
        from live_demo_qr import QrDecoderError

        raise QrDecoderError("QR_UNREADABLE")


def write_credential_file(root: Path) -> Path:
    """Create the /dev/shm-style credential file the session layer reads."""
    private = root / "onelayer-devnet-demo"
    private.mkdir(parents=True, exist_ok=True)
    private.chmod(0o700)
    path = private / "admin-credentials.json"
    path.write_text(json.dumps({"operator": FIXTURE_CREDENTIAL_SECRET}))
    path.chmod(0o600)
    return path


def package_document(package: bytes, certificate_hash: str, qr_url: str) -> bytes:
    """The saved package document shape ``verify_package_file`` accepts."""
    return json.dumps(
        {
            "package_base64url": base64.urlsafe_b64encode(package).rstrip(b"=").decode("ascii"),
            "certificateHash": certificate_hash,
            "qrUrl": qr_url,
        },
        indent=2,
        sort_keys=True,
    ).encode("utf-8")


def tamper_document_area(document: bytes, *, new_area: str = "9999.99", repair_hash: bool = False) -> bytes:
    """Rewrite the package body's ``areaSquareMeters`` and return the document.

    ``repair_hash=False`` keeps the original claimed ``certificateHash`` (the
    QR/document hash check must catch it). ``repair_hash=True`` recomputes the
    claim so only the issuer signature check can catch the edit.
    """
    parsed = json.loads(document.decode("utf-8"))
    package = base64.urlsafe_b64decode(parsed["package_base64url"] + "=" * (-len(parsed["package_base64url"]) % 4))
    decoded = decode_certificate_package(package)
    signature = package_signature(package)
    fields = {path: value for path, value in decoded.disclosed_fields}
    if "areaSquareMeters" not in fields:
        raise ValueError("fixture package has no areaSquareMeters")
    fields["areaSquareMeters"] = new_area
    rebuilt, digest, _qr = build_fixture_package(
        disclosed=fields,
        certificate_id=decoded.certificate_id.hex(),
        record_version=decoded.record_version,
        disclosure_mode=decoded.disclosure_mode,
        issuer_signature=signature,
        record_id_commitment=decoded.record_id_commitment,
    )
    parsed["package_base64url"] = base64.urlsafe_b64encode(rebuilt).rstrip(b"=").decode("ascii")
    if repair_hash:
        parsed["certificateHash"] = digest
    return json.dumps(parsed, indent=2, sort_keys=True).encode("utf-8")
