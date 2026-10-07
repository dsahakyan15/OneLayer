"""UI-facing live-demo adapters over the existing legacy loopback stack.

This module is the API half of the live demo «Поддельная выписка перед
ипотекой». It speaks to the *existing* services only — demo-api
(``127.0.0.1:8090``) for records / publish intents / certificates and the
verifier (``127.0.0.1:8080``) for package verification — over the fixed IPv4
loopback profile of ADR-0006. It performs no chain mutation of its own, never
auto-starts a process, and never opens an off-loopback URL.

Public surface
--------------
* :class:`LiveDemoProfile` — the fixed loopback service endpoints.
* :class:`LiveDemoApi` — records, publish, certificates, verify.
* result dataclasses — sanitized, UI-safe, no secret material.
* :class:`PackageHashResult` / :class:`PackageHashVerifier` — the package hash
  contract (see below).

Package hash contract (CertificatePackageV1)
-------------------------------------------
A certificate package is a canonical CBOR map. Its ``certificateHash`` is
``sha256(certificateBodyCbor(body))`` — the hash of the canonical encoding of
the **signed body**, *excluding* ``issuerSignature``. The hash is not stored
inside the package; the QR URL carries it as ``?h=``.

Comparing an attacker-supplied ``h`` with an attacker-supplied
``certificateHash`` proves nothing. Verifying a package therefore always
re-encodes the decoded body canonically and hashes it;
:class:`CanonicalPackageHasher` does exactly that in pure Python. A later
authoritative helper (for example a Node process built on
``packages/canonical-ts``) can be plugged in through the same
:class:`PackageHashVerifier` seam; :class:`DeferredPackageHashVerifier` returns
:data:`HashVerdict.DEFERRED` and is never treated as a match, so a hash check is
never a false positive.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol, Sequence
from urllib.parse import parse_qsl, urlsplit

from live_demo_session import (
    AdminSession,
    ApiRefusal,
    CredentialError,
    LiveDemoError,
    LoopbackHttp,
    ProtocolError,
    SessionSummary,
    TransportError,
    build_loopback_url,
    decode_base64url,
    decode_json_body,
    encode_base64url,
    loopback_origin,
)

__all__ = [
    "AccountReview",
    "ACCOUNT_ROLES",
    "ACCOUNT_ROLE_UNSPECIFIED",
    "ApiRefusal",
    "CanonicalPackageHasher",
    "CertificateMetadata",
    "CertificatePackage",
    "CredentialError",
    "DeferredPackageHashVerifier",
    "DISCLOSED_PATH_INVALID",
    "HASH_VERIFICATION_DEFERRED",
    "HashVerdict",
    "INTENT_STATE_SIMULATED",
    "INTENT_STATE_SIMULATION_FAILED",
    "IssuedCertificate",
    "LiveDemoApi",
    "LiveDemoError",
    "LiveDemoProfile",
    "PackageFormatError",
    "PackageHashResult",
    "PackageHashVerifier",
    "ProtocolError",
    "PublishPlan",
    "PublishReview",
    "RecordSummary",
    "RecordVersion",
    "SessionSummary",
    "TransportError",
    "VerificationReport",
    "certificate_body_cbor",
    "certificate_hash_hex",
    "configured_registry_id",
    "decode_certificate_package",
    "loopback_origin",
    "normalize_verification_result",
    "parse_qr_payload",
    "qr_hash_to_hex",
    "validate_explorer_url",
]

# --------------------------------------------------------------------------
# Loopback profile (ADR-0006): fixed service endpoints, nothing else.
# --------------------------------------------------------------------------

DEMO_API_PORT = 8090
VERIFIER_PORT = 8080
WEB_PORT = 8091
REGISTRY_ID = "gov.registry.land"
# The ADR-0010 isolated live-demo namespace. Selected only by explicit
# configuration (``ONELAYER_REGISTRY_ID``); the legacy default is never
# switched implicitly.
REGISTRY_ID_ENV = "ONELAYER_REGISTRY_ID"
SYNTHETIC_PROFILE_ENV = "ONELAYER_SYNTHETIC_PROFILE"
# The publication cluster + pinned chain identity the launcher expects. The
# default is the public devnet; an explicit local profile sets
# ONELAYER_PUBLICATION_CLUSTER=solana:local and ONELAYER_RPC_GENESIS_HASH=<the
# local validator's actual getGenesisHash>. The launcher refuses a review whose
# cluster does not match this profile and never assumes devnet.
PUBLICATION_CLUSTER_ENV = "ONELAYER_PUBLICATION_CLUSTER"
RPC_GENESIS_HASH_ENV = "ONELAYER_RPC_GENESIS_HASH"
DEFAULT_PUBLICATION_CLUSTER = "solana:devnet"
_CLUSTER_TEXT = re.compile(r"^[A-Za-z0-9:._-]{1,64}$")

RECORD_STATUSES = ("ACTIVE", "ARCHIVED", "PENDING", "DISPUTED")
DISCLOSURE_MODES = ("FULL_RECORD", "SELECTIVE_FIELDS")

# Account roles as produced by demo-api's ``prepareAnchorTransaction``
# (``AccountReview`` in apps/demo-api/src/admin-transaction.ts). A bare address
# string carries no role information and is shown as unspecified.
ACCOUNT_ROLES = ("signer-writable", "signer", "writable", "readonly")
ACCOUNT_ROLE_UNSPECIFIED = "unspecified"

# Publish-intent states. Only a fully simulated intent can be approved; a
# failed simulation can never reach the signer.
INTENT_STATE_SIMULATED = "SIMULATED"
INTENT_STATE_SIMULATION_FAILED = "SIMULATION_FAILED"

VERIFIED = "VERIFIED"
VERIFIED_HISTORICAL = "VERIFIED_HISTORICAL"
VERIFIED_NO_INCIDENT_CHECK = "VERIFIED_NO_INCIDENT_CHECK"
SUPERSEDED = "SUPERSEDED"
DISPUTED = "DISPUTED"
INVALID = "INVALID"
# The verifier's /v2 vocabulary. ``UNKNOWN`` is the honest answer when no
# complete, authenticated lifecycle source exists (backend contract §4); it is
# never displayed as verified or current.
UNKNOWN = "UNKNOWN"
REVOKED = "REVOKED"
HISTORICAL = "HISTORICAL"
KNOWN_VERIFICATION_STATUSES = (
    VERIFIED,
    VERIFIED_HISTORICAL,
    VERIFIED_NO_INCIDENT_CHECK,
    SUPERSEDED,
    DISPUTED,
    INVALID,
    UNKNOWN,
    REVOKED,
    HISTORICAL,
)
# Statuses that may never be presented as "current rights". ``UNKNOWN`` is the
# deliberate lifecycle answer and must stay distinguishable from ``INVALID``.
NOT_CURRENT_STATUSES = (UNKNOWN, REVOKED, HISTORICAL, SUPERSEDED, DISPUTED, INVALID)

QR_HASH_MISMATCH = "QR_HASH_MISMATCH"
HASH_VERIFICATION_DEFERRED = "HASH_VERIFICATION_DEFERRED"
CERTIFICATE_FORMAT_INVALID = "CERTIFICATE_FORMAT_INVALID"
DISCLOSED_PATH_INVALID = "DISCLOSED_PATH_INVALID"
VERIFICATION_STATUS_UNKNOWN = "VERIFICATION_STATUS_UNKNOWN"

_RECORD_ID = re.compile(r"^SYNTHETIC-[1-9][0-9]*$")
_CERTIFICATE_ID = re.compile(r"^[0-9a-f]{32}$")
_INT_STRING = re.compile(r"^(?:0|[1-9][0-9]*)$")
# The A1 signer's decimal() shape: 1..20 digits, no leading zeros.
_DECIMAL_20 = re.compile(r"^(?:0|[1-9][0-9]{0,19})$")
_DECIMAL_2 = re.compile(r"^-?(?:0|[1-9][0-9]*)\.[0-9]{2}$")
_FIELD_PATH = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,62}$")
_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,62}$")
_HASH_HEX = re.compile(r"^[0-9a-f]{64}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_PUBKEY = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
_SIGNATURE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{64,96}$")
_OPERATION_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_IDENT = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_INTENT_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_QR_HASH = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SIGNED_TX_B64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_REGISTRY_ID_TEXT = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_WORKFLOW_RECORD = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_TIMESTAMP = re.compile(r"^[A-Za-z0-9:.+T-]{1,64}$")

MAX_PACKAGE_BYTES = 1 << 20
MAX_QR_IMAGE_BYTES = 1 << 20
MAX_REQUEST_BODY_BYTES = 4 * MAX_PACKAGE_BYTES

# CBOR nesting is capped far above the certificate schema depth (6) so a
# maliciously nested blob raises PackageFormatError instead of RecursionError.
_MAX_CBOR_DEPTH = 32
_MAX_ACCOUNTS = 64
_MAX_RECORD_FIELDS = 256
# publish-anchor instruction data is a fixed-size struct in the A1 signer.
_INSTRUCTION_DATA_BYTES = 8 + 32 + 128 + 4 + 4 + 2
_MAX_TRANSACTION_BYTES = 1232


class PackageFormatError(ValueError):
    """The package bytes are not a well-formed canonical CertificatePackageV1."""


def configured_registry_id(environ: Mapping[str, str] | None = None) -> str:
    """The registry namespace this launcher will use.

    The legacy ``gov.registry.land`` is the default. A different namespace is
    selected only when it is explicitly configured (``ONELAYER_REGISTRY_ID``);
    nothing switches the legacy one implicitly (ADR-0010).
    """
    env = os.environ if environ is None else environ
    raw = env.get(REGISTRY_ID_ENV)
    if raw is None or raw == "":
        return REGISTRY_ID
    if not _REGISTRY_ID_TEXT.match(raw):
        raise ValueError(f"{REGISTRY_ID_ENV} is not a valid registry id")
    return raw


def configured_publication_cluster(environ: Mapping[str, str] | None = None) -> str:
    """The publication cluster this launcher profile expects.

    Defaults to public devnet. A local-validator profile sets
    ``ONELAYER_PUBLICATION_CLUSTER=solana:local`` explicitly; nothing switches
    the devnet default implicitly.
    """
    env = os.environ if environ is None else environ
    raw = env.get(PUBLICATION_CLUSTER_ENV)
    if raw is None or raw == "":
        return DEFAULT_PUBLICATION_CLUSTER
    if not _CLUSTER_TEXT.match(raw):
        raise ValueError(f"{PUBLICATION_CLUSTER_ENV} is not a valid cluster label")
    return raw


def configured_genesis_hash(environ: Mapping[str, str] | None = None) -> str | None:
    """The pinned expected genesis hash, or ``None`` for a known public cluster."""
    env = os.environ if environ is None else environ
    raw = env.get(RPC_GENESIS_HASH_ENV)
    if raw is None or raw == "":
        return None
    if not _HASH_HEX.match(raw) and not _PUBKEY.match(raw):
        raise ValueError(f"{RPC_GENESIS_HASH_ENV} is not a valid genesis hash")
    return raw


@dataclass(frozen=True)
class LiveDemoProfile:
    """The fixed loopback service set. There is no way to add an endpoint.

    ``registry_id`` is the *selected namespace*. It defaults to the legacy
    ``gov.registry.land``; an isolated ADR-0010 namespace must be passed
    explicitly (or selected via ``ONELAYER_REGISTRY_ID``). The profile never
    silently re-points the legacy registry.
    """

    demo_api_origin: str
    verifier_origin: str
    registry_id: str = REGISTRY_ID
    publication_cluster: str = DEFAULT_PUBLICATION_CLUSTER
    expected_genesis_hash: str | None = None

    def __post_init__(self) -> None:
        loopback_origin(self.demo_api_origin)
        loopback_origin(self.verifier_origin)
        if not _REGISTRY_ID_TEXT.match(self.registry_id):
            raise ValueError("registry_id is not a valid registry id")
        if not _CLUSTER_TEXT.match(self.publication_cluster):
            raise ValueError("publication_cluster is not a valid cluster label")
        if self.expected_genesis_hash is not None and not (
            _HASH_HEX.match(self.expected_genesis_hash) or _PUBKEY.match(self.expected_genesis_hash)
        ):
            raise ValueError("expected_genesis_hash is not a valid genesis hash")

    @classmethod
    def local(cls, *, registry_id: str | None = None) -> "LiveDemoProfile":
        return cls(
            demo_api_origin=f"http://127.0.0.1:{DEMO_API_PORT}",
            verifier_origin=f"http://127.0.0.1:{VERIFIER_PORT}",
            registry_id=registry_id if registry_id is not None else configured_registry_id(),
            publication_cluster=configured_publication_cluster(),
            expected_genesis_hash=configured_genesis_hash(),
        )

    @property
    def expected_cluster(self) -> str:
        """The cluster a durable review must report to be approvable here."""
        return self.publication_cluster

    @property
    def is_local_cluster(self) -> bool:
        return self.publication_cluster == "solana:local"

    @property
    def is_legacy_registry(self) -> bool:
        return self.registry_id == REGISTRY_ID

    @property
    def namespace_label(self) -> str:
        """How the UI must label the selected namespace. Never implies production."""
        if self.is_legacy_registry:
            return "Legacy registry (gov.registry.land)"
        return "Synthetic demo namespace"

    @property
    def namespace_detail(self) -> str:
        if self.is_legacy_registry:
            return (
                "The legacy registry's governance authority is permanently lost; "
                "governance-signed setup is blocked (GOVERNANCE_KEY_UNAVAILABLE)."
            )
        return (
            "Isolated synthetic namespace on the deployed demo program "
            "(ADR-0010). Not the production registry."
        )

    @property
    def services(self) -> Mapping[str, str]:
        return {"demo-api": self.demo_api_origin, "verifier": self.verifier_origin}


# --------------------------------------------------------------------------
# Canonical CBOR (mirrors packages/canonical-ts encode/decodeCanonical).
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _Cbor:
    kind: str
    value: Any = None


_NULL = _Cbor("null")
_TRUE = _Cbor("bool", True)
_FALSE = _Cbor("bool", False)

_ANCHOR_BYTE_FIELDS = frozenset(
    {"merkleRoot", "manifestHash", "solanaProgramId", "segmentPda", "transactionSignature"}
)


def _cbor_int(value: int) -> _Cbor:
    return _Cbor("int", value)


def _cbor_text(value: str) -> _Cbor:
    return _Cbor("text", value)


def _cbor_bytes(value: bytes) -> _Cbor:
    return _Cbor("bytes", value)


def _cbor_array(items: Iterable[_Cbor]) -> _Cbor:
    return _Cbor("array", tuple(items))


def _cbor_map(entries: Iterable[tuple[str, _Cbor]]) -> _Cbor:
    pairs = tuple(entries)
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise PackageFormatError("duplicate CBOR map key")
    return _Cbor("map", pairs)


def _head(major: int, argument: int) -> bytes:
    if argument < 0 or argument >= 1 << 64:
        raise PackageFormatError("CBOR argument out of range")
    prefix = major << 5
    if argument <= 23:
        return bytes((prefix | argument,))
    if argument <= 0xFF:
        return bytes((prefix | 24, argument))
    if argument <= 0xFFFF:
        return bytes((prefix | 25,)) + argument.to_bytes(2, "big")
    if argument <= 0xFFFFFFFF:
        return bytes((prefix | 26,)) + argument.to_bytes(4, "big")
    return bytes((prefix | 27,)) + argument.to_bytes(8, "big")


def _encode(value: _Cbor) -> bytes:
    kind = value.kind
    if kind == "null":
        return b"\xf6"
    if kind == "bool":
        return b"\xf5" if value.value else b"\xf4"
    if kind == "int":
        number = int(value.value)
        return _head(0, number) if number >= 0 else _head(1, -(number + 1))
    if kind == "text":
        payload = unicodedata.normalize("NFC", str(value.value)).encode("utf-8")
        return _head(3, len(payload)) + payload
    if kind == "bytes":
        payload = bytes(value.value)
        return _head(2, len(payload)) + payload
    if kind == "array":
        items = tuple(value.value)
        return _head(4, len(items)) + b"".join(_encode(item) for item in items)
    if kind == "map":
        encoded = [(_encode(_cbor_text(key)), _encode(entry)) for key, entry in value.value]
        encoded.sort(key=lambda item: item[0])
        return _head(5, len(encoded)) + b"".join(k + v for k, v in encoded)
    raise PackageFormatError("unsupported CBOR value")


class _CborReader:
    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

    def read_value(self, depth: int = 0) -> _Cbor:
        if depth > _MAX_CBOR_DEPTH:
            # Fail closed on adversarial nesting: a RecursionError must never
            # escape into the verifier flow.
            raise PackageFormatError("CBOR nesting is too deep")
        initial = self._read_byte()
        major = initial >> 5
        additional = initial & 0x1F
        if major == 7:
            if additional == 20:
                return _FALSE
            if additional == 21:
                return _TRUE
            if additional == 22:
                return _NULL
            raise PackageFormatError("CBOR simple value is not supported")
        argument = self._read_argument(additional)
        if major == 0:
            return _cbor_int(argument)
        if major == 1:
            return _cbor_int(-1 - argument)
        length = self._safe_length(argument)
        if major == 2:
            return _cbor_bytes(self._read_bytes(length))
        if major == 3:
            raw = self._read_bytes(length)
            try:
                return _cbor_text(raw.decode("utf-8"))
            except UnicodeDecodeError:
                raise PackageFormatError("CBOR text is not valid UTF-8") from None
        if major == 4:
            return _cbor_array(self.read_value(depth + 1) for _ in range(length))
        if major == 5:
            entries: list[tuple[str, _Cbor]] = []
            seen: set[str] = set()
            for _ in range(length):
                key = self.read_value(depth + 1)
                if key.kind != "text":
                    raise PackageFormatError("CBOR map key must be text")
                if key.value in seen:
                    raise PackageFormatError("duplicate CBOR map key")
                seen.add(key.value)
                entries.append((key.value, self.read_value(depth + 1)))
            return _cbor_map(entries)
        raise PackageFormatError("unsupported CBOR major type")

    def _read_argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        size = {24: 1, 25: 2, 26: 4, 27: 8}.get(additional)
        if size is None:
            raise PackageFormatError("indefinite-length CBOR is not supported")
        raw = self._read_bytes(size)
        value = int.from_bytes(raw, "big")
        minimum = {1: 24, 2: 0x100, 4: 0x10000, 8: 0x100000000}[size]
        if value < minimum:
            raise PackageFormatError("non-shortest CBOR integer or length")
        return value

    @staticmethod
    def _safe_length(argument: int) -> int:
        if argument > (1 << 53) - 1:
            raise PackageFormatError("CBOR length exceeds safe integer range")
        return argument

    def _read_byte(self) -> int:
        if self._offset >= len(self._data):
            raise PackageFormatError("truncated CBOR")
        byte = self._data[self._offset]
        self._offset += 1
        return byte

    def _read_bytes(self, length: int) -> bytes:
        end = self._offset + length
        if end > len(self._data):
            raise PackageFormatError("truncated CBOR")
        value = self._data[self._offset : end]
        self._offset = end
        return value


def decode_canonical(data: bytes) -> _Cbor:
    reader = _CborReader(data)
    value = reader.read_value()
    if reader.offset != len(data):
        raise PackageFormatError("trailing bytes after CBOR value")
    if _encode(value) != data:
        raise PackageFormatError("CBOR encoding is not canonical")
    return value


# --------------------------------------------------------------------------
# CertificatePackageV1: decode and canonical signed-body hashing.
# --------------------------------------------------------------------------

_ROOT_KEYS = (
    "format",
    "version",
    "certificateId",
    "registryId",
    "issuedAt",
    "recordIdCommitment",
    "recordVersion",
    "schemaVersion",
    "disclosureMode",
    "disclosedFields",
    "fieldSalts",
    "fieldRoot",
    "fieldProofs",
    "batchProof",
    "anchor",
    "issuer",
    "issuerSignature",
)
_BATCH_PROOF_KEYS = ("treeAlgorithm", "leafIndex", "leafHash", "siblings", "expectedRoot")
_ANCHOR_KEYS = (
    "batchSequence",
    "registryVersion",
    "merkleRoot",
    "manifestHash",
    "solanaProgramId",
    "segmentIndex",
    "segmentPda",
    "transactionSignature",
    "anchorSlot",
    "commitmentRequired",
)
_ISSUER_KEYS = ("keyId", "publicKey", "signatureAlgorithm")
_PROOF_STEP_KEYS = ("side", "hash")
_FIELD_PROOF_KEYS = ("path", "leafIndex", "siblings")

_FORMAT_VALUE = "ONELAYER_CERTIFICATE"
_VERSION_VALUE = 1
_TREE_ALGORITHM = "RFC6962_SHA256_V1"
_COMMITMENT_REQUIRED = "finalized"
_SIGNATURE_ALGORITHM = "Ed25519"


def _as_map(value: _Cbor, label: str) -> Mapping[str, _Cbor]:
    if value.kind != "map":
        raise PackageFormatError(f"{label} must be a CBOR map")
    return dict(value.value)


def _as_text(value: _Cbor, label: str) -> str:
    if value.kind != "text":
        raise PackageFormatError(f"{label} must be CBOR text")
    return value.value


def _as_int(value: _Cbor, label: str, maximum: int) -> int:
    if value.kind != "int":
        raise PackageFormatError(f"{label} must be a CBOR integer")
    number = int(value.value)
    if number < 0 or number > maximum:
        raise PackageFormatError(f"{label} is out of range")
    return number


def _as_bytes(value: _Cbor, label: str, length: int) -> bytes:
    if value.kind != "bytes":
        raise PackageFormatError(f"{label} must be CBOR bytes")
    raw = bytes(value.value)
    if len(raw) != length:
        raise PackageFormatError(f"{label} must be {length} bytes")
    return raw


def _as_array(value: _Cbor, label: str) -> Sequence[_Cbor]:
    if value.kind != "array":
        raise PackageFormatError(f"{label} must be a CBOR array")
    return tuple(value.value)


def _exact_keys(value: Mapping[str, _Cbor], expected: Sequence[str], label: str) -> None:
    if sorted(value) != sorted(expected):
        raise PackageFormatError(f"{label} fields are invalid")


def _proof_steps(value: _Cbor, label: str) -> tuple[tuple[str, bytes], ...]:
    steps = []
    for index, item in enumerate(_as_array(value, label)):
        step = _as_map(item, f"{label}[{index}]")
        _exact_keys(step, _PROOF_STEP_KEYS, f"{label}[{index}]")
        side = _as_text(step["side"], f"{label}[{index}].side")
        if side not in ("LEFT", "RIGHT"):
            raise PackageFormatError(f"{label}[{index}].side is invalid")
        steps.append((side, _as_bytes(step["hash"], f"{label}[{index}].hash", 32)))
    return tuple(steps)


def _field_proofs(value: _Cbor) -> tuple[tuple[str, int, tuple[tuple[str, bytes], ...]], ...]:
    proofs = []
    for index, item in enumerate(_as_array(value, "fieldProofs")):
        proof = _as_map(item, f"fieldProofs[{index}]")
        _exact_keys(proof, _FIELD_PROOF_KEYS, f"fieldProofs[{index}]")
        proofs.append(
            (
                _as_text(proof["path"], f"fieldProofs[{index}].path"),
                _as_int(proof["leafIndex"], f"fieldProofs[{index}].leafIndex", 0xFFFFFFFF),
                _proof_steps(proof["siblings"], f"fieldProofs[{index}].siblings"),
            )
        )
    return tuple(proofs)


@dataclass(frozen=True)
class _DecodedBody:
    certificate_id: bytes
    registry_id: str
    issued_at: str
    record_id_commitment: bytes
    record_version: int
    schema_version: int
    disclosure_mode: str
    disclosed_fields: tuple[tuple[str, _Cbor], ...]
    field_salts: tuple[tuple[str, bytes], ...]
    field_root: bytes
    field_proofs: tuple[tuple[str, int, tuple[tuple[str, bytes], ...]], ...]
    batch_leaf_index: int
    batch_leaf_hash: bytes
    batch_siblings: tuple[tuple[str, bytes], ...]
    batch_expected_root: bytes
    anchor: tuple[tuple[str, Any], ...]
    issuer_key_id: str
    issuer_public_key: bytes


def decode_certificate_package(data: bytes) -> _DecodedBody:
    """Decode a CertificatePackageV1 and return its normalized signed body.

    The normalization mirrors ``decodeBody`` in
    ``apps/verifier/src/certificate-codec.ts``; the result is exactly what
    :func:`certificate_body_cbor` re-encodes for hashing.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise PackageFormatError("certificate package must be bytes")
    data = bytes(data)
    if len(data) > MAX_PACKAGE_BYTES:
        raise PackageFormatError("certificate package is too large")
    root = _as_map(decode_canonical(data), "certificate package")
    _exact_keys(root, _ROOT_KEYS, "certificate package")

    if _as_text(root["format"], "format") != _FORMAT_VALUE:
        raise PackageFormatError("certificate format is invalid")
    if _as_int(root["version"], "version", 0xFFFF) != _VERSION_VALUE:
        raise PackageFormatError("certificate version is invalid")

    disclosure_mode = _as_text(root["disclosureMode"], "disclosureMode")
    if disclosure_mode not in DISCLOSURE_MODES:
        raise PackageFormatError("disclosureMode is invalid")

    disclosed = _as_map(root["disclosedFields"], "disclosedFields")
    salts = _as_map(root["fieldSalts"], "fieldSalts")
    batch_proof = _as_map(root["batchProof"], "batchProof")
    _exact_keys(batch_proof, _BATCH_PROOF_KEYS, "batchProof")
    if _as_text(batch_proof["treeAlgorithm"], "batchProof.treeAlgorithm") != _TREE_ALGORITHM:
        raise PackageFormatError("batchProof.treeAlgorithm is invalid")

    anchor = _as_map(root["anchor"], "anchor")
    _exact_keys(anchor, _ANCHOR_KEYS, "anchor")
    if _as_text(anchor["commitmentRequired"], "anchor.commitmentRequired") != _COMMITMENT_REQUIRED:
        raise PackageFormatError("anchor commitment must be finalized")

    issuer = _as_map(root["issuer"], "issuer")
    _exact_keys(issuer, _ISSUER_KEYS, "issuer")
    if _as_text(issuer["signatureAlgorithm"], "issuer.signatureAlgorithm") != _SIGNATURE_ALGORITHM:
        raise PackageFormatError("issuer signature algorithm is invalid")

    if not disclosed:
        raise PackageFormatError("CERTIFICATE_FORMAT_INVALID: empty disclosure")

    salt_items: list[tuple[str, bytes]] = []
    for path, value in salts.items():
        salt_items.append((path, _as_bytes(value, f"fieldSalts.{path}", 32)))
    if sorted(disclosed) != sorted(dict(salt_items)):
        raise PackageFormatError("CERTIFICATE_FORMAT_INVALID: disclosure paths mismatch")

    field_proofs = _field_proofs(root["fieldProofs"])
    proof_paths = sorted(path for path, _, _ in field_proofs)
    disclosed_paths = sorted(disclosed)
    if disclosure_mode == "FULL_RECORD" and field_proofs:
        raise PackageFormatError("CERTIFICATE_FORMAT_INVALID: FULL_RECORD fieldProofs must be empty")
    if disclosure_mode == "SELECTIVE_FIELDS" and (
        disclosed_paths != proof_paths or len(proof_paths) != len(field_proofs)
    ):
        raise PackageFormatError("CERTIFICATE_FORMAT_INVALID: disclosure paths mismatch")

    return _DecodedBody(
        certificate_id=_as_bytes(root["certificateId"], "certificateId", 16),
        registry_id=_as_text(root["registryId"], "registryId"),
        issued_at=_as_text(root["issuedAt"], "issuedAt"),
        record_id_commitment=_as_bytes(root["recordIdCommitment"], "recordIdCommitment", 32),
        record_version=_as_int(root["recordVersion"], "recordVersion", 0xFFFFFFFFFFFFFFFF),
        schema_version=_as_int(root["schemaVersion"], "schemaVersion", 0xFFFF),
        disclosure_mode=disclosure_mode,
        disclosed_fields=tuple(sorted(disclosed.items())),
        field_salts=tuple(sorted(salt_items)),
        field_root=_as_bytes(root["fieldRoot"], "fieldRoot", 32),
        field_proofs=field_proofs,
        batch_leaf_index=_as_int(batch_proof["leafIndex"], "batchProof.leafIndex", 0xFFFFFFFF),
        batch_leaf_hash=_as_bytes(batch_proof["leafHash"], "batchProof.leafHash", 32),
        batch_siblings=_proof_steps(batch_proof["siblings"], "batchProof.siblings"),
        batch_expected_root=_as_bytes(batch_proof["expectedRoot"], "batchProof.expectedRoot", 32),
        anchor=(
            ("batchSequence", _as_int(anchor["batchSequence"], "anchor.batchSequence", 0xFFFFFFFFFFFF)),
            ("registryVersion", _as_int(anchor["registryVersion"], "anchor.registryVersion", 0xFFFFFFFFFFFF)),
            ("merkleRoot", _as_bytes(anchor["merkleRoot"], "anchor.merkleRoot", 32)),
            ("manifestHash", _as_bytes(anchor["manifestHash"], "anchor.manifestHash", 32)),
            ("solanaProgramId", _as_bytes(anchor["solanaProgramId"], "anchor.solanaProgramId", 32)),
            ("segmentIndex", _as_int(anchor["segmentIndex"], "anchor.segmentIndex", 0xFFFF)),
            ("segmentPda", _as_bytes(anchor["segmentPda"], "anchor.segmentPda", 32)),
            (
                "transactionSignature",
                _as_bytes(anchor["transactionSignature"], "anchor.transactionSignature", 64),
            ),
            ("anchorSlot", _as_int(anchor["anchorSlot"], "anchor.anchorSlot", 0xFFFFFFFFFFFF)),
        ),
        issuer_key_id=_as_text(issuer["keyId"], "issuer.keyId"),
        issuer_public_key=_as_bytes(issuer["publicKey"], "issuer.publicKey", 32),
    )


def _proof_steps_cbor(steps: Sequence[tuple[str, bytes]]) -> _Cbor:
    return _cbor_array(
        _cbor_map((("side", _cbor_text(side)), ("hash", _cbor_bytes(hash_)))) for side, hash_ in steps
    )


def certificate_body_cbor(body: _DecodedBody) -> bytes:
    """Canonical encoding of the signed body, exactly as ``certificateBodyCbor``.

    ``issuerSignature`` is deliberately absent: the certificate hash covers the
    body only, so a tampered body cannot keep its old hash.
    """
    field_proofs = _cbor_array(
        _cbor_map(
            (
                ("path", _cbor_text(path)),
                ("leafIndex", _cbor_int(leaf_index)),
                ("siblings", _proof_steps_cbor(siblings)),
            )
        )
        for path, leaf_index, siblings in body.field_proofs
    )
    batch_proof = _cbor_map(
        (
            ("treeAlgorithm", _cbor_text(_TREE_ALGORITHM)),
            ("leafIndex", _cbor_int(body.batch_leaf_index)),
            ("leafHash", _cbor_bytes(body.batch_leaf_hash)),
            ("siblings", _proof_steps_cbor(body.batch_siblings)),
            ("expectedRoot", _cbor_bytes(body.batch_expected_root)),
        )
    )
    anchor_entries = [
        (name, _cbor_int(value) if name not in _ANCHOR_BYTE_FIELDS else _cbor_bytes(value))
        for name, value in body.anchor
    ]
    anchor_entries.append(("commitmentRequired", _cbor_text(_COMMITMENT_REQUIRED)))
    issuer = _cbor_map(
        (
            ("keyId", _cbor_text(body.issuer_key_id)),
            ("publicKey", _cbor_bytes(body.issuer_public_key)),
            ("signatureAlgorithm", _cbor_text(_SIGNATURE_ALGORITHM)),
        )
    )
    entries = [
        ("format", _cbor_text(_FORMAT_VALUE)),
        ("version", _cbor_int(_VERSION_VALUE)),
        ("certificateId", _cbor_bytes(body.certificate_id)),
        ("registryId", _cbor_text(body.registry_id)),
        ("issuedAt", _cbor_text(body.issued_at)),
        ("recordIdCommitment", _cbor_bytes(body.record_id_commitment)),
        ("recordVersion", _cbor_int(body.record_version)),
        ("schemaVersion", _cbor_int(body.schema_version)),
        ("disclosureMode", _cbor_text(body.disclosure_mode)),
        ("disclosedFields", _cbor_map(body.disclosed_fields)),
        ("fieldSalts", _cbor_map((path, _cbor_bytes(salt)) for path, salt in body.field_salts)),
        ("fieldRoot", _cbor_bytes(body.field_root)),
        ("fieldProofs", field_proofs),
        ("batchProof", batch_proof),
        ("anchor", _cbor_map(anchor_entries)),
        ("issuer", issuer),
    ]
    return _encode(_cbor_map(entries))


def certificate_hash_hex(body: _DecodedBody) -> str:
    """``sha256(certificateBodyCbor(body))`` as lowercase hex."""
    return hashlib.sha256(certificate_body_cbor(body)).hexdigest()


# --------------------------------------------------------------------------
# Package hash verification seam — never a false positive.
# --------------------------------------------------------------------------


class HashVerdict:
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    UNPARSEABLE = "UNPARSEABLE"
    DEFERRED = "DEFERRED"


@dataclass(frozen=True)
class PackageHashResult:
    """Outcome of hashing a package against an expected certificate hash.

    ``matched`` is True **only** for :data:`HashVerdict.MATCH`, which an
    implementation may report only after actually hashing the canonical signed
    body and comparing it with ``expected_hash_hex``.
    """

    verdict: str
    computed_hash_hex: str | None
    expected_hash_hex: str | None
    detail: str
    expected_source: str | None = None

    @property
    def matched(self) -> bool:
        return self.verdict == HashVerdict.MATCH

    @property
    def validated(self) -> bool:
        """True only when a real hash comparison was performed and succeeded."""
        return self.verdict == HashVerdict.MATCH

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "computedHashHex": self.computed_hash_hex,
            "expectedHashHex": self.expected_hash_hex,
            "expectedSource": self.expected_source,
            "detail": self.detail,
        }


class PackageHashVerifier(Protocol):
    def verify(
        self, package: bytes, expected_hash_hex: str | None, *, expected_source: str | None = None
    ) -> PackageHashResult:
        """Hash ``package``'s canonical signed body.

        Implementations must never report :data:`HashVerdict.MATCH` unless the
        computed hash was compared with ``expected_hash_hex`` and equal to it.
        """


class CanonicalPackageHasher:
    """Default verifier: pure-Python canonical re-encode + SHA-256."""

    def verify(
        self, package: bytes, expected_hash_hex: str | None, *, expected_source: str | None = None
    ) -> PackageHashResult:
        expected = expected_hash_hex.lower() if isinstance(expected_hash_hex, str) else None
        if expected is not None and not _HASH_HEX.match(expected):
            return PackageHashResult(
                HashVerdict.MISMATCH, None, expected, "expected hash is malformed", expected_source
            )
        try:
            body = decode_certificate_package(package)
            computed = certificate_hash_hex(body)
        except RecursionError:
            return PackageHashResult(
                HashVerdict.UNPARSEABLE,
                None,
                expected,
                "certificate package is too deeply nested",
                expected_source,
            )
        except PackageFormatError as error:
            return PackageHashResult(
                HashVerdict.UNPARSEABLE, None, expected, str(error), expected_source
            )
        if expected is None:
            # No value to compare against: record the digest but claim nothing.
            return PackageHashResult(
                HashVerdict.DEFERRED,
                computed,
                None,
                "no expected hash supplied",
                expected_source,
            )
        if computed != expected:
            return PackageHashResult(
                HashVerdict.MISMATCH, computed, expected, "package hash does not match", expected_source
            )
        return PackageHashResult(
            HashVerdict.MATCH, computed, expected, "package hash matches", expected_source
        )


class DeferredPackageHashVerifier:
    """Placeholder for a later authoritative helper.

    It never returns :data:`HashVerdict.MATCH`. Callers must treat
    :data:`HashVerdict.DEFERRED` as *unverified* — never as success.
    """

    def verify(
        self, package: bytes, expected_hash_hex: str | None, *, expected_source: str | None = None
    ) -> PackageHashResult:
        return PackageHashResult(
            HashVerdict.DEFERRED, None, expected_hash_hex, "hash verification is deferred", expected_source
        )


# --------------------------------------------------------------------------
# Verification result normalization.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationReport:
    """UI-facing verification verdict. Disclosed fields are cleared on failure."""

    status: str
    code: str | None
    certificate_id: str
    batch_sequence: str | None = None
    solana_slot: str | None = None
    record_version: str | None = None
    current_record_version: str | None = None
    certificate_lifecycle: str | None = None
    incident_index_status: str | None = None
    warnings: tuple[str, ...] = ()
    disclosure_mode: str | None = None
    disclosed_fields: Mapping[str, Any] = field(default_factory=dict)
    explorer_url: str | None = None
    package_hash: PackageHashResult | None = None
    # /v2 strict detail (M2). The overall ``status`` is the honest lifecycle
    # answer (UNKNOWN until an authenticated lifecycle source exists); the proof
    # status is surfaced separately so "proof VERIFIED + overall UNKNOWN" is
    # visible instead of being conflated with a current-verifiable result.
    result_version: int | None = None
    proofs_status: str | None = None
    registry_id: str | None = None
    registry_status: str | None = None
    lifecycle_status: str | None = None
    lifecycle_code: str | None = None
    checked_slot: str | None = None
    observed_indexed_through_slot: str | None = None
    observed_finalized_head_slot: str | None = None
    observed_lag_slots: str | None = None

    @property
    def is_verified(self) -> bool:
        return self.status == VERIFIED

    @property
    def discloses_fields(self) -> bool:
        return bool(self.disclosed_fields)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "code": self.code,
            "certificateId": self.certificate_id,
            "batchSequence": self.batch_sequence,
            "solanaSlot": self.solana_slot,
            "recordVersion": self.record_version,
            "currentRecordVersion": self.current_record_version,
            "certificateLifecycle": self.certificate_lifecycle,
            "incidentIndexStatus": self.incident_index_status,
            "warnings": list(self.warnings),
            "disclosureMode": self.disclosure_mode,
            "disclosedFields": dict(self.disclosed_fields),
            "explorerUrl": self.explorer_url,
            "packageHash": self.package_hash.as_dict() if self.package_hash else None,
            "resultVersion": self.result_version,
            "proofsStatus": self.proofs_status,
            "registryId": self.registry_id,
            "registryStatus": self.registry_status,
            "lifecycleStatus": self.lifecycle_status,
            "lifecycleCode": self.lifecycle_code,
            "checkedSlot": self.checked_slot,
            "observedIndexedThroughSlot": self.observed_indexed_through_slot,
            "observedFinalizedHeadSlot": self.observed_finalized_head_slot,
            "observedLagSlots": self.observed_lag_slots,
        }


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _report_certificate_id(value: Any) -> str:
    """Keep a verifier-supplied certificate id only in its exact canonical shape."""
    return value if isinstance(value, str) and _CERTIFICATE_ID.match(value) else ""


def normalize_verification_result(
    payload: Any,
    *,
    package_hash: PackageHashResult | None = None,
    explorer_url: str | None = None,
) -> VerificationReport:
    """Turn a verifier response into a UI-safe report.

    * ``INVALID`` (and any unrecognized status) clears ``disclosedFields`` and
      ``disclosureMode`` — a failed verification discloses nothing.
    * ``VERIFIED_NO_INCIDENT_CHECK`` is reported exactly as received and is
      never promoted to ``VERIFIED``.
    """
    if not isinstance(payload, dict):
        return VerificationReport(
            status=INVALID,
            code="VERIFIER_RESPONSE_INVALID",
            certificate_id="",
            package_hash=package_hash,
            explorer_url=explorer_url,
        )
    raw_status = payload.get("status")
    status = raw_status if isinstance(raw_status, str) else INVALID
    if status not in KNOWN_VERIFICATION_STATUSES:
        status = INVALID
        code = VERIFICATION_STATUS_UNKNOWN
    else:
        code = _string_or_none(payload.get("code"))

    disclosed = payload.get("disclosedFields")
    disclosure_mode = payload.get("disclosureMode")
    if status == INVALID:
        # A failed verification must not disclose any field value.
        disclosed = {}
        disclosure_mode = None
    elif not isinstance(disclosed, dict):
        disclosed = {}

    warnings = payload.get("warnings")
    if not isinstance(warnings, list):
        warnings = []
    clean_warnings = tuple(item for item in warnings if isinstance(item, str))[:16]

    return VerificationReport(
        status=status,
        code=code,
        certificate_id=_report_certificate_id(payload.get("certificateId")),
        batch_sequence=_string_or_none(payload.get("batchSequence")),
        solana_slot=_string_or_none(payload.get("solanaSlot")),
        record_version=_string_or_none(payload.get("recordVersion")),
        current_record_version=_string_or_none(payload.get("currentRecordVersion")),
        certificate_lifecycle=_string_or_none(payload.get("certificateLifecycle")),
        incident_index_status=_string_or_none(payload.get("incidentIndexStatus")),
        warnings=clean_warnings,
        disclosure_mode=disclosure_mode if isinstance(disclosure_mode, str) else None,
        disclosed_fields=dict(disclosed),
        explorer_url=explorer_url,
        package_hash=package_hash,
    )


def normalize_verification_result_v2(
    payload: Any,
    *,
    package_hash: PackageHashResult | None = None,
    explorer_url: str | None = None,
) -> VerificationReport:
    """Turn a ``/v2/verify`` response into a UI-safe report (strict, versioned).

    The /v2 wire contract is authoritative (``resultVersion == 2``); there is no
    fallback to the /v1 shape and nothing here may claim proven currentness.
    Nested ``proofs`` / ``registry`` / ``incidents`` / ``lifecycle`` are parsed
    strictly and their checked/observed slots are normalized. The overall
    ``status`` is the honest verdict — ``UNKNOWN`` until a complete,
    authenticated lifecycle source exists — while the proof status is surfaced
    separately so "proof VERIFIED + overall UNKNOWN" is visible. A response that
    is not a well-formed v2 body is ``INVALID`` and discloses nothing.
    """

    def invalid(code: str) -> VerificationReport:
        return VerificationReport(
            status=INVALID,
            code=code,
            certificate_id="",
            package_hash=package_hash,
            explorer_url=explorer_url,
            result_version=2,
        )

    if not isinstance(payload, dict) or payload.get("resultVersion") != 2:
        return invalid("VERIFIER_RESPONSE_INVALID")

    raw_status = payload.get("status")
    status = raw_status if isinstance(raw_status, str) and raw_status in KNOWN_VERIFICATION_STATUSES else INVALID
    if raw_status != status:
        # Unrecognized status is treated as INVALID and claims nothing.
        return invalid(VERIFICATION_STATUS_UNKNOWN)
    code = _string_or_none(payload.get("code"))

    proofs = payload.get("proofs") if isinstance(payload.get("proofs"), dict) else {}
    registry = payload.get("registry") if isinstance(payload.get("registry"), dict) else {}
    incidents = payload.get("incidents") if isinstance(payload.get("incidents"), dict) else {}
    lifecycle = payload.get("lifecycle") if isinstance(payload.get("lifecycle"), dict) else {}
    reported = lifecycle.get("reported") if isinstance(lifecycle.get("reported"), dict) else {}

    disclosed = payload.get("disclosedFields")
    disclosure_mode = payload.get("disclosureMode")
    if status == INVALID:
        # A failed verification must not disclose any field value.
        disclosed = {}
        disclosure_mode = None
    elif not isinstance(disclosed, dict):
        disclosed = {}

    warnings = payload.get("warnings")
    if not isinstance(warnings, list):
        warnings = []
    clean_warnings = tuple(item for item in warnings if isinstance(item, str))[:16]

    return VerificationReport(
        status=status,
        code=code,
        certificate_id=_report_certificate_id(payload.get("certificateId")),
        batch_sequence=_string_or_none(payload.get("batchSequence")),
        solana_slot=_string_or_none(proofs.get("anchorSlot")),
        record_version=_string_or_none(payload.get("recordVersion")),
        current_record_version=_string_or_none(reported.get("currentRecordVersion")),
        certificate_lifecycle=_string_or_none(reported.get("certificateStatus")) or _string_or_none(lifecycle.get("status")),
        incident_index_status=_string_or_none(incidents.get("status")),
        warnings=clean_warnings,
        disclosure_mode=disclosure_mode if isinstance(disclosure_mode, str) else None,
        disclosed_fields=dict(disclosed),
        explorer_url=explorer_url,
        package_hash=package_hash,
        result_version=2,
        proofs_status=_string_or_none(proofs.get("status")),
        registry_id=_string_or_none(registry.get("registryId")),
        registry_status=_string_or_none(registry.get("status")),
        lifecycle_status=_string_or_none(lifecycle.get("status")),
        lifecycle_code=_string_or_none(lifecycle.get("code")),
        checked_slot=_string_or_none(proofs.get("anchorSlot")),
        observed_indexed_through_slot=_string_or_none(incidents.get("indexedThroughSlot")),
        observed_finalized_head_slot=_string_or_none(incidents.get("finalizedHeadSlot")),
        observed_lag_slots=_string_or_none(incidents.get("lagSlots")),
    )


# --------------------------------------------------------------------------
# URL helpers — loopback only; explorer URL is validated and never fetched.
# --------------------------------------------------------------------------


def validate_explorer_url(value: Any) -> str | None:
    """Accept only a canonical Solana explorer devnet transaction URL.

    The URL is shown for "Open in Explorer"; this module never fetches it. Any
    other shape is dropped rather than rendered as a link.
    """
    if not isinstance(value, str):
        return None
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "explorer.solana.com"
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        return None
    match = re.fullmatch(r"/tx/([1-9A-HJ-NP-Za-km-z]{32,96})", parsed.path)
    if match is None:
        return None
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if query != {"cluster": "devnet"}:
        return None
    return f"https://explorer.solana.com/tx/{match.group(1)}?cluster=devnet"


def parse_qr_payload(payload: Any) -> tuple[str, str]:
    """Extract ``(certificate_id, qr_hash)`` from a decoded QR URL.

    The QR URL is only parsed — never fetched. It must be an explicit IPv4
    loopback URL shaped like ``http://127.0.0.1:<port>/c/<id>?h=<hash>``.
    """
    if not isinstance(payload, str) or not payload or len(payload) > 2048:
        raise ProtocolError("error", "QR payload is malformed")
    parsed = urlsplit(payload)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or not parsed.port
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ProtocolError("error", "QR payload is not a loopback URL")
    match = re.fullmatch(r"/c/([0-9a-f]{32})", parsed.path)
    if match is None:
        raise ProtocolError("error", "QR payload path is malformed")
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if len(query) != 1 or query[0][0] != "h":
        raise ProtocolError("error", "QR payload query is malformed")
    qr_hash = query[0][1]
    if not _QR_HASH.match(qr_hash):
        raise ProtocolError("error", "QR payload hash is malformed")
    return match.group(1), qr_hash


def qr_hash_to_hex(value: Any) -> str | None:
    """Decode the 32-byte base64url QR hash the way demo-api's qrHashHex does."""
    if not isinstance(value, str) or not _QR_HASH.match(value):
        return None
    try:
        raw = decode_base64url(value, label="qr hash")
    except ProtocolError:
        return None
    if len(raw) != 32:
        return None
    return raw.hex()


# --------------------------------------------------------------------------
# UI-facing result dataclasses.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RecordVersion:
    internal_record_id: str
    record_version: str
    status: str
    origin: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "internalRecordId": self.internal_record_id,
            "recordVersion": self.record_version,
            "status": self.status,
            "origin": self.origin,
        }


@dataclass(frozen=True)
class RecordSummary:
    internal_record_id: str
    record_version: str
    status: str
    origin: str
    fields: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "internalRecordId": self.internal_record_id,
            "recordVersion": self.record_version,
            "status": self.status,
            "origin": self.origin,
            "fields": dict(self.fields),
        }


@dataclass(frozen=True)
class AccountReview:
    """One account of the prepared publish transaction, as reviewed on screen."""

    address: str
    role: str

    def as_dict(self) -> dict[str, Any]:
        return {"address": self.address, "role": self.role}


def _parse_account(item: Any, index: int) -> AccountReview:
    label = f"review.accounts[{index}]"
    if isinstance(item, str):
        # Validated-address fallback for a role-less entry; the real API always
        # sends {address, role} objects (admin-transaction.ts AccountReview).
        return AccountReview(
            address=_require_string(item, label, _PUBKEY),
            role=ACCOUNT_ROLE_UNSPECIFIED,
        )
    if isinstance(item, dict):
        if set(item) != {"address", "role"}:
            raise ProtocolError("error", f"{label} fields are invalid")
        role = item.get("role")
        if role not in ACCOUNT_ROLES:
            raise ProtocolError("error", f"{label}.role is invalid")
        return AccountReview(
            address=_require_string(item.get("address"), f"{label}.address", _PUBKEY),
            role=role,
        )
    raise ProtocolError("error", f"{label} is invalid")


def _parse_accounts(value: Any) -> tuple[AccountReview, ...]:
    if not isinstance(value, list) or not value or len(value) > _MAX_ACCOUNTS:
        raise ProtocolError("error", "review.accounts is malformed")
    return tuple(_parse_account(item, index) for index, item in enumerate(value))


@dataclass(frozen=True)
class PublishPlan:
    """The exact parameters the operator must see before approving a publish.

    Types mirror the demo-api review payload exactly: decimal identifiers stay
    decimal strings (the A1 signer's ``decimal()`` shape) while counts and
    indexes are real numbers. Nothing here is a secret.
    """

    cluster: str
    registry_id: str
    program_id: str
    config_pda: str
    role_pda: str
    segment_pda: str
    segment_index: int
    day_utc: int
    fee_payer: str
    batch_sequence: str
    registry_version: str
    cursor_start: str
    cursor_end: str
    leaf_count: int
    merkle_root: str
    manifest_hash: str
    previous_anchor_hash: str
    instruction_data: str
    transaction_base64: str
    accounts: tuple[AccountReview, ...]
    simulation_ok: bool
    simulation_error: str | None
    units_consumed: int | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "cluster": self.cluster,
            "registryId": self.registry_id,
            "programId": self.program_id,
            "configPda": self.config_pda,
            "rolePda": self.role_pda,
            "segmentPda": self.segment_pda,
            "segmentIndex": self.segment_index,
            "dayUtc": self.day_utc,
            "feePayer": self.fee_payer,
            "batchSequence": self.batch_sequence,
            "registryVersion": self.registry_version,
            "cursorStart": self.cursor_start,
            "cursorEnd": self.cursor_end,
            "leafCount": self.leaf_count,
            "merkleRoot": self.merkle_root,
            "manifestHash": self.manifest_hash,
            "previousAnchorHash": self.previous_anchor_hash,
            "instructionData": self.instruction_data,
            "transactionBase64": self.transaction_base64,
            "accounts": [account.as_dict() for account in self.accounts],
            "simulation": {
                "ok": self.simulation_ok,
                "error": self.simulation_error,
                "unitsConsumed": self.units_consumed,
            },
        }


@dataclass(frozen=True)
class PublishReview:
    """A publish intent exactly as the server reports it, with no secret material.

    Parsing is fail-closed: every signer-facing field is required and strictly
    typed, so an unknown or malformed core review can never reach an approve
    action.
    """

    intent_id: str
    intent_hash: str
    state: str
    batch_sequence: str
    plan: PublishPlan
    recent_blockhash: str
    last_valid_block_height: str
    expires_at: str | None
    transaction_signature: str | None
    anchor_slot: str | None
    certificate_id: str | None
    failure_code: str | None
    replayed: bool

    @property
    def can_approve(self) -> bool:
        """True only for a fully simulated intent; a failed simulation never is."""
        return self.state == INTENT_STATE_SIMULATED and self.plan.simulation_ok

    def signer_request_fields(self, approved: bool = False) -> dict[str, Any]:
        """Assemble the exact A1 signer request for this review. Never signs.

        ``approved`` is the explicit approval marker the launcher sets only
        after the operator pressed Approve; it defaults to ``False`` so a
        preview can never be piped to the signer as an approved request. The
        signer contract (``apps/demo-api/scripts/live-demo-sign.ts``) expects
        ``merkleRootHex``/``manifestHashHex``/``previousAnchorHashHex``, which
        map from the review's ``merkleRoot``/``manifestHash``/
        ``previousAnchorHash``; ``messageBase64`` is deliberately absent.
        """
        if not isinstance(approved, bool):
            raise ProtocolError("error", "approval marker must be a boolean")
        if not self.can_approve:
            raise ProtocolError("error", "publish review is not approvable")
        plan = self.plan
        return {
            "approved": approved,
            "intentId": self.intent_id,
            "cluster": plan.cluster,
            "intentHash": self.intent_hash,
            "transactionBase64": plan.transaction_base64,
            "instructionData": plan.instruction_data,
            "intent": {
                "registryId": plan.registry_id,
                "batchSequence": plan.batch_sequence,
                "registryVersion": plan.registry_version,
                "cursorStart": plan.cursor_start,
                "cursorEnd": plan.cursor_end,
                "leafCount": plan.leaf_count,
                "merkleRootHex": plan.merkle_root,
                "manifestHashHex": plan.manifest_hash,
                "previousAnchorHashHex": plan.previous_anchor_hash,
                "programId": plan.program_id,
                "configPda": plan.config_pda,
                "rolePda": plan.role_pda,
                "segmentPda": plan.segment_pda,
                "segmentIndex": plan.segment_index,
                "dayUtc": plan.day_utc,
                "feePayer": plan.fee_payer,
                "recentBlockhash": self.recent_blockhash,
                "lastValidBlockHeight": self.last_valid_block_height,
            },
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "intentId": self.intent_id,
            "intentHash": self.intent_hash,
            "state": self.state,
            "batchSequence": self.batch_sequence,
            "plan": self.plan.as_dict(),
            "recentBlockhash": self.recent_blockhash,
            "lastValidBlockHeight": self.last_valid_block_height,
            "expiresAt": self.expires_at,
            "transactionSignature": self.transaction_signature,
            "anchorSlot": self.anchor_slot,
            "certificateId": self.certificate_id,
            "failureCode": self.failure_code,
            "replayed": self.replayed,
            "canApprove": self.can_approve,
        }


@dataclass(frozen=True)
class IssuedCertificate:
    intent_id: str
    certificate_id: str
    certificate_hash: str
    qr_url: str
    transaction_signature: str
    anchor_slot: str
    explorer_url: str | None
    disclosure_mode: str
    disclosed_paths: tuple[str, ...]
    field_count: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "intentId": self.intent_id,
            "certificateId": self.certificate_id,
            "certificateHash": self.certificate_hash,
            "qrUrl": self.qr_url,
            "transactionSignature": self.transaction_signature,
            "anchorSlot": self.anchor_slot,
            "explorerUrl": self.explorer_url,
            "disclosureMode": self.disclosure_mode,
            "disclosedPaths": list(self.disclosed_paths),
            "fieldCount": self.field_count,
        }


@dataclass(frozen=True)
class CertificateMetadata:
    certificate_id: str
    registry_id: str
    cluster: str
    status: str
    issued_at: str
    record_version: str
    certificate_hash: str
    qr_url: str
    disclosure_mode: str
    disclosed_paths: tuple[str, ...]
    batch_sequence: str
    anchor_slot: str
    transaction_signature: str
    merkle_root: str
    manifest_hash: str
    explorer_url: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "certificateId": self.certificate_id,
            "registryId": self.registry_id,
            "cluster": self.cluster,
            "status": self.status,
            "issuedAt": self.issued_at,
            "recordVersion": self.record_version,
            "certificateHash": self.certificate_hash,
            "qrUrl": self.qr_url,
            "disclosureMode": self.disclosure_mode,
            "disclosedPaths": list(self.disclosed_paths),
            "batchSequence": self.batch_sequence,
            "anchorSlot": self.anchor_slot,
            "transactionSignature": self.transaction_signature,
            "merkleRoot": self.merkle_root,
            "manifestHash": self.manifest_hash,
            "explorerUrl": self.explorer_url,
        }


@dataclass(frozen=True)
class CertificatePackage:
    certificate_id: str
    package_base64url: str
    package_bytes: bytes
    certificate_hash_hex: str | None
    qr_url: str
    hash_result: PackageHashResult


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def _require_string(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise ProtocolError("error", f"{label} is malformed")
    return value


def _require_int_string(value: Any, label: str) -> str:
    return _require_string(value, label, _INT_STRING)


def _require_decimal(value: Any, label: str) -> str:
    """A signer-decimal string: 1..20 digits, no leading zeros."""
    return _require_string(value, label, _DECIMAL_20)


def _require_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError("error", f"{label} is malformed")
    if not minimum <= value <= maximum:
        raise ProtocolError("error", f"{label} is out of range")
    return value


def _require_day_utc(value: Any, label: str) -> int:
    """A ledger day: the UTC calendar day encoded as ``YYYYMMDD``.

    The same numeric contract as ``utc_day`` in the registry program,
    ``ledgerDay`` in the demo-api and ``validDayUtc`` in the readiness probe.
    An ordinal day number would be rejected on chain (``WrongLedgerDay``), so
    it is refused here before the review is shown for approval.
    """
    day = _require_int(value, label, 19700101, 99991231)
    year, month, date = day // 10_000, (day // 100) % 100, day % 100
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    month_days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    if not 1 <= month <= 12 or not 1 <= date <= month_days[month - 1]:
        raise ProtocolError("error", f"{label} is not a UTC calendar day")
    return day


def _optional(value: Any, label: str, pattern: re.Pattern[str]) -> str | None:
    if value is None:
        return None
    return _require_string(value, label, pattern)


def _standard_base64_length(value: str) -> int | None:
    """Decoded length of a standard-base64 string, or None when it is invalid."""
    if not _SIGNED_TX_B64.match(value):
        return None
    try:
        return len(base64.b64decode(value, validate=True))
    except (ValueError, TypeError):
        return None


def _record_fields(value: Any, label: str) -> dict[str, Any]:
    """Normalize the demo-api ``json_agg`` field array to a ``{path: value}`` map.

    ``GET /v1/admin/records`` returns ``fields`` as a JSON **array** of
    ``{path, type, value}`` objects (see ``RECORD_QUERY`` in
    ``apps/demo-api/src/admin.ts``); a mapping is never accepted. Malformed
    entries fail closed instead of being silently dropped.
    """
    if value is None:
        return {}
    if not isinstance(value, list) or len(value) > _MAX_RECORD_FIELDS:
        raise ProtocolError("error", f"{label} is malformed")
    fields: dict[str, Any] = {}
    for item in value:
        if not isinstance(item, dict):
            raise ProtocolError("error", f"{label} is malformed")
        path = item.get("path")
        if not isinstance(path, str) or not _FIELD_PATH.match(path):
            raise ProtocolError("error", f"{label} path is malformed")
        if path in fields:
            raise ProtocolError("error", f"{label} path is duplicated")
        field_value = item.get("value")
        if isinstance(field_value, str):
            if len(field_value.encode("utf-8")) > 4096:
                raise ProtocolError("error", f"{label} value is too long")
        elif field_value is not None and not isinstance(field_value, (int, float, bool)):
            raise ProtocolError("error", f"{label} value is malformed")
        fields[path] = field_value
    return fields


def _peek_certificate_id(package_bytes: bytes) -> str | None:
    """Best-effort certificate id for error reporting; never a verification."""
    try:
        body = decode_certificate_package(package_bytes)
    except (PackageFormatError, RecursionError):
        return None
    return body.certificate_id.hex()


# --------------------------------------------------------------------------
# LiveDemoApi — the single object the UI talks to.
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Durable workflow publication (M1) — the real /v2/admin/workflow/publications
# consumer. This is the reviewed-intent → approved reserved attempt → finalized
# anchor → certificate path. The legacy /v1 facade is not an acceptable live
# workflow consumer; the launcher drives THIS surface.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class DurableMember:
    event_id: str
    record_id: str
    version: int
    operation: str
    payload_hash: str


@dataclass(frozen=True)
class DurableSimulation:
    ok: bool
    error: str | None
    units_consumed: int | None

    def as_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "error": self.error, "unitsConsumed": self.units_consumed}


@dataclass(frozen=True)
class DurablePublicationReview:
    """The reviewed publication exactly as the server reports it (H3/r5).

    ``attemptPlanHash`` is the per-attempt approval commitment over the exact
    reserved bytes (semantic intent + lifetime + fee + message). It is the value
    the operator approves and passes to ``run`` as ``approvedAttemptPlanHash``;
    a new signature is never produced without it. ``None`` means there is nothing
    to approve (blocked, or a live signed attempt already exists → reconcile).
    Parsing is fail-closed: a malformed core review never reaches an approve.
    """

    operation_id: str
    intent_hash: str
    registry_id: str
    program_id: str
    config_pda: str
    operator: str
    operator_key_id: str
    batch_sequence: str
    registry_version: str
    previous_anchor_hash: str
    cursor_start: str
    cursor_end: str
    merkle_root: str
    manifest_hash: str
    leaf_count: int
    members: tuple[DurableMember, ...]
    blocked_reason: str | None
    attempt_states: tuple[tuple[int, str], ...]
    has_signed_attempt: bool
    has_live_signed_attempt: bool
    attempt_plan_hash: str | None
    attempt_no: int | None
    cluster: str
    fee_lamports: str
    fee_limit_lamports: str
    segment_pda: str | None
    segment_index: int | None
    blockhash: str | None
    last_valid_block_height: str | None
    message_base64: str | None
    simulation: DurableSimulation | None

    @property
    def can_approve(self) -> bool:
        """True only when a new signature is needed and a plan is reserved.

        A live signed attempt needs reconciliation (no approval); a blocked
        operation or an already-consumed plan never arms a new signature.
        """
        return self.attempt_plan_hash is not None and self.blocked_reason is None

    def as_dict(self) -> dict[str, Any]:
        """The exact hash/fee/lifetime/message plan the review card must show."""
        return {
            "operationId": self.operation_id,
            "intentHash": self.intent_hash,
            "registryId": self.registry_id,
            "programId": self.program_id,
            "configPda": self.config_pda,
            "operator": self.operator,
            "operatorKeyId": self.operator_key_id,
            "batchSequence": self.batch_sequence,
            "registryVersion": self.registry_version,
            "previousAnchorHash": self.previous_anchor_hash,
            "cursorStart": self.cursor_start,
            "cursorEnd": self.cursor_end,
            "merkleRoot": self.merkle_root,
            "manifestHash": self.manifest_hash,
            "leafCount": self.leaf_count,
            "members": [
                {
                    "eventId": m.event_id, "recordId": m.record_id, "version": m.version,
                    "operation": m.operation, "payloadHash": m.payload_hash,
                }
                for m in self.members
            ],
            "blockedReason": self.blocked_reason,
            "attemptStates": [{"attemptNo": n, "state": s} for n, s in self.attempt_states],
            "hasSignedAttempt": self.has_signed_attempt,
            "hasLiveSignedAttempt": self.has_live_signed_attempt,
            # Per-attempt approval commitment (H3) + reserved lifetime/fee/message.
            "attemptPlanHash": self.attempt_plan_hash,
            "attemptNo": self.attempt_no,
            "cluster": self.cluster,
            "feeLamports": self.fee_lamports,
            "feeLimitLamports": self.fee_limit_lamports,
            "segmentPda": self.segment_pda,
            "segmentIndex": self.segment_index,
            "blockhash": self.blockhash,
            "lastValidBlockHeight": self.last_valid_block_height,
            "messageBase64": self.message_base64,
            "simulation": self.simulation.as_dict() if self.simulation else None,
        }


def _durable_members(value: Any) -> tuple[DurableMember, ...]:
    if not isinstance(value, list) or len(value) > 512:
        raise ProtocolError("error", "review.members is malformed")
    members: list[DurableMember] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ProtocolError("error", f"review.members[{index}] is invalid")
        version = item.get("version")
        if not isinstance(version, int) or version < 1:
            raise ProtocolError("error", f"review.members[{index}].version is invalid")
        members.append(DurableMember(
            event_id=_require_string(item.get("eventId"), f"review.members[{index}].eventId", _IDENT),
            record_id=_require_string(item.get("recordId"), f"review.members[{index}].recordId", _IDENT),
            version=version,
            operation=_require_string(item.get("operation"), f"review.members[{index}].operation", _IDENT),
            payload_hash=_require_string(item.get("payloadHash"), f"review.members[{index}].payloadHash", _HASH_HEX),
        ))
    return tuple(members)


def _durable_simulation(value: Any) -> DurableSimulation | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ProtocolError("error", "review.simulation is malformed")
    ok = value.get("ok")
    if not isinstance(ok, bool):
        raise ProtocolError("error", "review.simulation.ok is invalid")
    units = value.get("unitsConsumed")
    return DurableSimulation(
        ok=ok,
        error=_string_or_none(value.get("error")),
        units_consumed=units if isinstance(units, int) and units >= 0 else None,
    )


def _durable_review(operation_id: str, review: Any) -> DurablePublicationReview:
    if not isinstance(review, dict):
        raise ProtocolError("error", "publication review is malformed")
    plan_hash = review.get("attemptPlanHash")
    if plan_hash is not None and not (isinstance(plan_hash, str) and _HASH_HEX.match(plan_hash)):
        raise ProtocolError("error", "review.attemptPlanHash is invalid")
    attempt_no = review.get("attemptNo")
    if attempt_no is not None and not (isinstance(attempt_no, int) and attempt_no >= 1):
        raise ProtocolError("error", "review.attemptNo is invalid")

    def opt_str(key: str) -> str | None:
        return _string_or_none(review.get(key))

    def req_str(key: str) -> str:
        value = review.get(key)
        if not isinstance(value, str) or not _IDENT.match(value):
            raise ProtocolError("error", f"review.{key} is malformed")
        return value

    raw_states = review.get("attemptStates")
    states: list[tuple[int, str]] = []
    if isinstance(raw_states, list):
        for item in raw_states[:64]:
            if isinstance(item, dict) and isinstance(item.get("attemptNo"), int) and isinstance(item.get("state"), str):
                states.append((int(item["attemptNo"]), item["state"]))
    segment_index = review.get("segmentIndex")
    leaf_count = review.get("leafCount")
    return DurablePublicationReview(
        operation_id=operation_id,
        intent_hash=_require_string(review.get("intentHash"), "review.intentHash", _HASH_HEX),
        registry_id=req_str("registryId"),
        program_id=_require_string(review.get("programId"), "review.programId", _PUBKEY),
        config_pda=_require_string(review.get("configPda"), "review.configPda", _PUBKEY),
        operator=_require_string(review.get("operator"), "review.operator", _PUBKEY),
        operator_key_id=req_str("operatorKeyId"),
        batch_sequence=_require_int_string(review.get("batchSequence"), "review.batchSequence"),
        registry_version=_require_int_string(review.get("registryVersion"), "review.registryVersion"),
        previous_anchor_hash=opt_str("previousAnchorHash") or "",
        cursor_start=_require_int_string(review.get("cursorStart"), "review.cursorStart"),
        cursor_end=_require_int_string(review.get("cursorEnd"), "review.cursorEnd"),
        merkle_root=_require_string(review.get("merkleRoot"), "review.merkleRoot", _HASH_HEX),
        manifest_hash=_require_string(review.get("manifestHash"), "review.manifestHash", _HASH_HEX),
        leaf_count=leaf_count if isinstance(leaf_count, int) and leaf_count >= 0 else 0,
        members=_durable_members(review.get("members")),
        blocked_reason=opt_str("blockedReason"),
        attempt_states=tuple(states),
        has_signed_attempt=bool(review.get("hasSignedAttempt")),
        has_live_signed_attempt=bool(review.get("hasLiveSignedAttempt")),
        attempt_plan_hash=plan_hash,
        attempt_no=attempt_no,
        cluster=req_str("cluster"),
        fee_lamports=_require_int_string(review.get("feeLamports"), "review.feeLamports"),
        fee_limit_lamports=_require_int_string(review.get("feeLimitLamports"), "review.feeLimitLamports"),
        segment_pda=opt_str("segmentPda"),
        segment_index=segment_index if isinstance(segment_index, int) and segment_index >= 0 else None,
        blockhash=opt_str("blockhash"),
        last_valid_block_height=opt_str("lastValidBlockHeight"),
        message_base64=opt_str("messageBase64"),
        simulation=_durable_simulation(review.get("simulation")),
    )


def _workflow_record_id(value: Any) -> str:
    return _require_string(value, "recordId", _WORKFLOW_RECORD)


def _draft_id(value: Any) -> str:
    return _require_string(value, "draftId", _OPERATION_ID)


def _workflow_version(value: Any, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 2147483647:
        raise ProtocolError("error", "workflow version is malformed")
    return value


def _workflow_operation(value: Any) -> str:
    if value not in ("upsert", "tombstone"):
        raise ProtocolError("error", "workflow operation is malformed")
    return value


def _workflow_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProtocolError("error", "workflow payload is malformed")
    try:
        encoded = json.dumps(dict(value), ensure_ascii=False, allow_nan=False).encode("utf8")
    except (TypeError, ValueError, UnicodeError):
        raise ProtocolError("error", "workflow payload is malformed") from None
    if len(encoded) > 65536:
        raise ProtocolError("error", "workflow payload is too large")
    return json.loads(encoded)


def _workflow_result(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError("error", f"{label} response is malformed")
    # Read endpoints expose database column names; mutation receipts expose
    # camelCase. Normalize both into the same UI contract.
    result = dict(value)
    for public, stored in (("draftId", "draft_id"), ("recordId", "record_id"),
                           ("payloadHash", "payload_hash"), ("baseVersion", "base_version")):
        if public not in result and stored in result:
            result[public] = result[stored]
    _draft_id(result.get("draftId"))
    _workflow_version(result.get("revision"), minimum=1)
    _workflow_version(result.get("baseVersion"))
    _require_string(result.get("payloadHash"), "payloadHash", _HASH_HEX)
    if result.get("state") not in ("DRAFT", "SUBMITTED", "APPROVED", "REJECTED", "COMMITTED"):
        raise ProtocolError("error", "workflow state is malformed")
    return result


class LiveDemoApi:
    """Records / publish / certificate / verify adapters for the demo launcher.

    Construction is cheap; nothing is contacted until a method is called. The
    UI never sees cookies, CSRF tokens, passwords or key material.
    """

    def __init__(
        self,
        profile: LiveDemoProfile,
        session: AdminSession,
        *,
        hash_verifier: PackageHashVerifier | None = None,
    ):
        if session.origin != profile.demo_api_origin:
            raise ValueError("session origin must be the profile demo-api origin")
        self._profile = profile
        self._session = session
        self._hash_verifier: PackageHashVerifier = hash_verifier or CanonicalPackageHasher()
        self._verifier_http = LoopbackHttp(
            profile.verifier_origin,
            max_response_bytes=1 << 20,
            max_request_bytes=MAX_REQUEST_BODY_BYTES,
        )

    # -- properties --------------------------------------------------------

    @property
    def profile(self) -> LiveDemoProfile:
        return self._profile

    @property
    def session(self) -> AdminSession:
        return self._session

    @property
    def signed_in(self) -> bool:
        return self._session.signed_in

    @property
    def session_summary(self) -> SessionSummary | None:
        return self._session.summary

    # -- session -----------------------------------------------------------

    def sign_in(self, identity: str = "operator") -> SessionSummary:
        """Sign in as one configured demo identity (password from the private file).

        The identity is a username; the returned role/permissions come from the
        server session only.
        """
        return self._session.sign_in(identity)

    def served_identity(self) -> dict[str, Any]:
        """The live demo-api identity from ``/v1/health`` (server configuration).

        Returns the served registry/cluster/genesis/program/config identity. A
        missing or malformed field is left absent so a caller fails closed.
        """
        response = self._session.request_bytes("GET", "/v1/health")
        payload = decode_json_body(response.body)
        if response.status != 200 or not isinstance(payload, dict):
            raise ProtocolError("error", "health response is malformed")

        def text(key: str) -> str | None:
            value = payload.get(key)
            return value if isinstance(value, str) and value else None

        return {
            "status": text("status"),
            "registryId": text("registryId"),
            "cluster": text("cluster"),
            "genesisHash": text("genesisHash"),
            "programId": text("programId"),
            "configPda": text("configPda"),
            "contractVersion": text("contractVersion"),
        }

    def verify_served_identity(self) -> dict[str, Any]:
        """Compare the served live identity to this profile; fail closed on drift.

        The launcher never asserts a fixed devnet: it requires the running stack
        to report exactly the configured namespace and cluster, and (when pinned)
        the configured genesis hash. A missing field is a mismatch, not a pass.
        """
        served = self.served_identity()
        mismatches: list[str] = []
        if served.get("registryId") != self._profile.registry_id:
            mismatches.append("registryId")
        if served.get("cluster") != self._profile.expected_cluster:
            mismatches.append("cluster")
        expected_genesis = self._profile.expected_genesis_hash
        if expected_genesis is not None and served.get("genesisHash") != expected_genesis:
            mismatches.append("genesisHash")
        return {"served": served, "matches": not mismatches, "mismatches": mismatches}

    def refresh(self) -> SessionSummary:
        return self._session.refresh()

    def sign_out(self) -> None:
        self._session.sign_out()

    # -- records -----------------------------------------------------------

    def create_record_version(
        self,
        internal_record_id: str,
        *,
        status: str,
        cadastral_number: str,
        area_square_meters: str,
        extra_fields: Mapping[str, Any] | None = None,
    ) -> RecordVersion:
        """Create the next version of a synthetic record.

        Re-sending the same ``internalRecordId`` creates a new version on the
        server; the previous version stays addressable by its version number.
        """
        record_id = _require_string(internal_record_id, "internalRecordId", _RECORD_ID)
        if status not in RECORD_STATUSES:
            raise ProtocolError("error", "record status is invalid")
        if not isinstance(cadastral_number, str) or not cadastral_number:
            raise ProtocolError("error", "cadastralNumber is required")
        if len(cadastral_number.encode("utf-8")) > 64:
            raise ProtocolError("error", "cadastralNumber is too long")
        if not isinstance(area_square_meters, str) or not _DECIMAL_2.match(area_square_meters):
            raise ProtocolError("error", "areaSquareMeters must have exactly two decimal places")
        fields: dict[str, Any] = {
            "status": status,
            "cadastralNumber": cadastral_number,
            "areaSquareMeters": area_square_meters,
        }
        if extra_fields:
            for key, value in extra_fields.items():
                if not isinstance(key, str) or not _FIELD_PATH.match(key):
                    raise ProtocolError("error", "record field path is invalid")
                if key in fields:
                    raise ProtocolError("error", "record field path is duplicated")
                if isinstance(value, str) and len(value.encode("utf-8")) > 4096:
                    raise ProtocolError("error", "record field value is too long")
                if not isinstance(value, (str, int, bool, type(None))):
                    raise ProtocolError("error", "record field value is invalid")
                fields[key] = value
        response = self._session.request_json(
            "POST",
            "/v1/admin/records",
            json_body={"internalRecordId": record_id, "status": status, "fields": fields},
        )
        payload = response.payload if isinstance(response.payload, dict) else {}
        return RecordVersion(
            internal_record_id=_require_string(payload.get("internalRecordId"), "internalRecordId", _RECORD_ID),
            record_version=_require_int_string(payload.get("recordVersion"), "recordVersion"),
            status=_require_string(payload.get("status"), "status", _TOKEN),
            origin=_require_string(payload.get("origin"), "origin", _TOKEN),
        )

    def list_records(self) -> list[RecordSummary]:
        response = self._session.request_json("GET", "/v1/admin/records")
        payload = response.payload if isinstance(response.payload, dict) else {}
        records = payload.get("records")
        if not isinstance(records, list):
            raise ProtocolError("error", "records response is malformed")
        summaries: list[RecordSummary] = []
        for item in records[:256]:
            if not isinstance(item, dict):
                raise ProtocolError("error", "records response is malformed")
            summaries.append(
                RecordSummary(
                    internal_record_id=_require_string(
                        item.get("internalRecordId"), "internalRecordId", _RECORD_ID
                    ),
                    record_version=_require_int_string(item.get("recordVersion"), "recordVersion"),
                    status=_require_string(item.get("status"), "status", _TOKEN),
                    origin=_require_string(item.get("origin"), "origin", _TOKEN),
                    fields=_record_fields(item.get("fields"), "record fields"),
                )
            )
        return summaries

    def get_record(self, internal_record_id: str) -> dict[str, Any]:
        record_id = _require_string(internal_record_id, "internalRecordId", _RECORD_ID)
        response = self._session.request_json("GET", f"/v1/admin/records/{record_id}")
        if not isinstance(response.payload, dict):
            raise ProtocolError("error", "record response is malformed")
        return dict(response.payload)

    def get_preview(self) -> dict[str, Any]:
        response = self._session.request_json("GET", "/v1/admin/preview")
        if not isinstance(response.payload, dict):
            raise ProtocolError("error", "preview response is malformed")
        return dict(response.payload)

    # -- publish -----------------------------------------------------------

    def prepare_publish(
        self,
        operator_pubkey: str,
        *,
        idempotency_key: str,
        cluster: str = "solana:devnet",
    ) -> PublishReview:
        """Simulate a publish and return the review parameters to approve."""
        operator = _require_string(operator_pubkey, "operator", _PUBKEY)
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY.match(idempotency_key):
            raise ProtocolError("error", "idempotency key is malformed")
        if cluster != "solana:devnet":
            raise ProtocolError("error", "cluster must be solana:devnet")
        return self._intent_call(
            "POST",
            "/v1/admin/publish-intents",
            json_body={"operator": operator, "cluster": cluster},
            idempotency_key=idempotency_key,
        )

    def get_publish_intent(self, intent_id: str) -> PublishReview:
        return self._intent_call("GET", f"/v1/admin/publish-intents/{_intent_id(intent_id)}")

    def submit_signature(self, intent_id: str, signed_transaction_base64: str) -> PublishReview:
        """Submit the locally signed transaction. The signer never leaves the box.

        The wire transaction is standard base64 (the server decodes it with
        ``Buffer.from(value, "base64")`` and then checks that the message bytes
        are byte-identical to the prepared ``messageBase64`` and that the
        Ed25519 signature is valid for the operator key).
        """
        if not isinstance(signed_transaction_base64, str) or not signed_transaction_base64:
            raise ProtocolError("error", "signed transaction is required")
        if len(signed_transaction_base64) > 8192:
            raise ProtocolError("error", "signed transaction is too large")
        if not _SIGNED_TX_B64.match(signed_transaction_base64):
            raise ProtocolError("error", "signed transaction is not base64")
        return self._intent_call(
            "POST",
            f"/v1/admin/publish-intents/{_intent_id(intent_id)}/signature",
            json_body={"signedTransactionBase64": signed_transaction_base64},
        )

    def reconcile(self, intent_id: str) -> PublishReview:
        """Ask the server to confirm FINALIZED on devnet."""
        return self._intent_call(
            "POST", f"/v1/admin/publish-intents/{_intent_id(intent_id)}/reconciliation"
        )

    def reject_signature(self, intent_id: str) -> PublishReview:
        return self._intent_call(
            "POST", f"/v1/admin/publish-intents/{_intent_id(intent_id)}/rejection"
        )

    def issue_certificate(
        self,
        intent_id: str,
        internal_record_id: str,
        *,
        disclosed_paths: Sequence[str] | None = None,
    ) -> IssuedCertificate:
        """Issue a certificate for one record from a FINALIZED publish intent.

        ``disclosed_paths`` selects selective disclosure (for this demo:
        ``status`` and ``areaSquareMeters`` only). Omit it for the whole record.
        """
        record_id = _require_string(internal_record_id, "internalRecordId", _RECORD_ID)
        body: dict[str, Any] = {"internalRecordId": record_id}
        if disclosed_paths is not None:
            if not disclosed_paths:
                raise ProtocolError("error", "disclosedPaths must not be empty")
            paths = []
            for path in disclosed_paths:
                if not isinstance(path, str) or not _FIELD_PATH.match(path):
                    raise ProtocolError("error", DISCLOSED_PATH_INVALID)
                paths.append(path)
            if len(set(paths)) != len(paths):
                raise ProtocolError("error", "disclosedPaths is duplicated")
            body["disclosedPaths"] = paths
        response = self._session.request_json(
            "POST",
            f"/v1/admin/publish-intents/{_intent_id(intent_id)}/certificate",
            json_body=body,
        )
        payload = response.payload if isinstance(response.payload, dict) else {}
        disclosed = payload.get("disclosedPaths")
        field_count = payload.get("fieldCount")
        return IssuedCertificate(
            intent_id=_require_string(payload.get("intentId"), "intentId", _INTENT_ID),
            certificate_id=_require_string(payload.get("certificateId"), "certificateId", _CERTIFICATE_ID),
            certificate_hash=_require_string(payload.get("certificateHash"), "certificateHash", _HASH_HEX),
            qr_url=_require_string(payload.get("qrUrl"), "qrUrl", re.compile(r"^.{1,2048}$")),
            transaction_signature=_require_string(
                payload.get("transactionSignature"), "transactionSignature", _SIGNATURE
            ),
            anchor_slot=_require_int_string(payload.get("anchorSlot"), "anchorSlot"),
            explorer_url=validate_explorer_url(payload.get("explorerUrl")),
            disclosure_mode=_require_string(payload.get("disclosureMode"), "disclosureMode", _TOKEN),
            disclosed_paths=tuple(disclosed) if isinstance(disclosed, list) else (),
            field_count=field_count if isinstance(field_count, int) and field_count >= 0 else 0,
        )

    # -- certificates ------------------------------------------------------

    def list_certificates(self) -> list[dict[str, Any]]:
        response = self._session.request_json("GET", "/v1/admin/certificates")
        payload = response.payload if isinstance(response.payload, dict) else {}
        certificates = payload.get("certificates")
        if not isinstance(certificates, list):
            raise ProtocolError("error", "certificates response is malformed")
        return [dict(item) for item in certificates[:256] if isinstance(item, dict)]

    def get_certificate_metadata(self, certificate_id: str) -> CertificateMetadata:
        cert_id = _certificate_id(certificate_id)
        response = self._session.request_json("GET", f"/v1/certificates/{cert_id}/metadata")
        payload = response.payload if isinstance(response.payload, dict) else {}
        disclosed = payload.get("disclosedPaths")
        return CertificateMetadata(
            certificate_id=_require_string(payload.get("certificateId"), "certificateId", _CERTIFICATE_ID),
            registry_id=_string_or_none(payload.get("registryId")) or "",
            cluster=_string_or_none(payload.get("cluster")) or "",
            status=_require_string(payload.get("status"), "status", _TOKEN),
            issued_at=_string_or_none(payload.get("issuedAt")) or "",
            record_version=_require_int_string(payload.get("recordVersion"), "recordVersion"),
            certificate_hash=_require_string(payload.get("certificateHash"), "certificateHash", _HASH_HEX),
            qr_url=_string_or_none(payload.get("qrUrl")) or "",
            disclosure_mode=_require_string(payload.get("disclosureMode"), "disclosureMode", _TOKEN),
            disclosed_paths=tuple(disclosed) if isinstance(disclosed, list) else (),
            batch_sequence=_require_int_string(payload.get("batchSequence"), "batchSequence"),
            anchor_slot=_require_int_string(payload.get("anchorSlot"), "anchorSlot"),
            transaction_signature=_require_string(
                payload.get("transactionSignature"), "transactionSignature", _SIGNATURE
            ),
            merkle_root=_require_string(payload.get("merkleRoot"), "merkleRoot", _HASH_HEX),
            manifest_hash=_require_string(payload.get("manifestHash"), "manifestHash", _HASH_HEX),
            explorer_url=validate_explorer_url(payload.get("explorerUrl")),
        )

    def get_certificate_package(
        self, certificate_id: str, *, qr_hash: str | None = None
    ) -> CertificatePackage:
        """Fetch a certificate package, optionally pinned to a QR-carried hash."""
        cert_id = _certificate_id(certificate_id)
        path = f"/v1/certificates/{cert_id}/package"
        expected_hex: str | None = None
        expected_source: str | None = None
        if qr_hash is not None:
            if not _QR_HASH.match(qr_hash):
                raise ProtocolError("error", "QR hash is malformed")
            expected_hex = qr_hash_to_hex(qr_hash)
            if expected_hex is None:
                raise ProtocolError("error", "QR hash is malformed")
            expected_source = "qr"
            path = f"{path}?h={qr_hash}"
        response = self._session.request_json("GET", path)
        payload = response.payload if isinstance(response.payload, dict) else {}
        package_base64url = payload.get("package_base64url")
        if not isinstance(package_base64url, str) or not _BASE64URL.match(package_base64url):
            raise ProtocolError("error", "package response is malformed")
        package_bytes = decode_base64url(package_base64url, label="package_base64url")
        if len(package_bytes) > MAX_PACKAGE_BYTES:
            raise ProtocolError("error", "certificate package is too large")
        stored_hash = payload.get("certificateHash")
        if expected_hex is None and isinstance(stored_hash, str) and _HASH_HEX.match(stored_hash):
            # No QR hash to pin against: use the served hash as an explicit
            # self-consistency check and label it as such.
            expected_hex = stored_hash
            expected_source = "document"
        hash_result = self._hash_verifier.verify(
            package_bytes, expected_hex, expected_source=expected_source
        )
        return CertificatePackage(
            certificate_id=cert_id,
            package_base64url=package_base64url,
            package_bytes=package_bytes,
            certificate_hash_hex=stored_hash if isinstance(stored_hash, str) else None,
            qr_url=_string_or_none(payload.get("qrUrl")) or "",
            hash_result=hash_result,
        )

    def get_qr_image(self, certificate_id: str, *, fmt: str = "png") -> bytes:
        """Fetch a QR image. The payload is the certificate's loopback QR URL."""
        if fmt not in ("png", "svg"):
            raise ProtocolError("error", "QR format must be png or svg")
        cert_id = _certificate_id(certificate_id)
        response = self._session.request_bytes("GET", f"/v1/qr/{cert_id}.{fmt}")
        if response.status >= 400:
            raise ApiRefusal(response.status, None, "error")
        if len(response.body) > MAX_QR_IMAGE_BYTES:
            raise ProtocolError("error", "QR image is too large")
        if fmt == "png" and not response.body.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ProtocolError("error", "QR image is not a PNG")
        return response.body

    def get_certificate_lifecycle(self, certificate_id: str) -> dict[str, Any]:
        cert_id = _certificate_id(certificate_id)
        path = f"/v1/certificates/{cert_id}/lifecycle?registryId={self._profile.registry_id}"
        response = self._session.request_json("GET", path)
        if not isinstance(response.payload, dict):
            raise ProtocolError("error", "lifecycle response is malformed")
        return dict(response.payload)

    def get_certificate_status(self, certificate_id: str) -> dict[str, Any]:
        cert_id = _certificate_id(certificate_id)
        response = self._session.request_json("GET", f"/v1/certificates/{cert_id}/status")
        if not isinstance(response.payload, dict):
            raise ProtocolError("error", "status response is malformed")
        return dict(response.payload)

    # -- registry workflow drafts (role-aware /v2) -------------------------
    #
    # The durable draft lifecycle: discover → create → read → edit (revise) →
    # submit → a DIFFERENT authenticated approver approve/reject → commit. The
    # commit produces the outbox row the durable publication review later
    # reserves. Every call is authorized by the server session; the renderer
    # never decides the role or the scope.

    def list_workflow_drafts(self, after: str | None = None) -> dict[str, Any]:
        path = "/v2/admin/workflow/drafts"
        if after is not None:
            if not _OPERATION_ID.match(after):
                raise ProtocolError("error", "draft cursor is malformed")
            path += "?after=" + after
        response = self._session.request_json("GET", path)
        if not isinstance(response.payload, dict) or not isinstance(response.payload.get("drafts"), list):
            raise ProtocolError("error", "draft list is malformed")
        return dict(response.payload)

    def read_workflow_draft(self, draft_id: str) -> dict[str, Any]:
        response = self._session.request_json("GET", f"/v2/admin/workflow/drafts/{_draft_id(draft_id)}")
        if not isinstance(response.payload, dict):
            raise ProtocolError("error", "draft is malformed")
        return dict(response.payload)

    def create_workflow_draft(
        self,
        *,
        record_id: str,
        base_version: int,
        operation: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
    ) -> dict[str, Any]:
        body = {
            "recordId": _workflow_record_id(record_id),
            "baseVersion": _workflow_version(base_version),
            "operation": _workflow_operation(operation),
            "payload": _workflow_payload(payload),
        }
        response = self._session.request_json(
            "POST", "/v2/admin/workflow/drafts", json_body=body, idempotency_key=idempotency_key
        )
        return _workflow_result(response.payload, "draft")

    def edit_workflow_draft(
        self,
        draft_id: str,
        *,
        expected_revision: int,
        operation: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
    ) -> dict[str, Any]:
        body = {
            "expectedRevision": _workflow_version(expected_revision, minimum=1),
            "operation": _workflow_operation(operation),
            "payload": _workflow_payload(payload),
        }
        response = self._session.request_json(
            "POST", f"/v2/admin/workflow/drafts/{_draft_id(draft_id)}/edit",
            json_body=body, idempotency_key=idempotency_key,
        )
        return _workflow_result(response.payload, "draft")

    def _workflow_action(
        self,
        draft_id: str,
        action: str,
        *,
        expected_revision: int,
        payload_hash: str,
        base_version: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        if not _HASH_HEX.match(payload_hash):
            raise ProtocolError("error", "payload hash is malformed")
        body = {
            "expectedRevision": _workflow_version(expected_revision, minimum=1),
            "payloadHash": payload_hash,
            "baseVersion": _workflow_version(base_version),
        }
        response = self._session.request_json(
            "POST", f"/v2/admin/workflow/drafts/{_draft_id(draft_id)}/{action}",
            json_body=body, idempotency_key=idempotency_key,
        )
        return _workflow_result(response.payload, "draft")

    def submit_workflow_draft(self, draft_id: str, **binding: Any) -> dict[str, Any]:
        return self._workflow_action(draft_id, "submit", **binding)

    def approve_workflow_draft(self, draft_id: str, **binding: Any) -> dict[str, Any]:
        return self._workflow_action(draft_id, "approve", **binding)

    def reject_workflow_draft(self, draft_id: str, **binding: Any) -> dict[str, Any]:
        return self._workflow_action(draft_id, "reject", **binding)

    def commit_workflow_draft(self, draft_id: str, **binding: Any) -> dict[str, Any]:
        return self._workflow_action(draft_id, "commit", **binding)

    def read_workflow_record_version(self, record_id: str, version: str | int = "latest") -> dict[str, Any]:
        if version != "latest" and not (isinstance(version, int) and version >= 1):
            raise ProtocolError("error", "record version is malformed")
        response = self._session.request_json(
            "GET", f"/v2/admin/workflow/records/{_workflow_record_id(record_id)}/versions/{version}"
        )
        if not isinstance(response.payload, dict):
            raise ProtocolError("error", "record version is malformed")
        return dict(response.payload)

    # -- durable workflow publication (M1) --------------------------------
    #
    # The real reviewed-intent → approved reserved attempt → finalized anchor →
    # certificate consumer. The operator approves the exact reserved bytes via
    # `approvedAttemptPlanHash`; this layer never signs or holds an issuer key.
    # A receipt/result always comes from the trusted backend, never a
    # renderer-held key. There is no fallback to the legacy /v1 facade.

    def durable_publications(self) -> dict[str, Any]:
        """Open/blocked operations + finalized anchors for the served registry."""
        response = self._session.request_json("GET", "/v2/admin/workflow/publications")
        if not isinstance(response.payload, dict):
            raise ProtocolError("error", "publications response is malformed")
        return dict(response.payload)

    def review_publication(self, operation_id: str | None = None) -> DurablePublicationReview:
        """Reserve/reuse the next unsigned attempt and return its exact plan.

        This is a no-sign/no-send review: it returns the reserved
        ``attemptPlanHash`` over the exact message + lifetime + fee. Calling it
        again returns the same plan (it does not reserve a second attempt).
        """
        body: dict[str, Any] = {}
        if operation_id is not None:
            body["operationId"] = _require_string(operation_id, "operationId", _OPERATION_ID)
        response = self._session.request_json(
            "POST", "/v2/admin/workflow/publications/review", json_body=body
        )
        payload = response.payload if isinstance(response.payload, dict) else {}
        returned_op = _require_string(payload.get("operationId"), "operationId", _OPERATION_ID)
        return _durable_review(returned_op, payload.get("review"))

    def run_publication(
        self,
        *,
        approved_attempt_plan_hash: str | None,
        approved_intent_hash: str | None = None,
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        """Advance one durable step.

        A NEW signature requires ``approved_attempt_plan_hash`` — the exact
        ``attemptPlanHash`` returned by :meth:`review_publication`. A stale or
        missing plan never arms a new lifetime (the backend refuses with
        ``PUBLICATION_ATTEMPT_PLAN_MISMATCH`` /
        ``PUBLICATION_INTENT_APPROVAL_REQUIRED``). Reconciliation of an already
        live signed attempt passes ``approved_attempt_plan_hash=None`` and needs
        no approval. ``approved_intent_hash`` is optional defence-in-depth.
        """
        body: dict[str, Any] = {}
        if operation_id is not None:
            body["operationId"] = _require_string(operation_id, "operationId", _OPERATION_ID)
        if approved_attempt_plan_hash is not None:
            body["approvedAttemptPlanHash"] = _require_string(
                approved_attempt_plan_hash, "approvedAttemptPlanHash", _HASH_HEX
            )
        if approved_intent_hash is not None:
            body["approvedIntentHash"] = _require_string(
                approved_intent_hash, "approvedIntentHash", _HASH_HEX
            )
        response = self._session.request_json(
            "POST", "/v2/admin/workflow/publications/run", json_body=body
        )
        if not isinstance(response.payload, dict):
            raise ProtocolError("error", "publication run response is malformed")
        return dict(response.payload)

    def issue_workflow_certificate(
        self,
        operation_id: str,
        record_id: str,
        version: int,
        *,
        disclosed_paths: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        """Issue a certificate from a FINALIZED workflow operation.

        The server enforces object/record AND every disclosed field path against
        the session's resource policy; an omitted disclosure is FULL_RECORD and
        requires unrestricted access. Idempotent per (operation, record, version,
        disclosure).
        """
        op = _require_string(operation_id, "operationId", _OPERATION_ID)
        rid = _workflow_record_id(record_id)
        if not isinstance(version, int) or version < 1:
            raise ProtocolError("error", "version is invalid")
        body: dict[str, Any] = {"recordId": rid, "version": version}
        if disclosed_paths is not None:
            paths = []
            for path in disclosed_paths:
                if not isinstance(path, str) or not (_FIELD_PATH.match(path) or "." in path):
                    raise ProtocolError("error", "disclosed field path is invalid")
                paths.append(path)
            if len(paths) != len(set(paths)):
                raise ProtocolError("error", "disclosed field path is duplicated")
            body["disclosedPaths"] = paths
        response = self._session.request_json(
            "POST", f"/v2/admin/workflow/publications/{op}/certificate", json_body=body
        )
        if not isinstance(response.payload, dict):
            raise ProtocolError("error", "workflow certificate response is malformed")
        return dict(response.payload)

    # -- verify ------------------------------------------------------------

    def verify_package(
        self,
        package: bytes | str,
        *,
        expected_hash_hex: str | None = None,
        expected_source: str | None = None,
    ) -> VerificationReport:
        """Verify a certificate package with the loopback verifier.

        The package hash is checked against the canonical signed body first; a
        mismatch short-circuits to ``QR_HASH_MISMATCH`` without contacting the
        verifier. A package that cannot be parsed is ``INVALID`` /
        ``CERTIFICATE_FORMAT_INVALID``. ``VERIFIED_NO_INCIDENT_CHECK`` is never
        promoted to ``VERIFIED``, and an ``INVALID`` verdict never discloses
        field values.
        """
        if isinstance(package, str):
            package_bytes = decode_base64url(package, label="certificatePackage")
        elif isinstance(package, (bytes, bytearray)):
            package_bytes = bytes(package)
        else:
            raise ProtocolError("error", "certificate package is malformed")
        if len(package_bytes) > MAX_PACKAGE_BYTES:
            raise ProtocolError("error", "certificate package is too large")

        hash_result = self._hash_verifier.verify(
            package_bytes, expected_hash_hex, expected_source=expected_source
        )
        certificate_id = _peek_certificate_id(package_bytes) or ""
        if hash_result.verdict == HashVerdict.MISMATCH:
            return VerificationReport(
                status=INVALID,
                code=QR_HASH_MISMATCH,
                certificate_id=certificate_id,
                package_hash=hash_result,
            )
        if hash_result.verdict == HashVerdict.UNPARSEABLE:
            return VerificationReport(
                status=INVALID,
                code=CERTIFICATE_FORMAT_INVALID,
                certificate_id="",
                package_hash=hash_result,
            )
        if hash_result.verdict == HashVerdict.DEFERRED and expected_hash_hex is not None:
            # A QR-carried hash that cannot be confirmed is not a pass.
            return VerificationReport(
                status=INVALID,
                code=HASH_VERIFICATION_DEFERRED,
                certificate_id=certificate_id,
                package_hash=hash_result,
            )

        try:
            response = self._verifier_json(
                "POST",
                "/v2/verify",
                {"certificatePackage": encode_base64url(package_bytes), "requiredCommitment": "finalized"},
            )
        except LiveDemoError as error:
            code = getattr(error, "code", None) or (
                "VERIFIER_RESPONSE_INVALID"
                if isinstance(error, ProtocolError)
                else "VERIFIER_UNAVAILABLE"
            )
            return VerificationReport(
                status=INVALID,
                code=code,
                certificate_id=certificate_id,
                package_hash=hash_result,
            )
        explorer_url = None
        if isinstance(response, dict) and isinstance(response.get("certificateId"), str):
            explorer_url = self._explorer_for(response["certificateId"])
        return normalize_verification_result_v2(response, package_hash=hash_result, explorer_url=explorer_url)

    def verify_package_file(
        self,
        path: Path | str,
        *,
        expected_hash_hex: str | None = None,
        expected_source: str | None = None,
    ) -> VerificationReport:
        """Verify a locally saved package file. Reads a bounded amount only.

        A JSON document's self-declared ``certificateHash`` is used only as an
        explicit *self-consistency* check (labeled ``document``); it is never
        treated as proof. Pass the QR-carried hash when one is available.
        """
        file_path = Path(path)
        if file_path.is_symlink() or not file_path.is_file():
            raise ProtocolError("error", "package file is not a regular file")
        if file_path.stat().st_size > MAX_PACKAGE_BYTES:
            raise ProtocolError("error", "package file is too large")
        data = file_path.read_bytes()
        text = None
        try:
            text = data.decode("utf-8").strip()
        except UnicodeDecodeError:
            text = None
        if text and text.startswith("{"):
            try:
                document = json.loads(text)
            except RecursionError:
                raise ProtocolError("error", "package file is not JSON") from None
            except ValueError:
                raise ProtocolError("error", "package file is not JSON") from None
            if not isinstance(document, dict):
                raise ProtocolError("error", "package file is not a package document")
            payload = document.get("package_base64url")
            if not isinstance(payload, str):
                raise ProtocolError("error", "package document has no package_base64url")
            if expected_hash_hex is None:
                claimed = document.get("certificateHash")
                if isinstance(claimed, str) and _HASH_HEX.match(claimed):
                    expected_hash_hex = claimed
                    expected_source = expected_source or "document"
            return self.verify_package(
                payload, expected_hash_hex=expected_hash_hex, expected_source=expected_source
            )
        if text and _BASE64URL.match(text) and len(text) >= 100:
            return self.verify_package(
                text, expected_hash_hex=expected_hash_hex, expected_source=expected_source
            )
        return self.verify_package(
            data, expected_hash_hex=expected_hash_hex, expected_source=expected_source
        )

    def verify_qr_payload(self, qr_payload: str) -> VerificationReport:
        """Verify a decoded QR image payload: fetch the package, then verify.

        The QR URL is parsed but never fetched; the package comes from the
        demo-api loopback endpoint pinned to the hash the code carried.
        """
        certificate_id, qr_hash = parse_qr_payload(qr_payload)
        expected_hex = qr_hash_to_hex(qr_hash)
        if expected_hex is None:
            raise ProtocolError("error", "QR payload hash is malformed")
        try:
            package = self.get_certificate_package(certificate_id, qr_hash=qr_hash)
        except ApiRefusal as error:
            return VerificationReport(
                status=INVALID,
                code=error.code or "PACKAGE_UNAVAILABLE",
                certificate_id=certificate_id,
            )
        report = self.verify_package(
            package.package_base64url, expected_hash_hex=expected_hex, expected_source="qr"
        )
        if report.certificate_id:
            return report
        return VerificationReport(
            status=report.status,
            code=report.code,
            certificate_id=certificate_id,
            batch_sequence=report.batch_sequence,
            solana_slot=report.solana_slot,
            record_version=report.record_version,
            current_record_version=report.current_record_version,
            certificate_lifecycle=report.certificate_lifecycle,
            incident_index_status=report.incident_index_status,
            warnings=report.warnings,
            disclosure_mode=report.disclosure_mode,
            disclosed_fields=report.disclosed_fields,
            explorer_url=report.explorer_url,
            package_hash=report.package_hash,
        )

    # -- internals ---------------------------------------------------------

    def _explorer_for(self, certificate_id: str) -> str | None:
        if self._profile.is_local_cluster:
            return None
        # A verifier-supplied id never reaches a request path unvalidated.
        if not isinstance(certificate_id, str) or not _CERTIFICATE_ID.match(certificate_id):
            return None
        try:
            response = self._session.request_json("GET", f"/v1/certificates/{certificate_id}/metadata")
        except LiveDemoError:
            return None
        if isinstance(response.payload, dict):
            return validate_explorer_url(response.payload.get("explorerUrl"))
        return None

    def _verifier_json(self, method: str, path: str, body: Mapping[str, Any]) -> Any:
        # LoopbackHttp pins the verifier origin and refuses redirects; the path
        # is origin-relative so it cannot leave the loopback profile.
        build_loopback_url(self._profile.verifier_origin, path)
        payload = json.dumps(dict(body), separators=(",", ":")).encode("utf-8")
        if len(payload) > MAX_REQUEST_BODY_BYTES:
            raise ProtocolError("error", "verifier request is too large")
        response = self._verifier_http.request(
            method,
            path,
            body=payload,
            headers={"content-type": "application/json"},
        )
        if response.status == 422:
            # A 422 from the verifier carries the INVALID verdict body.
            return self._decode_verifier_body(response.body)
        if response.status >= 400:
            raise ApiRefusal(response.status, None, "error")
        return self._decode_verifier_body(response.body)

    @staticmethod
    def _decode_verifier_body(raw: bytes) -> Any:
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ProtocolError("error", "verifier response is not JSON") from None
        except RecursionError:
            raise ProtocolError("error", "verifier response is too deeply nested") from None

    def _intent_call(self, method: str, path: str, **kwargs: Any) -> PublishReview:
        """One publish-intent request.

        A 422 refusal that still carries a review (the failed-simulation
        contract) is returned as a parsed review so the operator can see why the
        simulation failed; any other refusal stays an :class:`ApiRefusal`.
        """
        try:
            response = self._session.request_json(method, path, **kwargs)
        except ApiRefusal as error:
            review = self._review_from_refusal(error)
            if review is not None:
                return review
            raise
        return self._parse_intent(response.payload)

    def _review_from_refusal(self, error: ApiRefusal) -> PublishReview | None:
        payload = error.payload
        if not isinstance(payload, dict) or "intentId" not in payload or "review" not in payload:
            return None
        try:
            return self._parse_intent(payload)
        except ProtocolError:
            # A malformed review never reaches the UI as a review.
            return None

    def _parse_intent(self, payload: Any) -> PublishReview:
        if not isinstance(payload, dict):
            raise ProtocolError("error", "publish intent response is malformed")
        plan = self._parse_plan(payload.get("review"))
        batch_sequence = _require_decimal(payload.get("batchSequence"), "batchSequence")
        if batch_sequence != plan.batch_sequence:
            raise ProtocolError("error", "publish intent batchSequence is inconsistent")
        return PublishReview(
            intent_id=_require_string(payload.get("intentId"), "intentId", _INTENT_ID),
            intent_hash=_require_string(payload.get("intentHash"), "intentHash", _HASH_HEX),
            state=_require_string(payload.get("state"), "state", _TOKEN),
            batch_sequence=batch_sequence,
            plan=plan,
            recent_blockhash=_require_string(payload.get("recentBlockhash"), "recentBlockhash", _PUBKEY),
            last_valid_block_height=_require_decimal(
                payload.get("lastValidBlockHeight"), "lastValidBlockHeight"
            ),
            expires_at=_optional(payload.get("expiresAt"), "expiresAt", _TIMESTAMP),
            transaction_signature=_optional(
                payload.get("transactionSignature"), "transactionSignature", _SIGNATURE
            ),
            anchor_slot=_optional(payload.get("anchorSlot"), "anchorSlot", _DECIMAL_20),
            certificate_id=_optional(payload.get("certificateId"), "certificateId", _CERTIFICATE_ID),
            failure_code=_optional(payload.get("failureCode"), "failureCode", _TOKEN),
            replayed=payload.get("replayed") is True,
        )

    def _parse_plan(self, review: Any) -> PublishPlan:
        """Strict, typed parse of the demo-api review payload.

        Every signer-facing field is required and validated against the A1
        signer's own request schema, so a review that is unknown or malformed in
        a core field fails closed instead of producing an approvable plan.
        """
        if not isinstance(review, dict):
            raise ProtocolError("error", "publish review is malformed")
        simulation = review.get("simulation")
        if not isinstance(simulation, dict):
            raise ProtocolError("error", "review.simulation is malformed")
        simulation_ok = simulation.get("ok")
        if not isinstance(simulation_ok, bool):
            raise ProtocolError("error", "review.simulation.ok is malformed")
        simulation_error = simulation.get("error")
        if simulation_error is not None and (
            not isinstance(simulation_error, str) or len(simulation_error) > 4096
        ):
            raise ProtocolError("error", "review.simulation.error is malformed")
        units = simulation.get("unitsConsumed")
        units_consumed = (
            None if units is None else _require_int(units, "review.simulation.unitsConsumed", 0, 1 << 40)
        )
        registry_id = _require_string(review.get("registryId"), "review.registryId", _REGISTRY_ID_TEXT)
        if registry_id != self._profile.registry_id:
            raise ProtocolError("error", "review.registryId is invalid")
        cluster = review.get("cluster")
        if cluster != "solana:devnet":
            raise ProtocolError("error", "review.cluster is invalid")
        instruction_data = _require_string(
            review.get("instructionData"), "review.instructionData", _SIGNED_TX_B64
        )
        if _standard_base64_length(instruction_data) != _INSTRUCTION_DATA_BYTES:
            raise ProtocolError("error", "review.instructionData is malformed")
        transaction_base64 = _require_string(
            review.get("transactionBase64"), "review.transactionBase64", _SIGNED_TX_B64
        )
        transaction_length = _standard_base64_length(transaction_base64)
        if transaction_length is None or not 1 <= transaction_length <= _MAX_TRANSACTION_BYTES:
            raise ProtocolError("error", "review.transactionBase64 is malformed")
        return PublishPlan(
            cluster=cluster,
            registry_id=registry_id,
            program_id=_require_string(review.get("programId"), "review.programId", _PUBKEY),
            config_pda=_require_string(review.get("configPda"), "review.configPda", _PUBKEY),
            role_pda=_require_string(review.get("rolePda"), "review.rolePda", _PUBKEY),
            segment_pda=_require_string(review.get("segmentPda"), "review.segmentPda", _PUBKEY),
            segment_index=_require_int(review.get("segmentIndex"), "review.segmentIndex", 0, 2),
            day_utc=_require_day_utc(review.get("dayUtc"), "review.dayUtc"),
            fee_payer=_require_string(review.get("feePayer"), "review.feePayer", _PUBKEY),
            batch_sequence=_require_decimal(review.get("batchSequence"), "review.batchSequence"),
            registry_version=_require_decimal(review.get("registryVersion"), "review.registryVersion"),
            cursor_start=_require_decimal(review.get("cursorStart"), "review.cursorStart"),
            cursor_end=_require_decimal(review.get("cursorEnd"), "review.cursorEnd"),
            leaf_count=_require_int(review.get("leafCount"), "review.leafCount", 1, 10_000),
            merkle_root=_require_string(review.get("merkleRoot"), "review.merkleRoot", _HASH_HEX),
            manifest_hash=_require_string(review.get("manifestHash"), "review.manifestHash", _HASH_HEX),
            previous_anchor_hash=_require_string(
                review.get("previousAnchorHash"), "review.previousAnchorHash", _HASH_HEX
            ),
            instruction_data=instruction_data,
            transaction_base64=transaction_base64,
            accounts=_parse_accounts(review.get("accounts")),
            simulation_ok=simulation_ok,
            simulation_error=simulation_error,
            units_consumed=units_consumed,
        )


def _intent_id(value: Any) -> str:
    return _require_string(value, "intentId", _INTENT_ID)


def _certificate_id(value: Any) -> str:
    return _require_string(value, "certificateId", _CERTIFICATE_ID)
