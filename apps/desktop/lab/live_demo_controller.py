"""Non-GTK scenario controller for the live-demo launcher (B3).

Owns the whole «Поддельная выписка перед ипотекой» flow as plain Python state:
connection → records → publish review → explicit approve + local sign →
finalized anchor → selective-disclosure certificate → package/QR verify.
The GTK pages in :mod:`live_demo_view` only render :meth:`snapshot` and forward
user events; every request runs on a worker thread so the window stays
responsive.

Invariants worth naming
-----------------------
* **Explicit approve binds the displayed intent.** ``approve_and_sign`` takes
  the ``intentHash`` the view actually rendered and refuses when the review
  changed underneath it (``APPROVAL_STALE``), so editing a record or refreshing
  the review invalidates an outstanding approval.
* **No double sign.** A signed intent id is remembered and refused again
  (``ALREADY_SIGNED``); an in-progress marker under the lock keeps even two
  direct callers of :meth:`approve_and_sign` from racing (``SIGN_IN_PROGRESS``).
* **Session-bound state cannot resurrect.** Sign-out (and sign-in) bump a
  session generation; every records/review/certificate/verdict commit carries
  the generation it started under and is dropped (``SESSION_CHANGED``) if the
  session changed underneath it. Sign-out clears all of that state outright.
* **Devnet only.** Signing is refused unless the review pins
  ``cluster == "solana:devnet"`` and the simulation succeeded.
* **Honest states.** A failed simulation is a real review with
  ``SIMULATION_FAILED`` and is never approvable; nothing here invents a
  success, and the controller never substitutes fixture data for live API
  answers. ``mode`` is reported so the UI can label fixture runs.
* **No secrets.** Passwords are read from ``/dev/shm`` inside the session layer
  at sign-in time; keys stay in the Node signer helper. Nothing in this module
  prints, stores or logs either.
"""
from __future__ import annotations

import os
import re
import secrets
import threading
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from live_demo_api import (
    INTENT_STATE_SIMULATED,
    INTENT_STATE_SIMULATION_FAILED,
    INVALID,
    LiveDemoApi,
    LiveDemoProfile,
    RecordSummary,
    VerificationReport,
    validate_explorer_url,
)
from live_demo_session import AdminSession, LiveDemoError
from live_demo_signer import OperatorSigner
from live_demo_qr import QrImageDecoder

__all__ = [
    "ControllerError",
    "LiveDemoController",
    "PUBLISH_STATES",
]

# Publish states as the launcher reports them (server states plus launcher-local
# bookkeeping). Only SIMULATED with an OK simulation is approvable.
PUBLISH_IDLE = "idle"
PUBLISH_SIMULATED = INTENT_STATE_SIMULATED
PUBLISH_SIMULATION_FAILED = INTENT_STATE_SIMULATION_FAILED
PUBLISH_SUBMITTED = "SUBMITTED"
PUBLISH_FINALIZED = "FINALIZED"
PUBLISH_ISSUED = "ISSUED"
PUBLISH_STATES = (
    PUBLISH_IDLE,
    PUBLISH_SIMULATED,
    PUBLISH_SIMULATION_FAILED,
    PUBLISH_SUBMITTED,
    PUBLISH_FINALIZED,
    PUBLISH_ISSUED,
)

# Selective-disclosure defaults for this demo: the certificate shows only the
# record status and the area. Everything else stays hidden behind the proof.
DEFAULT_DISCLOSED_PATHS = ("status", "areaSquareMeters")
MAX_DISCLOSURE_CHOICES = 24

OPERATION_SIGN_IN = "sign_in"
OPERATION_OPERATOR_ADDRESS = "load_operator_address"
OPERATION_CREATE_RECORD = "create_record"
OPERATION_PREPARE = "prepare_publish"
OPERATION_APPROVE = "approve_and_sign"
OPERATION_RECONCILE = "check_finalization"
OPERATION_ISSUE = "issue_certificate"
OPERATION_SAVE_PACKAGE = "save_package"
OPERATION_SAVE_QR = "save_qr"
OPERATION_VERIFY = "verify_file"

# Launcher-local refusal codes (the server's own codes pass through unchanged).
SESSION_CHANGED = "SESSION_CHANGED"
SIGN_IN_PROGRESS = "SIGN_IN_PROGRESS"
INTERNAL_ERROR = "INTERNAL_ERROR"
SAVE_EXISTS = "SAVE_EXISTS"
VERIFY_FAILED = "VERIFY_FAILED"
OFFLINE = "OFFLINE"

# Saved artifacts are small documents / one PNG; anything bigger is refused.
MAX_SAVE_BYTES = 8 * 1024 * 1024
_CODE_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{0,62}$")


class ControllerError(LiveDemoError):
    """A launcher-side refusal. ``detail`` is a bare code, never raw output."""

    def __init__(self, code: str, detail: str | None = None):
        super().__init__("error", detail or code)
        self.code = code

    def __str__(self) -> str:
        return self.code


class LiveDemoController:
    """Scenario state + operations for one live-demo session."""

    def __init__(
        self,
        api: LiveDemoApi,
        *,
        signer: Any,
        qr_decoder: Any,
        mode: str = "live",
        emit: Callable[[str, Mapping[str, Any]], None] | None = None,
        setup: Any = None,
    ):
        if mode not in ("live", "fixture"):
            raise ValueError("mode must be live or fixture")
        self._api = api
        self._signer = signer
        self._qr = qr_decoder
        self._mode = mode
        self._emit_fn = emit
        self._setup = setup
        self._lock = threading.RLock()
        self._busy: str | None = None
        self._generation = 0
        self._signing = False

        self._session_state = "signed-out"
        self._operator_address: str | None = None
        self._records: list[RecordSummary] = []
        self._review = None
        self._approval_bound_hash: str | None = None
        self._signed_intents: set[str] = set()
        self._publish_state = PUBLISH_IDLE
        self._issued = None
        self._saved_package: str | None = None
        self._saved_qr: str | None = None
        self._report: VerificationReport | None = None
        self._verify_pending = False
        self._error: dict[str, str] | None = None
        self._setup_assessment: dict[str, Any] | None = None

    # -- construction helpers ---------------------------------------------

    @classmethod
    def local(cls, *, mode: str = "live", **kwargs: Any) -> "LiveDemoController":
        """Controller against the fixed loopback profile (ADR-0006)."""
        profile = LiveDemoProfile.local()
        # A publish prepare/simulate round trip can exceed the transport default.
        session = AdminSession(profile.demo_api_origin, timeout=20.0)
        api = LiveDemoApi(profile, session)
        return cls(
            api,
            signer=OperatorSigner(),
            qr_decoder=QrImageDecoder(),
            mode=mode,
            **kwargs,
        )

    # -- events -----------------------------------------------------------

    def set_emit(self, emit: Callable[[str, Mapping[str, Any]], None] | None) -> None:
        self._emit_fn = emit

    def _emit(self, event: str, payload: Mapping[str, Any] | None = None) -> None:
        emit = self._emit_fn
        if emit is None:
            return
        emit(event, dict(payload or {}))

    # -- state ------------------------------------------------------------

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def signed_in(self) -> bool:
        return self._api.signed_in

    def snapshot(self) -> dict[str, Any]:
        """Everything the pages render. Contains no secret material."""
        with self._lock:
            review = self._review
            profile = self._api.profile
            return {
                "mode": self._mode,
                "registryId": profile.registry_id,
                "namespaceLabel": profile.namespace_label,
                "namespaceDetail": profile.namespace_detail,
                "legacyRegistry": profile.is_legacy_registry,
                "sessionState": self._session_state,
                "operatorAddress": self._operator_address,
                "session": self._api.session_summary.as_dict() if self._api.session_summary else None,
                "records": [record.as_dict() for record in self._records],
                "review": review.as_dict() if review is not None else None,
                "canApprove": bool(review is not None and review.can_approve),
                "approvalBound": self._approval_bound(review),
                "signed": bool(review is not None and review.intent_id in self._signed_intents),
                "publishState": self._publish_state,
                "certificate": self._issued.as_dict() if self._issued is not None else None,
                "savedPackage": self._saved_package,
                "savedQr": self._saved_qr,
                "report": self._report.as_dict() if self._report is not None else None,
                "setupAvailable": self.setup_available,
                "setup": dict(self._setup_assessment) if self._setup_assessment else None,
                "error": dict(self._error) if self._error is not None else None,
                "busy": self._busy,
            }

    def explorer_target(self) -> str | None:
        """Validated devnet explorer URL for the current anchor, or ``None``.

        A failed verification never offers an anchor link: the only URL this
        launcher can open is the canonical devnet explorer transaction URL of
        an anchor the flow actually produced (and, after a verify, of one that
        did not fail). A verify attempt in flight — and any attempt that failed
        to produce a verdict — is never green and never keeps a previous
        anchor's link.
        """
        with self._lock:
            report = self._report
            issued = self._issued
            pending = self._verify_pending
        if pending:
            return None
        if report is not None:
            if report.status == "INVALID":
                return None
            return validate_explorer_url(report.explorer_url)
        if issued is not None:
            return validate_explorer_url(issued.explorer_url)
        return None

    # -- async plumbing ---------------------------------------------------

    def submit(self, operation: str, **kwargs: Any) -> bool:
        """Run one operation on a worker thread. Returns False when busy."""
        with self._lock:
            if self._busy is not None:
                return False
            self._busy = operation
        self._emit("busy", {"operation": operation})

        def run() -> None:
            try:
                self.call(operation, **kwargs)
            except LiveDemoError:
                # Already reported through the "error" event; a worker thread
                # must never dump a traceback into the launcher's stderr.
                pass
            except Exception:  # noqa: BLE001 - UI thread stays alive either way
                # call() reports unexpected failures itself; this is the last
                # resort so nothing is swallowed invisibly.
                self._report_internal_error(operation)
            finally:
                with self._lock:
                    self._busy = None
                self._emit("busy", {"operation": None})

        threading.Thread(target=run, daemon=True).start()
        return True

    def call(self, operation: str, **kwargs: Any) -> Any:
        """Run one operation synchronously (tests and workers share this)."""
        handler = {
            OPERATION_SIGN_IN: self.sign_in,
            OPERATION_OPERATOR_ADDRESS: self.load_operator_address,
            "sign_out": self.sign_out,
            "refresh": self.refresh,
            "reload_records": self.reload_records,
            OPERATION_CREATE_RECORD: self.create_record,
            OPERATION_PREPARE: self.prepare_publish,
            OPERATION_APPROVE: self.approve_and_sign,
            OPERATION_RECONCILE: self.check_finalization,
            OPERATION_ISSUE: self.issue_certificate,
            OPERATION_SAVE_PACKAGE: self.save_package,
            OPERATION_SAVE_QR: self.save_qr,
            OPERATION_VERIFY: self.verify_file,
            "assess_setup": self.assess_setup,
            "prepare_setup": self.prepare_setup,
        }.get(operation)
        if handler is None:
            raise ControllerError("UNKNOWN_OPERATION")
        with self._lock:
            # A new operation retires the previous operation's error text.
            self._error = None
        try:
            return handler(**kwargs)
        except LiveDemoError as error:
            code = getattr(error, "code", None) or error.state
            detail = str(error)
            with self._lock:
                self._error = {"operation": operation, "code": str(code), "detail": detail}
            self._emit(
                "error",
                {"operation": operation, "code": str(code), "detail": detail},
            )
            raise
        except Exception:  # noqa: BLE001 - sanitized; no stack, message or secret
            self._report_internal_error(operation)
            raise ControllerError(INTERNAL_ERROR) from None

    def _report_internal_error(self, operation: str) -> None:
        """Surface an unexpected failure as a bare code; never its text."""
        with self._lock:
            self._error = {"operation": operation, "code": INTERNAL_ERROR, "detail": INTERNAL_ERROR}
        self._emit(
            "error",
            {"operation": operation, "code": INTERNAL_ERROR, "detail": INTERNAL_ERROR},
        )

    # -- session ----------------------------------------------------------

    def load_operator_address(self) -> str:
        """Public operator address from the signer helper (no key material)."""
        result = self._signer.operator_address()
        with self._lock:
            self._operator_address = result.address
        self._emit("operator", {"address": result.address})
        return result.address

    def sign_in(self):
        """Sign in as the demo operator; the password comes from /dev/shm."""
        with self._lock:
            # A new session retires every completion of the previous one.
            self._generation += 1
            self._session_state = "loading"
        self._emit("session", {"state": "loading"})
        try:
            summary = self._api.sign_in()
        except LiveDemoError as error:
            # "offline" is a real, distinct blocked state; never a fake error.
            state = "offline" if error.state == "offline" else "error"
            with self._lock:
                self._session_state = state
            self._emit("session", {"state": state})
            raise
        with self._lock:
            self._session_state = "authenticated"
        self._emit("session", {"state": "authenticated", "summary": summary.as_dict()})
        # Local-only convenience: fill the operator address label. A missing key
        # must not block sign-in — it blocks prepare instead, honestly.
        try:
            self.load_operator_address()
        except LiveDemoError:
            pass
        return summary

    def refresh(self):
        summary = self._api.refresh()
        with self._lock:
            self._session_state = "authenticated"
        self._emit("session", {"state": "authenticated", "summary": summary.as_dict()})
        return summary

    def sign_out(self) -> None:
        self._api.sign_out()
        with self._lock:
            # Bumping the generation makes every in-flight completion stale, so
            # a slow response can never resurrect records, reviews, certificates
            # or verdicts into the signed-out (or next) session.
            self._generation += 1
            self._session_state = "signed-out"
            self._records = []
            self._invalidate_review()
            self._signed_intents = set()
            self._issued = None
            self._saved_package = None
            self._saved_qr = None
            self._report = None
            self._verify_pending = False
            self._error = None
        self._emit("session", {"state": "signed-out"})

    # -- devnet setup (ADR-0010) -----------------------------------------
    #
    # Read-only assessment and explicitly-approved preparation. Nothing here
    # runs automatically: `prepare_setup` is only ever called after the
    # operator has seen `planned_action_summary` and pressed confirm.

    @property
    def setup_available(self) -> bool:
        return self._setup is not None and self._mode == "live"

    def assess_setup(self):
        """Read-only chain assessment. Never signs or sends a transaction."""
        if not self.setup_available:
            raise ControllerError("SETUP_UNAVAILABLE")
        assessment = self._setup.assess()
        with self._lock:
            self._setup_assessment = assessment.as_dict()
        self._emit("setup", {"assessment": assessment.as_dict()})
        return assessment

    def prepare_setup(self):
        """Idempotent chain preparation. Requires explicit user confirmation.

        The caller must have already shown `planned_action_summary` and gotten
        an explicit approve click. The seed's own pre-mutation gate still
        refuses a missing authority before the first chain mutation.
        """
        if not self.setup_available:
            raise ControllerError("SETUP_UNAVAILABLE")
        assessment = self._setup.prepare()
        with self._lock:
            self._setup_assessment = assessment.as_dict()
        self._emit("setup", {"assessment": assessment.as_dict()})
        return assessment

    # -- records ----------------------------------------------------------

    def reload_records(self) -> list[RecordSummary]:
        generation = self._begin()
        records = self._api.list_records()
        with self._lock:
            self._require_session(generation)
            self._records = records
        self._emit("records", {"records": [record.as_dict() for record in records]})
        return records

    def create_record(
        self,
        *,
        record_id: str,
        status: str,
        cadastral_number: str,
        area_square_meters: str,
        encumbered: bool,
    ):
        """Create the next version of one synthetic record.

        The status is the *schema* lifecycle enum (ACTIVE / ARCHIVED / PENDING /
        DISPUTED) and the encumbrance flag is the schema's ``encumbered`` bool —
        the faithful mapping of the demo's clean/arrest distinction. There is no
        invented "clean"/"arrest" status value.
        """
        if not isinstance(encumbered, bool):
            raise ControllerError("RECORD_FIELD_INVALID")
        generation = self._begin()
        version = self._api.create_record_version(
            record_id,
            status=status,
            cadastral_number=cadastral_number,
            area_square_meters=area_square_meters,
            extra_fields={"encumbered": encumbered},
        )
        with self._lock:
            self._require_session(generation)
            # Editing the record invalidates any outstanding publish approval.
            self._invalidate_review()
        self.reload_records()
        self._emit(
            "record",
            {"record": version.as_dict(), "encumbered": encumbered},
        )
        return version

    # -- publish ----------------------------------------------------------

    def prepare_publish(self, *, operator: str | None = None, idempotency_key: str | None = None):
        """Simulate a publish and bind the displayed review."""
        target = operator or self._operator_address or self.load_operator_address()
        key = idempotency_key or self.new_idempotency_key()
        generation = self._begin()
        review = self._api.prepare_publish(target, idempotency_key=key)
        with self._lock:
            self._require_session(generation)
            self._set_review(review)
        self._emit("review", self._review_payload())
        return review

    def approve_and_sign(self, *, intent_hash: str):
        """Explicit approve: sign exactly the displayed intent, locally.

        The caller passes the ``intentHash`` of the review it rendered. A
        changed review, a failed simulation, a non-devnet cluster or an intent
        that was already signed is refused here, before any key is touched.

        The single-sign lifecycle is atomic across the whole span a second
        caller could race: the in-progress marker is taken under the lock and
        only dropped in the outer ``finally``, i.e. *after* the HTTP submit and
        the record commit. The intent is marked consumed the moment the signer
        returns a signature — before the submit — so an ambiguous transport
        failure can never produce a second signature. Such an intent stays
        signed and can only be reconciled (:meth:`check_finalization`); a retry
        here reconciles too and never re-signs. A signer that fails *before*
        producing a signature leaves the intent unsigned and retryable.

        A concurrent approver is refused ``SIGN_IN_PROGRESS`` even when the
        method is called outside the UI.
        """
        generation = self._begin()
        with self._lock:
            review = self._review
            if review is None:
                raise ControllerError("NO_REVIEW")
            if intent_hash != review.intent_hash:
                raise ControllerError("APPROVAL_STALE")
            # Single-flight across signer -> submit -> record commit.
            if self._signing:
                raise ControllerError(SIGN_IN_PROGRESS)
            intent_id = review.intent_id
            if intent_id in self._signed_intents:
                if review.state != INTENT_STATE_SIMULATED:
                    # The signature is confirmed: refuse, never replay.
                    raise ControllerError("ALREADY_SIGNED")
                # Signature exists but its submit is unconfirmed (e.g. an
                # ambiguous transport failure). The only safe move from here
                # is reconciliation — never a second signature.
                reconcile_only = True
                request: dict[str, Any] | None = None
            else:
                if not review.can_approve:
                    raise ControllerError("APPROVAL_REQUIRED")
                if review.plan.cluster != "solana:devnet":
                    raise ControllerError("CLUSTER_REFUSED")
                request = review.signer_request_fields(approved=True)
                self._signing = True
                reconcile_only = False
        if reconcile_only:
            updated = self._api.reconcile(intent_id)
            with self._lock:
                self._require_session(generation)
                self._set_review(updated)
            self._emit("review", self._review_payload())
            return updated
        try:
            signed = self._signer.sign(request)
            with self._lock:
                # Consumed the instant a signature exists — before submit —
                # so no transport failure can ever lead to a second one.
                self._signed_intents.add(intent_id)
                # The approval binds the exact hash that was displayed and
                # checked.
                self._approval_bound_hash = intent_hash
            with self._lock:
                # Never submit a signature into a session that already ended.
                self._require_session(generation)
            review = self._api.submit_signature(intent_id, signed)
            with self._lock:
                self._require_session(generation)
                self._set_review(review)
        finally:
            with self._lock:
                self._signing = False
        self._emit("review", self._review_payload())
        return review

    def check_finalization(self):
        """Ask the server for the anchor status; bounded retries are the caller's."""
        with self._lock:
            review = self._review
        if review is None:
            raise ControllerError("NO_REVIEW")
        generation = self._begin()
        updated = self._api.reconcile(review.intent_id)
        with self._lock:
            self._require_session(generation)
            self._set_review(updated)
        self._emit("review", self._review_payload())
        return updated

    # -- certificates -----------------------------------------------------

    def disclosure_choices(self, record_id: str | None = None) -> tuple[str, ...]:
        """Field paths offered for selective disclosure (bounded)."""
        with self._lock:
            records = list(self._records)
        paths: set[str] = set(DEFAULT_DISCLOSED_PATHS)
        for record in records:
            if record_id is None or record.internal_record_id == record_id:
                paths.update(record.fields.keys())
        return tuple(sorted(paths))[:MAX_DISCLOSURE_CHOICES]

    def issue_certificate(
        self, *, record_id: str, disclosed_paths: Sequence[str] | None = None
    ):
        """Issue a certificate from a FINALIZED intent. Default: status + area."""
        with self._lock:
            review = self._review
            if review is None:
                raise ControllerError("NO_REVIEW")
            if self._publish_state != PUBLISH_FINALIZED or review.state != PUBLISH_FINALIZED:
                raise ControllerError("NOT_FINALIZED")
            intent_id = review.intent_id
        chosen = tuple(disclosed_paths) if disclosed_paths is not None else DEFAULT_DISCLOSED_PATHS
        # Deterministic order for the request, the UI and the saved artifact.
        paths = tuple(sorted(dict.fromkeys(chosen)))
        generation = self._begin()
        issued = self._api.issue_certificate(intent_id, record_id, disclosed_paths=list(paths))
        with self._lock:
            self._require_session(generation)
            self._issued = issued
            self._publish_state = PUBLISH_ISSUED
        self._emit("certificate", {"certificate": issued.as_dict()})
        return issued

    def save_package(self, *, path: str | Path) -> Path:
        """Write the certificate package document for later offline verify."""
        destination = self._writable_destination(path)
        with self._lock:
            issued = self._issued
        if issued is None:
            raise ControllerError("NO_CERTIFICATE")
        generation = self._begin()
        package = self._api.get_certificate_package(issued.certificate_id)
        document = {
            "package_base64url": package.package_base64url,
            "certificateHash": package.certificate_hash_hex,
            "qrUrl": package.qr_url,
        }
        payload = _json_bytes(document)
        with self._lock:
            # Session check, exclusive create and the record update are one
            # atomic step against sign-out: a stale completion reports
            # SESSION_CHANGED and never leaves an orphan file behind.
            self._require_session(generation)
            self._write_bytes(destination, payload)
            self._saved_package = str(destination)
        self._emit("saved", {"kind": "package", "path": str(destination)})
        return destination

    def save_qr(self, *, path: str | Path) -> Path:
        """Write the certificate QR image (PNG) chosen in a native dialog."""
        destination = self._writable_destination(path)
        with self._lock:
            issued = self._issued
        if issued is None:
            raise ControllerError("NO_CERTIFICATE")
        generation = self._begin()
        image = self._api.get_qr_image(issued.certificate_id, fmt="png")
        with self._lock:
            # See save_package: check + exclusive write + record stay atomic
            # against a concurrent sign-out.
            self._require_session(generation)
            self._write_bytes(destination, image)
            self._saved_qr = str(destination)
        self._emit("saved", {"kind": "qr", "path": str(destination)})
        return destination

    # -- verify -----------------------------------------------------------

    def verify_file(self, *, path: str | Path) -> VerificationReport:
        """Verify a saved package document or a QR image, honestly.

        A PNG is decoded with the QR helper and verified through its carried
        hash; anything else is treated as a package document. ``INVALID`` and
        ``QR_HASH_MISMATCH`` clear every disclosed field (the API layer already
        guarantees this).

        Every attempt first retires the previous verdict — a failed verify can
        never leave an earlier green report, its disclosed fields or its
        explorer link on screen. An attempt that could not run at all (missing
        file, failed decode, unreadable file, unreachable verifier) is reported
        as an honest failed ``INVALID`` state carrying the failure code, and
        then re-raised. A raw ``OSError`` from the file or the QR helper is
        converted to the safe code ``FILE_UNREADABLE`` (never its text), any
        other unexpected exception to ``VERIFY_FAILED``; either way the pending
        flag is retired and the previous verdict stays cleared.
        """
        generation = self._begin()
        self._commit(generation, self._begin_verify)
        self._emit("verify", {"report": None})
        try:
            source = Path(path)
            if source.is_symlink() or not source.is_file():
                raise ControllerError("FILE_UNREADABLE")
            try:
                with source.open("rb") as handle:
                    data = handle.read(8)
            except OSError:
                raise ControllerError("FILE_UNREADABLE") from None
            if data.startswith(b"\x89PNG\r\n\x1a\n"):
                payload = self._qr.decode(source)
                report = self._api.verify_qr_payload(payload)
            else:
                report = self._api.verify_package_file(source)
        except LiveDemoError as error:
            failed = VerificationReport(
                status=INVALID,
                code=_attempt_failure_code(error),
                certificate_id="",
            )
            self._retire_failed_attempt(generation, failed)
            raise
        except OSError:
            # An unreadable file is an honest failed attempt, not a crash.
            failed = VerificationReport(
                status=INVALID,
                code="FILE_UNREADABLE",
                certificate_id="",
            )
            self._retire_failed_attempt(generation, failed)
            raise ControllerError("FILE_UNREADABLE") from None
        except Exception:  # noqa: BLE001 - sanitized; no stack, message or secret
            failed = VerificationReport(
                status=INVALID,
                code=VERIFY_FAILED,
                certificate_id="",
            )
            self._retire_failed_attempt(generation, failed)
            raise ControllerError(VERIFY_FAILED) from None
        self._commit(generation, lambda: self._store_report(report))
        self._emit("verify", {"report": report.as_dict()})
        return report

    # -- internals ---------------------------------------------------------

    @staticmethod
    def new_idempotency_key() -> str:
        return "live-demo-" + secrets.token_hex(8)

    def _begin(self) -> int:
        """Session generation for one operation; commits must carry it back."""
        with self._lock:
            return self._generation

    def _require_session(self, generation: int) -> None:
        """Refuse a commit whose session ended or changed mid-operation."""
        if generation != self._generation:
            raise ControllerError(SESSION_CHANGED)

    def _commit(self, generation: int, mutate: Callable[[], None]) -> None:
        with self._lock:
            self._require_session(generation)
            mutate()

    def _approval_bound(self, review: Any) -> bool:
        return bool(
            review is not None
            and self._approval_bound_hash is not None
            and self._approval_bound_hash == review.intent_hash
        )

    def _begin_verify(self) -> None:
        """Retire the previous verdict before any new verify attempt."""
        self._report = None
        self._verify_pending = True
        self._error = None

    def _store_report(self, report: VerificationReport) -> None:
        self._report = report
        self._verify_pending = False

    def _retire_failed_attempt(self, generation: int, failed: VerificationReport) -> None:
        """Record an honest failed attempt; never resurrect a stale session.

        The pending flag is always retired — a raw failure can never leave the
        explorer side permanently off with no verdict to explain it. If the
        session ended mid-attempt, the store is skipped (a sign-out already
        reset the verdict and the pending flag) so nothing leaks into the next
        session.
        """
        with self._lock:
            if generation != self._generation:
                return
            self._store_report(failed)
        self._emit("verify", {"report": failed.as_dict()})

    def _review_payload(self) -> dict[str, Any]:
        review = self._review
        return {
            "review": review.as_dict() if review is not None else None,
            "canApprove": bool(review is not None and review.can_approve),
            "approvalBound": self._approval_bound(review),
            "signed": bool(review is not None and review.intent_id in self._signed_intents),
            "publishState": self._publish_state,
        }

    def _set_review(self, review: Any) -> None:
        """Adopt a server review.

        An approval stays bound to the exact ``intentHash`` it approved; a
        different review simply no longer matches that hash. Only
        :meth:`_invalidate_review` (a record edit, sign-out) drops the binding
        outright.
        """
        self._review = review
        state = review.state
        self._publish_state = {
            INTENT_STATE_SIMULATED: PUBLISH_SIMULATED,
            INTENT_STATE_SIMULATION_FAILED: PUBLISH_SIMULATION_FAILED,
            "SUBMITTED": PUBLISH_SUBMITTED,
            "FINALIZED": PUBLISH_FINALIZED,
            "ISSUED": PUBLISH_ISSUED,
        }.get(state, PUBLISH_IDLE if review is None else state)

    def _invalidate_review(self) -> None:
        self._review = None
        self._approval_bound_hash = None
        self._publish_state = PUBLISH_IDLE

    @staticmethod
    def _writable_destination(path: str | Path) -> Path:
        """Validate a save destination that must be a *new* regular file.

        An existing file, a directory, a symlink or a dangling symlink is
        refused (``SAVE_EXISTS`` / ``SAVE_PATH_INVALID``): nothing is ever
        overwritten and no link is ever followed.
        """
        destination = Path(path)
        if not destination.is_absolute():
            raise ControllerError("SAVE_PATH_INVALID")
        if destination.is_symlink() or destination.exists():
            raise ControllerError(SAVE_EXISTS)
        parent = destination.parent
        if not parent.is_dir():
            raise ControllerError("SAVE_PATH_INVALID")
        return destination

    @staticmethod
    def _write_bytes(destination: Path, payload: bytes) -> None:
        """Create ``destination`` exclusively and write exactly ``payload``.

        ``O_CREAT | O_EXCL | O_NOFOLLOW``: the write loses the race against any
        pre-existing file or link instead of clobbering it, and a partial write
        is removed again. The bytes are bounded before anything is written.
        """
        if not isinstance(payload, bytes) or not payload or len(payload) > MAX_SAVE_BYTES:
            raise ControllerError("SAVE_FAILED")
        try:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
        except FileExistsError:
            raise ControllerError(SAVE_EXISTS) from None
        except OSError:
            raise ControllerError("SAVE_FAILED") from None
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            try:
                os.unlink(destination)
            except OSError:
                pass
            raise ControllerError("SAVE_FAILED") from None


def _json_bytes(document: Mapping[str, Any]) -> bytes:
    import json

    return json.dumps(dict(document), indent=2, sort_keys=True).encode("utf-8")


def _attempt_failure_code(error: LiveDemoError) -> str:
    """Bare code for a verify attempt that could not produce a verdict."""
    code = getattr(error, "code", None)
    if isinstance(code, str) and _CODE_TOKEN.match(code):
        return code
    if getattr(error, "state", None) == "offline":
        return OFFLINE
    return VERIFY_FAILED
