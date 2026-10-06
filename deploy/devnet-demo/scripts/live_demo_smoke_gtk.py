#!/usr/bin/python3
"""Opt-in live-demo GTK smoke (B4/B5): real widgets against real services.

Runs only when ``ONELAYER_LIVE_DEVNET_SMOKE=1``. The gate, preflight and run
loop live in :mod:`live_demo_smoke_gate` and execute before this module ever
imports GTK or the desktop lab modules, so an unset flag touches no network or
chain and a missing governance authority reports ``BLOCKED`` with ``"0/3"``
runs completed without starting a UI.

With the flag the smoke preflights loopback health plus the readiness probe
and then walks the ordinary launcher pages — real ``Gtk.Button.clicked()``
callbacks and the real file-chooser seams — against the local demo-api,
verifier and local signing flow (``mode="live"``, never fixture success). Each
run drives the complete scenario on its own synthetic record: clean version →
publish to FINALIZED → certificate disclosing status + areaSquareMeters only →
saved package and QR → VERIFIED (package and QR image) → tampered area through
the accepted tamper helper → INVALID / QR_HASH_MISMATCH → arrest version
(DISPUTED, encumbered) published to FINALIZED → its own certificate → the old
package SUPERSEDED → the real devnet explorer anchor target asserted through
the Explorer button seam without ever opening a browser.

Three consecutive runs are requested; the runner reports exactly how many
completed. Screenshots and a public-ID log are kept only for runs that
succeeded, in a private (0700) tree outside the repository.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Callable

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent.parent
LAB_DIR = REPO_ROOT / "apps" / "desktop" / "lab"
A2_READINESS = REPO_ROOT / "apps" / "demo-api" / "scripts" / "live-demo-registry.ts"
TAMPER = HERE / "live-demo-tamper"
sys.path.insert(0, str(HERE))

import live_demo_smoke_gate as gate

HEALTH_TIMEOUT_SECONDS = 5.0
READINESS_TIMEOUT_SECONDS = 60.0
WALK_TIMEOUT_SECONDS = 240.0
NODE_ARGS = ["node", "--experimental-transform-types", "--disable-warning=ExperimentalWarning"]

TamperFn = Callable[[Path, Path], None]


def fetch_health(url: str) -> bool:
    """Bounded loopback health probe; a response body of ``{"status":"ok"}``."""
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=HEALTH_TIMEOUT_SECONDS) as response:
            raw = response.read(65536)
    except Exception:
        return False
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    return isinstance(payload, dict) and payload.get("status") == "ok"


def probe_readiness() -> dict:
    """The accepted A2 readiness probe (read-only) as one JSON report."""
    result = subprocess.run(
        [*NODE_ARGS, str(A2_READINESS)],
        capture_output=True,
        timeout=READINESS_TIMEOUT_SECONDS,
        check=False,
        cwd=str(REPO_ROOT),
    )
    if result.returncode not in (0, 4):
        raise gate.SmokeError("READINESS_UNAVAILABLE", "the readiness probe refused to produce a report")
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise gate.SmokeError("READINESS_UNAVAILABLE", "the readiness report is not valid JSON") from error
    if not isinstance(payload, dict):
        raise gate.SmokeError("READINESS_UNAVAILABLE", "the readiness report is not an object")
    return payload


class _Walk:
    """One live launcher walk on a real GTK display.

    ``walk()`` is the scenario itself and is driven against a controller that
    is either the real live one (``mode="live"``) or, only in the hermetic
    contract test, a fixture-backed one (``mode="fixture"``). Nothing in here
    reports a fixture outcome as live: a live run refuses a fixture controller.
    """

    def __init__(
        self,
        attempt: int,
        staging: Path,
        *,
        record_id: str | None = None,
        mode: str = "live",
        tamper: TamperFn | None = None,
    ):
        self.attempt = attempt
        self.staging = staging
        self.record_id = record_id or f"SYNTHETIC-{attempt}"
        self.mode = mode
        self.tamper = tamper or self.tamper_with_accepted_helper
        self.approvals = 0
        self.explorer_opened: list[str] = []
        self.evidence: dict[str, object] = {
            "schema": "onelayer.live-demo.smoke-run.v1",
            "attempt": attempt,
            "mode": mode,
            "recordId": self.record_id,
            "screens": [],
            "publicIds": {},
        }

    # -- seams -----------------------------------------------------------

    def tamper_with_accepted_helper(self, source: Path, target: Path) -> None:
        """Rewrite the saved package's area with the accepted A3 CLI."""
        result = subprocess.run(
            [
                str(TAMPER),
                "--in",
                str(source),
                "--out",
                str(target),
                "--mode",
                "area",
                "--field",
                "areaSquareMeters",
                "--value",
                "9999.99",
            ],
            capture_output=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0:
            try:
                code = json.loads(result.stderr.decode("utf-8"))["error"]["code"]
            except Exception:
                code = f"exit-{result.returncode}"
            raise gate.SmokeError("TAMPER_FAILED", str(code))

    # -- entry -----------------------------------------------------------

    def run(self) -> None:
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            raise gate.SmokeError("DISPLAY_UNAVAILABLE", "no display is available")
        sys.path.insert(0, str(LAB_DIR))
        import gi

        gi.require_version("Gdk", "3.0")
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk

        import launcher_view
        from live_demo_controller import LiveDemoController

        controller = LiveDemoController.local(mode="live")
        window = Gtk.Window(title=f"OneLayer — Demo · LIVE · run {self.attempt}")
        window.set_default_size(1120, 780)
        view = launcher_view.LauncherView(window, live_demo=controller)
        pages = view._live_pages
        saved: dict[str, str] = {}

        def confirm_approve(_review: object) -> bool:
            self.approvals += 1
            return True

        def choose_save(kind: str) -> str:
            target = self.staging / f"artifact-{len(saved)}-{kind}.{'json' if kind == 'package' else 'png'}"
            saved[kind] = str(target)
            return str(target)

        def choose_open() -> str | None:
            return saved.get("open")

        pages._confirm_approve = confirm_approve
        pages._choose_save = choose_save
        pages._choose_open = choose_open
        window.show_all()
        try:
            self.walk(controller, view, pages, window, saved)
        finally:
            # A live run always destroys its window: no leaked UI between runs.
            window.destroy()
            while Gtk.events_pending():
                Gtk.main_iteration_do(False)

    def walk(self, controller, view, pages, window, saved: dict[str, str]) -> None:
        """The complete scenario against ordinary launcher widgets."""
        import gi

        gi.require_version("Gdk", "3.0")
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gdk, Gtk

        if self.mode == "live" and getattr(controller, "mode", None) != "live":
            raise gate.SmokeError("FIXTURE_IN_LIVE_RUN", "a live run refuses a fixture-backed controller")

        def pump(seconds: float = 0.3) -> None:
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                while Gtk.events_pending():
                    Gtk.main_iteration_do(False)
                time.sleep(0.01)

        def wait_until(predicate, what: str, timeout: float = 30.0) -> None:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                while Gtk.events_pending():
                    Gtk.main_iteration_do(False)
                if predicate():
                    pump(0.2)
                    return
                time.sleep(0.02)
            raise gate.SmokeError("RUN_TIMEOUT", f"the launcher never reached {what}")

        def settled() -> None:
            wait_until(lambda: controller.snapshot()["busy"] is None, "an idle operation", 60.0)

        def go(page: str) -> None:
            view._nav[page].clicked()
            pump(0.3)

        def shot(name: str) -> None:
            native = window.get_window()
            if native is None:
                raise gate.SmokeError("RUN_FAILED", "native window missing")
            pixbuf = Gdk.pixbuf_get_from_window(native, 0, 0, native.get_width(), native.get_height())
            if pixbuf is None:
                raise gate.SmokeError("RUN_FAILED", "native capture failed")
            path = self.staging / f"{name}.png"
            pixbuf.savev(str(path), "png", [], [])
            self.evidence["screens"].append(path.name)

        def require_status(label: str, expected: str) -> None:
            shown = pages.verify_status_label.get_text()
            if shown != expected:
                raise gate.SmokeError("VERIFY_FAILED", f"{label}: expected {expected}, saw {shown}")

        def open_and_verify(path: Path, label: str) -> None:
            saved["open"] = str(path)
            go("verify")
            pages.open_verify_button.clicked()
            settled()
            snapshot = controller.snapshot()
            if snapshot.get("busy") is not None:
                raise gate.SmokeError("RUN_FAILED", f"{label}: the walk did not settle")

        def publish(prefix: str) -> None:
            """One reviewed publish: prepare, explicit approve, FINALIZED."""
            go("publish")
            pages.prepare_button.clicked()
            settled()
            snapshot = controller.snapshot()
            review = snapshot.get("review")
            if not isinstance(review, dict) or not snapshot.get("canApprove"):
                raise gate.SmokeError("PUBLISH_PREPARE_FAILED", "the review is not approvable")
            intent_ids = self.evidence["publicIds"].setdefault("intentIds", [])
            intent_ids.append(review.get("intentId"))
            shot(f"{prefix}-publish-review")
            pages.approve_button.clicked()
            settled()
            snapshot = controller.snapshot()
            if not snapshot.get("signed"):
                raise gate.SmokeError("APPROVE_FAILED", "the publish was not signed locally")
            shot(f"{prefix}-publish-submitted")
            deadline = time.monotonic() + 180.0
            while time.monotonic() < deadline:
                if controller.snapshot().get("publishState") == "FINALIZED":
                    break
                pages.reconcile_button.clicked()
                settled()
                time.sleep(2.0)
            snapshot = controller.snapshot()
            if snapshot.get("publishState") != "FINALIZED":
                raise gate.SmokeError("NOT_FINALIZED", "the anchor did not finalize")
            review = snapshot.get("review") or {}
            if isinstance(review, dict):
                signatures = self.evidence["publicIds"].setdefault("transactionSignatures", [])
                signatures.append(review.get("transactionSignature"))
                slots = self.evidence["publicIds"].setdefault("anchorSlots", [])
                slots.append(review.get("anchorSlot"))
            shot(f"{prefix}-publish-finalized")

        def issue_certificate(prefix: str) -> dict:
            """Selective disclosure: exactly status + areaSquareMeters."""
            go("certificates")
            pages.certificate_record_combo.set_active_id(self.record_id)
            pump(0.3)
            for path, check in pages.disclosure_checks.items():
                check.set_active(path in ("status", "areaSquareMeters"))
            pump(0.1)
            pages.issue_button.clicked()
            settled()
            snapshot = controller.snapshot()
            certificate = snapshot.get("certificate")
            if not isinstance(certificate, dict):
                raise gate.SmokeError("ISSUE_FAILED", "the certificate was not issued")
            disclosed = list(certificate.get("disclosedPaths") or [])
            if sorted(disclosed) != ["areaSquareMeters", "status"]:
                raise gate.SmokeError("ISSUE_FAILED", f"unexpected disclosure {disclosed}")
            self.evidence["publicIds"]["certificateId"] = certificate.get("certificateId")
            self.evidence["publicIds"]["certificateHash"] = certificate.get("certificateHash")
            self.evidence["publicIds"]["disclosedPaths"] = disclosed
            return certificate

        # 1. sign in with the /dev/shm runtime password (never typed or shown)
        go("connection")
        pages.sign_in_button.clicked()
        settled()
        snapshot = controller.snapshot()
        if snapshot.get("sessionState") != "authenticated" or not snapshot.get("session"):
            raise gate.SmokeError("SIGN_IN_REFUSED", "the live session did not open")
        shot("01-connection-signed-in")

        # 2. one clean synthetic record version for this run only
        go("records")
        pages.record_id_entry.set_text(self.record_id)
        pages.status_combo.set_active_id("ACTIVE")
        pages.cadastral_entry.set_text("01-004-0123-045")
        pages.area_entry.set_text("1250.50")
        pages.encumbered_check.set_active(False)
        pages.create_record_button.clicked()
        settled()
        snapshot = controller.snapshot()
        if not snapshot.get("records"):
            raise gate.SmokeError("RECORD_CREATE_FAILED", "the record was not created")
        shot("02-records-clean")

        # 3. publish version 1 to FINALIZED (explicit approve #1)
        publish("03")

        # 4. certificate disclosing status + area only, then save package and QR
        issue_certificate("04")
        pages.save_package_button.clicked()
        settled()
        pages.save_qr_button.clicked()
        settled()
        snapshot = controller.snapshot()
        if not snapshot.get("savedPackage") or not snapshot.get("savedQr"):
            raise gate.SmokeError("SAVE_FAILED", "the certificate artifacts were not saved")
        shot("04-certificates-issued")
        package_v1 = Path(saved["package"])
        qr_v1 = Path(saved["qr"])

        # 5. the saved package verifies, and so does the saved QR image
        open_and_verify(package_v1, "package")
        report = controller.snapshot().get("report")
        if not isinstance(report, dict) or report.get("status") != "VERIFIED":
            raise gate.SmokeError("VERIFY_FAILED", "the saved package did not verify")
        require_status("package", "VERIFIED")
        shot("05-verify-verified-package")
        open_and_verify(qr_v1, "QR image")
        report = controller.snapshot().get("report")
        if not isinstance(report, dict) or report.get("status") != "VERIFIED":
            raise gate.SmokeError("VERIFY_FAILED", "the saved QR image did not verify")
        require_status("QR image", "VERIFIED")
        shot("05-verify-verified-qr")

        # 6. tamper the area through the accepted helper → INVALID
        tampered = self.staging / "tampered-area.json"
        self.tamper(package_v1, tampered)
        open_and_verify(tampered, "tampered package")
        snapshot = controller.snapshot()
        report = snapshot.get("report")
        if not isinstance(report, dict) or report.get("status") != "INVALID":
            raise gate.SmokeError("VERIFY_FAILED", "the tampered package was not refused")
        code = str(report.get("code") or "")
        if "QR_HASH_MISMATCH" not in code and "CERT_SIGNATURE_INVALID" not in code:
            raise gate.SmokeError("VERIFY_FAILED", f"unexpected tamper verdict {code}")
        require_status("tampered package", "INVALID")
        if pages.explorer_button.get_sensitive():
            raise gate.SmokeError("VERIFY_FAILED", "a failed verification must not offer an anchor link")
        shot("06-verify-tampered")

        # 7. arrest: a DISPUTED, encumbered version of the same record
        go("records")
        pages.record_id_entry.set_text(self.record_id)
        pages.status_combo.set_active_id("DISPUTED")
        pages.cadastral_entry.set_text("01-004-0123-045")
        pages.area_entry.set_text("1250.50")
        pages.encumbered_check.set_active(True)
        pages.create_record_button.clicked()
        settled()
        shot("07-records-arrest")

        # 8. publish version 2 to FINALIZED (explicit approve #2)
        publish("08")

        # 9. the certificate of the new version
        issue_certificate("09")
        pages.save_package_button.clicked()
        settled()
        snapshot = controller.snapshot()
        if not snapshot.get("savedPackage"):
            raise gate.SmokeError("SAVE_FAILED", "the new certificate package was not saved")
        shot("09-certificates-new")
        package_v2 = Path(saved["package"])

        # 10. the old package is now SUPERSEDED, not silently VERIFIED
        open_and_verify(package_v1, "superseded package")
        report = controller.snapshot().get("report")
        if not isinstance(report, dict) or report.get("status") != "SUPERSEDED":
            raise gate.SmokeError("VERIFY_FAILED", "the old package was not reported SUPERSEDED")
        require_status("superseded package", "SUPERSEDED")
        shot("10-verify-superseded")

        # 11. the real explorer anchor target, through the button, no browser
        target = controller.explorer_target()
        if not isinstance(target, str) or not target.startswith("https://explorer.solana.com/tx/"):
            raise gate.SmokeError("EXPLORER_FAILED", "no validated devnet anchor link is offered")
        if "?cluster=devnet" not in target:
            raise gate.SmokeError("EXPLORER_FAILED", "the anchor link is not the devnet one")
        if not pages.explorer_button.get_sensitive():
            raise gate.SmokeError("EXPLORER_FAILED", "the Explorer button is not available")
        opened: list[str] = []
        original = Gtk.show_uri_on_window

        def capture(_window_arg, uri, _timestamp):
            opened.append(str(uri))
            return True

        Gtk.show_uri_on_window = capture
        try:
            pages.explorer_button.clicked()
            pump(0.2)
        finally:
            Gtk.show_uri_on_window = original
        if opened != [target]:
            raise gate.SmokeError("EXPLORER_FAILED", f"the Explorer button opened {opened!r}, expected {target!r}")
        self.explorer_opened = opened
        self.evidence["publicIds"]["explorerUrl"] = target
        shot("11-explorer-anchor")

        if self.mode == "live" and self.approvals < 2:
            raise gate.SmokeError("APPROVAL_COUNT", f"expected an explicit approve per publish, saw {self.approvals}")
        self.evidence["approvals"] = self.approvals


def run_once(attempt: int) -> Path | None:
    """One live run: stage evidence privately, publish it only on success."""
    staging = Path(tempfile.mkdtemp(prefix=f"onelayer-live-smoke-{attempt}-", dir="/dev/shm"))
    walk = _Walk(attempt, staging)
    try:
        walk.run()
        (staging / "run.json").write_text(json.dumps(walk.evidence, indent=2) + "\n")
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        return gate.publish_evidence(staging, gate.evidence_root() / f"run-{stamp}-{attempt}")
    except gate.SmokeError:
        raise
    except Exception as error:
        raise gate.SmokeError("RUN_FAILED", type(error).__name__) from None
    finally:
        # Staging is always cleaned, successful run or not.
        shutil.rmtree(staging, ignore_errors=True)


def main() -> int:
    report = gate.run_smoke_plan(
        os.environ,
        fetch_health=fetch_health,
        readiness=probe_readiness,
        run_once=run_once,
    )
    sys.stdout.write(gate.render(report))
    return gate.exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
