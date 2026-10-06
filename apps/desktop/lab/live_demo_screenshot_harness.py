#!/usr/bin/python3
"""TEST-ONLY screenshot harness for the live-demo launcher (B3 evidence).

Walks the «Поддельная выписка перед ипотекой» scenario on a real GTK display
against the **fixture** backends and saves one screenshot per screen. Every
capture is labeled ``fixture`` in its filename and the window carries the
visible "FIXTURE DATA" banner — these images are launcher-UI evidence, not a
live-devnet pass. The real chain scenario is blocked on the lost governance key
(``4Y4pGizJm5CL789jRKYx5jeQLJ58eBBmf5UzGRFChikn``).

This script is never imported by the launcher and never runs in CI tests.

    /usr/bin/python3 apps/desktop/lab/live_demo_screenshot_harness.py
    /usr/bin/python3 apps/desktop/lab/live_demo_screenshot_harness.py --output DIR

Screenshots are written outside the repository, to
``~/.local/state/onelayer-devnet-demo/evidence/gtk/`` by default (0700 tree),
and no secret value is ever rendered or captured.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB_DIR))

import gi
gi.require_version("Gdk", "3.0")
gi.require_version("Gtk", "3.0")
from gi.repository import Gdk, GLib, Gtk

import launcher_view
import live_demo_fixtures as fx
from live_demo_api import LiveDemoApi, LiveDemoProfile
from live_demo_controller import LiveDemoController
from live_demo_session import AdminSession

SECRET = fx.FIXTURE_CREDENTIAL_SECRET


def pump(seconds: float = 0.4) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        while Gtk.events_pending():
            Gtk.main_iteration_do(False)
        time.sleep(0.01)


def wait_until(predicate, timeout: float = 10.0, what: str = "state") -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        while Gtk.events_pending():
            Gtk.main_iteration_do(False)
        if predicate():
            return
        time.sleep(0.01)
    raise RuntimeError(f"launcher never reached the expected {what}")


def label_texts(widget) -> list[str]:
    texts: list[str] = []
    if isinstance(widget, Gtk.Label):
        texts.append(widget.get_text())
    if isinstance(widget, Gtk.Container):
        for child in widget.get_children():
            texts.extend(label_texts(child))
    return texts


def capture(window: Gtk.Window, path: Path, note: str) -> Path:
    native = window.get_window()
    if native is None:
        raise RuntimeError("native window missing")
    pixbuf = Gdk.pixbuf_get_from_window(native, 0, 0, native.get_width(), native.get_height())
    if pixbuf is None:
        raise RuntimeError("native capture failed")
    window.set_title(f"OneLayer — Demo · FIXTURE · {note}")
    pixbuf.savev(str(path), "png", [], [])
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    if not Gtk.init_check()[0]:
        raise SystemExit("native display required (run under the desktop session or Xvfb)")

    output = args.output
    if output is None:
        output = Path.home() / ".local" / "state" / "onelayer-devnet-demo" / "evidence" / "gtk"
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(output.parent, 0o700)
        os.chmod(output, 0o700)
    except OSError:
        pass

    stack = fx.FixtureStack()
    scratch = Path(tempfile.mkdtemp(prefix="onelayer-live-demo-evidence-", dir="/dev/shm"))
    try:
        credential = fx.write_credential_file(scratch)
        profile = LiveDemoProfile(
            demo_api_origin=stack.demo_origin, verifier_origin=stack.verifier_origin)
        session = AdminSession(
            profile.demo_api_origin, credential_path=credential, private_root=scratch)
        api = LiveDemoApi(profile, session)
        signer = fx.FakeSigner()
        qr = fx.FakeQrDecoder()
        controller = LiveDemoController(
            api, signer=signer, qr_decoder=qr, mode="fixture")

        window = Gtk.Window(title="OneLayer — Demo · FIXTURE")
        window.set_default_size(1120, 780)
        view = launcher_view.LauncherView(window, live_demo=controller)
        pages = view._live_pages
        # Test-only seams: no modal dialog or native chooser in a headless walk.
        pages._confirm_approve = lambda review: True
        saved: dict[str, str] = {}
        counter = {"n": 0}

        def choose_save(kind: str) -> str:
            counter["n"] += 1
            path = scratch / (
                f"package-{counter['n']}.json" if kind == "package" else f"qr-{counter['n']}.png")
            saved[kind] = str(path)
            return str(path)

        pages._choose_save = choose_save
        pages._choose_open = lambda: saved.get("open")
        window.show_all()
        pump()

        shots: list[tuple[str, str]] = []
        writeup: list[str] = []

        def shot(name: str, note: str) -> None:
            assert_no_secrets(window)
            texts = label_texts(window)
            if not any("FIXTURE DATA" in item for item in texts):
                raise RuntimeError(f"fixture banner missing from capture {name}")
            path = capture(window, output / f"{name}.png", note)
            shots.append((str(path), note))
            writeup.append(f"{path.name}: {note}")

        def go(page: str) -> None:
            view._nav[page].clicked()
            pump()

        def settled() -> None:
            wait_until(lambda: controller.snapshot()["busy"] is None, what="operation")
            pump(0.3)

        def show(page: str, note: str, name: str) -> None:
            go(page)
            pump(0.5)
            shot(name, note)

        # 1. overview — fixture banner and service cards
        show("overview", "launcher overview, fixture mode", "fixture-01-overview")

        # 2. connection — sign in with the /dev/shm password
        go("connection")
        pages.sign_in_button.clicked()
        settled()
        pump(0.5)
        shot("fixture-02-connection-signed-in", "signed in as operator (password from /dev/shm)")

        # 3. records — clean record version
        go("records")
        pages.record_id_entry.set_text("SYNTHETIC-1")
        pages.status_combo.set_active_id("ACTIVE")
        pages.cadastral_entry.set_text("01-004-0123-045")
        pages.area_entry.set_text("1250.50")
        pages.encumbered_check.set_active(False)
        pages.create_record_button.clicked()
        settled()
        pump(0.5)
        shot("fixture-03-records-clean", "clean record: ACTIVE, encumbered=false")

        # 4. publish — immutable review before any signature
        go("publish")
        pages.prepare_button.clicked()
        settled()
        pump(0.5)
        shot("fixture-04-publish-review", "immutable review before Approve")

        # 5. publish — after explicit approve + local sign
        pages.approve_button.clicked()
        settled()
        pump(0.5)
        shot("fixture-05-publish-submitted", "signed locally, state SUBMITTED")

        # 6. publish — FINALIZED anchor
        pages.reconcile_button.clicked()
        settled()
        pump(0.5)
        shot("fixture-06-publish-finalized", "anchor FINALIZED on devnet (fixture slot)")

        # 7. certificates — selective disclosure (status + area only)
        go("certificates")
        pages.certificate_record_combo.set_active_id("SYNTHETIC-1")
        pump(0.2)
        pages.issue_button.clicked()
        settled()
        pages.save_package_button.clicked()
        settled()
        pages.save_qr_button.clicked()
        settled()
        pump(0.5)
        shot("fixture-07-certificates-issued", "certificate issued: status + areaSquareMeters")

        first_package = Path(saved["package"])
        first_qr = saved["qr"]
        qr_info = stack.certificates[controller.snapshot()["certificate"]["certificateId"]]

        # 8. verify — VERIFIED with disclosed fields and the explorer anchor
        go("verify")
        saved["open"] = str(first_package)
        pages.open_verify_button.clicked()
        settled()
        pump(0.5)
        shot("fixture-08-verify-verified", "VERIFIED: status + area disclosed, explorer anchor")

        # 9. verify — tampered area, original claimed hash
        tampered = scratch / "tampered.json"
        tampered.write_bytes(fx.tamper_document_area(first_package.read_bytes()))
        saved["open"] = str(tampered)
        pages.open_verify_button.clicked()
        settled()
        pump(0.5)
        shot("fixture-09-verify-tampered", "tampered area: QR_HASH_MISMATCH / INVALID")

        # 10. verify — QR image path
        qr.payloads[first_qr] = stack.qr_url(qr_info["certificateId"], qr_info["qrHash"])
        saved["open"] = first_qr
        pages.open_verify_button.clicked()
        settled()
        pump(0.5)
        shot("fixture-10-verify-qr-image", "QR image path: VERIFIED through the carried hash")

        # 11. records — arrest version (encumbered + DISPUTED)
        go("records")
        pages.record_id_entry.set_text("SYNTHETIC-1")
        pages.status_combo.set_active_id("DISPUTED")
        pages.cadastral_entry.set_text("01-004-0123-045")
        pages.area_entry.set_text("1250.50")
        pages.encumbered_check.set_active(True)
        pages.create_record_button.clicked()
        settled()
        pump(0.5)
        shot("fixture-11-records-arrest", "arrest version: DISPUTED, encumbered=true")

        # 12. certificates — the new certificate
        go("publish")
        pages.prepare_button.clicked()
        settled()
        pages.approve_button.clicked()
        settled()
        pages.reconcile_button.clicked()
        settled()
        go("certificates")
        pages.issue_button.clicked()
        settled()
        pump(0.5)
        shot("fixture-12-certificates-new", "certificate for the arrest version")

        # 13. verify — the first package is now SUPERSEDED
        go("verify")
        saved["open"] = str(first_package)
        pages.open_verify_button.clicked()
        settled()
        pump(0.5)
        shot("fixture-13-verify-superseded", "first package is now SUPERSEDED")

        # 14. verify — a failed attempt is an honest failed state, never stale
        saved["open"] = str(scratch / "missing.json")
        pages.open_verify_button.clicked()
        settled()
        pump(0.5)
        shot("fixture-14-verify-unreadable",
             "failed attempt: INVALID + FILE_UNREADABLE, previous verdict cleared")

        # 15. sign out — session-bound state is reset
        go("connection")
        pages.sign_out_button.clicked()
        settled()
        pump(0.5)
        shot("fixture-15-connection-signed-out",
             "signed out: records/review/certificate/verdict state reset")

        # 16. verify — the page shows no stale verdict after sign-out
        go("verify")
        pump(0.5)
        shot("fixture-16-verify-cleared", "verify page after sign-out: Not verified, explorer off")

        manifest = {
            "schema": "onelayer.live-demo.evidence.v1",
            "mode": "fixture",
            "note": (
                "Fixture-backed launcher UI evidence. Not a live-devnet pass: the "
                "real chain scenario is blocked on the lost governance key 4Y4p…"
            ),
            "signerCalls": signer.calls,
            "screens": [{"file": Path(path).name, "note": note} for path, note in shots],
        }
        (output / "index.json").write_text(json.dumps(manifest, indent=2) + "\n")
        for line in writeup:
            print(line)
        print(f"index: {output / 'index.json'}")
        print("PASS: fixture screenshots captured (no secrets)")
        return 0
    finally:
        stack.close()
        import shutil
        shutil.rmtree(scratch, ignore_errors=True)


def assert_no_secrets(window: Gtk.Window) -> None:
    joined = "\n".join(label_texts(window))
    if SECRET in joined or "csrf" in joined.lower():
        raise RuntimeError("secret material reached the rendered UI")


if __name__ == "__main__":
    raise SystemExit(main())
