"""End-to-end live-demo scenario through the real GTK pages (B3).

One narrative walk over hermetic loopback fixtures — the same steps the manual
demo runs: clean record → publish → explicit approve → FINALIZED anchor →
selective certificate (status + area only) → save package/QR → VERIFIED →
tampered area → QR_HASH_MISMATCH / INVALID → arrest version + new certificate →
old package SUPERSEDED → explorer anchor URL. Plus the approval gate and the
no-secret surfaces.

Fixture screens are labeled; these tests assert that too. Nothing here claims
a live devnet pass — the real chain scenario is blocked on the lost governance
key (``4Y4p…``).
"""
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

import live_demo_fixtures as fx
from live_demo_api import LiveDemoApi, LiveDemoProfile
from live_demo_controller import ControllerError, LiveDemoController
from live_demo_session import AdminSession
from live_demo_view import LiveDemoPages

SECRET = fx.FIXTURE_CREDENTIAL_SECRET


def drain_until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        while Gtk.events_pending():
            Gtk.main_iteration_do(False)
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("native UI did not reach the expected state")


def label_texts(widget):
    texts = []
    if isinstance(widget, Gtk.Label):
        texts.append(widget.get_text())
    if isinstance(widget, Gtk.Container):
        for child in widget.get_children():
            texts.extend(label_texts(child))
    return texts


class FlowFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Gtk.init_check()[0]:
            raise RuntimeError("Native display required for live-demo flow checks")

    def setUp(self):
        self.stack = fx.FixtureStack()
        self.addCleanup(self.stack.close)
        self.root = Path(tempfile.mkdtemp(prefix="onelayer-live-demo-flow-", dir="/dev/shm"))
        self.addCleanup(self._cleanup_root)
        credential = fx.write_credential_file(self.root)
        profile = LiveDemoProfile(
            demo_api_origin=self.stack.demo_origin,
            verifier_origin=self.stack.verifier_origin,
        )
        session = AdminSession(
            profile.demo_api_origin, credential_path=credential, private_root=self.root
        )
        self.api = LiveDemoApi(profile, session)
        self.signer = fx.FakeSigner()
        self.qr = fx.FakeQrDecoder()
        self.controller = LiveDemoController(
            self.api, signer=self.signer, qr_decoder=self.qr, mode="fixture"
        )
        self.saved = {}
        self.window = Gtk.Window()
        self.window.set_default_size(1024, 720)
        self.pages = LiveDemoPages(
            self.controller,
            window=self.window,
            confirm_approve=lambda review: True,
            choose_save=self._choose_save,
            choose_open=self._choose_open,
        )
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        outer.pack_start(self.pages.connection_card, False, False, 0)
        self.view_stack = Gtk.Stack()
        for name, widget in self.pages.pages():
            self.view_stack.add_named(widget, name)
        outer.pack_start(self.view_stack, True, True, 0)
        self.window.add(outer)
        self.window.show_all()
        self.addCleanup(self.window.destroy)

    def _cleanup_root(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def _choose_save(self, kind):
        self.saved.setdefault("count", 0)
        self.saved["count"] += 1
        suffix = self.saved["count"]
        path = self.root / (
            f"package-{suffix}.json" if kind == "package" else f"qr-{suffix}.png")
        self.saved[kind] = str(path)
        return str(path)

    def _choose_open(self):
        return self.saved.get("open")

    def settled(self):
        drain_until(lambda: self.controller.snapshot()["busy"] is None)
        self.flush()

    @staticmethod
    def flush():
        for _ in range(5):
            while Gtk.events_pending():
                Gtk.main_iteration_do(False)

    def run_op(self, *predicates):
        self.settled()
        for predicate in predicates:
            drain_until(predicate)
        self.settled()

    def texts(self):
        return label_texts(self.window)

    def assertNoSecrets(self):
        joined = "\n".join(self.texts())
        self.assertNotIn(SECRET, joined)
        self.assertNotIn("csrf", joined.lower())
        self.assertNotIn("signedtransactionbase64", joined.lower())

    # -- narrative helpers ------------------------------------------------

    def sign_in(self):
        self.pages.sign_in_button.clicked()
        self.run_op(lambda: self.pages.connection_chip.get_text() == "Signed in")

    def create_version(self, *, status, area, encumbered, record_id="SYNTHETIC-1"):
        self.pages.record_id_entry.set_text(record_id)
        self.pages.status_combo.set_active_id(status)
        self.pages.cadastral_entry.set_text("01-004-0123-045")
        self.pages.area_entry.set_text(area)
        self.pages.encumbered_check.set_active(encumbered)
        self.pages.create_record_button.clicked()
        self.run_op(lambda: bool(self.pages.records_list.get_children()))

    def prepare_approve_finalize(self):
        self.pages.prepare_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() == "Simulated")
        self.pages.approve_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() == "Submitted")
        self.pages.reconcile_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() == "Finalized")

    def issue_and_save(self):
        self.assertTrue(self.pages.issue_button.get_sensitive())
        self.pages.issue_button.clicked()
        self.run_op(lambda: self.controller.snapshot()["certificate"] is not None)
        self.pages.save_package_button.clicked()
        self.run_op(lambda: self.controller.snapshot()["savedPackage"] is not None)
        self.pages.save_qr_button.clicked()
        self.run_op(lambda: self.controller.snapshot()["savedQr"] is not None)

    def verify_opened(self, path):
        self.saved["open"] = str(path)
        self.pages.open_verify_button.clicked()
        self.settled()

    def issue(self):
        self.pages.certificate_record_combo.set_active_id("SYNTHETIC-1")
        self.pages.issue_button.clicked()
        self.run_op(lambda: self.controller.snapshot()["certificate"] is not None)


class ScenarioTests(FlowFixture):
    def test_full_scenario_clean_certificate_tamper_arrest_and_supersede(self):
        # 1. clean record
        self.sign_in()
        self.create_version(status="ACTIVE", area="1250.50", encumbered=False)
        self.assertEqual(self.pages.records_list.get_children()[0].get_child().get_text(),
                         "SYNTHETIC-1 · v1 · ACTIVE · 1250.50 m² · 01-004-0123-045 · encumbered=false")

        # 2. publish → explicit approve → FINALIZED
        self.prepare_approve_finalize()
        self.assertEqual(self.signer.calls, 1)
        self.assertTrue(self.signer.requests[0]["approved"] is True)

        # 3. certificate with status + area only, saved package and QR
        self.pages.certificate_record_combo.set_active_id("SYNTHETIC-1")
        self.issue_and_save()
        certificate = self.controller.snapshot()["certificate"]
        self.assertEqual(certificate["disclosedPaths"], ["areaSquareMeters", "status"])
        self.assertEqual(certificate["disclosureMode"], "SELECTIVE_FIELDS")
        first_package = self.saved["package"]
        first_qr = self.saved["qr"]

        # 4. VERIFIED with exactly the two disclosed fields
        self.verify_opened(self.saved["package"])
        self.assertEqual(self.pages.verify_status_label.get_text(), "VERIFIED")
        fields = self.pages.verify_fields_label.get_text()
        self.assertIn("status = ACTIVE", fields)
        self.assertIn("areaSquareMeters = 1250.50", fields)
        self.assertNotIn("cadastral", fields)
        self.assertTrue(self.pages.explorer_button.get_sensitive())
        self.assertIn("https://explorer.solana.com/tx/", self.pages.explorer_label.get_text())
        self.assertIn("?cluster=devnet", self.pages.explorer_label.get_text())
        self.assertNoSecrets()

        # 5. tampered area with the original claimed hash → QR_HASH_MISMATCH
        tampered = fx.tamper_document_area(Path(first_package).read_bytes())
        path = self.root / "tampered.json"
        path.write_bytes(tampered)
        self.verify_opened(path)
        self.assertEqual(self.pages.verify_status_label.get_text(), "INVALID")
        self.assertIn("QR_HASH_MISMATCH", self.pages.verify_code_label.get_text())
        self.assertIn("none", self.pages.verify_fields_label.get_text())
        self.assertFalse(self.pages.explorer_button.get_sensitive())
        self.assertNoSecrets()

        # 5b. tampered area with a repaired hash → the signature check fails
        repaired = fx.tamper_document_area(
            Path(first_package).read_bytes(), repair_hash=True)
        path = self.root / "tampered-repaired.json"
        path.write_bytes(repaired)
        self.verify_opened(path)
        self.assertEqual(self.pages.verify_status_label.get_text(), "INVALID")
        self.assertIn("CERT_SIGNATURE_INVALID", self.pages.verify_code_label.get_text())
        self.assertIn("none", self.pages.verify_fields_label.get_text())
        self.assertNoSecrets()

        # 6. QR image path verifies too (decoder double carries the QR URL)
        qr_info = self.stack.certificates[certificate["certificateId"]]
        self.qr.payloads[first_qr] = self.stack.qr_url(
            certificate["certificateId"], qr_info["qrHash"])
        self.verify_opened(first_qr)
        self.assertEqual(self.pages.verify_status_label.get_text(), "VERIFIED")
        self.assertNoSecrets()

        # 6b. a QR whose ?h= does not match is a QR_HASH_MISMATCH, not a pass
        self.qr.payloads[first_qr] = self.stack.qr_url(
            certificate["certificateId"], fx.FIXTURE_OTHER_QR_HASH)
        self.verify_opened(first_qr)
        self.assertEqual(self.pages.verify_status_label.get_text(), "INVALID")
        self.assertIn("QR_HASH_MISMATCH", self.pages.verify_code_label.get_text())
        self.assertNoSecrets()

        # 7. arrest version (encumbered + DISPUTED) and its own certificate
        self.create_version(status="DISPUTED", area="1250.50", encumbered=True)
        self.prepare_approve_finalize()
        self.pages.certificate_record_combo.set_active_id("SYNTHETIC-1")
        self.issue_and_save()
        newer = self.controller.snapshot()["certificate"]
        self.assertNotEqual(newer["certificateId"], certificate["certificateId"])

        # 8. the old package is now SUPERSEDED, not silently VERIFIED
        self.verify_opened(first_package)
        self.assertEqual(self.pages.verify_status_label.get_text(), "SUPERSEDED")
        verify_texts = label_texts(self.pages.verify_page)
        self.assertTrue(any("SUPERSEDED" in item for item in verify_texts), verify_texts)
        self.assertNoSecrets()

        # 9. the anchor link stays a validated devnet explorer URL
        target = self.controller.explorer_target()
        self.assertTrue(target.startswith("https://explorer.solana.com/tx/"))
        self.assertTrue(target.endswith("?cluster=devnet"))
        self.assertNoSecrets()


class ApprovalGateTests(FlowFixture):
    def test_approve_requires_a_successful_simulation(self):
        self.sign_in()
        self.create_version(status="ACTIVE", area="10.00", encumbered=False)
        self.stack.fail_simulation = True
        self.pages.prepare_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() == "Simulation failed")
        self.assertFalse(self.pages.approve_button.get_sensitive())
        self.assertEqual(self.signer.calls, 0)
        review = self.controller.snapshot()["review"]
        with self.assertRaises(ControllerError) as caught:
            self.controller.approve_and_sign(intent_hash=review["intentHash"])
        self.assertEqual(caught.exception.code, "APPROVAL_REQUIRED")
        self.assertNoSecrets()

    def test_double_sign_is_refused_after_the_first_signature(self):
        self.sign_in()
        self.create_version(status="ACTIVE", area="10.00", encumbered=False)
        self.prepare_approve_finalize()
        review = self.controller.snapshot()["review"]
        self.assertEqual(self.signer.calls, 1)
        with self.assertRaises(ControllerError) as caught:
            self.controller.approve_and_sign(intent_hash=review["intentHash"])
        self.assertEqual(caught.exception.code, "ALREADY_SIGNED")
        self.assertEqual(self.signer.calls, 1)
        self.assertNoSecrets()

    def test_rejecting_the_confirmation_dialog_never_signs(self):
        self.pages._confirm_approve = lambda review: False
        self.sign_in()
        self.create_version(status="ACTIVE", area="10.00", encumbered=False)
        self.pages.prepare_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() == "Simulated")
        self.pages.approve_button.clicked()
        self.settled()
        self.assertEqual(self.signer.calls, 0)
        self.assertEqual(self.pages.publish_chip.get_text(), "Simulated")
        self.assertNoSecrets()

    def test_signer_failure_is_reported_without_key_material(self):
        self.signer.fail = True
        self.sign_in()
        self.create_version(status="ACTIVE", area="10.00", encumbered=False)
        self.pages.prepare_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() == "Simulated")
        self.pages.approve_button.clicked()
        self.run_op(lambda: "SIGNER_FAILED" in " ".join(self.texts()))
        self.assertEqual(self.pages.publish_chip.get_text(), "Simulated")
        self.assertNoSecrets()

    def test_certificate_requires_a_finalized_publish(self):
        self.sign_in()
        self.create_version(status="ACTIVE", area="10.00", encumbered=False)
        self.assertFalse(self.pages.issue_button.get_sensitive())
        self.pages.prepare_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() == "Simulated")
        self.assertFalse(self.pages.issue_button.get_sensitive())
        self.assertNoSecrets()


class BlockedStateTests(FlowFixture):
    def test_unreachable_api_stays_blocked_and_never_fakes_success(self):
        profile = LiveDemoProfile(
            demo_api_origin="http://127.0.0.1:1",
            verifier_origin="http://127.0.0.1:1",
        )
        session = AdminSession(
            profile.demo_api_origin,
            credential_path=self.root / "onelayer-devnet-demo" / "admin-credentials.json",
            private_root=self.root,
            timeout=1.0,
        )
        controller = LiveDemoController(
            LiveDemoApi(profile, session),
            signer=self.signer, qr_decoder=self.qr, mode="live",
        )
        window = Gtk.Window()
        self.addCleanup(window.destroy)
        pages = LiveDemoPages(controller, window=window, confirm_approve=lambda r: True)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        outer.pack_start(pages.connection_card, False, False, 0)
        stack = Gtk.Stack()
        for name, widget in pages.pages():
            stack.add_named(widget, name)
        outer.pack_start(stack, True, True, 0)
        window.add(outer)
        window.show_all()
        pages.sign_in_button.clicked()
        drain_until(lambda: controller.snapshot()["busy"] is None, timeout=10)
        self.assertEqual(pages.connection_chip.get_text(), "No connection")
        self.assertEqual(pages.publish_chip.get_text(), "Not prepared")
        self.assertEqual(pages.verify_status_label.get_text(), "Not verified")
        self.assertFalse(pages.approve_button.get_sensitive())
        self.assertFalse(pages.issue_button.get_sensitive())
        self.assertTrue(any("Local devnet" in text for text in label_texts(window)))


class VerifyHonestyTests(FlowFixture):
    def _verified_package(self):
        self.sign_in()
        self.create_version(status="ACTIVE", area="10.00", encumbered=False)
        self.prepare_approve_finalize()
        self.issue()
        self.pages.save_package_button.clicked()
        self.run_op(lambda: self.controller.snapshot()["savedPackage"] is not None)
        self.verify_opened(self.saved["package"])
        self.assertEqual(self.pages.verify_status_label.get_text(), "VERIFIED")

    def test_failed_attempt_clears_the_previous_verdict_fields_and_explorer(self):
        self._verified_package()
        self.assertTrue(self.pages.explorer_button.get_sensitive())
        self.assertIn("ACTIVE", self.pages.verify_fields_label.get_text())
        # A missing file must not leave the green verdict on screen.
        self.verify_opened(self.root / "missing.json")
        self.assertEqual(self.pages.verify_status_label.get_text(), "INVALID")
        self.assertIn("FILE_UNREADABLE", self.pages.verify_code_label.get_text())
        self.assertIn("none", self.pages.verify_fields_label.get_text())
        self.assertNotIn("ACTIVE", self.pages.verify_fields_label.get_text())
        self.assertFalse(self.pages.explorer_button.get_sensitive())
        self.assertEqual(self.pages.explorer_label.get_text(), "")
        self.assertIsNone(self.controller.explorer_target())
        self.assertNoSecrets()

    def test_a_successful_verify_after_a_failed_one_is_green_again(self):
        self._verified_package()
        self.verify_opened(self.root / "missing.json")
        self.assertEqual(self.pages.verify_status_label.get_text(), "INVALID")
        self.verify_opened(self.saved["package"])
        self.assertEqual(self.pages.verify_status_label.get_text(), "VERIFIED")
        self.assertIn("ACTIVE", self.pages.verify_fields_label.get_text())
        self.assertTrue(self.pages.explorer_button.get_sensitive())

    def test_operation_error_is_cleared_by_the_next_operation(self):
        self._verified_package()
        self.verify_opened(self.root / "missing.json")
        self.assertIn("FILE_UNREADABLE", self.pages.verify_error.get_text())
        self.pages.reload_records_button.clicked()
        self.run_op(lambda: bool(self.pages.records_list.get_children()))
        self.assertEqual(self.pages.verify_error.get_text(), "")
        self.assertNoSecrets()

    def test_unexpected_failures_surface_as_internal_error_without_their_text(self):
        self.sign_in()

        def explode():
            raise RuntimeError("secret-canary-9f3a must never be rendered")

        self.api.list_records = explode
        with self.assertRaises(ControllerError) as caught:
            self.controller.call("reload_records")
        self.assertEqual(caught.exception.code, "INTERNAL_ERROR")
        error = self.controller.snapshot()["error"]
        self.assertEqual(error["code"], "INTERNAL_ERROR")
        self.assertNotIn("secret-canary", json.dumps(error))
        self.assertNotIn("secret-canary", str(caught.exception))
        self.flush()
        self.assertNotIn("secret-canary", " ".join(self.texts()))
        self.assertNoSecrets()


class SaveSafetyTests(FlowFixture):
    def _issued(self):
        self.sign_in()
        self.create_version(status="ACTIVE", area="10.00", encumbered=False)
        self.prepare_approve_finalize()
        self.issue()

    def test_save_refuses_existing_files_and_never_overwrites(self):
        self._issued()
        existing = self.root / "sentinel.json"
        existing.write_text("sentinel-content")
        with self.assertRaises(ControllerError) as caught:
            self.controller.save_package(path=existing)
        self.assertEqual(caught.exception.code, "SAVE_EXISTS")
        self.assertEqual(existing.read_text(), "sentinel-content")

    def test_save_refuses_symlinked_and_dangling_targets(self):
        self._issued()
        victim = self.root / "victim.json"
        victim.write_text("victim-content")
        link = self.root / "link.json"
        link.symlink_to(victim)
        with self.assertRaises(ControllerError) as caught:
            self.controller.save_package(path=link)
        self.assertEqual(caught.exception.code, "SAVE_EXISTS")
        self.assertEqual(victim.read_text(), "victim-content")
        dangling = self.root / "dangling.json"
        dangling.symlink_to(self.root / "never-created.json")
        with self.assertRaises(ControllerError) as caught:
            self.controller.save_package(path=dangling)
        self.assertEqual(caught.exception.code, "SAVE_EXISTS")
        self.assertFalse((self.root / "never-created.json").exists())

    def test_save_refuses_directories_and_relative_paths(self):
        self._issued()
        directory = self.root / "a-directory"
        directory.mkdir()
        with self.assertRaises(ControllerError) as caught:
            self.controller.save_package(path=directory)
        self.assertEqual(caught.exception.code, "SAVE_EXISTS")
        with self.assertRaises(ControllerError) as caught:
            self.controller.save_package(path="relative-name.json")
        self.assertEqual(caught.exception.code, "SAVE_PATH_INVALID")

    def test_save_succeeds_exactly_once_for_a_fresh_path(self):
        self._issued()
        target = self.root / "fresh.json"
        self.controller.save_package(path=target)
        self.assertTrue(target.is_file())
        self.assertIn("package_base64url", target.read_text())
        with self.assertRaises(ControllerError) as caught:
            self.controller.save_package(path=target)
        self.assertEqual(caught.exception.code, "SAVE_EXISTS")

    def test_chooser_refusal_is_explained_on_screen(self):
        self._issued()
        existing = self.root / "sentinel.json"
        existing.write_text("sentinel-content")
        self.pages._choose_save = lambda kind: str(existing)
        self.pages.save_package_button.clicked()
        self.settled()
        text = self.pages.certificate_error.get_text()
        self.assertIn("SAVE_EXISTS", text)
        self.assertIn("choose a new file name", text)
        self.assertEqual(existing.read_text(), "sentinel-content")
        self.assertNoSecrets()


class SessionResetTests(FlowFixture):
    def _full_state(self):
        self.sign_in()
        self.create_version(status="ACTIVE", area="10.00", encumbered=False)
        self.prepare_approve_finalize()
        self.issue()
        self.pages.save_package_button.clicked()
        self.run_op(lambda: self.controller.snapshot()["savedPackage"] is not None)
        self.verify_opened(self.saved["package"])
        self.assertEqual(self.pages.verify_status_label.get_text(), "VERIFIED")

    def test_sign_out_resets_records_review_certificate_and_verdict(self):
        self._full_state()
        self.pages.sign_out_button.clicked()
        self.run_op(lambda: self.pages.connection_chip.get_text() == "Signed out")
        snapshot = self.controller.snapshot()
        self.assertEqual(snapshot["records"], [])
        self.assertIsNone(snapshot["review"])
        self.assertIsNone(snapshot["certificate"])
        self.assertIsNone(snapshot["report"])
        self.assertIsNone(snapshot["savedPackage"])
        self.assertIsNone(snapshot["savedQr"])
        self.assertFalse(snapshot["approvalBound"])
        self.assertFalse(snapshot["signed"])
        self.assertEqual(self.pages.verify_status_label.get_text(), "Not verified")
        self.assertFalse(self.pages.explorer_button.get_sensitive())
        self.assertFalse(self.pages.save_package_button.get_sensitive())
        self.assertFalse(self.pages.approve_button.get_sensitive())
        self.assertFalse(self.pages.issue_button.get_sensitive())
        self.assertEqual(self.pages.verify_fields_label.get_text(), "—")
        self.assertNotIn("ACTIVE", self.pages.verify_fields_label.get_text())
        self.assertNoSecrets()

    def test_in_flight_completion_cannot_resurrect_state_after_sign_out(self):
        import threading

        self._full_state()
        records_before = self.controller.snapshot()["records"]
        self.assertTrue(records_before)
        gate = threading.Event()
        self.api.list_records = lambda: (gate.wait(5), records_before)[1]
        caught = []
        thread = threading.Thread(
            target=lambda: caught.extend(
                _capture(self.controller, "reload_records")))
        thread.start()
        time.sleep(0.2)
        self.controller.sign_out()
        gate.set()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        snapshot = self.controller.snapshot()
        self.assertEqual(snapshot["records"], [])
        self.assertIsNone(snapshot["report"])
        self.assertTrue(caught, "the stale completion should be refused")
        self.assertEqual(caught[0].code, "SESSION_CHANGED")

    def test_approval_bound_matches_the_displayed_intent(self):
        self.sign_in()
        self.create_version(status="ACTIVE", area="10.00", encumbered=False)
        self.pages.prepare_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() == "Simulated")
        self.assertFalse(self.controller.snapshot()["approvalBound"])
        self.pages.approve_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() == "Submitted")
        self.assertTrue(self.controller.snapshot()["approvalBound"])
        # A record edit invalidates the review and its binding.
        self.pages.record_id_entry.set_text("SYNTHETIC-9")
        self.pages.create_record_button.clicked()
        self.run_op(lambda: self.controller.snapshot()["review"] is None)
        self.assertFalse(self.controller.snapshot()["approvalBound"])

    def test_concurrent_approvers_sign_exactly_once(self):
        import threading

        self.sign_in()
        self.create_version(status="ACTIVE", area="10.00", encumbered=False)
        self.pages.prepare_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() == "Simulated")
        review = self.controller.snapshot()["review"]
        gate = threading.Event()
        original_sign = self.signer.sign

        def gated_sign(request):
            gate.wait(5)
            return original_sign(request)

        self.signer.sign = gated_sign
        outcomes = []
        errors = []

        def approve():
            try:
                self.controller.approve_and_sign(intent_hash=review["intentHash"])
                outcomes.append("signed")
            except ControllerError as error:
                errors.append(error.code)

        threads = [threading.Thread(target=approve) for _ in range(2)]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + 5
        while not errors and time.monotonic() < deadline:
            time.sleep(0.01)
        gate.set()
        for thread in threads:
            thread.join(5)
        self.assertEqual(outcomes, ["signed"])
        self.assertEqual(len(errors), 1)
        self.assertIn(errors[0], ("SIGN_IN_PROGRESS", "ALREADY_SIGNED"))
        self.assertEqual(self.signer.calls, 1)
        self.signer.sign = original_sign


def _capture(controller, operation):
    try:
        controller.call(operation)
    except ControllerError as error:
        return [error]
    return []


if __name__ == "__main__":
    unittest.main()
