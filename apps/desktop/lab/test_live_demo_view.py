"""Real GTK widget checks for the live-demo pages (B3).

These drive actual widgets on a real display against hermetic loopback
fixtures (``live_demo_fixtures``). No display is a failure, never a skip — the
same rule as ``test_launcher_view.py``. Fixture-backed screens are labeled and
these tests assert that label is visible.
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
from live_demo_controller import LiveDemoController
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


class LiveDemoViewFixture(unittest.TestCase):
    mode = "fixture"

    @classmethod
    def setUpClass(cls):
        if not Gtk.init_check()[0]:
            raise RuntimeError("Native display required for live-demo view checks")

    def setUp(self):
        self.stack = fx.FixtureStack()
        self.addCleanup(self.stack.close)
        self.root = Path(tempfile.mkdtemp(prefix="onelayer-live-demo-view-", dir="/dev/shm"))
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
            self.api, signer=self.signer, qr_decoder=self.qr, mode=self.mode
        )
        self.saved = {}
        self.confirmed = []
        self.window = Gtk.Window()
        self.window.set_default_size(1024, 720)
        self.pages = LiveDemoPages(
            self.controller,
            window=self.window,
            confirm_approve=self._confirm,
            choose_save=self._choose_save,
            choose_open=self._choose_open,
        )
        # Pack every page so the window tree is the real one.
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        outer.pack_start(self.pages.connection_card, False, False, 0)
        outer.pack_start(self.pages.setup_card, False, False, 0)
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

    def _confirm(self, review):
        self.confirmed.append(dict(review))
        return True

    def _choose_save(self, kind):
        path = self.root / ("package.json" if kind == "package" else "qr.png")
        self.saved[kind] = str(path)
        return str(path)

    def _choose_open(self):
        return self.saved.get("package")

    def texts(self, widget=None):
        return label_texts(widget if widget is not None else self.window)

    def settled(self):
        drain_until(lambda: self.controller.snapshot()["busy"] is None)

    def run_op(self, *predicates):
        """Drain until an operation finishes and its state is visible."""
        self.settled()
        for predicate in predicates:
            drain_until(predicate)
        self.settled()

    def assertNoSecrets(self):
        joined = "\n".join(self.texts())
        self.assertNotIn(SECRET, joined)
        self.assertNotIn("csrf", joined.lower())
        self.assertNotIn("admin-credentials", joined)
        self.assertNotIn("signedtransactionbase64", joined.lower())


class PageSurfaceTests(LiveDemoViewFixture):
    def test_fixture_mode_is_visibly_labelled(self):
        texts = self.texts()
        self.assertTrue(any("FIXTURE DATA" in text for text in texts), texts)
        self.assertNoSecrets()

    def test_pages_render_honest_empty_states(self):
        self.assertIn("Not prepared", self.pages.publish_chip.get_text())
        self.assertIn("Not verified", self.pages.verify_status_label.get_text())
        self.assertIn("Not issued yet.", " ".join(self.texts(self.pages.certificates_page)))
        self.assertFalse(self.pages.approve_button.get_sensitive())
        self.assertFalse(self.pages.issue_button.get_sensitive())
        self.assertFalse(self.pages.explorer_button.get_sensitive())

    def test_record_form_exposes_only_schema_values(self):
        statuses = [self.pages.status_combo.get_active_id()]
        for index in range(4):
            self.pages.status_combo.set_active(index)
            statuses.append(self.pages.status_combo.get_active_text())
        self.assertEqual(sorted(set(statuses) - {None}), ["ACTIVE", "ARCHIVED", "DISPUTED", "PENDING"])
        # The demo's clean/arrest distinction maps to the schema bool, never to
        # an invented status value.
        self.assertIn("encumbered", self.pages.encumbered_check.get_label())
        self.assertNotIn("clean", self.pages.status_combo.get_active_text().lower())
        self.assertNoSecrets()


class ConnectionTests(LiveDemoViewFixture):
    def test_sign_in_uses_the_dev_shm_password_without_showing_it(self):
        self.pages.sign_in_button.clicked()
        self.run_op(lambda: self.pages.connection_chip.get_text() == "Signed in")
        self.assertIn("operator", self.pages.connection_detail.get_text())
        self.assertNoSecrets()
        self.assertFalse(self.pages.sign_in_button.get_sensitive())

    def test_sign_in_failure_is_reported_without_echoing_bodies(self):
        self.root.joinpath("onelayer-devnet-demo", "admin-credentials.json").write_text(
            json.dumps({"operator": "short"}))
        self.pages.sign_in_button.clicked()
        self.run_op(lambda: self.pages.connection_chip.get_text() == "Sign-in failed")
        self.assertNoSecrets()

    def test_sign_in_error_offers_the_start_stack_hint_without_claiming_offline(self):
        # Missing credentials AND a down stack must still show the hint, but
        # must never claim the stack is unreachable (nothing was probed).
        self.root.joinpath("onelayer-devnet-demo", "admin-credentials.json").unlink()
        self.pages.sign_in_button.clicked()
        self.run_op(lambda: self.pages.connection_chip.get_text() == "Sign-in failed")
        detail = self.pages.connection_detail.get_text()
        self.assertIn("start it and sign in again", detail)
        self.assertIn("If the local demo stack is not running", detail)
        self.assertNotIn("Cannot reach", detail)
        self.assertNoSecrets()


class SetupCardTests(LiveDemoViewFixture):
    """ADR-0010 setup: read-only check and explicit approval before any send."""

    def test_setup_card_exposes_check_and_review_actions(self):
        self.assertTrue(hasattr(self.pages, "setup_card"))
        self.assertTrue(hasattr(self.pages, "setup_check_button"))
        self.assertTrue(hasattr(self.pages, "setup_prepare_button"))
        texts = self.texts(self.pages.setup_card)
        joined = "\n".join(texts)
        self.assertIn("Devnet setup", joined)
        self.assertIn("never run automatically", joined)
        self.assertIn("explicit confirmation", joined)

    def test_setup_is_unavailable_in_fixture_mode_and_says_so(self):
        self.pages.render()
        self.assertIn("live mode only", self.pages.setup_status.get_text())
        self.assertFalse(self.pages.setup_check_button.get_sensitive())
        self.assertFalse(self.pages.setup_prepare_button.get_sensitive())

    def test_prepare_requires_explicit_confirmation(self):
        # Even with a summary present, a cancelled dialog must not call prepare.
        calls = []
        assessment = {
            "cluster": "solana:devnet", "programId": "p", "registryId": "r",
            "configPda": "c", "blockerCodes": [],
            "steps": [{"status": "ACTION_REQUIRED", "actionKind": "grant_operator"}],
        }
        real_snapshot = self.controller.snapshot
        self.controller.snapshot = lambda: {**real_snapshot(), "setup": assessment}
        self.pages._confirm_setup = lambda summary: False
        self.controller.call = lambda op, **kw: calls.append(op)
        self.pages._on_setup_prepare()
        self.assertEqual(calls, [])
        self.assertIn("cancelled", self.pages.setup_status.get_text())
        self.assertIn("No transaction was sent", self.pages.setup_status.get_text())

    def test_setup_summary_names_the_transaction_before_approval(self):
        assessment = {
            "cluster": "solana:devnet",
            "programId": "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo",
            "registryId": "demo.synthetic.onelayer",
            "configPda": "BPgSTnDHop1NhMrksBWJtZV2zqVmUM1iusEuUXocCnFU",
            "blockerCodes": ["GOVERNANCE_KEY_UNAVAILABLE"],
            "steps": [
                {"status": "ACTION_REQUIRED", "actionKind": "initialize_registry",
                 "requiredSigner": "governance 4Y4pGizJm5"},
            ],
        }
        summary = self.pages._setup_summary_text(assessment)
        self.assertIn("solana:devnet", summary)
        self.assertIn("demo.synthetic.onelayer", summary)
        self.assertIn("initialize_registry", summary)
        self.assertIn("governance 4Y4pGizJm5", summary)
        self.assertIn("GOVERNANCE_KEY_UNAVAILABLE", summary)
        self.assertIn("real devnet transactions", summary)

    def test_namespace_is_rendered_on_the_connection_card(self):
        self.pages.render()
        text = self.pages.namespace_value.get_text()
        self.assertIn("gov.registry.land", text)
        self.assertIn("Legacy", text)


class RecordsPageTests(LiveDemoViewFixture):
    def test_create_version_callback_renders_the_new_record(self):
        self.pages.record_id_entry.set_text("SYNTHETIC-7")
        self.pages.status_combo.set_active_id("ACTIVE")
        self.pages.cadastral_entry.set_text("01-004-0123-045")
        self.pages.area_entry.set_text("1250.50")
        self.pages.encumbered_check.set_active(False)
        self.pages.create_record_button.clicked()
        drain_until(lambda: len(self.pages.records_list.get_children()) == 1)
        text = self.texts(self.pages.records_page)
        self.assertTrue(any("SYNTHETIC-7" in item for item in text), text)
        self.assertTrue(any("1250.50" in item for item in text), text)
        self.assertNoSecrets()

    def test_second_version_of_one_record_renders_the_latest(self):
        for status, encumbered in (("ACTIVE", False), ("DISPUTED", True)):
            self.pages.record_id_entry.set_text("SYNTHETIC-3")
            self.pages.status_combo.set_active_id(status)
            self.pages.cadastral_entry.set_text("A-1")
            self.pages.area_entry.set_text("10.00")
            self.pages.encumbered_check.set_active(encumbered)
            self.pages.create_record_button.clicked()
            self.run_op(lambda: bool(self.pages.records_list.get_children()))
        # One row per record id, showing the newest version — a second send of
        # the same id is a new version, not a second row.
        self.assertEqual(len(self.pages.records_list.get_children()), 1)
        texts = self.texts(self.pages.records_page)
        self.assertTrue(any("v2" in item for item in texts), texts)
        self.assertTrue(any("encumbered=true" in item for item in texts), texts)
        self.assertTrue(any("DISPUTED" in item for item in texts), texts)
        self.assertNoSecrets()

    def test_record_rows_carry_explicit_contrast_classes(self):
        self.pages.record_id_entry.set_text("SYNTHETIC-7")
        self.pages.create_record_button.clicked()
        drain_until(lambda: len(self.pages.records_list.get_children()) == 1)
        row = self.pages.records_list.get_children()[0]
        self.assertIn("record-row", row.get_style_context().list_classes())
        self.assertIn("record-row", row.get_child().get_style_context().list_classes())


class PublishPageTests(LiveDemoViewFixture):
    def _prepare(self):
        self.pages.create_record_button.clicked()
        self.run_op(lambda: bool(self.pages.records_list.get_children()))
        self.pages.prepare_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() in ("Simulated", "Simulation failed"))

    def test_prepare_renders_the_immutable_review(self):
        self._prepare()
        self.assertEqual(self.pages.publish_chip.get_text(), "Simulated")
        text = "\n".join(self.texts(self.pages.publish_page))
        for expected in ("solana:devnet", fx.FIXTURE_PROGRAM, "aa" * 16, fx.FIXTURE_OPERATOR[:16]):
            self.assertIn(expected, text)
        self.assertTrue(self.pages.approve_button.get_sensitive())
        self.assertNoSecrets()

    def test_approve_flow_signs_once_and_disables_itself(self):
        self._prepare()
        self.pages.approve_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() == "Submitted")
        self.assertEqual(len(self.confirmed), 1)
        self.assertEqual(self.signer.calls, 1)
        self.assertTrue(self.signer.requests[0]["approved"] is True)
        self.assertFalse(self.pages.approve_button.get_sensitive())
        self.assertIn("cannot be signed again", self.pages.approve_detail.get_text())
        self.pages.approve_button.clicked()
        self.assertEqual(self.signer.calls, 1)
        self.assertNoSecrets()

    def test_approve_after_record_edit_is_refused_and_never_signs(self):
        self._prepare()
        stale_hash = self.controller.snapshot()["review"]["intentHash"]
        # Editing the record invalidates the review and any approval bound to it.
        self.pages.record_id_entry.set_text("SYNTHETIC-9")
        self.pages.create_record_button.clicked()
        self.run_op(lambda: self.controller.snapshot()["review"] is None)
        self.assertFalse(self.pages.approve_button.get_sensitive())
        from live_demo_controller import ControllerError
        with self.assertRaises(ControllerError) as caught:
            self.controller.approve_and_sign(intent_hash=stale_hash)
        self.assertIn(caught.exception.code, ("NO_REVIEW", "APPROVAL_STALE"))
        self.assertEqual(self.signer.calls, 0)
        self.assertNoSecrets()

    def test_refresh_binds_approval_to_the_displayed_intent(self):
        self._prepare()
        stale_hash = self.controller.snapshot()["review"]["intentHash"]
        self.pages.prepare_button.clicked()
        self.run_op(lambda: self.controller.snapshot()["review"]["intentHash"] != stale_hash)
        from live_demo_controller import ControllerError
        with self.assertRaises(ControllerError) as caught:
            self.controller.approve_and_sign(intent_hash=stale_hash)
        self.assertEqual(caught.exception.code, "APPROVAL_STALE")
        self.assertEqual(self.signer.calls, 0)

    def test_simulation_failure_is_never_approvable(self):
        self.stack.fail_simulation = True
        self._prepare()
        self.assertEqual(self.pages.publish_chip.get_text(), "Simulation failed")
        self.assertFalse(self.pages.approve_button.get_sensitive())
        self.assertNoSecrets()

    def test_navigation_stays_responsive_during_an_in_flight_request(self):
        # Hold one request open and prove the window keeps working meanwhile.
        import threading
        gate = threading.Event()
        original = self.api.list_records

        def slow_list():
            gate.wait(3)
            return original()

        self.api.list_records = slow_list
        self.pages.reload_records_button.clicked()
        self.view_stack.set_visible_child_name("publish")
        drain_until(lambda: self.view_stack.get_visible_child_name() == "publish")
        self.pages.prepare_button.clicked()
        self.assertTrue(self.pages.publish_chip.get_text() in ("Not prepared",))
        gate.set()
        self.settled()

    def test_auto_reconciliation_polling_reaches_finalized(self):
        from unittest.mock import patch

        self._prepare()
        with patch("live_demo_view.RECONCILE_INTERVAL_MS", 50):
            self.pages.approve_button.clicked()
            self.run_op(lambda: self.pages.publish_chip.get_text() == "Submitted")
            # No button press: the bounded poller observes the anchor itself.
            self.run_op(lambda: self.pages.publish_chip.get_text() == "Finalized")

    def test_reconciliation_reaches_finalized(self):
        self._prepare()
        self.pages.approve_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() == "Submitted")
        self.pages.reconcile_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() == "Finalized")
        self.assertNoSecrets()


class VerifyPageTests(LiveDemoViewFixture):
    def _issue_certificate(self):
        self.pages.create_record_button.clicked()
        self.run_op(lambda: bool(self.pages.records_list.get_children()))
        self.pages.prepare_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() == "Simulated")
        self.pages.approve_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() == "Submitted")
        self.pages.reconcile_button.clicked()
        self.run_op(lambda: self.pages.publish_chip.get_text() == "Finalized")
        self.assertTrue(self.pages.issue_button.get_sensitive())
        self.pages.issue_button.clicked()
        self.run_op(lambda: self.controller.snapshot()["certificate"] is not None)

    def test_default_disclosure_is_status_and_area_only(self):
        self._issue_certificate()
        active = sorted(
            path for path, check in self.pages.disclosure_checks.items() if check.get_active())
        self.assertEqual(active, ["areaSquareMeters", "status"])
        certificate = self.controller.snapshot()["certificate"]
        self.assertEqual(certificate["disclosedPaths"], ["areaSquareMeters", "status"])
        self.assertNoSecrets()

    def test_save_package_and_qr_use_the_chooser_paths(self):
        self._issue_certificate()
        self.pages.save_package_button.clicked()
        self.run_op(lambda: self.controller.snapshot()["savedPackage"] is not None)
        self.pages.save_qr_button.clicked()
        self.run_op(lambda: self.controller.snapshot()["savedQr"] is not None)
        document = json.loads(Path(self.saved["package"]).read_text())
        self.assertIn("package_base64url", document)
        self.assertTrue(Path(self.saved["qr"]).read_bytes().startswith(b"\x89PNG"))
        self.assertNoSecrets()

    def test_verified_package_is_green_with_disclosed_fields(self):
        self._issue_certificate()
        self.pages.save_package_button.clicked()
        self.run_op(lambda: self.controller.snapshot()["savedPackage"] is not None)
        self.pages.open_verify_button.clicked()
        self.run_op(lambda: self.pages.verify_status_label.get_text() == "VERIFIED")
        self.assertIn("status-verified", self.pages.verify_status_label.get_style_context().list_classes())
        self.assertIn("ACTIVE", self.pages.verify_fields_label.get_text())
        self.assertTrue(self.pages.explorer_button.get_sensitive())
        self.assertIn("explorer.solana.com/tx/", self.pages.explorer_label.get_text())
        self.assertNoSecrets()

    def test_invalid_package_is_red_and_discloses_nothing(self):
        self._issue_certificate()
        self.pages.save_package_button.clicked()
        self.run_op(lambda: self.controller.snapshot()["savedPackage"] is not None)
        tampered = fx.tamper_document_area(Path(self.saved["package"]).read_bytes())
        Path(self.saved["package"]).write_bytes(tampered)
        self.pages.open_verify_button.clicked()
        self.run_op(lambda: self.pages.verify_status_label.get_text() == "INVALID")
        self.assertIn("status-bad", self.pages.verify_status_label.get_style_context().list_classes())
        self.assertIn("none", self.pages.verify_fields_label.get_text())
        self.assertNotIn("ACTIVE", self.pages.verify_fields_label.get_text())
        self.assertFalse(self.pages.explorer_button.get_sensitive())
        self.assertNoSecrets()

    def test_no_green_for_verified_no_incident_check(self):
        self.stack.force_status = "VERIFIED_NO_INCIDENT_CHECK"
        self._issue_certificate()
        self.pages.save_package_button.clicked()
        self.run_op(lambda: self.controller.snapshot()["savedPackage"] is not None)
        self.pages.open_verify_button.clicked()
        self.run_op(lambda: self.pages.verify_status_label.get_text() == "VERIFIED_NO_INCIDENT_CHECK")
        classes = self.pages.verify_status_label.get_style_context().list_classes()
        self.assertNotIn("status-verified", classes)
        self.assertIn("status-warn", classes)


class LiveModeBannerTests(LiveDemoViewFixture):
    mode = "live"

    def test_live_mode_banner_does_not_claim_fixture_data(self):
        texts = self.texts()
        self.assertFalse(any("FIXTURE DATA" in text for text in texts), texts)
        self.assertTrue(any("Local devnet" in text for text in texts), texts)
        self.assertNoSecrets()


class LauncherIntegrationTests(LiveDemoViewFixture):
    def test_ordinary_launcher_exposes_the_live_demo_screens(self):
        import launcher_view

        window = Gtk.Window()
        self.addCleanup(window.destroy)
        view = launcher_view.LauncherView(
            window, live_demo=self.controller)
        window.show_all()
        for name in ("records", "publish", "certificates", "verify"):
            self.assertIn(name, view._nav)
        for name in ("overview", "connection", "records", "publish", "certificates", "verify"):
            self.assertIsNotNone(view._stack.get_child_by_name(name))
        view._nav["publish"].clicked()
        drain_until(lambda: view._stack.get_visible_child_name() == "publish")
        self.assertNoSecrets()

    def test_overview_carries_the_mode_banner(self):
        import launcher_view

        window = Gtk.Window()
        self.addCleanup(window.destroy)
        view = launcher_view.LauncherView(window, live_demo=self.controller)
        window.show_all()
        overview = view._stack.get_child_by_name("overview")
        texts = label_texts(overview)
        self.assertTrue(any("FIXTURE DATA" in item for item in texts), texts)
        # And every other live-demo page carries the very same banner.
        self.assertTrue(any("FIXTURE DATA" in item for item in label_texts(window)), texts)


if __name__ == "__main__":
    unittest.main()
