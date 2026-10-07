"""HERMETIC smoke-walk contract test (B4/B5) — explicitly not a live run.

This drives the *same* ``_Walk.walk`` scenario the opt-in live smoke runs, but
against the fixture backends (``live_demo_fixtures``) and a ``mode="fixture"``
controller, with the fixture tamper seam instead of the accepted A3 CLI
helper. Its only job is to catch stale widget or controller-state seams in
the walk (a renamed button, a session-state string that no longer matches, a
missing page) so a live smoke cannot fail for wiring reasons.

Nothing here is a live-devnet result: every outcome is fixture-labeled, and
the walk itself refuses a fixture controller in live mode
(``FIXTURE_IN_LIVE_RUN``). The real-devnet smoke stays BLOCKED on the lost
governance key (``4Y4p…``).
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "apps" / "desktop" / "lab"))

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

import launcher_view
import live_demo_fixtures as fx
import live_demo_smoke_gate as gate
import live_demo_smoke_gtk as smoke_gtk
from live_demo_api import LiveDemoApi, LiveDemoProfile
from live_demo_controller import LiveDemoController
from live_demo_session import AdminSession


class SmokeWalkContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Gtk.init_check()[0]:
            raise RuntimeError("Native display required for the smoke-walk contract test")

    def setUp(self):
        self.stack = fx.FixtureStack()
        self.addCleanup(self.stack.close)
        self.root = Path(tempfile.mkdtemp(prefix="onelayer-smoke-walk-", dir="/dev/shm"))
        self.addCleanup(self._cleanup_root)
        staging = self.root / "staging"
        staging.mkdir()
        credential = fx.write_credential_file(self.root)
        profile = LiveDemoProfile(
            demo_api_origin=self.stack.demo_origin,
            verifier_origin=self.stack.verifier_origin,
        )
        session = AdminSession(
            profile.demo_api_origin, credential_path=credential, private_root=self.root
        )
        self.api = LiveDemoApi(profile, session)
        self.qr = fx.FakeQrDecoder()
        self.controller = LiveDemoController(
            self.api, signer=fx.FakeSigner(), qr_decoder=self.qr, mode="fixture"
        )
        self.window = Gtk.Window()
        self.window.set_default_size(1024, 720)
        self.view = launcher_view.LauncherView(self.window, live_demo=self.controller)
        self.pages = self.view._live_pages
        self.saved: dict[str, str] = {}
        self.staging = staging
        self.walk = smoke_gtk._Walk(
            1,
            staging,
            record_id="SYNTHETIC-1",
            mode="fixture",
            tamper=self._tamper,
        )
        self.pages._confirm_approve = self._confirm_approve
        self.pages._choose_save = self._choose_save
        self.pages._choose_open = self._choose_open
        self.window.show_all()
        self.addCleanup(self._destroy_window)

    def _cleanup_root(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _destroy_window(self):
        self.window.destroy()
        while Gtk.events_pending():
            Gtk.main_iteration_do(False)

    def _tamper(self, source: Path, target: Path) -> None:
        """Fixture stand-in for the accepted A3 tamper helper."""
        target.write_bytes(fx.tamper_document_area(Path(source).read_bytes()))

    def _confirm_approve(self, _review):
        self.walk.approvals += 1
        return True

    def _choose_save(self, kind: str) -> str:
        target = self.staging / f"artifact-{len(self.saved)}-{kind}.{'json' if kind == 'package' else 'png'}"
        self.saved[kind] = str(target)
        if kind == "qr":
            # The fixture QR decoder is a path -> payload double (the real A4
            # helper decodes the PNG). Seed it for the file about to be written
            # so the walk's QR verify step exercises the real payload binding.
            certificate = self.controller.snapshot().get("certificate") or {}
            qr_url = certificate.get("qrUrl") if isinstance(certificate, dict) else None
            if isinstance(qr_url, str) and qr_url:
                self.qr.payloads[str(target)] = qr_url
        return str(target)

    def _choose_open(self):
        return self.saved.get("open")

    def test_walk_contract_runs_the_complete_scenario_against_fixtures(self):
        self.walk.walk(self.controller, self.view, self.pages, self.window, self.saved)
        self.assertEqual(self.walk.approvals, 2, "one explicit approve per reviewed publish")
        public = self.walk.evidence["publicIds"]
        self.assertEqual(len(public["intentIds"]), 2)
        self.assertEqual(len(public["transactionSignatures"]), 2)
        explorer = str(public.get("explorerUrl") or "")
        self.assertTrue(explorer.startswith("https://explorer.solana.com/tx/"), explorer)
        self.assertIn("?cluster=devnet", explorer)
        self.assertEqual(self.walk.explorer_opened, [explorer], "the Explorer button seam opened exactly the anchor")
        self.assertEqual(sorted(public.get("disclosedPaths") or []), ["areaSquareMeters", "status"])
        self.assertEqual(self.walk.evidence["mode"], "fixture")
        self.assertEqual(self.walk.evidence["recordId"], "SYNTHETIC-1")

    def test_live_mode_refuses_a_fixture_backed_controller(self):
        walk = smoke_gtk._Walk(2, self.staging, record_id="SYNTHETIC-2", mode="live", tamper=self._tamper)
        with self.assertRaises(gate.SmokeError) as raised:
            walk.walk(self.controller, self.view, self.pages, self.window, self.saved)
        self.assertEqual(raised.exception.code, "FIXTURE_IN_LIVE_RUN")

    def test_each_run_uses_its_own_synthetic_record(self):
        first = smoke_gtk._Walk(1, self.staging, mode="fixture", tamper=self._tamper)
        second = smoke_gtk._Walk(2, self.staging, mode="fixture", tamper=self._tamper)
        third = smoke_gtk._Walk(3, self.staging, mode="fixture", tamper=self._tamper)
        self.assertEqual([first.record_id, second.record_id, third.record_id], ["SYNTHETIC-1", "SYNTHETIC-2", "SYNTHETIC-3"])


if __name__ == "__main__":
    unittest.main()
