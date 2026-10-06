"""Actual GTK interaction checks; require a live display, never count a skip."""
import threading
import time
import unittest
from unittest.mock import patch

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk
from launcher_view import LauncherView


def drain_until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        while Gtk.events_pending():
            Gtk.main_iteration_do(False)
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("native UI did not reach the expected state")


class LauncherViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Gtk.init_check()[0]:
            raise RuntimeError("Native display required for launcher interaction checks")

    def setUp(self):
        self.window = Gtk.Window()
        self.view = LauncherView(self.window)
        self.window.show_all()
        self.addCleanup(self.window.destroy)

    def test_refresh_keeps_ui_responsive_and_suppresses_repeated_clicks(self):
        ready = threading.Event()
        release = threading.Event()
        calls = []

        def probe():
            calls.append(True)
            ready.set()
            release.wait(2)
            return {key: {"state": "available", "detail": "synthetic response"}
                    for key in ("api", "verifier", "web")}

        self.addCleanup(release.set)
        with patch("launcher_view.probe_services", probe):
            self.view._probe_button.clicked()
            self.assertTrue(ready.wait(1))
            # A second signal must not launch another network batch. Navigation
            # must still work while the first batch is held outside the GTK thread.
            self.view._probe_button.clicked()
            self.view._nav["connection"].clicked()
            drain_until(lambda: self.view._stack.get_visible_child_name() == "connection")
            self.assertEqual(len(calls), 1)
            self.assertFalse(self.view._probe_button.get_sensitive())
            release.set()
            drain_until(lambda: self.view._probe_button.get_sensitive())
        self.assertTrue(self.view._probe_status.get_text().startswith("Checked at"))

    def test_transport_failure_allows_retry_without_echoing_error_contents(self):
        with patch("launcher_view.probe_services", side_effect=RuntimeError("private-canary")):
            self.view._probe_button.clicked()
            drain_until(lambda: self.view._probe_button.get_sensitive())
        self.assertEqual(self.view._probe_status.get_text(), "Check interrupted")
        for card in self.view._cards.values():
            self.assertNotIn("private-canary", card._detail.get_text())

    def test_late_completion_cannot_update_destroyed_window(self):
        ready = threading.Event()
        release = threading.Event()
        finished = threading.Event()

        def probe():
            ready.set()
            release.wait(2)
            finished.set()
            return {}

        self.addCleanup(release.set)
        with patch("launcher_view.probe_services", probe):
            self.view._probe_button.clicked()
            self.assertTrue(ready.wait(1))
            self.window.destroy()
            release.set()
            self.assertTrue(finished.wait(1))
            drain_until(self.view.is_closed)
            self.assertFalse(self.view._apply_probe_result({}, None))


if __name__ == "__main__":
    unittest.main()
