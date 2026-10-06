#!/usr/bin/python3
"""GTK runtime harness. Not a third proposed production desktop stack."""
import argparse
import json
import sys
import threading
from pathlib import Path

import gi
gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, GLib, Gtk

import launcher_view


def _live_demo_controller():
    """Live-demo scenario controller (B3); contacts nothing until used."""
    from live_demo_controller import LiveDemoController
    return LiveDemoController.local()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true", help="Open own window and close after rendering")
    parser.add_argument("--screenshot", type=Path)
    parser.add_argument("--lab-backend", help="Synthetic loopback backend origin only")
    parser.add_argument("--lab-issuer", help="Synthetic loopback IdP origin only")
    parser.add_argument("--integration-smoke", action="store_true")
    args = parser.parse_args()
    if bool(args.lab_backend) != bool(args.lab_issuer) or (args.integration_smoke and not args.lab_backend):
        parser.error("integration requires both synthetic origins")
    session = None
    if args.lab_backend:
        from session import LabSession, SessionFailure
        session = LabSession(args.lab_backend, args.lab_issuer)
    if not Gtk.init_check()[0]:
        raise SystemExit("Native display unavailable")
    window = Gtk.Window(title="OneLayer — Demo")
    window.set_default_size(980, 640)
    window.connect("destroy", Gtk.main_quit)

    def completed(state, summary):
        if view.is_closed():
            return False
        if state == "authenticated" and args.screenshot:
            native_window = window.get_window()
            pixbuf = Gdk.pixbuf_get_from_window(native_window, 0, 0,
                                                native_window.get_width(), native_window.get_height())
            if pixbuf is None:
                raise RuntimeError("Native capture failed")
            pixbuf.savev(str(args.screenshot), "png", [], [])
        print(json.dumps({"state": state, "summary": summary, "synthetic": True}), flush=True)
        return False

    view = launcher_view.LauncherView(
        window,
        session=session is not None,
        on_command=lambda command: action(command),
        on_close=window.destroy,
        live_demo=_live_demo_controller(),
    )
    busy = threading.Lock()

    def display(state, summary=None):
        if view.is_closed():
            return False
        view.set_session(state, summary)
        if state == "authenticated" and args.screenshot:
            GLib.timeout_add(100, completed, state, summary)
        else:
            completed(state, summary)
        return False

    def action(command):
        if not busy.acquire(blocking=False):
            return
        GLib.idle_add(display, "loading")

        def run():
            try:
                if command == "login":
                    result = session.login()
                elif command == "refresh":
                    result = session.refresh()
                elif command == "logout":
                    session.logout()
                    result = None
                else:
                    raise ValueError("Unknown lab command")
                GLib.idle_add(display, "authenticated" if result else "signed-out", result)
            except SessionFailure as error:
                GLib.idle_add(display, error.state)
            finally:
                busy.release()
        threading.Thread(target=run, daemon=True).start()

    if args.integration_smoke:
        def commands():
            for line in sys.stdin:
                command = line.strip()
                if command == "close":
                    GLib.idle_add(window.destroy)
                    break
                if command in ("login", "refresh", "logout"):
                    action(command)
        threading.Thread(target=commands, daemon=True).start()
        GLib.idle_add(display, "signed-out")
    window.show_all()

    def rendered():
        native_window = window.get_window()
        if native_window is None or not window.get_mapped():
            raise RuntimeError("Native window was not mapped")
        if args.screenshot:
            width, height = native_window.get_width(), native_window.get_height()
            pixbuf = Gdk.pixbuf_get_from_window(native_window, 0, 0, width, height)
            if pixbuf is None:
                raise RuntimeError("Native capture failed")
            pixbuf.savev(str(args.screenshot), "png", [], [])
        print(json.dumps({"native_window": "mapped", "gtk": f"{Gtk.get_major_version()}.{Gtk.get_minor_version()}.{Gtk.get_micro_version()}", "synthetic": True}), flush=True)
        window.destroy()
        return False

    if args.smoke:
        GLib.timeout_add(600, rendered)
    Gtk.main()
    if session:
        session.clear()


if __name__ == "__main__":
    main()
