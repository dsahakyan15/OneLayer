"""Polished GTK 3 view for the installed OneLayer Linux lab launcher.

Display-only surface: English labels, a plain "Demo" profile badge and the
optional synthetic lab session controls. Service observations come from the
launcher_state module and are refreshed only when the operator presses the
explicit button. The view exposes no tokens, keys, credential reads, shell,
arbitrary URL input or runtime auto-start.
"""
import threading
import time

import gi
gi.require_version("Gdk", "3.0")
gi.require_version("Gtk", "3.0")
from gi.repository import Gdk, GLib, Gtk

from launcher_state import HEALTH_STATES, SERVICE_LABELS, probe_services


SESSION_STATES = {
    "signed-out": "Signed out",
    "loading": "Working…",
    "authenticated": "Signed in",
    "expired": "Session expired",
    "offline": "Server unreachable",
    "error": "Request failed",
}
SESSION_CHIPS = {
    "signed-out": "chip-idle",
    "loading": "chip-load",
    "authenticated": "chip-ok",
    "expired": "chip-bad",
    "offline": "chip-bad",
    "error": "chip-bad",
}
HEALTH_CHIPS = {
    "unknown": "chip-idle",
    "loading": "chip-load",
    "available": "chip-ok",
    "offline": "chip-bad",
    "error": "chip-bad",
}
CHIP_CLASSES = ("chip-idle", "chip-load", "chip-ok", "chip-bad")
TRANSPORT_STATES = ("available", "offline", "error")
ROLE_LABELS = {
    "operator": "Operator",
    "auditor": "Auditor",
    "chief_admin": "Chief Admin",
    "registry_worker": "Registry Worker",
    "registry_approver": "Registry Approver",
    "identity_admin": "Identity Admin",
    "key_holder": "Key Holder",
    "storage_custodian": "Storage Custodian",
}
PROBE_LABEL = "_Check connection"
PROBE_BUSY_LABEL = "Checking…"
UNCHECKED_DETAIL = "Check not started"
PROBE_REQUEST_DETAIL = "Request in progress…"

_CSS = b"""
.ol-window { background-color: #f4f6fa; }
.ol-window combobox cellview { color: #1d2839; }
.ol-window entry { color: #1d2839; background-color: #ffffff; }
.ol-window entry:disabled { color: #72809a; background-color: #f4f6fa; }
.ol-window button:disabled { color: #72809a; background-color: #edf1f7; }
.ol-header { background-color: #ffffff; border-bottom: 1px solid #dce3ee; }
.ol-header-title { font-size: 17px; font-weight: bold; color: #1d2839; }
.badge { background-color: #2f6fdd; color: #ffffff; border-radius: 9px;
         padding: 1px 9px; font-size: 11px; font-weight: bold; }
.sidebar { background-color: #edf1f7; border-right: 1px solid #dce3ee; }
.sidebar-caption { color: #71809a; font-size: 11px; font-weight: bold; }
.nav-item { background-image: none; background-color: transparent;
            border: 1px solid transparent; border-radius: 8px;
            padding: 8px 12px; color: #3b4a63; }
.nav-item:hover { background-color: #e2e9f5; }
.nav-item-active { background-color: #dfeaff; color: #1d4ed8; }
.card { background-color: #ffffff; border: 1px solid #dfe5ef;
        border-radius: 12px; padding: 16px; }
.card-title { font-size: 15px; font-weight: bold; color: #1d2839; }
.card-title-small { font-size: 13px; font-weight: bold; color: #1d2839; }
.section-title { font-size: 15px; font-weight: bold; color: #1d2839; }
.subtle { color: #5c6a80; font-size: 12px; }
.value { color: #1d2839; font-size: 12px; }
.footer { background-color: #ffffff; border-top: 1px solid #dce3ee; }
.chip { border-radius: 9px; padding: 1px 9px; font-size: 11px; font-weight: bold; }
.chip-idle { background-color: #e9edf4; color: #56637a; }
.chip-load { background-color: #e3edfd; color: #1d4ed8; }
.chip-ok { background-color: #e0f2e5; color: #1c6b3c; }
.chip-bad { background-color: #fceaea; color: #a33737; }
.accent { background-image: none; background-color: #2f6fdd;
          border-color: #2f6fdd; color: #ffffff; font-weight: bold; }
.accent:hover { background-color: #2a63c6; }
.accent:disabled { background-color: #9db9ea; border-color: #9db9ea; color: #f2f6fd; }
.ghost { background-image: none; background-color: #ffffff;
         border: 1px solid #d5ddea; color: #33415c; }
.ghost:hover { background-color: #f2f5fb; }
"""

_CSS_INSTALLED = False


def _install_css():
    global _CSS_INSTALLED
    if _CSS_INSTALLED:
        return
    provider = Gtk.CssProvider()
    provider.load_from_data(_CSS)
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    _CSS_INSTALLED = True


def _add_classes(widget, *names):
    context = widget.get_style_context()
    for name in names:
        context.add_class(name)


def _label(text, *classes, wrap=False, max_chars=96):
    label = Gtk.Label(label=text)
    label.set_xalign(0.0)
    if wrap:
        label.set_line_wrap(True)
        label.set_max_width_chars(max_chars)
    if classes:
        _add_classes(label, *classes)
    return label


def _scrolled(child):
    window = Gtk.ScrolledWindow()
    window.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    window.set_propagate_natural_width(False)
    window.set_propagate_natural_height(False)
    window.add(child)
    return window


class _ServiceCard(Gtk.Box):
    """One service observation: name, human state chip and probe detail."""

    def __init__(self, title):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        _add_classes(self, "card")
        self.pack_start(_label(title, "card-title-small"), False, False, 0)
        self._chip = _label("", "chip", "chip-idle")
        self._chip.set_halign(Gtk.Align.START)
        self.pack_start(self._chip, False, False, 0)
        self._detail = _label("", "subtle", wrap=True, max_chars=34)
        self.pack_start(self._detail, False, False, 0)

    def render(self, state, detail):
        self._chip.set_text(HEALTH_STATES.get(state, HEALTH_STATES["unknown"]))
        context = self._chip.get_style_context()
        for name in CHIP_CLASSES:
            context.remove_class(name)
        context.add_class(HEALTH_CHIPS.get(state, "chip-idle"))
        self._detail.set_text(detail)


class LauncherView:
    """Builds the launcher inside the window and owns the health probe thread."""

    def __init__(self, window, session=False, on_command=None, on_close=None, live_demo=None):
        _install_css()
        self._window = window
        self._on_command = on_command
        self._on_close = on_close
        self._session_available = session
        self._session_buttons = []
        self._cards = {}
        self._closed = False
        self._probe_active = False
        window.get_style_context().add_class("ol-window")
        window.connect("destroy", self._on_destroy)

        # Live-demo pages (B3): always present in the ordinary launcher. The
        # controller is cheap to construct and contacts nothing until used.
        if live_demo is None:
            from live_demo_controller import LiveDemoController
            live_demo = LiveDemoController.local()
        from live_demo_view import LiveDemoPages
        self._live_demo = live_demo
        self._live_pages = LiveDemoPages(live_demo, window=window)
        from workflow_demo import build_page
        from live_demo_controller import LiveDemoController
        self._workflow = build_page(LiveDemoController.local()._api, window)

        header = Gtk.HeaderBar()
        header.set_show_close_button(True)
        _add_classes(header, "ol-header")
        title_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        title_row.set_valign(Gtk.Align.CENTER)
        title_row.pack_start(_label("OneLayer", "ol-header-title"), False, False, 0)
        badge = _label("Demo", "badge")
        badge.set_valign(Gtk.Align.CENTER)
        title_row.pack_start(badge, False, False, 0)
        header.set_custom_title(title_row)
        window.set_titlebar(header)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        window.add(root)
        content = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        content.set_vexpand(True)
        root.pack_start(content, True, True, 0)

        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.NONE)
        self._stack.set_hexpand(True)
        self._stack.set_vexpand(True)
        self._nav = self._build_sidebar()
        content.pack_start(self._nav_box, False, False, 0)
        content.pack_start(self._stack, True, True, 0)

        self._stack.add_named(self._workflow.widget, "workflow")
        self._stack.add_named(self._build_overview_page(), "overview")
        self._stack.add_named(self._build_connection_page(), "connection")
        for name, widget in self._live_pages.pages():
            self._stack.add_named(widget, name)
        self._show_page("workflow" if self._live_demo._api.profile.is_local_cluster else "overview")
        root.pack_start(self._build_footer(), False, False, 0)

    def _build_sidebar(self):
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        _add_classes(sidebar, "sidebar")
        sidebar.set_size_request(212, -1)
        sidebar.set_border_width(12)
        sidebar.pack_start(_label("Sections", "sidebar-caption"), False, False, 0)
        buttons = {}
        sections = (("overview", "_Overview"), ("connection", "_Connection"))
        if self._live_demo._api.profile.is_local_cluster:
            sections = (("workflow", "_Сценарий"),) + sections
        else:
            sections = sections + tuple(self._live_pages.nav_items())
        for name, text in sections:
            button = Gtk.Button.new_with_mnemonic(text)
            button.set_relief(Gtk.ReliefStyle.NONE)
            _add_classes(button, "nav-item")
            button.connect("clicked", lambda _widget, name=name: self._show_page(name))
            sidebar.pack_start(button, False, False, 0)
            buttons[name] = button
        sidebar.pack_start(Gtk.Box(), True, True, 0)
        self._nav_box = sidebar
        return buttons

    def _show_page(self, name):
        self._stack.set_visible_child_name(name)
        for page, button in self._nav.items():
            context = button.get_style_context()
            if page == name:
                context.add_class("nav-item-active")
            else:
                context.remove_class("nav-item-active")

    def _build_overview_page(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        page.set_border_width(20)
        page.set_valign(Gtk.Align.START)
        # The mode banner is registered with the live-demo pages, so every
        # launcher screen — including this overview — labels fixture runs.
        page.pack_start(self._live_pages.banner_row(), False, False, 0)
        page.pack_start(self._welcome_card(), False, False, 0)
        page.pack_start(self._session_card(), False, False, 0)
        page.pack_start(self._services_section(), False, False, 0)
        return _scrolled(page)

    def _welcome_card(self):
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        _add_classes(card, "card")
        card.pack_start(_label("Welcome", "card-title"), False, False, 0)
        card.pack_start(_label(
            "Connect to the work environment and check service availability.", "subtle", wrap=True),
            False, False, 0)
        return card

    def _session_card(self):
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        _add_classes(card, "card")
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        head.pack_start(_label("Session", "card-title"), True, True, 0)
        self._session_chip = _label("", "chip", "chip-idle")
        self._session_chip.set_valign(Gtk.Align.CENTER)
        head.pack_end(self._session_chip, False, False, 0)
        card.pack_start(head, False, False, 0)
        self._session_detail = _label("", "subtle", wrap=True)
        card.pack_start(self._session_detail, False, False, 0)
        self.set_session("signed-out")
        return card

    def _services_section(self):
        section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        head.pack_start(_label("Services", "section-title"), False, False, 0)
        self._probe_status = _label(UNCHECKED_DETAIL, "subtle")
        head.pack_start(self._probe_status, True, True, 0)
        self._probe_button = Gtk.Button.new_with_mnemonic(PROBE_LABEL)
        _add_classes(self._probe_button, "accent")
        self._probe_button.connect("clicked", lambda _widget: self.start_probe())
        head.pack_end(self._probe_button, False, False, 0)
        section.pack_start(head, False, False, 0)
        grid = Gtk.Grid()
        grid.set_column_spacing(12)
        grid.set_row_spacing(12)
        grid.set_column_homogeneous(True)
        for index, key in enumerate(("api", "verifier", "web")):
            card = _ServiceCard(SERVICE_LABELS.get(key, key))
            card.set_hexpand(True)
            grid.attach(card, index, 0, 1, 1)
            self._cards[key] = card
        section.pack_start(grid, False, False, 0)
        section.pack_start(_label(
            "Statuses refresh when you check the connection.", "subtle", wrap=True), False, False, 0)
        for card in self._cards.values():
            card.render("unknown", UNCHECKED_DETAIL)
        return section

    def _build_connection_page(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        page.set_border_width(20)
        page.set_valign(Gtk.Align.START)
        page.pack_start(self._session_control_card(), False, False, 0)
        page.pack_start(self._live_pages.connection_card, False, False, 0)
        page.pack_start(self._live_pages.setup_card, False, False, 0)
        return _scrolled(page)

    def _session_control_card(self):
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        _add_classes(card, "card")
        card.pack_start(_label("Connection", "card-title"), False, False, 0)
        if self._session_available:
            card.pack_start(_label("Sign in, refresh the session and sign out for the current connection.", "subtle",
                                   wrap=True), False, False, 0)
            buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            for text, command in (("_Sign in", "login"), ("Refres_h session", "refresh"),
                                  ("Sign ou_t", "logout")):
                button = Gtk.Button.new_with_mnemonic(text)
                _add_classes(button, "accent" if command == "login" else "ghost")
                button.connect("clicked", self._command_handler(command))
                buttons.pack_start(button, False, False, 0)
                self._session_buttons.append(button)
            card.pack_start(buttons, False, False, 0)
        else:
            card.pack_start(_label("Sign-in becomes available after the connection is configured.", "subtle",
                                   wrap=True), False, False, 0)
        return card

    def _build_footer(self):
        footer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        _add_classes(footer, "footer")
        footer.set_border_width(10)
        footer.pack_start(_label("OneLayer · Demo", "subtle"), True, True, 0)
        close = Gtk.Button.new_with_mnemonic("C_lose")
        _add_classes(close, "ghost")
        close.connect("clicked", lambda _widget: self._close())
        footer.pack_end(close, False, False, 0)
        return footer

    def _close(self):
        if self._on_close is not None:
            self._on_close()
        else:
            self._window.destroy()

    def _command_handler(self, command):
        def handler(_widget):
            if not self._closed and self._on_command is not None:
                self._on_command(command)
        return handler

    def set_session(self, state, summary=None):
        """Render a session state; machine states stay untouched for stdout."""
        if self._closed:
            return
        self._session_chip.set_text(SESSION_STATES.get(state, "Unknown state"))
        context = self._session_chip.get_style_context()
        for name in CHIP_CLASSES:
            context.remove_class(name)
        context.add_class(SESSION_CHIPS.get(state, "chip-idle"))
        username = summary.get("username") if isinstance(summary, dict) else None
        role = summary.get("role") if isinstance(summary, dict) else None
        if state == "authenticated" and (username or role):
            parts = []
            if username:
                parts.append("User: " + str(username))
            if role:
                parts.append("Role: " + ROLE_LABELS.get(str(role), str(role)))
            detail = " · ".join(parts)
        elif state == "authenticated":
            detail = "Signed in."
        elif state == "loading":
            detail = "Checking the connection…"
        elif state == "expired":
            detail = "Session expired. Sign in again on the Connection page."
        elif state == "offline":
            detail = "No connection to the server. Check the connection and sign in again."
        elif state == "error":
            detail = "Sign-in failed. Try again on the Connection page."
        elif self._session_available:
            detail = "Use the Connection page to sign in and sign out."
        else:
            detail = "Sign-in becomes available after the connection is configured."
        self._session_detail.set_text(detail)
        for button in self._session_buttons:
            button.set_sensitive(state != "loading")

    def start_probe(self):
        """Run one explicit reachability check in a background thread."""
        if self._closed or self._probe_active:
            return
        self._probe_active = True
        self._probe_button.set_sensitive(False)
        self._probe_button.set_label(PROBE_BUSY_LABEL)
        self._probe_status.set_text("Check in progress…")
        for card in self._cards.values():
            card.render("loading", PROBE_REQUEST_DETAIL)

        def run():
            result = None
            failure = False
            try:
                result = probe_services()
            except Exception:  # a transport crash must not kill the window
                failure = True
            GLib.idle_add(self._apply_probe_result, result, failure)

        threading.Thread(target=run, daemon=True).start()

    def _apply_probe_result(self, result, failure):
        if self._closed:
            return False
        self._probe_active = False
        self._probe_button.set_label(PROBE_LABEL)
        self._probe_button.set_sensitive(True)
        if failure:
            for card in self._cards.values():
                card.render("error", "The connection check failed. Try again.")
            self._probe_status.set_text("Check interrupted")
            return False
        for key, card in self._cards.items():
            observation = result.get(key) if isinstance(result, dict) else None
            state = observation.get("state") if isinstance(observation, dict) else None
            detail = observation.get("detail") if isinstance(observation, dict) else None
            if state not in TRANSPORT_STATES:
                state = "error"
            card.render(state, detail if isinstance(detail, str) and detail else "—")
        self._probe_status.set_text("Checked at " + time.strftime("%H:%M:%S"))
        return False

    def _on_destroy(self, *_args):
        self._closed = True

    def is_closed(self):
        return self._closed
