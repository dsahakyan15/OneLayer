"""GTK pages for the live-demo launcher scenario (B3).

Five English pages plugged into the existing lab launcher: Connection, Records,
Publish, Certificates and Verify. Everything on screen is rendered from
:mod:`live_demo_controller`'s snapshot, which holds no secrets; requests run on
worker threads so the window stays responsive.

Honesty rules enforced here:
* fixture runs carry a visible fixture banner; live runs say "Local devnet".
* ``VERIFIED`` is the only green verdict. ``VERIFIED_NO_INCIDENT_CHECK`` is
  never green, ``SUPERSEDED`` / ``DISPUTED`` / ``VERIFIED_HISTORICAL`` are
  caution-styled, and ``INVALID`` / ``QR_HASH_MISMATCH`` are red with no
  disclosed field values.
* the record form exposes the *schema* fields (status enum, cadastral number,
  area, ``encumbered``) — there is no invented clean/arrest status value.
* the Explorer button opens an external browser only for a validated
  ``https://explorer.solana.com/tx/<sig>?cluster=devnet`` URL. No other URL is
  ever opened, and no page embeds a browser.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Mapping

import gi
gi.require_version("Gdk", "3.0")
gi.require_version("Gtk", "3.0")
from gi.repository import Gdk, GLib, Gtk

from launcher_view import _add_classes, _install_css, _label, _scrolled

__all__ = ["LiveDemoPages"]

MAX_SHOWN_FIELD = 240
MAX_SHOWN_ROWS = 24
RECONCILE_ATTEMPTS = 6
RECONCILE_INTERVAL_MS = 2000

STATUS_STYLES = {
    "VERIFIED": ("status-verified", "chip-ok"),
    "VERIFIED_HISTORICAL": ("status-warn", "chip-warn"),
    "VERIFIED_NO_INCIDENT_CHECK": ("status-warn", "chip-warn"),
    "SUPERSEDED": ("status-warn", "chip-warn"),
    "DISPUTED": ("status-warn", "chip-warn"),
    "INVALID": ("status-bad", "chip-bad"),
    # The verifier's /v2 vocabulary. ``UNKNOWN`` is the honest lifecycle answer
    # (no complete authenticated lifecycle source) and must never be green.
    "UNKNOWN": ("status-warn", "chip-warn"),
    "REVOKED": ("status-bad", "chip-bad"),
    "HISTORICAL": ("status-warn", "chip-warn"),
}
PUBLISH_CHIPS = {
    "idle": ("chip-idle", "Not prepared"),
    "SIMULATED": ("chip-ok", "Simulated"),
    "SIMULATION_FAILED": ("chip-bad", "Simulation failed"),
    "SUBMITTED": ("chip-load", "Submitted"),
    "FINALIZED": ("chip-ok", "Finalized"),
    "ISSUED": ("chip-ok", "Certificate issued"),
}

_EXTRA_CSS = b"""
.chip-warn { background-color: #fdf0d5; color: #8a5a00; }
.status-verified { font-size: 22px; font-weight: bold; color: #1c6b3c; }
.status-bad { font-size: 22px; font-weight: bold; color: #a33737; }
.status-warn { font-size: 22px; font-weight: bold; color: #8a5a00; }
.fixture-banner { background-color: #7a4b00; color: #ffffff; border-radius: 8px;
                  padding: 4px 10px; font-size: 11px; font-weight: bold; }
.live-banner { background-color: #1d4ed8; color: #ffffff; border-radius: 8px;
               padding: 4px 10px; font-size: 11px; font-weight: bold; }
.mono { font-family: monospace; font-size: 11px; }
/* Explicit colors so record rows stay readable under dark system themes. */
row.record-row { background-image: none; background-color: #f4f6fa; border-radius: 8px; }
label.record-row { background-image: none; background-color: #f4f6fa; color: #1d2839; }
"""
_EXTRA_CSS_INSTALLED = False


def _install_extra_css():
    global _EXTRA_CSS_INSTALLED
    _install_css()
    if _EXTRA_CSS_INSTALLED:
        return
    provider = Gtk.CssProvider()
    provider.load_from_data(_EXTRA_CSS)
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    _EXTRA_CSS_INSTALLED = True


def _bounded(value: Any, limit: int = MAX_SHOWN_FIELD) -> str:
    text = "—" if value is None else str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _kv_row(grid: Gtk.Grid, row: int, key: str, value: Any) -> int:
    grid.attach(_label(key, "subtle"), 0, row, 1, 1)
    entry = _label(_bounded(value), "value", wrap=True, max_chars=52)
    entry.set_selectable(True)
    grid.attach(entry, 1, row, 1, 1)
    return row + 1


class LiveDemoPages:
    """Builds and renders the live-demo pages around one controller."""

    NAV = (
        ("records", "_Records"),
        ("publish", "_Publish"),
        ("certificates", "_Certificates"),
        ("verify", "_Verify"),
    )

    def __init__(self, controller, *, window: Gtk.Window | None = None,
                 confirm_approve=None, choose_save=None, choose_open=None):
        _install_extra_css()
        self._controller = controller
        self._window = window
        self._confirm_approve = confirm_approve or self._ask_approve
        self._choose_save = choose_save or self._ask_save
        self._choose_open = choose_open or self._ask_open
        self._reconcile_left = 0
        self._busy = False
        self._banners: list[Gtk.Label] = []
        self._certificate_record_ids: list[str] = []
        self._build()
        # Controller events arrive from worker threads; render on the GTK loop.
        controller.set_emit(lambda event, payload: GLib.idle_add(self.handle_event, event, payload))
        self.render()

    # -- construction -----------------------------------------------------

    def _build(self) -> None:
        self.connection_card = self._build_connection_card()
        self.setup_card = self._build_setup_card()
        self.records_page = self._build_records_page()
        self.publish_page = self._build_publish_page()
        self.certificates_page = self._build_certificates_page()
        self.verify_page = self._build_verify_page()
        self._pages = {
            "records": self.records_page,
            "publish": self.publish_page,
            "certificates": self.certificates_page,
            "verify": self.verify_page,
        }

    def nav_items(self):
        return self.NAV

    def page(self, name: str) -> Gtk.Widget:
        return self._pages[name]

    def pages(self):
        return list(self._pages.items())

    def set_window(self, window: Gtk.Window) -> None:
        self._window = window

    def banner_row(self) -> Gtk.Box:
        """A fixture/live banner row — also used by the launcher overview.

        The row registers itself with :meth:`render`, so every screenshot of
        the launcher carries the mode banner, not only the live-demo pages.
        """
        return self._banner()

    def _banner_text(self, snapshot: Mapping[str, Any] | None = None) -> str:
        fixture = (snapshot or {}).get("mode") == "fixture" if snapshot is not None \
            else self._controller.mode == "fixture"
        base = ("FIXTURE DATA — synthetic test backends, not live devnet"
                if fixture else "Local devnet · synthetic demo data only")
        if snapshot is not None:
            registry_id = snapshot.get("registryId")
            if isinstance(registry_id, str) and registry_id:
                base += " · registry " + registry_id
        return base

    def _banner(self) -> Gtk.Box:
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        fixture = self._controller.mode == "fixture"
        label = _label(self._banner_text(),
                       "fixture-banner" if fixture else "live-banner")
        self._banners.append(label)
        row.pack_start(label, False, False, 0)
        return row

    def _build_connection_card(self) -> Gtk.Widget:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        _add_classes(card, "card")
        card.pack_start(self._banner(), False, False, 0)
        card.pack_start(_label("Live demo — Local (devnet)", "card-title"), False, False, 0)
        card.pack_start(_label(
            "Profile: Local demo (devnet) · demo-api 127.0.0.1:8090 · verifier 127.0.0.1:8080. "
            "Everything runs over loopback only.", "subtle", wrap=True), False, False, 0)
        grid = Gtk.Grid()
        grid.set_column_spacing(12)
        grid.set_row_spacing(6)
        grid.attach(_label("Namespace", "subtle"), 0, 0, 1, 1)
        self.namespace_value = _label("—", "value", wrap=True, max_chars=52)
        self.namespace_value.set_selectable(True)
        grid.attach(self.namespace_value, 1, 0, 1, 1)
        _kv_row(grid, 1, "Operator", "operator (test operator of the demo registry)")
        _kv_row(grid, 2, "Password", "read from /dev/shm at sign-in · never typed, shown or logged")
        card.pack_start(grid, False, False, 0)
        self.namespace_detail_label = _label("", "subtle", wrap=True)
        card.pack_start(self.namespace_detail_label, False, False, 0)
        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.sign_in_button = Gtk.Button.new_with_mnemonic("_Sign in")
        _add_classes(self.sign_in_button, "accent")
        self.sign_in_button.connect("clicked", lambda _w: self._on_sign_in())
        buttons.pack_start(self.sign_in_button, False, False, 0)
        self.sign_out_button = Gtk.Button.new_with_mnemonic("Sign _out")
        _add_classes(self.sign_out_button, "ghost")
        self.sign_out_button.connect("clicked", lambda _w: self._on_sign_out())
        buttons.pack_start(self.sign_out_button, False, False, 0)
        card.pack_start(buttons, False, False, 0)
        self.connection_chip = _label("Signed out", "chip", "chip-idle")
        self.connection_chip.set_halign(Gtk.Align.START)
        card.pack_start(self.connection_chip, False, False, 0)
        self.connection_detail = _label(
            "Not signed in. Sign in to work with records, publish and certificates.",
            "subtle", wrap=True)
        card.pack_start(self.connection_detail, False, False, 0)
        self.connection_error = _label("", "subtle", wrap=True)
        card.pack_start(self.connection_error, False, False, 0)
        return card

    def _build_setup_card(self) -> Gtk.Widget:
        """Devnet chain setup (ADR-0010): read-only assessment and explicit
        approval before any transaction is signed or sent."""
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        _add_classes(card, "card")
        card.pack_start(_label("Devnet setup", "card-title"), False, False, 0)
        card.pack_start(_label(
            "Chain preparation (initialize_registry, grant_operator, fund_operator, "
            "create_ledger_segment) is never run automatically. Check the setup "
            "first; approving sends real devnet transactions and requires your "
            "explicit confirmation.", "subtle", wrap=True), False, False, 0)
        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.setup_check_button = Gtk.Button.new_with_mnemonic("C_heck setup (read-only)")
        _add_classes(self.setup_check_button, "ghost")
        self.setup_check_button.connect("clicked", lambda _w: self._on_setup_check())
        buttons.pack_start(self.setup_check_button, False, False, 0)
        self.setup_prepare_button = Gtk.Button.new_with_mnemonic("_Review and prepare…")
        _add_classes(self.setup_prepare_button, "accent")
        self.setup_prepare_button.set_sensitive(False)
        self.setup_prepare_button.connect("clicked", lambda _w: self._on_setup_prepare())
        buttons.pack_start(self.setup_prepare_button, False, False, 0)
        card.pack_start(buttons, False, False, 0)
        self.setup_status = _label("Not checked.", "subtle", wrap=True)
        card.pack_start(self.setup_status, False, False, 0)
        self.setup_steps_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card.pack_start(self.setup_steps_box, False, False, 0)
        self.setup_error = _label("", "subtle", wrap=True)
        card.pack_start(self.setup_error, False, False, 0)
        return card

    def _on_setup_check(self) -> None:
        if self._busy:
            return
        self._run_setup_operation("assess_setup")

    def _on_setup_prepare(self) -> None:
        """Explicit confirmation before any chain mutation.

        Shows the concrete planned actions and requires a deliberate approve
        click. Nothing is signed or sent without it.
        """
        if self._busy:
            return
        assessment = self._controller.snapshot().get("setup")
        if not isinstance(assessment, dict):
            self.setup_status.set_text("Check the setup first.")
            return
        summary = self._setup_summary_text(assessment)
        confirmed = self._confirm_setup(summary)
        if not confirmed:
            self.setup_status.set_text("Preparation cancelled. No transaction was sent.")
            return
        self._run_setup_operation("prepare_setup")

    def _confirm_setup(self, summary: str) -> bool:
        """Modal confirmation. Overridable in tests (``_confirm_setup`` seam)."""
        dialog = Gtk.MessageDialog(
            transient_for=self._window,
            flags=0,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.OK_CANCEL,
            text="Approve devnet chain setup?",
        )
        dialog.format_secondary_text(summary)
        response = dialog.run()
        dialog.destroy()
        return response == Gtk.ResponseType.OK

    @staticmethod
    def _setup_summary_text(assessment: Mapping[str, Any]) -> str:
        """Concrete action summary shown before the approve click."""
        lines = [
            "Cluster: {0}".format(assessment.get("cluster")),
            "Program: {0}".format(assessment.get("programId")),
            "Registry: {0}".format(assessment.get("registryId")),
            "Config PDA: {0}".format(assessment.get("configPda")),
            "",
            "Planned actions:",
        ]
        planned = [s for s in (assessment.get("steps") or [])
                   if isinstance(s, dict) and s.get("actionKind")]
        if not planned:
            lines.append("  (none — every step is already satisfied)")
        for step in planned:
            lines.append("  [{0}] {1}".format(step.get("status"), step.get("actionKind")))
            if step.get("requiredSigner"):
                lines.append("      signer: {0}".format(step.get("requiredSigner")))
        codes = assessment.get("blockerCodes") or []
        if codes:
            lines.append("")
            lines.append("Blockers: {0}".format(", ".join(str(c) for c in codes)))
            if "GOVERNANCE_KEY_UNAVAILABLE" in codes:
                lines.append(
                    "The legacy registry's governance authority is permanently lost; "
                    "governance-signed setup cannot run on this namespace.")
        lines.append("")
        lines.append("Approving sends real devnet transactions.")
        return "\n".join(lines)

    def _run_setup_operation(self, operation: str) -> None:
        self._busy = True
        self.setup_check_button.set_sensitive(False)
        self.setup_prepare_button.set_sensitive(False)
        self.setup_status.set_text("Working…")

        def run() -> None:
            try:
                self._controller.call(operation)
            except Exception:  # noqa: BLE001 - already reported as a code
                pass
            finally:
                GLib.idle_add(self._setup_finished)

        threading.Thread(target=run, daemon=True).start()

    def _setup_finished(self) -> bool:
        self._busy = False
        self.render()
        return False

    def _render_setup(self, snapshot: Mapping[str, Any]) -> None:
        self.setup_error.set_text(_error_text(snapshot.get("error"), "prepare_setup")
                                  or _error_text(snapshot.get("error"), "assess_setup"))
        assessment = snapshot.get("setup")
        available = bool(snapshot.get("setupAvailable"))
        self.setup_check_button.set_sensitive(not self._busy and available)
        if not available:
            self.setup_status.set_text(
                "Chain setup is available in live mode only.")
            for child in self.setup_steps_box.get_children():
                self.setup_steps_box.remove(child)
            return
        if not isinstance(assessment, dict):
            if not self._busy:
                self.setup_status.set_text("Not checked. Use “Check setup” for a read-only assessment.")
            return
        prepared = assessment.get("prepared")
        ok = assessment.get("ok")
        if prepared and ok:
            self.setup_status.set_text("Prepared. The registry is ready for the demo flow.")
        elif prepared:
            code = assessment.get("refusalCode")
            self.setup_status.set_text(
                "Preparation finished with a refusal: {0}".format(code or "unknown"))
        else:
            ready = sum(1 for s in (assessment.get("steps") or [])
                        if isinstance(s, dict) and s.get("status") in ("READY", "SATISFIED"))
            self.setup_status.set_text(
                "Assessment only — {0} step(s) ready. Nothing was sent.".format(ready))
        for child in self.setup_steps_box.get_children():
            self.setup_steps_box.remove(child)
        for step in (assessment.get("steps") or [])[:12]:
            if not isinstance(step, dict):
                continue
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            status = str(step.get("status") or "")
            chip_class = {
                "READY": "chip-ok", "SATISFIED": "chip-ok", "EXECUTED": "chip-ok",
                "ACTION_REQUIRED": "chip-load", "BLOCKED": "chip-bad",
            }.get(status, "chip-idle")
            chip = _label(status, "chip", chip_class)
            chip.set_halign(Gtk.Align.START)
            row.pack_start(chip, False, False, 0)
            detail = "{0} — {1}".format(step.get("actionKind") or step.get("id"), step.get("detail") or "")
            row.pack_start(_label(_bounded(detail, 110), "subtle", wrap=True), True, True, 0)
            self.setup_steps_box.pack_start(row, False, False, 0)
        self.setup_steps_box.show_all()
        codes = assessment.get("blockerCodes") or []
        if codes and "GOVERNANCE_KEY_UNAVAILABLE" in codes:
            warn = _label(
                "Governance-signed setup cannot run on the legacy registry "
                "(authority permanently lost). An isolated ADR-0010 namespace is "
                "the honest path and is never selected implicitly.", "subtle", wrap=True)
            self.setup_steps_box.pack_start(warn, False, False, 0)
        self.setup_steps_box.show_all()
        has_actions = any(isinstance(s, dict) and s.get("actionKind")
                          for s in (assessment.get("steps") or []))
        self.setup_prepare_button.set_sensitive(
            not self._busy and available and has_actions and not prepared)

    def _build_records_page(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        page.set_border_width(20)
        page.set_valign(Gtk.Align.START)

        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        _add_classes(form, "card")
        form.pack_start(self._banner(), False, False, 0)
        form.pack_start(_label("Create record version", "card-title"), False, False, 0)
        form.pack_start(_label(
            "Sending the same record id again creates the next version. "
            "Fields follow the land-registry-v1 schema: status is the record "
            "lifecycle enum and the encumbrance flag is the schema's "
            "“encumbered” boolean — the demo's clean/arrest distinction. "
            "There is no invented clean/arrest status value.",
            "subtle", wrap=True), False, False, 0)

        grid = Gtk.Grid()
        grid.set_column_spacing(10)
        grid.set_row_spacing(8)
        self.record_id_entry = Gtk.Entry()
        self.record_id_entry.set_text("SYNTHETIC-1")
        self.record_id_entry.set_width_chars(18)
        grid.attach(_label("Record id", "subtle"), 0, 0, 1, 1)
        grid.attach(self.record_id_entry, 1, 0, 1, 1)

        self.status_combo = Gtk.ComboBoxText()
        for value in ("ACTIVE", "ARCHIVED", "PENDING", "DISPUTED"):
            self.status_combo.append(value, value)
        self.status_combo.set_active_id("ACTIVE")
        grid.attach(_label("Status (schema enum)", "subtle"), 0, 1, 1, 1)
        grid.attach(self.status_combo, 1, 1, 1, 1)

        self.cadastral_entry = Gtk.Entry()
        self.cadastral_entry.set_text("01-004-0123-045")
        self.cadastral_entry.set_width_chars(22)
        grid.attach(_label("Cadastral number", "subtle"), 0, 2, 1, 1)
        grid.attach(self.cadastral_entry, 1, 2, 1, 1)

        self.area_entry = Gtk.Entry()
        self.area_entry.set_text("1250.50")
        self.area_entry.set_width_chars(12)
        grid.attach(_label("Area (m², scale 2)", "subtle"), 0, 3, 1, 1)
        grid.attach(self.area_entry, 1, 3, 1, 1)

        self.encumbered_check = Gtk.CheckButton.new_with_label(
            "Encumbrance registered (encumbered=true · demo “arrest”)")
        grid.attach(self.encumbered_check, 0, 4, 2, 1)
        form.pack_start(grid, False, False, 0)

        self.create_record_button = Gtk.Button.new_with_mnemonic("Create _version")
        _add_classes(self.create_record_button, "accent")
        self.create_record_button.connect("clicked", lambda _w: self._on_create_record())
        form.pack_start(self.create_record_button, False, False, 0)
        self.records_error = _label("", "subtle", wrap=True)
        form.pack_start(self.records_error, False, False, 0)
        page.pack_start(form, False, False, 0)

        listing = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        _add_classes(listing, "card")
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        head.pack_start(_label("Records", "card-title"), True, True, 0)
        self.reload_records_button = Gtk.Button.new_with_mnemonic("Ref_resh")
        _add_classes(self.reload_records_button, "ghost")
        self.reload_records_button.connect("clicked", lambda _w: self._on_reload_records())
        head.pack_end(self.reload_records_button, False, False, 0)
        listing.pack_start(head, False, False, 0)
        self.records_list = Gtk.ListBox()
        self.records_list.set_selection_mode(Gtk.SelectionMode.NONE)
        listing.pack_start(self.records_list, False, False, 0)
        self.records_hint = _label("No records loaded.", "subtle", wrap=True)
        listing.pack_start(self.records_hint, False, False, 0)
        page.pack_start(listing, False, False, 0)
        return _scrolled(page)

    def _build_publish_page(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        page.set_border_width(20)
        page.set_valign(Gtk.Align.START)

        prepare = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        _add_classes(prepare, "card")
        prepare.pack_start(self._banner(), False, False, 0)
        prepare.pack_start(_label("Prepare and simulate", "card-title"), False, False, 0)
        prepare.pack_start(_label(
            "Builds one publish intent for the local registry and simulates it on "
            "Solana devnet. Nothing is signed until you press Approve.",
            "subtle", wrap=True), False, False, 0)
        grid = Gtk.Grid()
        grid.set_column_spacing(12)
        grid.set_row_spacing(6)
        self.operator_address_label = _label("—", "value", wrap=True, max_chars=52)
        self.operator_address_label.set_selectable(True)
        grid.attach(_label("Operator address", "subtle"), 0, 0, 1, 1)
        grid.attach(self.operator_address_label, 1, 0, 1, 1)
        prepare.pack_start(grid, False, False, 0)
        self.prepare_button = Gtk.Button.new_with_mnemonic("_Prepare and simulate")
        _add_classes(self.prepare_button, "accent")
        self.prepare_button.connect("clicked", lambda _w: self._on_prepare())
        prepare.pack_start(self.prepare_button, False, False, 0)
        self.publish_error = _label("", "subtle", wrap=True)
        prepare.pack_start(self.publish_error, False, False, 0)
        page.pack_start(prepare, False, False, 0)

        review = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        _add_classes(review, "card")
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        head.pack_start(_label("Immutable review", "card-title"), True, True, 0)
        self.publish_chip = _label("Not prepared", "chip", "chip-idle")
        self.publish_chip.set_valign(Gtk.Align.CENTER)
        head.pack_end(self.publish_chip, False, False, 0)
        review.pack_start(head, False, False, 0)
        review.pack_start(_label(
            "These parameters are exactly what will be anchored. Editing the "
            "record or refreshing invalidates any approval.",
            "subtle", wrap=True), False, False, 0)
        self.review_grid = Gtk.Grid()
        self.review_grid.set_column_spacing(12)
        self.review_grid.set_row_spacing(4)
        review.pack_start(self.review_grid, False, False, 0)

        approve_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.approve_button = Gtk.Button.new_with_mnemonic("Appro_ve and sign locally")
        _add_classes(self.approve_button, "accent")
        self.approve_button.connect("clicked", lambda _w: self._on_approve())
        approve_row.pack_start(self.approve_button, False, False, 0)
        self.reconcile_button = Gtk.Button.new_with_mnemonic("Check fina_lization")
        _add_classes(self.reconcile_button, "ghost")
        self.reconcile_button.connect("clicked", lambda _w: self._on_reconcile())
        approve_row.pack_start(self.reconcile_button, False, False, 0)
        review.pack_start(approve_row, False, False, 0)
        review.pack_start(_label(
            "Signing uses the local devnet test key only. Key material is never "
            "shown, logged or written to disk by the launcher.",
            "subtle", wrap=True), False, False, 0)
        self.approve_detail = _label("", "subtle", wrap=True)
        review.pack_start(self.approve_detail, False, False, 0)
        page.pack_start(review, False, False, 0)
        return _scrolled(page)

    def _build_certificates_page(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        page.set_border_width(20)
        page.set_valign(Gtk.Align.START)

        issue = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        _add_classes(issue, "card")
        issue.pack_start(self._banner(), False, False, 0)
        issue.pack_start(_label("Issue certificate", "card-title"), False, False, 0)
        issue.pack_start(_label(
            "Available after the publish is FINALIZED. Selective disclosure "
            "defaults to status and areaSquareMeters only.",
            "subtle", wrap=True), False, False, 0)
        grid = Gtk.Grid()
        grid.set_column_spacing(12)
        grid.set_row_spacing(6)
        self.certificate_record_combo = Gtk.ComboBoxText()
        grid.attach(_label("Record", "subtle"), 0, 0, 1, 1)
        grid.attach(self.certificate_record_combo, 1, 0, 1, 1)
        issue.pack_start(grid, False, False, 0)

        self.disclosure_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        issue.pack_start(_label("Disclosed fields", "card-title-small"), False, False, 0)
        issue.pack_start(self.disclosure_box, False, False, 0)
        self.disclosure_checks: dict[str, Gtk.CheckButton] = {}

        self.issue_button = Gtk.Button.new_with_mnemonic("_Issue certificate")
        _add_classes(self.issue_button, "accent")
        self.issue_button.connect("clicked", lambda _w: self._on_issue())
        issue.pack_start(self.issue_button, False, False, 0)
        self.certificate_error = _label("", "subtle", wrap=True)
        issue.pack_start(self.certificate_error, False, False, 0)
        page.pack_start(issue, False, False, 0)

        result = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        _add_classes(result, "card")
        result.pack_start(_label("Certificate", "card-title"), False, False, 0)
        self.certificate_grid = Gtk.Grid()
        self.certificate_grid.set_column_spacing(12)
        self.certificate_grid.set_row_spacing(4)
        result.pack_start(self.certificate_grid, False, False, 0)
        save_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.save_package_button = Gtk.Button.new_with_mnemonic("Save package _JSON…")
        _add_classes(self.save_package_button, "ghost")
        self.save_package_button.connect("clicked", lambda _w: self._on_save("package"))
        save_row.pack_start(self.save_package_button, False, False, 0)
        self.save_qr_button = Gtk.Button.new_with_mnemonic("Save _QR PNG…")
        _add_classes(self.save_qr_button, "ghost")
        self.save_qr_button.connect("clicked", lambda _w: self._on_save("qr"))
        save_row.pack_start(self.save_qr_button, False, False, 0)
        result.pack_start(save_row, False, False, 0)
        self.save_detail = _label("", "subtle", wrap=True)
        result.pack_start(self.save_detail, False, False, 0)
        page.pack_start(result, False, False, 0)
        return _scrolled(page)

    def _build_verify_page(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        page.set_border_width(20)
        page.set_valign(Gtk.Align.START)

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        _add_classes(card, "card")
        card.pack_start(self._banner(), False, False, 0)
        card.pack_start(_label("Verify a certificate", "card-title"), False, False, 0)
        card.pack_start(_label(
            "Open a saved package document or a QR image. The verdict is the "
            "verifier's; failed checks disclose nothing.",
            "subtle", wrap=True), False, False, 0)
        self.open_verify_button = Gtk.Button.new_with_mnemonic("_Open package or QR image…")
        _add_classes(self.open_verify_button, "accent")
        self.open_verify_button.connect("clicked", lambda _w: self._on_open_verify())
        card.pack_start(self.open_verify_button, False, False, 0)

        self.verify_status_label = _label("Not verified", "status-warn")
        card.pack_start(self.verify_status_label, False, False, 0)
        self.verify_code_label = _label("", "subtle", wrap=True)
        card.pack_start(self.verify_code_label, False, False, 0)
        self.verify_grid = Gtk.Grid()
        self.verify_grid.set_column_spacing(12)
        self.verify_grid.set_row_spacing(4)
        card.pack_start(self.verify_grid, False, False, 0)
        card.pack_start(_label("Disclosed fields", "card-title-small"), False, False, 0)
        self.verify_fields_label = _label("—", "value", wrap=True, max_chars=64)
        card.pack_start(self.verify_fields_label, False, False, 0)
        self.verify_warnings_label = _label("", "subtle", wrap=True)
        card.pack_start(self.verify_warnings_label, False, False, 0)

        explorer_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.explorer_button = Gtk.Button.new_with_mnemonic("Open in E_xplorer")
        _add_classes(self.explorer_button, "ghost")
        self.explorer_button.connect("clicked", lambda _w: self._on_open_explorer())
        explorer_row.pack_start(self.explorer_button, False, False, 0)
        self.explorer_label = _label("", "subtle", wrap=True)
        explorer_row.pack_start(self.explorer_label, True, True, 0)
        card.pack_start(explorer_row, False, False, 0)
        self.verify_error = _label("", "subtle", wrap=True)
        card.pack_start(self.verify_error, False, False, 0)
        page.pack_start(card, False, False, 0)
        return _scrolled(page)

    # -- events from the controller (called on the GTK main loop) ----------

    def handle_event(self, event: str, payload: Mapping[str, Any]) -> None:
        if event == "busy":
            self._busy = bool(payload.get("operation"))
            self.render()
            return
        if event == "review":
            state = str(payload.get("publishState") or "")
            if state == "SUBMITTED":
                self._start_reconcile_polling()
        self.render()

    def render(self) -> None:
        snapshot = self._controller.snapshot()
        self._render_banner(snapshot)
        self._render_connection(snapshot)
        self._render_setup(snapshot)
        self._render_records(snapshot)
        self._render_publish(snapshot)
        self._render_certificates(snapshot)
        self._render_verify(snapshot)

    def _render_banner(self, snapshot: Mapping[str, Any]) -> None:
        fixture = snapshot.get("mode") == "fixture"
        text = self._banner_text(snapshot)
        for label in self._banners:
            label.set_text(text)
            context = label.get_style_context()
            context.remove_class("fixture-banner")
            context.remove_class("live-banner")
            context.add_class("fixture-banner" if fixture else "live-banner")

    def _render_connection(self, snapshot: Mapping[str, Any]) -> None:
        registry_id = snapshot.get("registryId")
        namespace_label = snapshot.get("namespaceLabel")
        namespace_detail = snapshot.get("namespaceDetail")
        if isinstance(registry_id, str) and registry_id:
            self.namespace_value.set_text(
                "{0} — {1}".format(registry_id, _bounded(namespace_label, 64)))
        else:
            self.namespace_value.set_text("—")
        self.namespace_detail_label.set_text(_bounded(namespace_detail, 160) if namespace_detail else "")
        state = snapshot.get("sessionState")
        chips = {
            "signed-out": ("chip-idle", "Signed out"),
            "loading": ("chip-load", "Working…"),
            "authenticated": ("chip-ok", "Signed in"),
            "offline": ("chip-bad", "No connection"),
            "error": ("chip-bad", "Sign-in failed"),
        }
        chip_class, text = chips.get(str(state), ("chip-idle", str(state)))
        self.connection_chip.set_text(text)
        context = self.connection_chip.get_style_context()
        for name in ("chip-idle", "chip-load", "chip-ok", "chip-bad"):
            context.remove_class(name)
        context.add_class(chip_class)
        summary = snapshot.get("session")
        if state == "authenticated" and isinstance(summary, dict):
            self.connection_detail.set_text(
                "Signed in as {0} · role {1}".format(
                    _bounded(summary.get("username"), 64), _bounded(summary.get("role"), 64)))
        elif state == "loading":
            self.connection_detail.set_text("Signing in…")
        elif state == "offline":
            self.connection_detail.set_text(
                "Cannot reach the local demo API (127.0.0.1:8090). Start the demo "
                "stack and sign in again.")
        elif state == "error":
            # Conditional on purpose: the stack may be down even when the
            # failure was a missing credential file — hint without claiming it.
            self.connection_detail.set_text(
                "Sign-in failed. If the local demo stack is not running, start it "
                "and sign in again.")
        else:
            self.connection_detail.set_text(
                "Not signed in. Sign in to work with records, publish and certificates.")
        error = snapshot.get("error")
        self.connection_error.set_text(_error_text(error, "sign_in"))
        sensitive = state != "loading" and not self._busy
        self.sign_in_button.set_sensitive(sensitive and state != "authenticated")
        self.sign_out_button.set_sensitive(sensitive and state == "authenticated")

    def _render_records(self, snapshot: Mapping[str, Any]) -> None:
        error = snapshot.get("error")
        self.records_error.set_text(_error_text(error, "create_record"))
        records = snapshot.get("records") or []
        for child in self.records_list.get_children():
            self.records_list.remove(child)
        for record in records[:MAX_SHOWN_ROWS]:
            row = Gtk.ListBoxRow()
            _add_classes(row, "record-row")
            fields = record.get("fields") if isinstance(record, dict) else {}
            fields = fields if isinstance(fields, dict) else {}
            parts = [
                str(record.get("internalRecordId")),
                "v" + str(record.get("recordVersion")),
                str(record.get("status")),
            ]
            if "areaSquareMeters" in fields:
                parts.append(str(_bounded(fields.get("areaSquareMeters"), 24)) + " m²")
            if "cadastralNumber" in fields:
                parts.append(str(_bounded(fields.get("cadastralNumber"), 24)))
            if "encumbered" in fields:
                parts.append("encumbered=" + ("true" if fields.get("encumbered") else "false"))
            row.add(_label(" · ".join(_bounded(part, 48) for part in parts), "value", "record-row",
                           wrap=True, max_chars=90))
            self.records_list.add(row)
        self.records_list.show_all()
        self.records_hint.set_text(
            "Loaded {0} record version(s).".format(len(records)) if records else "No records loaded.")
        self.create_record_button.set_sensitive(not self._busy)
        self.reload_records_button.set_sensitive(not self._busy)

    def _render_publish(self, snapshot: Mapping[str, Any]) -> None:
        state = str(snapshot.get("publishState") or "idle")
        chip_class, text = PUBLISH_CHIPS.get(state, ("chip-idle", state))
        self.publish_chip.set_text(text)
        context = self.publish_chip.get_style_context()
        for name in ("chip-idle", "chip-load", "chip-ok", "chip-bad", "chip-warn"):
            context.remove_class(name)
        context.add_class(chip_class)
        self.publish_error.set_text(_error_text(
            snapshot.get("error"), "prepare_publish", "approve_and_sign", "check_finalization"))
        address = snapshot.get("operatorAddress")
        self.operator_address_label.set_text(_bounded(address, 64) if address else "Not resolved yet.")
        review = snapshot.get("review")
        for child in self.review_grid.get_children():
            self.review_grid.remove(child)
        row = 0
        if isinstance(review, dict):
            plan = review.get("plan") if isinstance(review.get("plan"), dict) else {}
            for key, value in (
                ("Cluster", plan.get("cluster")),
                ("Program id", plan.get("programId")),
                ("Merkle root", plan.get("merkleRoot")),
                ("Manifest hash", plan.get("manifestHash")),
                ("Previous anchor", plan.get("previousAnchorHash")),
                ("Fee payer", plan.get("feePayer")),
                ("Batch sequence", plan.get("batchSequence")),
                ("Cursors", "{0} → {1} ({2} leaf/leaves)".format(
                    plan.get("cursorStart"), plan.get("cursorEnd"), plan.get("leafCount"))),
                ("Intent hash", review.get("intentHash")),
                ("Simulation", _simulation_text(plan)),
            ):
                row = _kv_row(self.review_grid, row, key, value)
            accounts = plan.get("accounts")
            if isinstance(accounts, list):
                shown = accounts[:6]
                row = _kv_row(
                    self.review_grid, row, "Accounts",
                    ", ".join(
                        "{0} ({1})".format(_bounded(item.get("address"), 16), item.get("role"))
                        for item in shown if isinstance(item, dict)))
        else:
            row = _kv_row(self.review_grid, row, "Review", "Not prepared yet.")
        self.review_grid.show_all()

        can_approve = bool(snapshot.get("canApprove"))
        signed = bool(snapshot.get("signed"))
        self.approve_button.set_sensitive(can_approve and not signed and not self._busy)
        self.reconcile_button.set_sensitive(
            state in ("SUBMITTED", "FINALIZED", "ISSUED") and not self._busy)
        if signed:
            self.approve_detail.set_text("Signed and submitted. This intent cannot be signed again.")
        elif can_approve:
            self.approve_detail.set_text("Ready to approve: review the parameters above, then approve.")
        else:
            self.approve_detail.set_text("Approval is possible only for a successful simulation.")
        self.prepare_button.set_sensitive(not self._busy)

    def _render_certificates(self, snapshot: Mapping[str, Any]) -> None:
        error = snapshot.get("error")
        save_text = _save_error_text(error)
        self.certificate_error.set_text(
            save_text if save_text else _error_text(error, "issue_certificate"))
        records = snapshot.get("records") or []
        current = self.certificate_record_combo.get_active_id()
        known = [str(item.get("internalRecordId")) for item in records if isinstance(item, dict)]
        if known != self._certificate_record_ids:
            self._certificate_record_ids = list(known)
            self.certificate_record_combo.remove_all()
            for record_id in known[:MAX_SHOWN_ROWS]:
                self.certificate_record_combo.append_text(record_id)
            if current in known:
                self.certificate_record_combo.set_active_id(current)
            elif known:
                self.certificate_record_combo.set_active(0)
        choices = self._controller.disclosure_choices()
        for path, check in list(self.disclosure_checks.items()):
            if path not in choices:
                self.disclosure_box.remove(check)
                self.disclosure_checks.pop(path, None)
        for path in choices:
            if path in self.disclosure_checks:
                continue
            check = Gtk.CheckButton.new_with_label(path)
            check.set_active(path in ("status", "areaSquareMeters"))
            self.disclosure_box.pack_start(check, False, False, 0)
            self.disclosure_checks[path] = check
        self.disclosure_box.show_all()

        certificate = snapshot.get("certificate")
        for child in self.certificate_grid.get_children():
            self.certificate_grid.remove(child)
        row = 0
        if isinstance(certificate, dict):
            for key, value in (
                ("Certificate id", certificate.get("certificateId")),
                ("Certificate hash", certificate.get("certificateHash")),
                ("Disclosure", "{0} · {1}".format(
                    certificate.get("disclosureMode"),
                    ", ".join(certificate.get("disclosedPaths") or []))),
                ("Anchor slot", certificate.get("anchorSlot")),
                ("Transaction", certificate.get("transactionSignature")),
                ("QR URL", certificate.get("qrUrl")),
            ):
                row = _kv_row(self.certificate_grid, row, key, value)
        else:
            row = _kv_row(self.certificate_grid, row, "Certificate", "Not issued yet.")
        self.certificate_grid.show_all()
        state = str(snapshot.get("publishState") or "idle")
        self.issue_button.set_sensitive(state == "FINALIZED" and not self._busy)
        self.save_package_button.set_sensitive(isinstance(certificate, dict) and not self._busy)
        self.save_qr_button.set_sensitive(isinstance(certificate, dict) and not self._busy)
        saved = []
        if snapshot.get("savedPackage"):
            saved.append("package: " + str(snapshot.get("savedPackage")))
        if snapshot.get("savedQr"):
            saved.append("QR: " + str(snapshot.get("savedQr")))
        self.save_detail.set_text("Saved — " + " · ".join(saved) if saved else "")

    def _render_verify(self, snapshot: Mapping[str, Any]) -> None:
        self.verify_error.set_text(_error_text(snapshot.get("error"), "verify_file"))
        report = snapshot.get("report")
        if not isinstance(report, dict):
            pending = snapshot.get("busy") == "verify_file"
            self.verify_status_label.set_text("Verifying…" if pending else "Not verified")
            self._style_status("—")
            self.verify_code_label.set_text("")
            for child in self.verify_grid.get_children():
                self.verify_grid.remove(child)
            self.verify_grid.show_all()
            self.verify_fields_label.set_text("—")
            self.verify_warnings_label.set_text("")
            self.explorer_button.set_sensitive(False)
            self.explorer_label.set_text("")
            self.open_verify_button.set_sensitive(not self._busy)
            return
        status = str(report.get("status") or "INVALID")
        self.verify_status_label.set_text(status)
        self._style_status(status)
        code = report.get("code")
        self.verify_code_label.set_text("Code: " + _bounded(code, 80) if code else "")
        for child in self.verify_grid.get_children():
            self.verify_grid.remove(child)
        row = 0
        for key, value in (
            ("Certificate id", report.get("certificateId")),
            ("Record version", report.get("recordVersion")),
            ("Current version", report.get("currentRecordVersion")),
            ("Batch sequence", report.get("batchSequence")),
            ("Solana slot", report.get("solanaSlot")),
            ("Lifecycle", report.get("certificateLifecycle")),
            ("Incident index", report.get("incidentIndexStatus")),
        ):
            if value not in (None, ""):
                row = _kv_row(self.verify_grid, row, key, value)
        self.verify_grid.show_all()
        disclosed = report.get("disclosedFields")
        if status == "INVALID" or not isinstance(disclosed, dict) or not disclosed:
            self.verify_fields_label.set_text(
                "— none (a failed verification discloses nothing)")
        else:
            items = list(disclosed.items())[:MAX_SHOWN_ROWS]
            self.verify_fields_label.set_text(
                "\n".join("{0} = {1}".format(_bounded(k, 32), _bounded(v, 48)) for k, v in items))
        warnings = report.get("warnings") or []
        self.verify_warnings_label.set_text(
            "; ".join(_bounded(item, 80) for item in list(warnings)[:6]))
        target = self._controller.explorer_target()
        self.explorer_button.set_sensitive(bool(target))
        self.explorer_label.set_text(target or "")
        self.open_verify_button.set_sensitive(not self._busy)

    def _style_status(self, status: str) -> None:
        style, _chip = STATUS_STYLES.get(status, ("status-warn", "chip-warn"))
        context = self.verify_status_label.get_style_context()
        for name in ("status-verified", "status-bad", "status-warn"):
            context.remove_class(name)
        context.add_class(style)

    # -- user events ------------------------------------------------------

    def _on_sign_in(self) -> None:
        self._controller.submit("sign_in")

    def _on_sign_out(self) -> None:
        self._controller.submit("sign_out")

    def _on_create_record(self) -> None:
        self._controller.submit(
            "create_record",
            record_id=self.record_id_entry.get_text().strip(),
            status=self.status_combo.get_active_text() or "ACTIVE",
            cadastral_number=self.cadastral_entry.get_text().strip(),
            area_square_meters=self.area_entry.get_text().strip(),
            encumbered=self.encumbered_check.get_active(),
        )

    def _on_reload_records(self) -> None:
        self._controller.submit("reload_records")

    def _on_prepare(self) -> None:
        self._controller.submit("prepare_publish")

    def _on_approve(self) -> None:
        review = self._controller.snapshot().get("review")
        if not isinstance(review, dict):
            return
        if not self._confirm_approve(review):
            return
        self._controller.submit(
            "approve_and_sign", intent_hash=str(review.get("intentHash") or ""))

    def _ask_approve(self, review: Mapping[str, Any]) -> bool:
        """Explicit human confirmation of the exact reviewed parameters."""
        window = self._window
        dialog = Gtk.MessageDialog(
            transient_for=window, modal=True, message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.CANCEL, text="Approve and sign this publish?")
        dialog.format_secondary_text(
            "Sign the exact reviewed transaction on Solana devnet?\n\n"
            "cluster: {0}\nmerkle root: {1}\nfee payer: {2}\nintent: {3}".format(
                _bounded((review.get("plan") or {}).get("cluster"), 40),
                _bounded((review.get("plan") or {}).get("merkleRoot"), 24),
                _bounded((review.get("plan") or {}).get("feePayer"), 24),
                _bounded(review.get("intentHash"), 24)))
        dialog.add_button("Approve and sign", Gtk.ResponseType.OK)
        response = dialog.run()
        dialog.destroy()
        return response == Gtk.ResponseType.OK

    def _on_reconcile(self) -> None:
        self._controller.submit("check_finalization")

    def _on_issue(self) -> None:
        record_id = self.certificate_record_combo.get_active_text()
        if not record_id:
            return
        paths = [path for path, check in self.disclosure_checks.items() if check.get_active()]
        self._controller.submit(
            "issue_certificate", record_id=record_id,
            disclosed_paths=paths or None)

    def _on_save(self, kind: str) -> None:
        filename = self._choose_save(kind)
        if not filename:
            return
        operation = "save_package" if kind == "package" else "save_qr"
        self._controller.submit(operation, path=filename)

    def _on_open_verify(self) -> None:
        filename = self._choose_open()
        if not filename:
            return
        self._controller.submit("verify_file", path=filename)

    def _ask_save(self, kind: str) -> str | None:
        chooser = Gtk.FileChooserNative.new(
            "Save certificate " + ("package" if kind == "package" else "QR image"),
            self._window,
            Gtk.FileChooserAction.SAVE,
            "_Save",
            "_Cancel",
        )
        # The controller never overwrites and never follows a link, so the
        # dialog must not promise a replace either: the refusal says to pick
        # a new file name.
        chooser.set_do_overwrite_confirmation(False)
        chooser.set_current_name(
            "certificate-package.json" if kind == "package" else "certificate-qr.png")
        response = chooser.run()
        filename = chooser.get_filename() if response == Gtk.ResponseType.ACCEPT else None
        chooser.destroy()
        return filename

    def _ask_open(self) -> str | None:
        chooser = Gtk.FileChooserNative.new(
            "Open certificate package or QR image",
            self._window,
            Gtk.FileChooserAction.OPEN,
            "_Open",
            "_Cancel",
        )
        response = chooser.run()
        filename = chooser.get_filename() if response == Gtk.ResponseType.ACCEPT else None
        chooser.destroy()
        return filename

    def _on_open_explorer(self) -> None:
        target = self._controller.explorer_target()
        if not target or self._window is None:
            return
        # The only URL this launcher ever opens, re-validated above.
        try:
            Gtk.show_uri_on_window(self._window, target, Gdk.CURRENT_TIME)
        except Exception:  # noqa: BLE001 - a failed external open is not fatal
            self.explorer_label.set_text("Could not open the external explorer.")

    def _start_reconcile_polling(self) -> None:
        if self._reconcile_left:
            return
        self._reconcile_left = RECONCILE_ATTEMPTS
        GLib.timeout_add(RECONCILE_INTERVAL_MS, self._reconcile_tick)

    def _reconcile_tick(self) -> bool:
        self._reconcile_left -= 1
        snapshot = self._controller.snapshot()
        state = str(snapshot.get("publishState") or "")
        if state != "SUBMITTED":
            self._reconcile_left = 0
            return False
        if self._reconcile_left <= 0 or self._busy:
            return self._reconcile_left > 0
        self._controller.submit("check_finalization")
        return True


def _simulation_text(plan: Mapping[str, Any]) -> str:
    simulation = plan.get("simulation") if isinstance(plan.get("simulation"), dict) else {}
    if simulation.get("ok"):
        units = simulation.get("unitsConsumed")
        return "OK" + (" · {0} units".format(units) if units is not None else "")
    return "FAILED · " + _bounded(simulation.get("error"), 80)


def _error_text(error: Any, *operations: str) -> str:
    if not isinstance(error, dict):
        return ""
    if str(error.get("operation")) not in operations:
        return ""
    return "Error {0}".format(_bounded(error.get("code"), 64))


def _save_error_text(error: Any) -> str:
    """Save refusals say what to do next; nothing is ever silently overwritten."""
    if not isinstance(error, dict):
        return ""
    if str(error.get("operation")) not in ("save_package", "save_qr"):
        return ""
    code = str(error.get("code") or "")
    if code == "SAVE_EXISTS":
        return ("Error SAVE_EXISTS — the file already exists (or is a link). "
                "Nothing was overwritten: choose a new file name in the save dialog.")
    if code == "SAVE_PATH_INVALID":
        return ("Error SAVE_PATH_INVALID — the chosen path is not a writable new "
                "file. Choose another location in the save dialog.")
    return "Error {0}".format(_bounded(code, 64))
