"""Devnet setup adapter for the live-demo launcher (ADR-0010).

Wraps the accepted deploy seed CLI (``deploy/devnet-demo/scripts/live-demo-seed``)
so the launcher can show a *read-only* chain assessment and — only after an
explicit user confirmation of a concrete summary — run the idempotent
preparation.

Transaction-review contract (solana-dev)
----------------------------------------
* :meth:`SetupController.assess` is read-only. It never signs or sends.
* :meth:`SetupController.prepare` runs the seed's ``--prepare`` path, which is
  the *only* mutating entry point. The launcher calls it **after** the operator
  has seen the exact planned actions and pressed an explicit confirm button.
* This module never passes ``--approve-fallback`` (that is a separate explicit
  publish) and never invents a governance key. A missing authority is reported
  as a refusal code before any chain mutation.
* Subprocesses run with ``shell=False``, an argv allow-list and bounded output.
  Key material never enters Python, argv, logs or the UI.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from live_demo_session import LiveDemoError

__all__ = [
    "SetupAssessment",
    "SetupController",
    "SetupError",
    "SetupStep",
    "planned_action_summary",
]

# Code-only failures; nothing from the seed's stderr is echoed.
SETUP_UNAVAILABLE = "SETUP_UNAVAILABLE"
SETUP_TIMEOUT = "SETUP_TIMEOUT"
SETUP_OUTPUT_INVALID = "SETUP_OUTPUT_INVALID"
SETUP_OUTPUT_TOO_LARGE = "SETUP_OUTPUT_TOO_LARGE"
SETUP_REFUSED = "SETUP_REFUSED"

MAX_OUTPUT_BYTES = 512 * 1024
DEFAULT_TIMEOUT_SECONDS = 120.0
_CODE_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{0,62}$")


class SetupError(LiveDemoError):
    """A setup assessment or preparation failed. ``detail`` is a bare code."""

    def __init__(self, code: str, detail: str | None = None):
        super().__init__("error", detail or code)
        self.code = code

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True)
class SetupStep:
    """One planned or evaluated chain step. Contains public data only."""

    step_id: str
    status: str
    detail: str
    action_kind: str | None
    blocker_codes: tuple[str, ...] = ()
    required_signer: str | None = None
    args: Mapping[str, Any] = field(default_factory=dict)
    signatures: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id,
            "status": self.status,
            "detail": self.detail,
            "actionKind": self.action_kind,
            "blockerCodes": list(self.blocker_codes),
            "requiredSigner": self.required_signer,
            "args": dict(self.args),
            "signatures": list(self.signatures),
        }


@dataclass(frozen=True)
class SetupAssessment:
    """The read-only chain assessment. No mutation has happened."""

    registry_id: str
    cluster: str
    program_id: str
    config_pda: str
    prepared: bool
    ok: bool
    steps: tuple[SetupStep, ...]
    refusal_code: str | None
    refusal_detail: str | None
    mutations: int

    @property
    def blocker_codes(self) -> tuple[str, ...]:
        seen: list[str] = []
        for step in self.steps:
            for code in step.blocker_codes:
                if code not in seen:
                    seen.append(code)
        return tuple(seen)

    @property
    def action_required(self) -> tuple[SetupStep, ...]:
        return tuple(s for s in self.steps if s.status == "ACTION_REQUIRED")

    def as_dict(self) -> dict[str, Any]:
        return {
            "registryId": self.registry_id,
            "cluster": self.cluster,
            "programId": self.program_id,
            "configPda": self.config_pda,
            "prepared": self.prepared,
            "ok": self.ok,
            "mutations": self.mutations,
            "refusalCode": self.refusal_code,
            "refusalDetail": self.refusal_detail,
            "blockerCodes": list(self.blocker_codes),
            "steps": [s.as_dict() for s in self.steps],
        }


def _assessment_from_as_dict(payload: Mapping[str, Any]) -> SetupAssessment:
    """Rebuild a :class:`SetupAssessment` from its ``as_dict`` snapshot shape.

    The launcher stores assessments as plain dicts in the controller snapshot;
    the single summary builder accepts either form so there is only ever one
    rendering of the planned actions (M5).
    """
    raw_steps = payload.get("steps") if isinstance(payload.get("steps"), list) else []
    steps = tuple(
        SetupStep(
            step_id=str(s.get("id") or ""),
            status=str(s.get("status") or ""),
            detail=str(s.get("detail") or ""),
            action_kind=str(s.get("actionKind")) if s.get("actionKind") else None,
            blocker_codes=tuple(str(c) for c in (s.get("blockerCodes") or [])),
            required_signer=str(s.get("requiredSigner")) if s.get("requiredSigner") else None,
            args={str(k): v for k, v in (s.get("args") or {}).items()},
            signatures=tuple(str(x) for x in (s.get("signatures") or [])),
        )
        for s in raw_steps if isinstance(s, dict)
    )
    return SetupAssessment(
        registry_id=str(payload.get("registryId") or ""),
        cluster=str(payload.get("cluster") or ""),
        program_id=str(payload.get("programId") or ""),
        config_pda=str(payload.get("configPda") or ""),
        prepared=bool(payload.get("prepared")),
        ok=bool(payload.get("ok")),
        steps=steps,
        refusal_code=str(payload.get("refusalCode")) if payload.get("refusalCode") else None,
        refusal_detail=str(payload.get("refusalDetail")) if payload.get("refusalDetail") else None,
        mutations=int(payload.get("mutations") or 0),
    )


def planned_action_summary(assessment: "SetupAssessment | Mapping[str, Any]") -> str:
    """A human-readable, concrete summary of what ``prepare`` would do.

    This is the ONE summary builder the confirmation dialog shows *before* any
    explicit approve click (M5). It names the cluster, program, config PDA and
    each planned action with its required signer and concrete args — including
    recipient (``to=``), amount (``lamports=``), fee, rent and accounts when the
    planner reports them. No key material, ever. Accepts either a
    :class:`SetupAssessment` or its ``as_dict`` snapshot form.
    """
    if isinstance(assessment, Mapping):
        # The as_dict snapshot carries the aggregate blocker codes at the top
        # level; carry them across so the one builder always shows them.
        top_codes = tuple(str(c) for c in (assessment.get("blockerCodes") or []))
        assessment = _assessment_from_as_dict(assessment)
    else:
        top_codes = ()
    lines = [
        f"Cluster: {assessment.cluster}",
        f"Program: {assessment.program_id}",
        f"Registry: {assessment.registry_id}",
        f"Config PDA: {assessment.config_pda}",
        "",
        "Planned actions (each signed only by its named key):",
    ]
    planned = [s for s in assessment.steps if s.action_kind]
    if not planned:
        lines.append("  (none — every step is already satisfied)")
    for step in planned:
        signer = step.required_signer or "unspecified"
        args = ", ".join(f"{k}={v}" for k, v in sorted(step.args.items())
                         if k not in ("keyFile",) and not str(v).endswith(".json"))
        lines.append(f"  [{step.status}] {step.action_kind}")
        lines.append(f"      signer: {signer}")
        if args:
            lines.append(f"      args: {args}")
    codes = tuple(dict.fromkeys([*assessment.blocker_codes, *top_codes]))
    if codes:
        lines.append("")
        lines.append("Blockers: " + ", ".join(codes))
        if "GOVERNANCE_KEY_UNAVAILABLE" in codes:
            lines.append(
                "The legacy registry's governance authority is permanently lost; "
                "governance-signed setup cannot run on this namespace.")
    lines.append("")
    lines.append("Approving sends real devnet transactions. Nothing is sent before you confirm.")
    return "\n".join(lines)


def _parse_step(item: Any) -> SetupStep:
    action = item.get("action") if isinstance(item.get("action"), dict) else {}
    blockers = item.get("blockers") if isinstance(item.get("blockers"), list) else []
    codes = tuple(
        str(b.get("code")) for b in blockers
        if isinstance(b, dict) and _CODE_TOKEN.match(str(b.get("code") or ""))
    )
    signer = action.get("requiredSigner") if isinstance(action, dict) else None
    required_signer = None
    if isinstance(signer, dict):
        role = signer.get("role")
        address = signer.get("address")
        required_signer = f"{role} {address}" if address else str(role or "unspecified")
    args = action.get("args") if isinstance(action.get("args"), dict) else {}
    signatures = item.get("signatures") if isinstance(item.get("signatures"), list) else []
    return SetupStep(
        step_id=str(item.get("id") or ""),
        status=str(item.get("status") or ""),
        detail=str(item.get("detail") or ""),
        action_kind=str(action.get("kind")) if action.get("kind") else None,
        blocker_codes=codes,
        required_signer=required_signer,
        args={str(k): v for k, v in args.items() if not str(k).lower().endswith("file")},
        signatures=tuple(str(s) for s in signatures),
    )


def _parse_assessment(payload: Mapping[str, Any]) -> SetupAssessment:
    raw_steps = payload.get("steps")
    steps = tuple(_parse_step(s) for s in raw_steps if isinstance(s, dict)) if isinstance(raw_steps, list) else ()
    refusal = payload.get("refusal") if isinstance(payload.get("refusal"), dict) else None
    return SetupAssessment(
        registry_id=str(payload.get("registryId") or ""),
        cluster=str(payload.get("cluster") or ""),
        program_id=str(payload.get("programId") or ""),
        config_pda=str(payload.get("configPda") or ""),
        prepared=bool(payload.get("prepared")),
        ok=bool(payload.get("ok")),
        steps=steps,
        refusal_code=str(refusal.get("code")) if refusal and refusal.get("code") else None,
        refusal_detail=str(refusal.get("detail")) if refusal and refusal.get("detail") else None,
        mutations=int(payload.get("mutations") or 0),
    )


class SetupController:
    """Read-only assessment and explicitly-approved preparation.

    Construction is cheap; nothing is contacted until a method is called.
    """

    def __init__(
        self,
        *,
        seed_cli: str | Path | None = None,
        registry_id: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        runner: Any = None,
    ):
        self._seed_cli = Path(seed_cli) if seed_cli is not None else self._discover_seed_cli()
        self._registry_id = registry_id
        self._timeout = timeout
        self._runner = runner or subprocess.run

    @staticmethod
    def _discover_seed_cli() -> Path:
        here = Path(__file__).resolve()
        # apps/desktop/lab/ -> repo root -> deploy/devnet-demo/scripts/live-demo-seed
        repo_root = here.parents[3]
        return repo_root / "deploy" / "devnet-demo" / "scripts" / "live-demo-seed"

    @property
    def seed_cli(self) -> Path:
        return self._seed_cli

    def _run(self, args: Sequence[str]) -> dict[str, Any]:
        argv = [str(self._seed_cli), *args]
        env = dict(os.environ)
        if self._registry_id:
            env["ONELAYER_REGISTRY_ID"] = self._registry_id
        try:
            result = self._runner(
                argv,
                capture_output=True,
                timeout=self._timeout,
                check=False,
                shell=False,
                env=env,
            )
        except FileNotFoundError:
            raise SetupError(SETUP_UNAVAILABLE) from None
        except subprocess.TimeoutExpired:
            raise SetupError(SETUP_TIMEOUT) from None
        except OSError:
            raise SetupError(SETUP_UNAVAILABLE) from None
        stdout = result.stdout or b""
        if len(stdout) > MAX_OUTPUT_BYTES:
            raise SetupError(SETUP_OUTPUT_TOO_LARGE)
        # Exit codes: 0 ready/prepared · 2 refused request · 3 refused
        # environment/authority · 4 report produced but not ready. 2/3/4 still
        # emit a report; only a missing/empty one is a hard failure.
        if not stdout.strip():
            code = SETUP_REFUSED if result.returncode in (2, 3) else SETUP_UNAVAILABLE
            raise SetupError(code)
        try:
            payload = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise SetupError(SETUP_OUTPUT_INVALID) from None
        if not isinstance(payload, dict):
            raise SetupError(SETUP_OUTPUT_INVALID)
        return payload

    def assess(self) -> SetupAssessment:
        """Read-only assessment. Never signs or sends a transaction."""
        return _parse_assessment(self._run([]))

    def prepare(self) -> SetupAssessment:
        """Idempotent preparation. Call only after explicit user confirmation.

        The seed's own pre-mutation gate still applies: a missing authority
        aborts before the first mutation. This method is the *only* mutating
        entry point and it is never called automatically.
        """
        return _parse_assessment(self._run(["--prepare"]))
