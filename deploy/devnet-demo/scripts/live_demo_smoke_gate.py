"""Gating, preflight and reporting for the opt-in live-demo GTK smoke (B4/B5).

No GTK, no desktop module and no network is imported or touched here: the
environment gate runs first, the live preflight (loopback health + the
readiness probe) is injected as callables, and the three real runs are injected
as a callable. That keeps every gating/refusal decision unit-testable while the
GTK driver in ``live_demo_smoke_gtk.py`` supplies the real widgets and the real
demo-api/verifier/signature flow.

Contract: without ``ONELAYER_LIVE_DEVNET_SMOKE=1`` nothing is contacted at all
(status ``DISABLED``). With the flag, a missing governance authority is
reported as ``BLOCKED`` with ``"0/3"`` runs completed — never a pass and never
a green skip. Evidence is written outside the repository, and only for runs
that actually succeeded.
"""
from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

SCHEMA = "onelayer.live-demo.smoke.v1"
SMOKE_ENV = "ONELAYER_LIVE_DEVNET_SMOKE"
RUNS_REQUESTED = 3
GOVERNANCE_BLOCKER = "GOVERNANCE_KEY_UNAVAILABLE"

DEMO_API_HEALTH = "http://127.0.0.1:8090/v1/health"
VERIFIER_HEALTH = "http://127.0.0.1:8080/v1/health"


class SmokeError(Exception):
    """A smoke step failed. ``detail`` is a short UI-safe token, never a secret."""

    def __init__(self, code: str, detail: str | None = None):
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


def smoke_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """The single opt-in gate. Anything but the exact value ``1`` is off."""
    source = os.environ if environ is None else environ
    return source.get(SMOKE_ENV, "") == "1"


@dataclass(frozen=True)
class Preflight:
    status: str
    blockers: tuple[dict[str, str], ...]
    detail: str


@dataclass
class SmokeReport:
    status: str
    runs_requested: int
    runs_completed: int
    blockers: list[dict[str, str]] = field(default_factory=list)
    evidence_dir: str | None = None
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "status": self.status,
            "performed": self.status == "PASS",
            "runsRequested": self.runs_requested,
            "runsCompleted": f"{self.runs_completed}/{self.runs_requested}",
            "blockers": self.blockers,
            "evidenceDir": self.evidence_dir,
            "detail": self.detail,
        }


def runs_label(completed: int, requested: int) -> str:
    return f"{completed}/{requested}"


def exit_code(report: SmokeReport) -> int:
    """0 only for a completed live run; disabled is the documented opt-out."""
    if report.status == "PASS":
        return 0
    if report.status == "DISABLED":
        return 0
    return 3


def _blocker(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail[:300]}


def readiness_blockers(report: Mapping[str, Any]) -> list[dict[str, str]]:
    """Collect honest blockers out of an A2 readiness report payload."""
    blockers: list[dict[str, str]] = []
    items = report.get("items")
    if not isinstance(items, Sequence):
        return blockers
    for item in items:
        if not isinstance(item, Mapping):
            continue
        for blocker in item.get("blockers", ()):
            if not isinstance(blocker, Mapping):
                continue
            code = blocker.get("code")
            detail = blocker.get("detail")
            if isinstance(code, str):
                blockers.append(_blocker(code, detail if isinstance(detail, str) else code))
    return blockers


def preflight(
    *,
    fetch_health: Callable[[str], bool],
    readiness: Callable[[], Mapping[str, Any]],
    demo_api_health: str = DEMO_API_HEALTH,
    verifier_health: str = VERIFIER_HEALTH,
) -> Preflight:
    """Health + readiness preflight. Missing authority blocks, never skips."""
    blockers: list[dict[str, str]] = []
    for label, url in (("demo-api", demo_api_health), ("verifier", verifier_health)):
        try:
            healthy = fetch_health(url)
        except Exception:
            healthy = False
        if not healthy:
            blockers.append(_blocker("SERVICE_UNREACHABLE", f"{label} health check failed at {url}"))
    try:
        report = readiness()
    except Exception:
        blockers.append(_blocker("READINESS_UNAVAILABLE", "the readiness probe did not produce a report"))
        return Preflight("REFUSED", tuple(blockers), "preflight refused before any live run")
    blockers.extend(readiness_blockers(report))

    if any(blocker["code"] == GOVERNANCE_BLOCKER for blocker in blockers):
        return Preflight(
            "BLOCKED",
            tuple(blockers),
            "the live run is blocked on the missing governance authority; 0 runs can complete",
        )
    if blockers:
        return Preflight("REFUSED", tuple(blockers), "preflight refused before any live run")
    if report.get("ok") is not True:
        blockers.append(_blocker("NOT_READY", "the readiness report is not ready"))
        return Preflight("REFUSED", tuple(blockers), "preflight refused before any live run")
    return Preflight("PASS", (), "preflight passed")


def evidence_root() -> Path:
    """Private (0700) evidence tree outside the repository."""
    root = Path.home() / ".local" / "state" / "onelayer-devnet-demo" / "evidence" / "live-smoke"
    root.mkdir(parents=True, exist_ok=True)
    for target in (root, root.parent):
        try:
            os.chmod(target, 0o700)
        except OSError:
            pass
    return root


def _copy_exclusive(source: Path, target: Path) -> None:
    """Copy one staged entry into a fresh path: never a link, never a clobber."""
    if source.is_symlink():
        raise SmokeError("OUTPUT_REFUSED", "staged evidence contains a link")
    if source.is_dir():
        os.mkdir(target, 0o700)
        for child in sorted(source.iterdir()):
            _copy_exclusive(child, target / child.name)
        return
    if not source.is_file():
        raise SmokeError("OUTPUT_REFUSED", "staged evidence is not a regular file")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out, open(source, "rb") as src:
        shutil.copyfileobj(src, out, 1 << 16)
        out.flush()
        os.fsync(out.fileno())


def publish_evidence(staging: Path, destination: Path) -> Path:
    """Publish one successful run's staged evidence into the private tree.

    Staging lives on tmpfs (/dev/shm) and the evidence tree on the home
    filesystem, so a rename would fail across mounts (`EXDEV`) or silently
    clobber an existing file. Publication is therefore an exclusive copy into
    a partial sibling of the destination followed by an atomic rename inside
    one directory: a colliding name refuses the whole publish, nothing
    pre-existing is ever opened for writing, and a failed publish removes only
    the partial tree it created.
    """
    entries = sorted(staging.iterdir())
    if not entries:
        raise SmokeError("OUTPUT_REFUSED", "no staged evidence to publish")
    if destination.exists() or destination.is_symlink():
        raise SmokeError("OUTPUT_REFUSED", "evidence directory already exists")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as error:
        raise SmokeError("OUTPUT_UNWRITABLE", f"evidence root is not writable: {error.errno}") from None
    partial = destination.parent / f".{destination.name}.partial-{os.getpid()}-{time.time_ns()}"
    published = False
    try:
        _copy_exclusive(staging, partial)
        if destination.exists() or destination.is_symlink():
            raise SmokeError("OUTPUT_REFUSED", "evidence directory already exists")
        os.rename(partial, destination)
        published = True
    except SmokeError:
        raise
    except OSError as error:
        raise SmokeError("OUTPUT_REFUSED", f"evidence could not be published: {error.errno}") from None
    finally:
        if not published:
            shutil.rmtree(partial, ignore_errors=True)
    try:
        os.chmod(destination, 0o700)
    except OSError:
        pass
    for root, directories, files in os.walk(destination):
        for name in directories:
            try:
                os.chmod(Path(root) / name, 0o700)
            except OSError:
                pass
        for name in files:
            try:
                os.chmod(Path(root) / name, 0o600)
            except OSError:
                pass
    return destination


def run_smoke_plan(
    environ: Mapping[str, str],
    *,
    fetch_health: Callable[[str], bool],
    readiness: Callable[[], Mapping[str, Any]],
    run_once: Callable[[int], Path | None],
    runs_requested: int = RUNS_REQUESTED,
) -> SmokeReport:
    """Gate → preflight → N real runs. Disabled contacts nothing at all."""
    if not smoke_enabled(environ):
        return SmokeReport(
            status="DISABLED",
            runs_requested=runs_requested,
            runs_completed=0,
            detail=f"{SMOKE_ENV} is not set to 1; no network or chain access was attempted",
        )
    outcome = preflight(fetch_health=fetch_health, readiness=readiness)
    if outcome.status != "PASS":
        return SmokeReport(
            status=outcome.status,
            runs_requested=runs_requested,
            runs_completed=0,
            blockers=list(outcome.blockers),
            detail=outcome.detail,
        )

    completed = 0
    failures: list[dict[str, str]] = []
    evidence_dir: str | None = None
    for attempt in range(1, runs_requested + 1):
        try:
            staged = run_once(attempt)
        except SmokeError as error:
            failures.append(_blocker(error.code, error.detail or error.code))
            continue
        except Exception:
            failures.append(_blocker("RUN_FAILED", f"live run {attempt} failed"))
            continue
        completed += 1
        if staged is not None:
            evidence_dir = str(staged)
    if completed == runs_requested:
        return SmokeReport(
            status="PASS",
            runs_requested=runs_requested,
            runs_completed=completed,
            evidence_dir=evidence_dir,
            detail=f"all {runs_requested} live runs completed against the real services",
        )
    return SmokeReport(
        status="FAIL",
        runs_requested=runs_requested,
        runs_completed=completed,
        blockers=failures,
        evidence_dir=evidence_dir,
        detail=f"only {runs_label(completed, runs_requested)} live runs completed",
    )


def render(report: SmokeReport) -> str:
    return json.dumps(report.as_dict(), indent=2) + "\n"
