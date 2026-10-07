"""Runtime plumbing shared by the launcher's Node helpers (B2 revision).

Two concerns live here so every helper adapter shares one implementation:

* :func:`discover_source_root` — find the repository root that actually holds
  the Node helpers. A source checkout is inferred from this file's own path
  (``apps/desktop/lab`` → root). A disposable installed prefix has no helpers of
  its own, so ``install.py`` writes a tiny ``live_demo_source_root.py`` binding
  module containing **one bounded, non-secret absolute path** into the trusted
  source tree. The path is validated (absolute, length-bounded, expected helper
  files present) before any helper is executed. Nothing here copies a key or
  any repository content, and no shell is involved.
* :func:`run_bounded` — run one helper process *tree* with no shell, bounded
  stdin, and *streamed* stdout/stderr that are capped **while the process
  runs**: a runaway helper is killed instead of being buffered into memory. The
  helper starts as a new session so a deadline or overflow kills its whole
  process group (descendants that inherited the pipes included), and the
  deadline covers EOF on both streams even after a normal parent exit. Output
  is never returned truncated: an incomplete run fails closed.

Failures are code-only (:class:`BoundedRunError` kinds); raw helper output is
returned to the caller for strict parsing and never interpreted here.
"""
from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

__all__ = [
    "BoundedRunError",
    "MAX_OUTPUT_BYTES",
    "MAX_SOURCE_ROOT_CHARS",
    "OUTPUT_TOO_LARGE",
    "TIMEOUT",
    "UNAVAILABLE",
    "discover_source_root",
    "expected_helper_paths",
    "run_bounded",
    "source_root_binding",
]

MAX_OUTPUT_BYTES = 64 * 1024
MAX_SOURCE_ROOT_CHARS = 1024
_READ_CHUNK = 8 * 1024
_POLL_SECONDS = 0.02
_JOIN_SECONDS = 2.0
# Reader/writer threads are joined with a tiny budget: a reader blocked on a
# pipe a descendant still holds must never stall the (failing) return.
_THREAD_JOIN_SECONDS = 0.2

TIMEOUT = "timeout"
UNAVAILABLE = "unavailable"
OUTPUT_TOO_LARGE = "output-too-large"

HELPER_PATHS = (
    ("apps", "demo-api", "scripts", "live-demo-sign.ts"),
    ("apps", "desktop", "lab", "live-demo-operator-address.ts"),
    ("apps", "mvp-web", "scripts", "live-demo-qr-decode.mjs"),
)


class BoundedRunError(Exception):
    """A bounded helper run failed. ``code`` is one of the three bare kinds."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


# -- bounded subprocess ---------------------------------------------------


def run_bounded(
    argv: Sequence[str],
    *,
    input_bytes: bytes = b"",
    timeout: float,
    env: Mapping[str, str] | None = None,
    max_output: int = MAX_OUTPUT_BYTES,
) -> tuple[int, bytes, bytes]:
    """Run one helper process tree; cap its output *while* it runs.

    ``input_bytes`` is written to stdin on a helper thread (it is bounded by the
    caller before the spawn), stdout/stderr are read incrementally and the tree
    is killed as soon as either stream would exceed ``max_output`` or ``timeout``
    elapses. Returns ``(returncode, stdout, stderr)``.

    The helper starts as a new session (process group), so the deadline kills
    the whole tree with ``killpg`` — a descendant that inherited the output
    pipes cannot keep a reader blocked past the deadline. The deadline covers
    EOF on both streams *even after a normal parent exit*: output held open by
    a lingering descendant is not complete. Output is never returned truncated
    or silently dropped — a run that could not deliver both streams in full
    fails closed with :class:`BoundedRunError`.
    """
    if not argv:
        raise BoundedRunError(UNAVAILABLE)
    try:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=dict(env) if env is not None else None,
            start_new_session=True,
        )
    except OSError:
        raise BoundedRunError(UNAVAILABLE) from None

    overflow = threading.Event()
    incomplete = threading.Event()
    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    out_done = threading.Event()
    err_done = threading.Event()

    def writer() -> None:
        try:
            if input_bytes:
                process.stdin.write(input_bytes)  # type: ignore[union-attr]
                process.stdin.flush()  # type: ignore[union-attr]
        except (OSError, ValueError):
            pass
        finally:
            try:
                process.stdin.close()  # type: ignore[union-attr]
            except (OSError, ValueError):
                pass

    def reader(pipe: Any, sink: list[bytes], done: threading.Event) -> None:
        total = 0
        try:
            while True:
                chunk = pipe.read(_READ_CHUNK)
                if not chunk:
                    return
                if total + len(chunk) > max_output:
                    room = max_output - total
                    if room > 0:
                        sink.append(chunk[:room])
                    overflow.set()
                    return
                sink.append(chunk)
                total += len(chunk)
        except (OSError, ValueError):
            # A read that ended without EOF is an incomplete stream: the run
            # must fail closed rather than return truncated output.
            incomplete.set()
            return
        finally:
            done.set()
            # A reader closes its own stream only after read() has returned;
            # the main thread never closes a stream a reader may be blocked on.
            try:
                pipe.close()
            except (OSError, ValueError):
                pass

    threads = [
        threading.Thread(target=writer, daemon=True),
        threading.Thread(target=reader, args=(process.stdout, out_chunks, out_done), daemon=True),
        threading.Thread(target=reader, args=(process.stderr, err_chunks, err_done), daemon=True),
    ]
    for thread in threads:
        thread.start()

    deadline = time.monotonic() + timeout
    returncode: int | None = None
    try:
        while True:
            if overflow.is_set():
                raise BoundedRunError(OUTPUT_TOO_LARGE)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BoundedRunError(TIMEOUT)
            if returncode is None:
                try:
                    returncode = process.wait(timeout=min(remaining, _POLL_SECONDS))
                except subprocess.TimeoutExpired:
                    continue
            # EOF on both streams is part of the deadline: a descendant can
            # hold an inherited pipe open long after a normal parent exit.
            if out_done.is_set() and err_done.is_set():
                break
            time.sleep(min(_POLL_SECONDS, max(remaining, 0.0)))
    finally:
        # Reap the whole group on every path — including the successful one,
        # so no descendant of a finished helper is left behind.
        _kill_group(process)
        for thread in threads:
            thread.join(timeout=_THREAD_JOIN_SECONDS)

    if overflow.is_set():
        raise BoundedRunError(OUTPUT_TOO_LARGE)
    if incomplete.is_set():
        raise BoundedRunError(TIMEOUT)
    return returncode, b"".join(out_chunks), b"".join(err_chunks)


def _kill_group(process: "subprocess.Popen[bytes]") -> None:
    """Kill the helper's whole process group; never block on a stream close.

    The helper runs as a session leader, so its process group id is its pid.
    Killing the group reaps descendants that inherited the output pipes — a
    kill of only the parent would leave those pipes open and a reader stuck in
    ``read()`` forever. Streams are deliberately *not* closed here: a reader
    thread may be blocked on exactly that fd, and closing it from this thread
    is what used to hang. Readers close their own streams once ``read()``
    returns; the caller fails closed instead of returning partial output.
    """
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=_JOIN_SECONDS)
    except (subprocess.TimeoutExpired, OSError):
        pass


# -- source-root binding --------------------------------------------------


def expected_helper_paths(root: Path) -> tuple[Path, ...]:
    return tuple(root.joinpath(*parts) for parts in HELPER_PATHS)


def _usable_root(candidate: Path) -> bool:
    try:
        if not candidate.is_absolute():
            return False
        if len(str(candidate)) > MAX_SOURCE_ROOT_CHARS:
            return False
        return all(path.is_file() for path in expected_helper_paths(candidate))
    except OSError:
        return False


def source_root_binding() -> Path | None:
    """The installer-written source root binding, validated; else ``None``.

    The binding is a single absolute path string written by ``install.py``. It
    is treated as data: absolute, length-bounded and required to contain the
    expected helper files before it is ever used.
    """
    try:
        import live_demo_source_root  # type: ignore
    except ImportError:
        return None
    value = getattr(live_demo_source_root, "SOURCE_REPO_ROOT", None)
    if not isinstance(value, str) or not value or len(value) > MAX_SOURCE_ROOT_CHARS:
        return None
    if "\x00" in value:
        return None
    candidate = Path(value)
    return candidate if _usable_root(candidate) else None


def discover_source_root() -> Path:
    """Repository root holding the Node helpers (source checkout or binding).

    The source checkout is inferred from this file's path and used when its
    helpers are present; an installed prefix falls back to the validated
    binding. When neither resolves the inferred path is returned so the caller
    reports its own "helper unavailable" code instead of inventing a root.
    """
    inferred = Path(__file__).resolve().parents[3]
    if _usable_root(inferred):
        return inferred
    bound = source_root_binding()
    if bound is not None:
        return bound
    return inferred
