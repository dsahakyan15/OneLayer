"""Hermetic tests for the live-demo smoke gate (B4/B5).

No GTK, no desktop module, no network and no chain: every call into health,
readiness and the live runs is an injected tripwire or stub.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import live_demo_smoke_gate as gate


class Tripwire:
    """A callable that must never be reached."""

    def __init__(self, name: str):
        self.name = name
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        raise AssertionError(f"{self.name} must not be called")


def readiness_ok():
    return {"ok": True, "items": []}


def readiness_blocked():
    return {
        "ok": False,
        "items": [
            {
                "id": "operator-role",
                "blockers": [
                    {
                        "code": "GOVERNANCE_KEY_UNAVAILABLE",
                        "detail": "on-chain governance authority X has no local key",
                    }
                ],
            }
        ],
    }


def readiness_not_ready():
    return {
        "ok": False,
        "items": [
            {
                "id": "funding",
                "blockers": [{"code": "OPERATOR_KEY_UNAVAILABLE", "detail": "no local operator key"}],
            }
        ],
    }


class SmokeGateTests(unittest.TestCase):
    def test_enabled_only_for_exact_one(self):
        self.assertTrue(gate.smoke_enabled({"ONELAYER_LIVE_DEVNET_SMOKE": "1"}))
        for value in ("", "0", "true", "yes", "1 ", " 1", "2"):
            self.assertFalse(gate.smoke_enabled({"ONELAYER_LIVE_DEVNET_SMOKE": value}), value)
        self.assertFalse(gate.smoke_enabled({}))

    def test_disabled_touches_no_network_and_no_runs(self):
        health = Tripwire("fetch_health")
        readiness = Tripwire("readiness")
        runs = Tripwire("run_once")
        report = gate.run_smoke_plan({}, fetch_health=health, readiness=readiness, run_once=runs)
        self.assertEqual(report.status, "DISABLED")
        self.assertEqual(report.as_dict()["runsCompleted"], "0/3")
        self.assertFalse(report.as_dict()["performed"])
        self.assertEqual(gate.exit_code(report), 0)
        self.assertEqual(health.calls, 0)
        self.assertEqual(readiness.calls, 0)
        self.assertEqual(runs.calls, 0)
        self.assertIn("no network or chain access was attempted", report.detail)

    def test_missing_authority_blocks_with_zero_of_three(self):
        runs = Tripwire("run_once")
        report = gate.run_smoke_plan(
            {"ONELAYER_LIVE_DEVNET_SMOKE": "1"},
            fetch_health=lambda _url: True,
            readiness=readiness_blocked,
            run_once=runs,
        )
        self.assertEqual(report.status, "BLOCKED")
        self.assertEqual(report.as_dict()["runsCompleted"], "0/3")
        self.assertEqual(gate.exit_code(report), 3)
        self.assertEqual(runs.calls, 0, "a blocked smoke never starts a UI run")
        self.assertIn(gate.GOVERNANCE_BLOCKER, [blocker["code"] for blocker in report.blockers])

    def test_unhealthy_services_refuse_explicitly(self):
        runs = Tripwire("run_once")
        report = gate.run_smoke_plan(
            {"ONELAYER_LIVE_DEVNET_SMOKE": "1"},
            fetch_health=lambda _url: False,
            readiness=readiness_ok,
            run_once=runs,
        )
        self.assertEqual(report.status, "REFUSED")
        self.assertEqual(report.as_dict()["runsCompleted"], "0/3")
        self.assertEqual(gate.exit_code(report), 3)
        self.assertEqual(runs.calls, 0)
        self.assertIn("SERVICE_UNREACHABLE", [blocker["code"] for blocker in report.blockers])

    def test_not_ready_refuses_without_running(self):
        runs = Tripwire("run_once")
        report = gate.run_smoke_plan(
            {"ONELAYER_LIVE_DEVNET_SMOKE": "1"},
            fetch_health=lambda _url: True,
            readiness=readiness_not_ready,
            run_once=runs,
        )
        self.assertEqual(report.status, "REFUSED")
        self.assertEqual(runs.calls, 0)
        self.assertEqual(gate.exit_code(report), 3)

    def test_readiness_failure_refuses(self):
        def explode():
            raise RuntimeError("probe crashed")

        report = gate.run_smoke_plan(
            {"ONELAYER_LIVE_DEVNET_SMOKE": "1"},
            fetch_health=lambda _url: True,
            readiness=explode,
            run_once=Tripwire("run_once"),
        )
        self.assertEqual(report.status, "REFUSED")
        self.assertIn("READINESS_UNAVAILABLE", [blocker["code"] for blocker in report.blockers])

    def test_three_successful_runs_pass(self):
        attempts = []

        def run_once(attempt):
            attempts.append(attempt)
            return Path(f"/tmp/evidence-{attempt}")

        report = gate.run_smoke_plan(
            {"ONELAYER_LIVE_DEVNET_SMOKE": "1"},
            fetch_health=lambda _url: True,
            readiness=readiness_ok,
            run_once=run_once,
        )
        self.assertEqual(report.status, "PASS")
        self.assertEqual(report.as_dict()["runsCompleted"], "3/3")
        self.assertTrue(report.as_dict()["performed"])
        self.assertEqual(gate.exit_code(report), 0)
        self.assertEqual(attempts, [1, 2, 3])
        self.assertTrue(str(report.evidence_dir).endswith("evidence-3"))

    def test_partial_failure_reports_completed_runs(self):
        attempts = []

        def run_once(attempt):
            attempts.append(attempt)
            if attempt == 2:
                raise gate.SmokeError("VERIFY_FAILED", "the saved package did not verify")
            return None

        report = gate.run_smoke_plan(
            {"ONELAYER_LIVE_DEVNET_SMOKE": "1"},
            fetch_health=lambda _url: True,
            readiness=readiness_ok,
            run_once=run_once,
        )
        self.assertEqual(report.status, "FAIL")
        self.assertEqual(report.as_dict()["runsCompleted"], "2/3")
        self.assertEqual(gate.exit_code(report), 3)
        self.assertEqual(attempts, [1, 2, 3], "all three runs are attempted")
        self.assertIn("VERIFY_FAILED", [blocker["code"] for blocker in report.blockers])

    def test_readiness_blocker_parsing(self):
        blockers = gate.readiness_blockers(readiness_blocked())
        self.assertEqual(blockers[0]["code"], gate.GOVERNANCE_BLOCKER)
        self.assertEqual(gate.readiness_blockers({}), [])
        self.assertEqual(gate.readiness_blockers({"items": "nope"}), [])

    def test_preflight_combines_health_and_readiness(self):
        outcome = gate.preflight(
            fetch_health=lambda url: "verifier" in url,
            readiness=readiness_blocked,
        )
        self.assertEqual(outcome.status, "BLOCKED")
        codes = [blocker["code"] for blocker in outcome.blockers]
        self.assertIn("SERVICE_UNREACHABLE", codes)
        self.assertIn(gate.GOVERNANCE_BLOCKER, codes)

    def test_evidence_is_fresh_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temporary:
            staging = Path(temporary) / "staging"
            staging.mkdir()
            (staging / "run.json").write_text("{}")
            (staging / "shot.png").write_bytes(b"png")
            destination = Path(temporary) / "out" / "run-1"
            published = gate.publish_evidence(staging, destination)
            self.assertEqual(published, destination)
            self.assertEqual(sorted(path.name for path in destination.iterdir()), ["run.json", "shot.png"])
            self.assertEqual((destination / "run.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            # The publish is a copy: the staging tree is never consumed.
            self.assertTrue((staging / "run.json").exists())

            second = Path(temporary) / "staging2"
            second.mkdir()
            (second / "run.json").write_text("{}")
            with self.assertRaises(gate.SmokeError) as raised:
                gate.publish_evidence(second, destination)
            self.assertEqual(raised.exception.code, "OUTPUT_REFUSED")
            self.assertEqual((destination / "run.json").read_text(), "{}", "existing evidence is kept")
            self.assertEqual(
                sorted(path.name for path in (Path(temporary) / "out").iterdir()),
                ["run-1"],
                "a refused publish leaves no partial tree",
            )

    def test_publish_across_filesystems_copies_instead_of_renaming(self):
        """The reviewed EXDEV case: tmpfs staging, private tree elsewhere.

        ``os.replace``/``Path.replace`` between these mounts fails with EXDEV
        (or would clobber a target on one mount); publication must be an
        exclusive copy into a partial sibling plus a same-directory rename.
        """
        shm = Path("/dev/shm")
        self.assertTrue(shm.is_dir(), "/dev/shm is required for the tmpfs staging case")
        staging = Path(tempfile.mkdtemp(prefix="onelayer-smoke-gate-", dir=str(shm)))
        self.addCleanup(shutil.rmtree, staging, ignore_errors=True)
        (staging / "run.json").write_text('{"mode": "live", "attempt": 1}\n')
        (staging / "01-shot.png").write_bytes(b"\x89PNG-fixture-bytes")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir(parents=True, mode=0o700)
            destination = root / "run-20261006T120000Z-1"
            cross_device = os.stat(staging).st_dev != os.stat(root).st_dev
            if cross_device:
                with self.assertRaises(OSError) as raised:
                    (staging / "run.json").replace(root / "cross-device.json")
                self.assertIn(raised.exception.errno, (18, 2), "EXDEV or ENOENT, never a silent clobber")
            published = gate.publish_evidence(staging, destination)
            self.assertEqual(published, destination)
            self.assertEqual(
                sorted(path.name for path in destination.iterdir()), ["01-shot.png", "run.json"]
            )
            self.assertEqual((destination / "run.json").read_text(), '{"mode": "live", "attempt": 1}\n')
            self.assertEqual((destination / "01-shot.png").read_bytes(), b"\x89PNG-fixture-bytes")
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            for entry in destination.iterdir():
                self.assertEqual(entry.stat().st_mode & 0o777, 0o600, entry.name)
            self.assertEqual((staging / "run.json").read_text(), '{"mode": "live", "attempt": 1}\n')

    def test_publish_refuses_links_and_cleans_up_its_partial_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            staging = Path(temporary) / "staging"
            staging.mkdir()
            (staging / "run.json").write_text("{}")
            (staging / "evil").symlink_to("/etc/passwd")
            destination = Path(temporary) / "out" / "run-3"
            with self.assertRaises(gate.SmokeError) as raised:
                gate.publish_evidence(staging, destination)
            self.assertEqual(raised.exception.code, "OUTPUT_REFUSED")
            self.assertFalse(destination.exists())
            self.assertEqual(list((Path(temporary) / "out").iterdir()), [], "no partial publish is left behind")

    def test_publish_refuses_an_empty_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            staging = Path(temporary) / "staging"
            staging.mkdir()
            destination = Path(temporary) / "out" / "run-4"
            with self.assertRaises(gate.SmokeError) as raised:
                gate.publish_evidence(staging, destination)
            self.assertEqual(raised.exception.code, "OUTPUT_REFUSED")
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
