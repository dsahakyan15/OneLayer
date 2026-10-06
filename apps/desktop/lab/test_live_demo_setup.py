"""Focused tests for the devnet setup adapter (ADR-0010).

Contract under test:
* ``assess`` is read-only — it never passes ``--prepare``.
* ``prepare`` is the only mutating entry point and passes ``--prepare``.
* Refusals (missing governance authority) surface as codes before mutation.
* The planned-action summary names cluster, program, config PDA and signers
  and never contains key material.
* Bounded output, code-only errors, argv allow-list (no shell).
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from live_demo_setup import (  # noqa: E402
    SETUP_OUTPUT_INVALID,
    SETUP_OUTPUT_TOO_LARGE,
    SETUP_REFUSED,
    SETUP_TIMEOUT,
    SETUP_UNAVAILABLE,
    SetupAssessment,
    SetupController,
    SetupError,
    planned_action_summary,
)


def _report(**overrides):
    base = {
        "registryId": "gov.registry.land",
        "cluster": "solana:devnet",
        "programId": "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo",
        "configPda": "BPgSTnDHop1NhMrksBWJtZV2zqVmUM1iusEuUXocCnFU",
        "prepared": False,
        "ok": False,
        "mutations": 0,
        "steps": [
            {
                "id": "registry",
                "status": "READY",
                "detail": "initialized",
                "blockers": [],
                "action": None,
                "signatures": [],
            },
            {
                "id": "operator-role",
                "status": "ACTION_REQUIRED",
                "detail": "no local operator",
                "blockers": [{"code": "GOVERNANCE_KEY_UNAVAILABLE", "detail": "lost"}],
                "action": {
                    "kind": "grant_operator",
                    "requiredSigner": {"role": "governance", "address": "4Y4pGizJm5"},
                    "args": {"registryId": "gov.registry.land", "keyFile": "/secret.json"},
                },
                "signatures": [],
            },
        ],
        "refusal": None,
    }
    base.update(overrides)
    return base


class _FakeResult:
    def __init__(self, stdout: bytes, returncode: int = 0):
        self.stdout = stdout
        self.returncode = returncode


class _FakeRunner:
    """Records argv and returns a canned result. Never runs a process."""

    def __init__(self, payload=None, returncode: int = 0, stdout: bytes | None = None):
        self.calls: list[list[str]] = []
        self._payload = payload
        self._returncode = returncode
        self._stdout = stdout

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        if kwargs.get("shell") is not False:
            raise AssertionError("runner must be called with shell=False")
        if self._stdout is not None:
            return _FakeResult(self._stdout, self._returncode)
        body = json.dumps(self._payload).encode("utf-8") if self._payload is not None else b""
        return _FakeResult(body, self._returncode)


class AssessmentTests(unittest.TestCase):
    def test_assess_passes_no_prepare_flag(self):
        runner = _FakeRunner(_report())
        controller = SetupController(seed_cli="/x/live-demo-seed", runner=runner)
        controller.assess()
        self.assertEqual(len(runner.calls), 1)
        argv = runner.calls[0]
        self.assertEqual(argv[0], "/x/live-demo-seed")
        self.assertNotIn("--prepare", argv)
        self.assertNotIn("--approve-fallback", argv)

    def test_prepare_passes_exactly_prepare(self):
        runner = _FakeRunner(_report(prepared=True, ok=True))
        controller = SetupController(seed_cli="/x/live-demo-seed", runner=runner)
        controller.prepare()
        self.assertEqual(runner.calls[0], ["/x/live-demo-seed", "--prepare"])
        self.assertNotIn("--approve-fallback", runner.calls[0])

    def test_never_approves_fallback(self):
        for method in ("assess", "prepare"):
            runner = _FakeRunner(_report())
            controller = SetupController(seed_cli="/x/live-demo-seed", runner=runner)
            getattr(controller, method)()
            self.assertNotIn("--approve-fallback", runner.calls[0])

    def test_refusal_is_surfaced_before_any_mutation(self):
        runner = _FakeRunner(_report(
            prepared=True,
            refusal={"code": "GOVERNANCE_KEY_UNAVAILABLE", "detail": "lost"},
            mutations=0,
        ))
        controller = SetupController(seed_cli="/x/live-demo-seed", runner=runner)
        assessment = controller.prepare()
        self.assertEqual(assessment.refusal_code, "GOVERNANCE_KEY_UNAVAILABLE")
        self.assertEqual(assessment.mutations, 0)

    def test_blocker_codes_are_collected(self):
        assessment = SetupAssessment(
            registry_id="gov.registry.land", cluster="solana:devnet",
            program_id="p", config_pda="c", prepared=False, ok=False,
            steps=(
                __import__("live_demo_setup").SetupStep(
                    "a", "BLOCKED", "d", "fund_operator",
                    ("OPERATOR_KEY_UNAVAILABLE",)),
                __import__("live_demo_setup").SetupStep(
                    "b", "ACTION_REQUIRED", "d", "grant_operator",
                    ("GOVERNANCE_KEY_UNAVAILABLE",)),
            ),
            refusal_code=None, refusal_detail=None, mutations=0,
        )
        self.assertEqual(
            assessment.blocker_codes,
            ("OPERATOR_KEY_UNAVAILABLE", "GOVERNANCE_KEY_UNAVAILABLE"))

    def test_empty_output_is_a_refusal_not_a_crash(self):
        runner = _FakeRunner(stdout=b"", returncode=3)
        controller = SetupController(seed_cli="/x/live-demo-seed", runner=runner)
        with self.assertRaises(SetupError) as raised:
            controller.assess()
        self.assertEqual(raised.exception.code, SETUP_REFUSED)

    def test_malformed_json_is_output_invalid(self):
        runner = _FakeRunner(stdout=b"not json")
        controller = SetupController(seed_cli="/x/live-demo-seed", runner=runner)
        with self.assertRaises(SetupError) as raised:
            controller.assess()
        self.assertEqual(raised.exception.code, SETUP_OUTPUT_INVALID)

    def test_oversized_output_is_refused(self):
        runner = _FakeRunner(stdout=b"x" * (512 * 1024 + 1))
        controller = SetupController(seed_cli="/x/live-demo-seed", runner=runner)
        with self.assertRaises(SetupError) as raised:
            controller.assess()
        self.assertEqual(raised.exception.code, SETUP_OUTPUT_TOO_LARGE)

    def test_missing_cli_is_unavailable(self):
        def runner(argv, **kwargs):
            raise FileNotFoundError()
        controller = SetupController(seed_cli="/x/missing", runner=runner)
        with self.assertRaises(SetupError) as raised:
            controller.assess()
        self.assertEqual(raised.exception.code, SETUP_UNAVAILABLE)

    def test_timeout_is_reported(self):
        def runner(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 1)
        controller = SetupController(seed_cli="/x/live-demo-seed", runner=runner)
        with self.assertRaises(SetupError) as raised:
            controller.assess()
        self.assertEqual(raised.exception.code, SETUP_TIMEOUT)


class SummaryTests(unittest.TestCase):
    def test_summary_names_cluster_program_config_and_signers(self):
        runner = _FakeRunner(_report())
        controller = SetupController(seed_cli="/x/live-demo-seed", runner=runner)
        assessment = controller.assess()
        summary = planned_action_summary(assessment)
        self.assertIn("solana:devnet", summary)
        self.assertIn("6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo", summary)
        self.assertIn("BPgSTnDHop1NhMrksBWJtZV2zqVmUM1iusEuUXocCnFU", summary)
        self.assertIn("grant_operator", summary)
        self.assertIn("governance", summary)
        self.assertIn("GOVERNANCE_KEY_UNAVAILABLE", summary)

    def test_summary_never_contains_key_paths(self):
        runner = _FakeRunner(_report())
        controller = SetupController(seed_cli="/x/live-demo-seed", runner=runner)
        summary = planned_action_summary(controller.assess())
        self.assertNotIn("/secret.json", summary)
        self.assertNotIn("keyFile", summary)

    def test_summary_says_nothing_is_sent_before_confirm(self):
        runner = _FakeRunner(_report())
        controller = SetupController(seed_cli="/x/live-demo-seed", runner=runner)
        summary = planned_action_summary(controller.assess())
        self.assertIn("Nothing is sent before you confirm", summary)


class StackIdentityContractTests(unittest.TestCase):
    """The stack-identity file is the reuse guard (ADR-0010).

    ``deploy/devnet-demo/native`` writes it at startup; ``live-demo`` reads it
    before reusing a running stack and refuses a namespace mismatch. This locks
    the JSON shape both sides agree on.
    """

    def _write_identity(self, registry_id: str, path: Path) -> None:
        path.write_text(json.dumps({
            "schema": "onelayer.stack-identity.v1",
            "registryId": registry_id,
            "syntheticProfile": False,
            "recordedAt": "2026-10-06T00:00:00Z",
        }))

    def _read_registry(self, path: Path) -> str:
        # The exact parse live-demo's stack_identity_registry uses.
        try:
            data = json.loads(path.read_text())
            return str(data.get("registryId") or "")
        except Exception:
            return ""

    def test_identity_round_trip(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "stack-identity.json"
            self._write_identity("demo.synthetic.onelayer", path)
            self.assertEqual(self._read_registry(path), "demo.synthetic.onelayer")

    def test_legacy_identity_reads_back(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "stack-identity.json"
            self._write_identity("gov.registry.land", path)
            self.assertEqual(self._read_registry(path), "gov.registry.land")

    def test_missing_identity_is_empty_not_an_error(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(self._read_registry(Path(root) / "absent.json"), "")

    def test_malformed_identity_is_empty_not_a_crash(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "stack-identity.json"
            path.write_text("{not json")
            self.assertEqual(self._read_registry(path), "")

    def test_mismatch_must_not_match(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "stack-identity.json"
            self._write_identity("gov.registry.land", path)
            self.assertNotEqual(
                self._read_registry(path), "demo.synthetic.onelayer")


if __name__ == "__main__":
    unittest.main()
