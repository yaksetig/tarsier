#!/usr/bin/env python3
"""Unit tests for benchmark replay harness."""

from __future__ import annotations

import copy
import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REPLAY_PATH = ROOT / "benchmarks" / "replay_library_bench.py"

spec = importlib.util.spec_from_file_location("replay_library_bench", REPLAY_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("failed to load replay_library_bench module")
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)


class ReplayHarnessTests(unittest.TestCase):
    def sample_report(self) -> dict:
        return {
            "schema_version": 1,
            "started_at_utc": "2026-01-01T00:00:00Z",
            "finished_at_utc": "2026-01-01T00:00:01Z",
            "config": {
                "mode": "quick",
                "solver": "z3",
                "depth": 4,
                "k": 8,
                "timeout_secs": 60,
                "samples": 1,
                "soundness": "strict",
                "fairness": "weak",
                "require_pass": False,
                "require_expectations": False,
            },
            "environment": {
                "python_version": "3.11.x",
                "platform": "linux",
                "rustc_version": "rustc 1.92.0",
                "z3_version": "Z3 version 4.12.5 - 64 bit",
                "cvc5_version": "This is cvc5 version 1.1.2",
            },
            "replay": {
                "harness": "benchmarks/replay_library_bench.py",
                "plan_sha256": "0" * 64,
                "result_sha256": "1" * 64,
            },
            "runs": [
                {
                    "protocol": "examples/library/trivial_live.trs",
                    "manifest_file": "trivial_live.trs",
                    "protocol_sha256": "a" * 64,
                    "overall": "pass",
                    "ok": True,
                    "run_is_valid": True,
                    "effective_network": "classic",
                    "expectations": {"checked": 0, "passed": 0, "failed": 0, "checks": []},
                    "json_parse_error": None,
                    "elapsed_ms": 42.0,
                    "samples_ms": [42.0],
                    "stderr": "",
                    "report": {
                        "overall": "pass",
                        "layers": [
                            {
                                "layer": "verify",
                                "details": {
                                    "result": "safe"
                                },
                            }
                        ],
                    },
                }
            ],
        }

    def test_validate_report_rejects_missing_protocol_hash(self) -> None:
        report = self.sample_report()
        del report["runs"][0]["protocol_sha256"]
        errors = replay.validate_report(report)
        self.assertTrue(any("protocol_sha256" in err for err in errors))

    def test_canonical_projection_ignores_timing_fields(self) -> None:
        report_a = self.sample_report()
        report_b = self.sample_report()
        report_b["started_at_utc"] = "2027-01-01T00:00:00Z"
        report_b["finished_at_utc"] = "2027-01-01T00:00:01Z"
        report_b["runs"][0]["elapsed_ms"] = 999.0
        report_b["runs"][0]["samples_ms"] = [999.0]
        report_b["runs"][0]["stderr"] = "timing noise"

        proj_a = replay.canonical_projection(report_a)
        proj_b = replay.canonical_projection(report_b)
        self.assertEqual(proj_a, proj_b)
        self.assertEqual(replay.projection_hash(proj_a), replay.projection_hash(proj_b))

    def test_build_replay_command_carries_flags(self) -> None:
        report = self.sample_report()
        report["config"]["require_pass"] = True
        report["config"]["require_expectations"] = True

        with tempfile.NamedTemporaryFile(suffix=".txt") as protocol_list:
            out_report = Path(tempfile.mktemp(suffix=".json"))
            cmd = replay.build_replay_command(
                baseline_report=report,
                protocol_list_file=Path(protocol_list.name),
                out_report=out_report,
                skip_build=True,
                max_protocols=3,
            )

        self.assertIn("--require-pass", cmd)
        self.assertIn("--require-expectations", cmd)
        self.assertIn("--skip-build", cmd)
        self.assertIn("--max-protocols", cmd)
        self.assertIn("3", cmd)


if __name__ == "__main__":
    unittest.main()
