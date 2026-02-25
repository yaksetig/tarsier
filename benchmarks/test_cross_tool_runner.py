#!/usr/bin/env python3
"""Tests for the cross-tool benchmark runner (P2-12).

AC1: Runner executes normalized scenarios across at least two external tools.
AC2: Output normalizes assumptions and reports apples-to-apples metrics.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure the benchmarks directory is on the path
sys.path.insert(0, str(Path(__file__).parent))

from cross_tool_runner import (
    NORMALIZED_VERDICTS,
    TOOL_REGISTRY,
    BymcAdapter,
    SpinAdapter,
    TarsierAdapter,
    ToolAdapter,
    _make_result,
    _normalize_tarsier_verdict,
    _parse_bymc_output,
    _parse_spin_output,
    build_comparison_entry,
    build_report,
    get_adapter,
    normalize_assumptions,
    run_cross_tool_benchmark,
)


class TestNormalizedVerdicts(unittest.TestCase):
    """Normalized verdict constants are well-defined."""

    def test_verdict_set_contains_required(self):
        for v in ("safe", "unsafe", "timeout", "unknown", "error"):
            self.assertIn(v, NORMALIZED_VERDICTS)


class TestTarsierVerdictNormalization(unittest.TestCase):
    def test_safe_variants(self):
        for ov in ("safe", "proved", "SAFE", "PROVED", "live_proved", "LIVE_PROVED"):
            self.assertEqual(
                _normalize_tarsier_verdict({"overall_verdict": ov}),
                "safe",
                f"expected 'safe' for overall_verdict={ov!r}",
            )

    def test_unsafe_variants(self):
        for ov in ("unsafe", "counterexample", "UNSAFE", "COUNTEREXAMPLE"):
            self.assertEqual(
                _normalize_tarsier_verdict({"overall_verdict": ov}),
                "unsafe",
            )

    def test_timeout(self):
        self.assertEqual(
            _normalize_tarsier_verdict({"overall_verdict": "timeout"}),
            "timeout",
        )

    def test_unknown_fallback(self):
        self.assertEqual(
            _normalize_tarsier_verdict({"overall_verdict": "inconclusive"}),
            "unknown",
        )
        self.assertEqual(
            _normalize_tarsier_verdict({}),
            "unknown",
        )


class TestBymcOutputParsing(unittest.TestCase):
    def test_safe(self):
        self.assertEqual(_parse_bymc_output("no error found", 0), "safe")
        self.assertEqual(_parse_bymc_output("property satisfied", 0), "safe")

    def test_unsafe(self):
        self.assertEqual(_parse_bymc_output("error found in state 5", 1), "unsafe")
        self.assertEqual(_parse_bymc_output("counterexample trace", 1), "unsafe")

    def test_error(self):
        self.assertEqual(_parse_bymc_output("some unexpected output", 2), "error")

    def test_unknown(self):
        self.assertEqual(_parse_bymc_output("some output", 0), "unknown")

    def test_real_bymc_safe_spec_holds(self):
        self.assertEqual(_parse_bymc_output("Spec agreement holds", 0), "safe")

    def test_real_bymc_safe_slps_verified(self):
        self.assertEqual(
            _parse_bymc_output("> SLPS: property agreement verified", 0), "safe"
        )

    def test_real_bymc_unsafe_slps_counterexample(self):
        self.assertEqual(
            _parse_bymc_output("SLPS: counterexample for agreement found", 1),
            "unsafe",
        )

    def test_real_bymc_mixed_output_safe(self):
        output = (
            "Loading model from pbft.ta...\n"
            "Checking schema...\n"
            "Spec agreement holds\n"
            "Done in 42.3s\n"
        )
        self.assertEqual(_parse_bymc_output(output, 0), "safe")

    def test_real_bymc_mixed_output_unsafe(self):
        output = (
            "Loading model from buggy.ta...\n"
            "Checking schema...\n"
            "SLPS: counterexample for agreement found\n"
            "Done in 12.1s\n"
        )
        self.assertEqual(_parse_bymc_output(output, 1), "unsafe")


class TestSpinOutputParsing(unittest.TestCase):
    def test_safe(self):
        self.assertEqual(_parse_spin_output("errors: 0", 0), "safe")

    def test_unsafe(self):
        self.assertEqual(_parse_spin_output("error: assertion violated", 1), "unsafe")

    def test_unknown(self):
        self.assertEqual(_parse_spin_output("completed", 0), "unknown")


class TestMakeResult(unittest.TestCase):
    def test_ok_result(self):
        r = _make_result(
            tool="tarsier",
            scenario_id="pbft_agreement",
            status="ok",
            verdict="safe",
            elapsed_ms=123.456,
        )
        self.assertEqual(r["tool"], "tarsier")
        self.assertEqual(r["scenario_id"], "pbft_agreement")
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["normalized_verdict"], "safe")
        self.assertEqual(r["elapsed_ms"], 123.456)
        self.assertNotIn("reason", r)

    def test_skip_result(self):
        r = _make_result(
            tool="bymc",
            scenario_id="x",
            status="skip",
            reason="not installed",
        )
        self.assertEqual(r["status"], "skip")
        self.assertEqual(r["normalized_verdict"], "skip")
        self.assertEqual(r["reason"], "not installed")

    def test_error_result_with_details(self):
        r = _make_result(
            tool="tarsier",
            scenario_id="x",
            status="error",
            reason="exit code 1",
            details={"mode": "audit"},
        )
        self.assertEqual(r["status"], "error")
        self.assertEqual(r["details"]["mode"], "audit")


class TestNormalizeAssumptions(unittest.TestCase):
    """AC2: assumptions are normalized for apples-to-apples comparison."""

    def test_full_assumptions(self):
        scenario = {
            "id": "test",
            "property": "agreement",
            "property_description": "No disagreement",
            "expected_verdict": "safe",
            "assumptions": {
                "fault_model": "byzantine",
                "fault_bound": "n >= 3f+1",
                "network": "partially_synchronous",
                "message_loss": False,
            },
        }
        norm = normalize_assumptions(scenario)
        self.assertEqual(norm["fault_model"], "byzantine")
        self.assertEqual(norm["fault_bound"], "n >= 3f+1")
        self.assertEqual(norm["network_model"], "partially_synchronous")
        self.assertFalse(norm["message_loss"])
        self.assertEqual(norm["property"], "agreement")
        self.assertEqual(norm["expected_verdict"], "safe")

    def test_missing_assumptions_default(self):
        scenario = {"id": "test"}
        norm = normalize_assumptions(scenario)
        self.assertEqual(norm["fault_model"], "unknown")
        self.assertEqual(norm["network_model"], "unknown")


class TestBuildComparisonEntry(unittest.TestCase):
    """AC2: comparison entries include normalized assumptions and
    apples-to-apples metrics."""

    def test_two_tools_agree(self):
        scenario = {
            "id": "pbft",
            "name": "PBFT Agreement",
            "protocol_family": "pbft",
            "property": "agreement",
            "property_description": "No disagreement",
            "expected_verdict": "safe",
            "assumptions": {
                "fault_model": "byzantine",
                "fault_bound": "n >= 3f+1",
                "network": "partially_synchronous",
                "message_loss": False,
            },
        }
        results = [
            _make_result("tarsier", "pbft", "ok", "safe", 100.0),
            _make_result("bymc", "pbft", "ok", "safe", 200.0),
        ]
        entry = build_comparison_entry(scenario, results)
        self.assertEqual(entry["scenario_id"], "pbft")
        self.assertTrue(entry["tools_agree"])
        self.assertIn("tarsier", entry["tool_results"])
        self.assertIn("bymc", entry["tool_results"])
        self.assertTrue(entry["tool_results"]["tarsier"]["matches_expected"])
        self.assertEqual(entry["normalized_assumptions"]["fault_model"], "byzantine")

    def test_two_tools_disagree(self):
        scenario = {
            "id": "x",
            "expected_verdict": "safe",
            "assumptions": {},
        }
        results = [
            _make_result("tarsier", "x", "ok", "safe", 50.0),
            _make_result("bymc", "x", "ok", "unsafe", 80.0),
        ]
        entry = build_comparison_entry(scenario, results)
        self.assertFalse(entry["tools_agree"])

    def test_single_tool_not_comparable(self):
        scenario = {"id": "y", "expected_verdict": "safe", "assumptions": {}}
        results = [
            _make_result("tarsier", "y", "ok", "safe", 50.0),
            _make_result("bymc", "y", "skip", reason="not available"),
        ]
        entry = build_comparison_entry(scenario, results)
        self.assertIsNone(entry["tools_agree"])

    def test_matches_expected(self):
        scenario = {"id": "z", "expected_verdict": "unsafe", "assumptions": {}}
        results = [
            _make_result("tarsier", "z", "ok", "unsafe", 40.0),
        ]
        entry = build_comparison_entry(scenario, results)
        self.assertTrue(entry["tool_results"]["tarsier"]["matches_expected"])


class TestBuildReport(unittest.TestCase):
    """AC2: top-level report has normalized structure and summary."""

    def test_report_schema(self):
        comparisons = [
            {
                "scenario_id": "a",
                "scenario_name": "A",
                "protocol_family": "pf",
                "normalized_assumptions": {},
                "expected_verdict": "safe",
                "tool_results": {},
                "tools_agree": True,
            },
            {
                "scenario_id": "b",
                "scenario_name": "B",
                "protocol_family": "pf",
                "normalized_assumptions": {},
                "expected_verdict": "unsafe",
                "tool_results": {},
                "tools_agree": None,
            },
        ]
        report = build_report(
            manifest={},
            comparisons=comparisons,
            tools_used=["tarsier", "bymc"],
            tools_available={"tarsier": True, "bymc": False},
            started_at="2025-01-01T00:00:00Z",
            finished_at="2025-01-01T00:01:00Z",
            elapsed_ms=60000.0,
        )
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["report_type"], "cross_tool_benchmark")
        self.assertEqual(report["summary"]["total_scenarios"], 2)
        self.assertEqual(report["summary"]["tools_agree"], 1)
        self.assertEqual(report["summary"]["not_comparable"], 1)
        self.assertEqual(report["tools"]["requested"], ["tarsier", "bymc"])
        self.assertTrue(report["tools"]["available"]["tarsier"])
        self.assertFalse(report["tools"]["available"]["bymc"])
        self.assertEqual(len(report["scenarios"]), 2)


class TestToolRegistry(unittest.TestCase):
    """AC1: at least two tools registered."""

    def test_at_least_two_tools(self):
        self.assertGreaterEqual(len(TOOL_REGISTRY), 2)
        self.assertIn("tarsier", TOOL_REGISTRY)
        self.assertIn("bymc", TOOL_REGISTRY)

    def test_three_tools_registered(self):
        self.assertIn("spin", TOOL_REGISTRY)

    def test_get_adapter_valid(self):
        adapter = get_adapter("tarsier")
        self.assertIsInstance(adapter, TarsierAdapter)

    def test_get_adapter_invalid(self):
        with self.assertRaises(ValueError):
            get_adapter("nonexistent_tool")


class TestToolAdapterAvailability(unittest.TestCase):
    def test_tarsier_adapter_checks_binary(self):
        adapter = TarsierAdapter(binary="/nonexistent/path")
        self.assertFalse(adapter.is_available())

    def test_bymc_adapter_checks_which(self):
        adapter = BymcAdapter(binary="bymc_nonexistent_xxx")
        self.assertFalse(adapter.is_available())

    def test_spin_adapter_checks_which(self):
        adapter = SpinAdapter(binary="spin_nonexistent_xxx")
        self.assertFalse(adapter.is_available())


class TestTarsierAdapterRunScenario(unittest.TestCase):
    def test_missing_model_file_returns_skip(self):
        adapter = TarsierAdapter(binary="target/debug/tarsier")
        scenario = {
            "id": "test",
            "tool_inputs": {
                "tarsier": {"file": "/nonexistent/model.trs"},
            },
        }
        result = adapter.run_scenario(scenario, timeout_secs=10)
        self.assertEqual(result["status"], "skip")
        self.assertIn("not found", result["reason"])

    def test_no_file_key_returns_skip(self):
        adapter = TarsierAdapter(binary="target/debug/tarsier")
        scenario = {"id": "test", "tool_inputs": {"tarsier": {}}}
        result = adapter.run_scenario(scenario, timeout_secs=10)
        self.assertEqual(result["status"], "skip")


class TestBymcAdapterRunScenario(unittest.TestCase):
    def test_no_model_file_returns_skip(self):
        adapter = BymcAdapter()
        scenario = {"id": "test", "tool_inputs": {"bymc": {"file": None}}}
        result = adapter.run_scenario(scenario, timeout_secs=10)
        self.assertEqual(result["status"], "skip")

    def test_no_command_template_returns_skip(self):
        with tempfile.NamedTemporaryFile(suffix=".ta", delete=False) as tmp:
            tmp.write(b"dummy")
            tmp_path = tmp.name
        try:
            adapter = BymcAdapter()
            scenario = {
                "id": "test",
                "tool_inputs": {
                    "bymc": {"file": tmp_path, "command_template": None},
                },
            }
            result = adapter.run_scenario(scenario, timeout_secs=10)
            self.assertEqual(result["status"], "skip")
        finally:
            os.unlink(tmp_path)


class TestBymcAdapterMode(unittest.TestCase):
    def test_default_mode_is_mock(self):
        adapter = BymcAdapter()
        self.assertEqual(adapter.mode, "mock")

    def test_real_mode_uses_real_template(self):
        """When mode=real, run_scenario should prefer command_template_real."""
        adapter = BymcAdapter(binary=sys.executable, mode="real")
        with tempfile.NamedTemporaryFile(suffix=".ta", delete=False) as tmp:
            tmp.write(b"dummy model")
            tmp_path = tmp.name
        try:
            scenario = {
                "id": "test_real",
                "tool_inputs": {
                    "bymc": {
                        "file": tmp_path,
                        "command_template": "{binary} benchmarks/mock_tools/mock_bymc.py {model_file} --bound {depth}",
                        "command_template_real": "{binary} -c \"print('Spec agreement holds')\" {model_file}",
                    },
                    "tarsier": {"depth": 10},
                },
            }
            result = adapter.run_scenario(scenario, timeout_secs=10)
            # The real template should be selected and produce a safe verdict
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["normalized_verdict"], "safe")
            self.assertEqual(result.get("execution_mode_override"), "real")
        finally:
            os.unlink(tmp_path)

    def test_mock_mode_uses_mock_template(self):
        """When mode=mock, run_scenario should use command_template."""
        adapter = BymcAdapter(binary=sys.executable, mode="mock")
        with tempfile.NamedTemporaryFile(suffix=".ta", delete=False) as tmp:
            tmp.write(b"dummy model")
            tmp_path = tmp.name
        try:
            scenario = {
                "id": "test_mock",
                "tool_inputs": {
                    "bymc": {
                        "file": tmp_path,
                        "command_template": "{binary} -c \"print('property satisfied')\"",
                        "command_template_real": "{binary} {model_file} --spec all",
                    },
                    "tarsier": {"depth": 10},
                },
            }
            result = adapter.run_scenario(scenario, timeout_secs=10)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["normalized_verdict"], "safe")
            self.assertEqual(result.get("execution_mode_override"), "mock")
        finally:
            os.unlink(tmp_path)


class TestScenarioManifest(unittest.TestCase):
    """Validate the scenario manifest file structure."""

    def test_manifest_valid_json(self):
        manifest_path = Path(__file__).parent / "cross_tool_scenarios" / "scenario_manifest.json"
        with open(manifest_path) as f:
            manifest = json.load(f)
        self.assertEqual(manifest["schema_version"], 1)
        self.assertIn("scenarios", manifest)
        self.assertGreater(len(manifest["scenarios"]), 0)

    def test_each_scenario_has_required_fields(self):
        manifest_path = Path(__file__).parent / "cross_tool_scenarios" / "scenario_manifest.json"
        with open(manifest_path) as f:
            manifest = json.load(f)
        for scenario in manifest["scenarios"]:
            self.assertIn("id", scenario, f"scenario missing 'id'")
            self.assertIn("property", scenario, f"scenario {scenario.get('id')} missing 'property'")
            self.assertIn("expected_verdict", scenario)
            self.assertIn("assumptions", scenario)
            self.assertIn("tool_inputs", scenario)
            # Must have at least tarsier input
            self.assertIn("tarsier", scenario["tool_inputs"])

    def test_each_scenario_has_at_least_two_tool_inputs(self):
        """AC1: scenarios define inputs for at least two tools."""
        manifest_path = Path(__file__).parent / "cross_tool_scenarios" / "scenario_manifest.json"
        with open(manifest_path) as f:
            manifest = json.load(f)
        for scenario in manifest["scenarios"]:
            self.assertGreaterEqual(
                len(scenario["tool_inputs"]),
                2,
                f"scenario {scenario['id']} must have >= 2 tool_inputs",
            )

    def test_tarsier_inputs_have_valid_files(self):
        manifest_path = Path(__file__).parent / "cross_tool_scenarios" / "scenario_manifest.json"
        with open(manifest_path) as f:
            manifest = json.load(f)
        for scenario in manifest["scenarios"]:
            tarsier_file = scenario["tool_inputs"]["tarsier"].get("file")
            if tarsier_file:
                self.assertTrue(
                    Path(tarsier_file).exists(),
                    f"scenario {scenario['id']}: Tarsier model file {tarsier_file} not found",
                )

    def test_external_tool_inputs_have_files_and_templates(self):
        """AC1: external tools are runnable via explicit file + command template."""
        manifest_path = Path(__file__).parent / "cross_tool_scenarios" / "scenario_manifest.json"
        with open(manifest_path) as f:
            manifest = json.load(f)
        for scenario in manifest["scenarios"]:
            sid = scenario["id"]
            for tool in ("bymc", "spin"):
                self.assertIn(
                    tool,
                    scenario["tool_inputs"],
                    f"scenario {sid} missing tool_inputs.{tool}",
                )
                cfg = scenario["tool_inputs"][tool]
                model_file = cfg.get("file")
                cmd_tpl = cfg.get("command_template")
                self.assertIsInstance(
                    model_file,
                    str,
                    f"scenario {sid} tool {tool} must set model file",
                )
                self.assertTrue(
                    Path(model_file).exists(),
                    f"scenario {sid} tool {tool} model file {model_file} not found",
                )
                self.assertIsInstance(
                    cmd_tpl,
                    str,
                    f"scenario {sid} tool {tool} must set command_template",
                )
                self.assertIn(
                    "{binary}",
                    cmd_tpl,
                    f"scenario {sid} tool {tool} command_template must include {{binary}}",
                )

    def _assert_real_smoke_manifest_contract(
        self,
        manifest_name: str,
        external_tool: str,
        *,
        require_command_template_real: bool = False,
    ):
        manifest_path = Path(__file__).parent / "cross_tool_scenarios" / manifest_name
        with open(manifest_path) as f:
            manifest = json.load(f)

        self.assertEqual(manifest["schema_version"], 1)
        self.assertGreaterEqual(len(manifest.get("scenarios", [])), 1)

        scenario = manifest["scenarios"][0]
        self.assertIn("tool_inputs", scenario)
        self.assertIn("tarsier", scenario["tool_inputs"])
        self.assertIn(external_tool, scenario["tool_inputs"])

        tarsier_cfg = scenario["tool_inputs"]["tarsier"]
        tarsier_model_file = tarsier_cfg.get("file")
        self.assertIsInstance(tarsier_model_file, str)
        self.assertTrue((Path(__file__).parent.parent / tarsier_model_file).exists())

        external_cfg = scenario["tool_inputs"][external_tool]
        self.assertEqual(external_cfg.get("execution_mode"), "real")
        self.assertIn("{binary}", external_cfg.get("command_template", ""))

        if require_command_template_real:
            self.assertIn("{binary}", external_cfg.get("command_template_real", ""))

        model_file = external_cfg.get("file")
        self.assertIsInstance(model_file, str)
        self.assertTrue((Path(__file__).parent.parent / model_file).exists())

    def test_real_bymc_smoke_manifest_contract(self):
        self._assert_real_smoke_manifest_contract(
            "scenario_manifest_real_bymc_smoke.json",
            "bymc",
            require_command_template_real=True,
        )

    def test_real_spin_smoke_manifest_contract(self):
        self._assert_real_smoke_manifest_contract(
            "scenario_manifest_real_spin_smoke.json",
            "spin",
        )


class TestExternalToolExecution(unittest.TestCase):
    """AC1: runner executes scenarios across at least two external tools."""

    def test_runner_executes_bymc_and_spin_with_mock_binaries(self):
        manifest_path = Path(__file__).parent / "cross_tool_scenarios" / "scenario_manifest.json"
        report = run_cross_tool_benchmark(
            manifest_path=str(manifest_path),
            tools=["bymc", "spin"],
            timeout_secs=10,
            bymc_binary=sys.executable,
            spin_binary=sys.executable,
            skip_unavailable=False,
        )
        self.assertEqual(report["report_type"], "cross_tool_benchmark")
        self.assertEqual(report["tools"]["requested"], ["bymc", "spin"])
        self.assertTrue(report["tools"]["available"]["bymc"])
        self.assertTrue(report["tools"]["available"]["spin"])
        self.assertGreater(len(report["scenarios"]), 0)

        for scenario in report["scenarios"]:
            bymc = scenario["tool_results"].get("bymc")
            spin = scenario["tool_results"].get("spin")
            self.assertIsNotNone(bymc, f"{scenario['scenario_id']} missing bymc result")
            self.assertIsNotNone(spin, f"{scenario['scenario_id']} missing spin result")
            self.assertEqual(
                bymc["status"],
                "ok",
                f"{scenario['scenario_id']} bymc should execute successfully",
            )
            self.assertEqual(
                spin["status"],
                "ok",
                f"{scenario['scenario_id']} spin should execute successfully",
            )
            self.assertIn(
                scenario["tools_agree"],
                (True, False),
                f"{scenario['scenario_id']} should be comparable with two external verdicts",
            )


class TestCrossToolReportNormalization(unittest.TestCase):
    """AC2: output normalizes assumptions and reports apples-to-apples metrics."""

    def test_report_includes_normalized_assumptions_per_scenario(self):
        scenario = {
            "id": "test",
            "name": "Test",
            "protocol_family": "test",
            "property": "agreement",
            "property_description": "desc",
            "expected_verdict": "safe",
            "assumptions": {
                "fault_model": "byzantine",
                "fault_bound": "n >= 3f+1",
                "network": "asynchronous",
                "message_loss": True,
            },
        }
        results = [
            _make_result("tarsier", "test", "ok", "safe", 100.0),
            _make_result("bymc", "test", "skip", reason="not available"),
        ]
        entry = build_comparison_entry(scenario, results)
        na = entry["normalized_assumptions"]
        self.assertEqual(na["fault_model"], "byzantine")
        self.assertEqual(na["fault_bound"], "n >= 3f+1")
        self.assertEqual(na["network_model"], "asynchronous")
        self.assertTrue(na["message_loss"])
        self.assertEqual(na["property"], "agreement")

    def test_apples_to_apples_timing_comparison(self):
        """Each tool result has elapsed_ms for direct comparison."""
        scenario = {
            "id": "test",
            "name": "Test",
            "expected_verdict": "safe",
            "assumptions": {},
        }
        results = [
            _make_result("tarsier", "test", "ok", "safe", 150.0),
            _make_result("bymc", "test", "ok", "safe", 300.0),
        ]
        entry = build_comparison_entry(scenario, results)
        self.assertEqual(entry["tool_results"]["tarsier"]["elapsed_ms"], 150.0)
        self.assertEqual(entry["tool_results"]["bymc"]["elapsed_ms"], 300.0)
        self.assertEqual(
            entry["tool_results"]["tarsier"]["normalized_verdict"],
            entry["tool_results"]["bymc"]["normalized_verdict"],
        )

    def test_report_serializable_to_json(self):
        report = build_report(
            manifest={},
            comparisons=[],
            tools_used=["tarsier", "bymc"],
            tools_available={"tarsier": True, "bymc": False},
            started_at="2025-01-01T00:00:00Z",
            finished_at="2025-01-01T00:01:00Z",
            elapsed_ms=60000.0,
        )
        serialized = json.dumps(report, indent=2)
        deserialized = json.loads(serialized)
        self.assertEqual(deserialized["schema_version"], 1)
        self.assertEqual(deserialized["report_type"], "cross_tool_benchmark")


class TestRealModelVerdictMapping(unittest.TestCase):
    """T1-TEST-2: real .ta models produce correct verdict mapping."""

    def _load_manifest(self) -> dict:
        manifest_path = Path(__file__).parent / "cross_tool_scenarios" / "scenario_manifest.json"
        with open(manifest_path) as f:
            return json.load(f)

    def test_real_ta_model_produces_correct_safe_verdict(self):
        """Non-placeholder safe .ta models, when executed with mock adapter,
        produce 'safe' normalized verdict matching expected_verdict."""
        manifest_path = Path(__file__).parent / "cross_tool_scenarios" / "scenario_manifest.json"
        report = run_cross_tool_benchmark(
            manifest_path=str(manifest_path),
            tools=["bymc", "spin"],
            timeout_secs=10,
            bymc_binary=sys.executable,
            spin_binary=sys.executable,
            skip_unavailable=False,
        )
        safe_scenarios = [
            s for s in report["scenarios"] if s["expected_verdict"] == "safe"
        ]
        self.assertGreater(len(safe_scenarios), 0, "no safe scenarios found")
        for s in safe_scenarios:
            bymc_result = s["tool_results"].get("bymc", {})
            if bymc_result.get("status") == "ok":
                self.assertEqual(
                    bymc_result["normalized_verdict"],
                    "safe",
                    f"{s['scenario_id']}: expected safe verdict from bymc",
                )

    def test_real_ta_model_produces_correct_unsafe_verdict(self):
        """Buggy .ta model produces 'unsafe' normalized verdict."""
        manifest_path = Path(__file__).parent / "cross_tool_scenarios" / "scenario_manifest.json"
        report = run_cross_tool_benchmark(
            manifest_path=str(manifest_path),
            tools=["bymc", "spin"],
            timeout_secs=10,
            bymc_binary=sys.executable,
            spin_binary=sys.executable,
            skip_unavailable=False,
        )
        unsafe_scenarios = [
            s for s in report["scenarios"] if s["expected_verdict"] == "unsafe"
        ]
        self.assertGreater(len(unsafe_scenarios), 0, "no unsafe scenarios found")
        for s in unsafe_scenarios:
            bymc_result = s["tool_results"].get("bymc", {})
            if bymc_result.get("status") == "ok":
                self.assertEqual(
                    bymc_result["normalized_verdict"],
                    "unsafe",
                    f"{s['scenario_id']}: expected unsafe verdict from bymc",
                )

    def test_no_placeholder_models_in_corpus(self):
        """All .ta files in the corpus are real models (>= 5 lines, no placeholder comment)."""
        manifest = self._load_manifest()
        for scenario in manifest["scenarios"]:
            for tool in ("bymc",):
                cfg = scenario["tool_inputs"].get(tool, {})
                model_file = cfg.get("file")
                if model_file and model_file.endswith(".ta"):
                    path = Path(model_file)
                    self.assertTrue(
                        path.exists(),
                        f"{scenario['id']}: {model_file} not found",
                    )
                    content = path.read_text()
                    lines = [l for l in content.splitlines() if l.strip()]
                    self.assertGreaterEqual(
                        len(lines),
                        5,
                        f"{scenario['id']}: {model_file} has only {len(lines)} non-empty lines (placeholder?)",
                    )
                    self.assertNotIn(
                        "placeholder",
                        content.lower(),
                        f"{scenario['id']}: {model_file} contains 'placeholder' (still a stub?)",
                    )
                    self.assertNotIn(
                        "specifications (0)",
                        content,
                        f"{scenario['id']}: {model_file} has empty specifications (0)",
                    )

    def test_execution_mode_propagated_in_report(self):
        """execution_mode from manifest is propagated into per-tool report results."""
        manifest_path = Path(__file__).parent / "cross_tool_scenarios" / "scenario_manifest.json"
        report = run_cross_tool_benchmark(
            manifest_path=str(manifest_path),
            tools=["bymc", "spin"],
            timeout_secs=10,
            bymc_binary=sys.executable,
            spin_binary=sys.executable,
            skip_unavailable=False,
        )
        for scenario in report["scenarios"]:
            for tool_name, tool_result in scenario["tool_results"].items():
                self.assertIn(
                    "execution_mode",
                    tool_result,
                    f"{scenario['scenario_id']}/{tool_name}: missing execution_mode",
                )
                self.assertIn(
                    tool_result["execution_mode"],
                    ("mock", "real", "unknown"),
                    f"{scenario['scenario_id']}/{tool_name}: invalid execution_mode",
                )

    def test_report_includes_execution_modes_summary(self):
        """Top-level report tools section includes execution_modes summary."""
        manifest_path = Path(__file__).parent / "cross_tool_scenarios" / "scenario_manifest.json"
        report = run_cross_tool_benchmark(
            manifest_path=str(manifest_path),
            tools=["bymc", "spin"],
            timeout_secs=10,
            bymc_binary=sys.executable,
            spin_binary=sys.executable,
            skip_unavailable=False,
        )
        self.assertIn(
            "execution_modes",
            report["tools"],
            "report tools section missing execution_modes",
        )


if __name__ == "__main__":
    unittest.main()
