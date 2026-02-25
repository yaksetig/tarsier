#!/usr/bin/env python3
"""Validate cross-tool benchmark infrastructure consistency.

Checks:
1. Scenario manifest exists and is valid JSON with required structure.
2. Cross-tool report schema exists and is valid JSON.
3. Runner script exists and defines required adapters.
4. Test file exists and covers AC1/AC2.
5. README documents the cross-tool runner.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

ERRORS: list[str] = []


def check_file_exists(path: Path, label: str) -> bool:
    if not path.exists():
        ERRORS.append(f"Missing required file: {path} ({label})")
        return False
    return True


def check_json_valid(path: Path, label: str) -> dict | None:
    if not check_file_exists(path, label):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        ERRORS.append(f"Invalid JSON in {path}: {e}")
        return None


def check_tool_model_file(sid: str, tool: str, model_file: object, manifest_label: str) -> None:
    if not isinstance(model_file, str) or not model_file:
        ERRORS.append(
            f"{manifest_label}: scenario '{sid}' tool '{tool}' missing non-empty file path"
        )
        return
    file_path = ROOT / model_file
    if not file_path.exists():
        ERRORS.append(
            f"{manifest_label}: scenario '{sid}' tool '{tool}' file does not exist: {model_file}"
        )


def check_tool_command_template(
    sid: str,
    tool: str,
    cfg: dict,
    manifest_label: str,
    *,
    required_key: str = "command_template",
) -> None:
    template = cfg.get(required_key)
    if not isinstance(template, str) or not template:
        ERRORS.append(
            f"{manifest_label}: scenario '{sid}' tool '{tool}' missing non-empty {required_key}"
        )
        return
    if "{binary}" not in template:
        ERRORS.append(
            f"{manifest_label}: scenario '{sid}' tool '{tool}' {required_key} must include '{{binary}}'"
        )


def check_manifest() -> None:
    manifest = check_json_valid(
        ROOT / "benchmarks" / "cross_tool_scenarios" / "scenario_manifest.json",
        "scenario manifest",
    )
    if manifest is None:
        return
    if "scenarios" not in manifest:
        ERRORS.append("Scenario manifest missing 'scenarios' key")
        return
    scenarios = manifest["scenarios"]
    if len(scenarios) < 1:
        ERRORS.append("Scenario manifest has no scenarios")
    for s in scenarios:
        sid = s.get("id", "<unknown>")
        for key in ("id", "property", "expected_verdict", "assumptions", "tool_inputs"):
            if key not in s:
                ERRORS.append(f"Scenario '{sid}' missing required key '{key}'")
        tool_inputs = s.get("tool_inputs", {})
        if len(tool_inputs) < 2:
            ERRORS.append(f"Scenario '{sid}' has fewer than 2 tool_inputs (AC1)")
        for external_tool in ("bymc", "spin"):
            if external_tool not in tool_inputs:
                ERRORS.append(
                    f"Scenario '{sid}' missing external tool input '{external_tool}' (AC1)"
                )
                continue
            ext_cfg = tool_inputs.get(external_tool, {})
            check_tool_model_file(
                sid,
                external_tool,
                ext_cfg.get("file"),
                "scenario manifest",
            )
            check_tool_command_template(
                sid,
                external_tool,
                ext_cfg,
                "scenario manifest",
            )
            # Optional: validate command_template_real if present
            ext_tpl_real = ext_cfg.get("command_template_real")
            if ext_tpl_real is not None:
                if not isinstance(ext_tpl_real, str) or not ext_tpl_real:
                    ERRORS.append(
                        f"Scenario '{sid}' external tool '{external_tool}' command_template_real is present but empty"
                    )
                elif "{binary}" not in ext_tpl_real:
                    ERRORS.append(
                        f"Scenario '{sid}' external tool '{external_tool}' command_template_real must include '{{binary}}'"
                    )


def check_real_smoke_manifests() -> None:
    smoke_contracts = [
        ("scenario_manifest_real_bymc_smoke.json", "bymc", True),
        ("scenario_manifest_real_spin_smoke.json", "spin", False),
    ]
    for filename, external_tool, require_real_template in smoke_contracts:
        manifest_label = f"{external_tool} real smoke manifest"
        manifest = check_json_valid(
            ROOT / "benchmarks" / "cross_tool_scenarios" / filename,
            manifest_label,
        )
        if manifest is None:
            continue

        if manifest.get("schema_version") != 1:
            ERRORS.append(f"{manifest_label}: schema_version must be 1")

        scenarios = manifest.get("scenarios")
        if not isinstance(scenarios, list) or not scenarios:
            ERRORS.append(f"{manifest_label}: scenarios must be a non-empty list")
            continue

        for scenario in scenarios:
            sid = scenario.get("id", "<unknown>")
            for key in ("id", "property", "expected_verdict", "assumptions", "tool_inputs"):
                if key not in scenario:
                    ERRORS.append(f"{manifest_label}: scenario '{sid}' missing required key '{key}'")

            tool_inputs = scenario.get("tool_inputs", {})
            tarsier_cfg = tool_inputs.get("tarsier")
            if not isinstance(tarsier_cfg, dict):
                ERRORS.append(f"{manifest_label}: scenario '{sid}' missing tool_inputs.tarsier")
            else:
                check_tool_model_file(
                    sid,
                    "tarsier",
                    tarsier_cfg.get("file"),
                    manifest_label,
                )

            ext_cfg = tool_inputs.get(external_tool)
            if not isinstance(ext_cfg, dict):
                ERRORS.append(
                    f"{manifest_label}: scenario '{sid}' missing tool_inputs.{external_tool}"
                )
                continue

            check_tool_model_file(
                sid,
                external_tool,
                ext_cfg.get("file"),
                manifest_label,
            )
            check_tool_command_template(
                sid,
                external_tool,
                ext_cfg,
                manifest_label,
            )

            if ext_cfg.get("execution_mode") != "real":
                ERRORS.append(
                    f"{manifest_label}: scenario '{sid}' tool '{external_tool}' must set execution_mode='real'"
                )

            if require_real_template:
                check_tool_command_template(
                    sid,
                    external_tool,
                    ext_cfg,
                    manifest_label,
                    required_key="command_template_real",
                )


def check_schema() -> None:
    schema = check_json_valid(
        ROOT / "docs" / "cross-tool-benchmark-report-schema-v1.json",
        "cross-tool report schema",
    )
    if schema is None:
        return
    for key in ("properties", "$defs"):
        if key not in schema:
            ERRORS.append(f"Report schema missing '{key}'")


def check_runner() -> None:
    runner = ROOT / "benchmarks" / "cross_tool_runner.py"
    if not check_file_exists(runner, "cross-tool runner script"):
        return
    content = runner.read_text()
    for adapter in ("TarsierAdapter", "BymcAdapter", "SpinAdapter"):
        if adapter not in content:
            ERRORS.append(f"Runner missing {adapter} class")
    if "TOOL_REGISTRY" not in content:
        ERRORS.append("Runner missing TOOL_REGISTRY")
    if "normalize_assumptions" not in content:
        ERRORS.append("Runner missing normalize_assumptions function")
    if "build_comparison_entry" not in content:
        ERRORS.append("Runner missing build_comparison_entry function")


def check_tests() -> None:
    tests = ROOT / "benchmarks" / "test_cross_tool_runner.py"
    if not check_file_exists(tests, "cross-tool runner tests"):
        return
    content = tests.read_text()
    if "AC1" not in content:
        ERRORS.append("Test file missing AC1 coverage marker")
    if "AC2" not in content:
        ERRORS.append("Test file missing AC2 coverage marker")


def check_no_placeholder_models() -> None:
    """T1-CI-1: Verify that all .ta model files in the manifest are real models,
    not placeholders."""
    manifest_paths = [
        ROOT / "benchmarks" / "cross_tool_scenarios" / "scenario_manifest.json",
        ROOT / "benchmarks" / "cross_tool_scenarios" / "scenario_manifest_real_bymc_smoke.json",
    ]
    for manifest_path in manifest_paths:
        if not manifest_path.exists():
            continue
        with open(manifest_path) as f:
            manifest = json.load(f)
        for s in manifest.get("scenarios", []):
            sid = s.get("id", "<unknown>")
            for tool in ("bymc",):
                cfg = s.get("tool_inputs", {}).get(tool, {})
                model_file = cfg.get("file")
                if not model_file or not model_file.endswith(".ta"):
                    continue
                file_path = ROOT / model_file
                if not file_path.exists():
                    continue  # file-existence checked in manifest checks
                content = file_path.read_text()
                non_empty_lines = [l for l in content.splitlines() if l.strip()]
                if len(non_empty_lines) < 5:
                    ERRORS.append(
                        f"Scenario '{sid}' tool '{tool}' model {model_file} has only "
                        f"{len(non_empty_lines)} non-empty lines (placeholder?)"
                    )
                lower = content.lower()
                if "mock" in lower.split("/*")[0] and "placeholder" in lower:
                    ERRORS.append(
                        f"Scenario '{sid}' tool '{tool}' model {model_file} "
                        f"contains 'Mock/Placeholder' comment (still a stub?)"
                    )
                if "specifications (0)" in content:
                    ERRORS.append(
                        f"Scenario '{sid}' tool '{tool}' model {model_file} "
                        f"has empty 'specifications (0)' (no properties exported)"
                    )


def check_readme() -> None:
    readme = ROOT / "benchmarks" / "README.md"
    if not check_file_exists(readme, "benchmarks README"):
        return
    content = readme.read_text()
    if "cross_tool_runner" not in content.lower() and "cross-tool" not in content.lower():
        ERRORS.append("README does not document the cross-tool runner")


def main() -> None:
    check_manifest()
    check_real_smoke_manifests()
    check_schema()
    check_runner()
    check_tests()
    check_readme()
    check_no_placeholder_models()

    if ERRORS:
        print("Cross-tool benchmark contract check FAILED:")
        for e in ERRORS:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("Cross-tool benchmark contract check passed.")


if __name__ == "__main__":
    main()
