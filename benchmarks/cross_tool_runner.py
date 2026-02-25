#!/usr/bin/env python3
"""Cross-tool benchmark runner: execute normalized scenarios across multiple
verification tools and produce an apples-to-apples comparison report.

P2-12: Cross-tool benchmark runner
  AC1: Runner executes normalized scenarios across at least two external tools.
  AC2: Output normalizes assumptions and reports apples-to-apples metrics.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Tool adapter interface
# ---------------------------------------------------------------------------

class ToolAdapter:
    """Base class for tool adapters.  Each adapter knows how to invoke a
    specific verification tool and parse its output into a normalized result."""

    name: str = "base"

    def is_available(self) -> bool:
        """Return True if the tool is installed and callable."""
        return False

    def run_scenario(
        self,
        scenario: dict[str, Any],
        timeout_secs: int,
    ) -> dict[str, Any]:
        """Run a single scenario and return a normalized result dict."""
        raise NotImplementedError


class TarsierAdapter(ToolAdapter):
    """Adapter for the Tarsier CLI (always available — it's this project)."""

    name = "tarsier"

    def __init__(self, binary: str = "target/debug/tarsier") -> None:
        self.binary = binary

    def is_available(self) -> bool:
        return Path(self.binary).exists()

    def run_scenario(
        self,
        scenario: dict[str, Any],
        timeout_secs: int,
    ) -> dict[str, Any]:
        tool_cfg = scenario["tool_inputs"].get("tarsier", {})
        model_file = tool_cfg.get("file")
        if not model_file or not Path(model_file).exists():
            return _make_result(
                tool="tarsier",
                scenario_id=scenario["id"],
                status="skip",
                reason=f"model file not found: {model_file}",
            )

        mode = tool_cfg.get("mode", "standard")
        depth = tool_cfg.get("depth", 10)
        k = tool_cfg.get("k", 12)
        per_timeout = tool_cfg.get("timeout_secs", timeout_secs)

        cmd = [
            self.binary,
            "analyze",
            model_file,
            "--profile", "pro",
            "--mode", mode,
            "--depth", str(depth),
            "--k", str(k),
            "--timeout", str(per_timeout),
            "--soundness", "strict",
            "--format", "json",
        ]

        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=per_timeout + 30,
            )
            elapsed_ms = (time.monotonic() - t0) * 1000
            if proc.returncode == 0 or proc.returncode == 2:
                try:
                    report = json.loads(proc.stdout)
                except json.JSONDecodeError:
                    return _make_result(
                        tool="tarsier",
                        scenario_id=scenario["id"],
                        status="error",
                        reason="invalid JSON output",
                        elapsed_ms=elapsed_ms,
                    )
                verdict = _normalize_tarsier_verdict(report)
                return _make_result(
                    tool="tarsier",
                    scenario_id=scenario["id"],
                    status="ok",
                    verdict=verdict,
                    elapsed_ms=elapsed_ms,
                    raw_verdict=report.get("overall_verdict", ""),
                    details={
                        "mode": report.get("mode", ""),
                        "layers": len(report.get("layers", [])),
                        "confidence_tier": report.get("confidence_tier", ""),
                    },
                )
            else:
                return _make_result(
                    tool="tarsier",
                    scenario_id=scenario["id"],
                    status="error",
                    reason=f"exit code {proc.returncode}",
                    elapsed_ms=elapsed_ms,
                )
        except subprocess.TimeoutExpired:
            elapsed_ms = (time.monotonic() - t0) * 1000
            return _make_result(
                tool="tarsier",
                scenario_id=scenario["id"],
                status="timeout",
                elapsed_ms=elapsed_ms,
            )


class BymcAdapter(ToolAdapter):
    """Adapter for ByMC (Byzantine Model Checker).

    ByMC operates on threshold automata and is the closest academic
    comparator to Tarsier.  When ByMC is not installed the adapter
    gracefully reports 'unavailable' rather than failing.
    """

    name = "bymc"

    def __init__(self, binary: str = "bymc", mode: str = "mock") -> None:
        self.binary = binary
        self.mode = mode

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None or Path(self.binary).is_file()

    def run_scenario(
        self,
        scenario: dict[str, Any],
        timeout_secs: int,
    ) -> dict[str, Any]:
        tool_cfg = scenario["tool_inputs"].get("bymc", {})
        model_file = tool_cfg.get("file")
        if not model_file:
            return _make_result(
                tool="bymc",
                scenario_id=scenario["id"],
                status="skip",
                reason="no model file specified for ByMC",
            )
        if not Path(model_file).exists():
            return _make_result(
                tool="bymc",
                scenario_id=scenario["id"],
                status="skip",
                reason=f"model file not found: {model_file}",
            )
        # Select command template based on mode
        if self.mode == "real":
            cmd_template = tool_cfg.get("command_template_real") or tool_cfg.get("command_template")
        else:
            cmd_template = tool_cfg.get("command_template")
        if not cmd_template:
            return _make_result(
                tool="bymc",
                scenario_id=scenario["id"],
                status="skip",
                reason="no command_template for ByMC",
            )

        depth = tool_cfg.get("depth", scenario["tool_inputs"].get("tarsier", {}).get("depth", 10))
        cmd_str = cmd_template.format(
            binary=self.binary,
            model_file=model_file,
            depth=depth,
            scenario_id=scenario["id"],
        )
        cmd = shlex.split(cmd_str)

        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_secs + 30,
            )
            elapsed_ms = (time.monotonic() - t0) * 1000
            verdict = _parse_bymc_output(proc.stdout, proc.returncode)
            result = _make_result(
                tool="bymc",
                scenario_id=scenario["id"],
                status="ok",
                verdict=verdict,
                elapsed_ms=elapsed_ms,
                raw_verdict=proc.stdout.strip()[-200:] if proc.stdout else "",
            )
            result["execution_mode_override"] = self.mode
            return result
        except subprocess.TimeoutExpired:
            elapsed_ms = (time.monotonic() - t0) * 1000
            result = _make_result(
                tool="bymc",
                scenario_id=scenario["id"],
                status="timeout",
                elapsed_ms=elapsed_ms,
            )
            result["execution_mode_override"] = self.mode
            return result
        except FileNotFoundError:
            return _make_result(
                tool="bymc",
                scenario_id=scenario["id"],
                status="unavailable",
                reason=f"binary '{self.binary}' not found",
            )


class SpinAdapter(ToolAdapter):
    """Adapter for SPIN model checker.

    SPIN is a general-purpose model checker.  Protocol models must be
    manually translated to Promela.  When SPIN is not installed, the
    adapter gracefully reports 'unavailable'.
    """

    name = "spin"

    def __init__(self, binary: str = "spin") -> None:
        self.binary = binary

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def run_scenario(
        self,
        scenario: dict[str, Any],
        timeout_secs: int,
    ) -> dict[str, Any]:
        tool_cfg = scenario["tool_inputs"].get("spin", {})
        model_file = tool_cfg.get("file")
        if not model_file:
            return _make_result(
                tool="spin",
                scenario_id=scenario["id"],
                status="skip",
                reason="no model file specified for SPIN",
            )
        if not Path(model_file).exists():
            return _make_result(
                tool="spin",
                scenario_id=scenario["id"],
                status="skip",
                reason=f"model file not found: {model_file}",
            )
        cmd_template = tool_cfg.get("command_template")
        if not cmd_template:
            return _make_result(
                tool="spin",
                scenario_id=scenario["id"],
                status="skip",
                reason="no command_template for SPIN",
            )

        cmd_str = cmd_template.format(
            binary=self.binary,
            model_file=model_file,
            scenario_id=scenario["id"],
        )
        cmd = shlex.split(cmd_str)

        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_secs + 30,
            )
            elapsed_ms = (time.monotonic() - t0) * 1000
            verdict = _parse_spin_output(proc.stdout, proc.returncode)
            return _make_result(
                tool="spin",
                scenario_id=scenario["id"],
                status="ok",
                verdict=verdict,
                elapsed_ms=elapsed_ms,
                raw_verdict=proc.stdout.strip()[-200:] if proc.stdout else "",
            )
        except subprocess.TimeoutExpired:
            elapsed_ms = (time.monotonic() - t0) * 1000
            return _make_result(
                tool="spin",
                scenario_id=scenario["id"],
                status="timeout",
                elapsed_ms=elapsed_ms,
            )
        except FileNotFoundError:
            return _make_result(
                tool="spin",
                scenario_id=scenario["id"],
                status="unavailable",
                reason=f"binary '{self.binary}' not found",
            )


# ---------------------------------------------------------------------------
# Verdict normalization helpers
# ---------------------------------------------------------------------------

# Canonical normalized verdicts
NORMALIZED_VERDICTS = {"safe", "unsafe", "timeout", "unknown", "error"}


def _normalize_tarsier_verdict(report: dict[str, Any]) -> str:
    ov = report.get("overall_verdict", "").lower()
    if ov in ("safe", "proved", "live_proved"):
        return "safe"
    if ov in ("unsafe", "counterexample"):
        return "unsafe"
    if ov in ("timeout",):
        return "timeout"
    return "unknown"


def _parse_bymc_output(stdout: str, returncode: int) -> str:
    lower = stdout.lower()
    # Real ByMC output patterns (from schemaCheckerPlugin.ml)
    if "holds" in lower and "spec" in lower:
        return "safe"
    if "slps:" in lower and "verified" in lower:
        return "safe"
    if "slps:" in lower and "counterexample" in lower:
        return "unsafe"
    # Mock adapter patterns (backward compatibility)
    if "no error found" in lower or "property satisfied" in lower:
        return "safe"
    if "error found" in lower or "counterexample" in lower or "violated" in lower:
        return "unsafe"
    if returncode != 0:
        return "error"
    return "unknown"


def _parse_spin_output(stdout: str, returncode: int) -> str:
    lower = stdout.lower()
    if "errors: 0" in lower:
        return "safe"
    if "error" in lower and "errors: 0" not in lower:
        return "unsafe"
    if returncode != 0:
        return "error"
    return "unknown"


# ---------------------------------------------------------------------------
# Result builder
# ---------------------------------------------------------------------------

def _make_result(
    tool: str,
    scenario_id: str,
    status: str,
    verdict: str = "unknown",
    elapsed_ms: float = 0.0,
    reason: str = "",
    raw_verdict: str = "",
    details: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    r: dict[str, Any] = {
        "tool": tool,
        "scenario_id": scenario_id,
        "status": status,
        "normalized_verdict": verdict if status == "ok" else status,
        "elapsed_ms": round(elapsed_ms, 3),
    }
    if reason:
        r["reason"] = reason
    if raw_verdict:
        r["raw_verdict"] = raw_verdict
    if details:
        r["details"] = details
    return r


# ---------------------------------------------------------------------------
# Assumption normalization
# ---------------------------------------------------------------------------

def normalize_assumptions(scenario: dict[str, Any]) -> dict[str, Any]:
    """Extract and normalize the assumptions section for apples-to-apples
    comparison across tools."""
    assumptions = scenario.get("assumptions", {})
    return {
        "fault_model": assumptions.get("fault_model", "unknown"),
        "fault_bound": assumptions.get("fault_bound", "unknown"),
        "network_model": assumptions.get("network", "unknown"),
        "message_loss": assumptions.get("message_loss", False),
        "property": scenario.get("property", "unknown"),
        "property_description": scenario.get("property_description", ""),
        "expected_verdict": scenario.get("expected_verdict", "unknown"),
    }


# ---------------------------------------------------------------------------
# Comparison report builder
# ---------------------------------------------------------------------------

def build_comparison_entry(
    scenario: dict[str, Any],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a per-scenario comparison entry with normalized assumptions
    and apples-to-apples metrics."""
    assumptions = normalize_assumptions(scenario)
    expected = scenario.get("expected_verdict", "unknown")

    tool_results: dict[str, Any] = {}
    for r in results:
        tool_name = r["tool"]
        tool_results[tool_name] = {
            "status": r["status"],
            "normalized_verdict": r["normalized_verdict"],
            "elapsed_ms": r["elapsed_ms"],
            "matches_expected": r.get("normalized_verdict") == expected if r["status"] == "ok" else None,
        }
        # Propagate execution_mode: prefer adapter override, fall back to manifest
        tool_cfg = scenario.get("tool_inputs", {}).get(tool_name, {})
        exec_mode = r.get("execution_mode_override") or tool_cfg.get("execution_mode", "unknown")
        tool_results[tool_name]["execution_mode"] = exec_mode
        if r.get("raw_verdict"):
            tool_results[tool_name]["raw_verdict"] = r["raw_verdict"]
        if r.get("details"):
            tool_results[tool_name]["details"] = r["details"]
        if r.get("reason"):
            tool_results[tool_name]["reason"] = r["reason"]

    # Determine agreement across tools that produced a verdict
    ok_verdicts = [r["normalized_verdict"] for r in results if r["status"] == "ok"]
    if len(ok_verdicts) >= 2:
        agreement = len(set(ok_verdicts)) == 1
    else:
        agreement = None  # not enough tools for comparison

    return {
        "scenario_id": scenario["id"],
        "scenario_name": scenario.get("name", scenario["id"]),
        "protocol_family": scenario.get("protocol_family", ""),
        "normalized_assumptions": assumptions,
        "expected_verdict": expected,
        "tool_results": tool_results,
        "tools_agree": agreement,
    }


def build_report(
    manifest: dict[str, Any],
    comparisons: list[dict[str, Any]],
    tools_used: list[str],
    tools_available: dict[str, bool],
    started_at: str,
    finished_at: str,
    elapsed_ms: float,
) -> dict[str, Any]:
    """Build the top-level cross-tool benchmark report."""
    total = len(comparisons)
    agreed = sum(1 for c in comparisons if c["tools_agree"] is True)
    disagreed = sum(1 for c in comparisons if c["tools_agree"] is False)
    not_comparable = sum(1 for c in comparisons if c["tools_agree"] is None)

    # Collect execution modes used across all scenarios
    execution_modes: dict[str, set[str]] = {}
    for c in comparisons:
        for tool_name, tr in c.get("tool_results", {}).items():
            mode = tr.get("execution_mode", "unknown")
            execution_modes.setdefault(tool_name, set()).add(mode)
    execution_modes_summary = {
        tool: sorted(modes) for tool, modes in execution_modes.items()
    }

    return {
        "schema_version": 1,
        "report_type": "cross_tool_benchmark",
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "elapsed_ms": round(elapsed_ms, 3),
        "environment": {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
        },
        "tools": {
            "requested": tools_used,
            "available": tools_available,
            "execution_modes": execution_modes_summary,
        },
        "summary": {
            "total_scenarios": total,
            "tools_agree": agreed,
            "tools_disagree": disagreed,
            "not_comparable": not_comparable,
        },
        "scenarios": comparisons,
    }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, type[ToolAdapter]] = {
    "tarsier": TarsierAdapter,
    "bymc": BymcAdapter,
    "spin": SpinAdapter,
}


def get_adapter(name: str, **kwargs: Any) -> ToolAdapter:
    cls = TOOL_REGISTRY.get(name)
    if cls is None:
        raise ValueError(f"Unknown tool: {name}. Available: {sorted(TOOL_REGISTRY)}")
    return cls(**kwargs)


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_cross_tool_benchmark(
    manifest_path: str,
    tools: list[str],
    timeout_secs: int = 120,
    tarsier_binary: str = "target/debug/tarsier",
    bymc_binary: str = "bymc",
    spin_binary: str = "spin",
    bymc_mode: str = "mock",
    skip_unavailable: bool = True,
) -> dict[str, Any]:
    """Execute all scenarios from the manifest across all requested tools."""
    with open(manifest_path) as f:
        manifest = json.load(f)

    scenarios = manifest.get("scenarios", [])
    if not scenarios:
        raise ValueError(f"No scenarios in manifest {manifest_path}")

    # Instantiate adapters
    adapters: list[ToolAdapter] = []
    tools_available: dict[str, bool] = {}
    for tool_name in tools:
        kwargs: dict[str, Any] = {}
        if tool_name == "tarsier":
            kwargs["binary"] = tarsier_binary
        elif tool_name == "bymc":
            kwargs["binary"] = bymc_binary
            kwargs["mode"] = bymc_mode
        elif tool_name == "spin":
            kwargs["binary"] = spin_binary
        adapter = get_adapter(tool_name, **kwargs)
        available = adapter.is_available()
        tools_available[tool_name] = available
        if available or not skip_unavailable:
            adapters.append(adapter)

    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    t0 = time.monotonic()

    comparisons: list[dict[str, Any]] = []
    for scenario in scenarios:
        results: list[dict[str, Any]] = []
        for adapter in adapters:
            if adapter.is_available():
                result = adapter.run_scenario(scenario, timeout_secs)
            else:
                result = _make_result(
                    tool=adapter.name,
                    scenario_id=scenario["id"],
                    status="unavailable",
                    reason=f"{adapter.name} not installed",
                )
            results.append(result)
        entry = build_comparison_entry(scenario, results)
        comparisons.append(entry)

    elapsed_ms = (time.monotonic() - t0) * 1000
    finished_at = dt.datetime.now(dt.timezone.utc).isoformat()

    return build_report(
        manifest=manifest,
        comparisons=comparisons,
        tools_used=tools,
        tools_available=tools_available,
        started_at=started_at,
        finished_at=finished_at,
        elapsed_ms=elapsed_ms,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run cross-tool benchmark scenarios and produce a normalized comparison report."
    )
    parser.add_argument(
        "--manifest",
        default="benchmarks/cross_tool_scenarios/scenario_manifest.json",
        help="Path to scenario manifest JSON.",
    )
    parser.add_argument(
        "--tools",
        default="tarsier,bymc",
        help="Comma-separated list of tools to run (default: tarsier,bymc).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Per-scenario timeout in seconds (default: 120).",
    )
    parser.add_argument(
        "--tarsier-binary",
        default="target/debug/tarsier",
        help="Path to tarsier binary (default: target/debug/tarsier).",
    )
    parser.add_argument(
        "--bymc-binary",
        default=sys.executable,
        help=(
            "ByMC executable to use for command templates. "
            "Defaults to current Python interpreter for reproducible mock scenarios."
        ),
    )
    parser.add_argument(
        "--spin-binary",
        default=sys.executable,
        help=(
            "SPIN executable to use for command templates. "
            "Defaults to current Python interpreter for reproducible mock scenarios."
        ),
    )
    parser.add_argument(
        "--bymc-mode",
        choices=["mock", "real"],
        default="mock",
        help="ByMC execution mode: mock (default) or real (uses real ByMC).",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Output report path. Default: benchmarks/results/cross-tool-<timestamp>.json",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip cargo build before running.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.skip_build:
        print("Building tarsier-cli ...", flush=True)
        subprocess.run(
            ["cargo", "build", "-p", "tarsier-cli"],
            check=True,
            env={**os.environ, "CMAKE_POLICY_VERSION_MINIMUM": "3.5"},
        )

    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    if len(tools) < 2:
        print(f"Warning: only {len(tools)} tool(s) requested. Cross-tool comparison requires >= 2.", file=sys.stderr)

    report = run_cross_tool_benchmark(
        manifest_path=args.manifest,
        tools=tools,
        timeout_secs=args.timeout,
        tarsier_binary=args.tarsier_binary,
        bymc_binary=args.bymc_binary,
        spin_binary=args.spin_binary,
        bymc_mode=args.bymc_mode,
    )

    if args.out:
        out_path = args.out
    else:
        ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
        out_path = f"benchmarks/results/cross-tool-{ts}.json"

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Cross-tool benchmark report written to {out_path}")

    # Print summary
    summary = report["summary"]
    print(f"\nSummary: {summary['total_scenarios']} scenarios")
    print(f"  Agree:          {summary['tools_agree']}")
    print(f"  Disagree:       {summary['tools_disagree']}")
    print(f"  Not comparable: {summary['not_comparable']}")

    tools_info = report["tools"]
    for tool, avail in tools_info["available"].items():
        status = "available" if avail else "NOT available"
        print(f"  {tool}: {status}")


if __name__ == "__main__":
    main()
