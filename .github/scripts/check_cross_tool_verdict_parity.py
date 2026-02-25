#!/usr/bin/env python3
"""Verify verdict parity across tools in a cross-tool benchmark report.

Loads a cross-tool report JSON, prints a parity table, and fails if any
non-mock tool pair disagrees on a verdict.

Usage:
    python3 .github/scripts/check_cross_tool_verdict_parity.py <report.json>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: check_cross_tool_verdict_parity.py <report.json>", file=sys.stderr)
        sys.exit(1)

    report_path = Path(sys.argv[1])
    if not report_path.exists():
        print(f"Report file not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    with open(report_path) as f:
        report = json.load(f)

    scenarios = report.get("scenarios", [])
    if not scenarios:
        print("No scenarios in report.", file=sys.stderr)
        sys.exit(1)

    failures: list[str] = []

    # Print parity table header
    print(f"{'Scenario':<45} {'Expected':<10}", end="")
    # Collect all tool names
    all_tools: list[str] = []
    for s in scenarios:
        for t in s.get("tool_results", {}):
            if t not in all_tools:
                all_tools.append(t)
    for t in all_tools:
        print(f" {t:<12}", end="")
    print(f" {'Agree':<8}")
    print("-" * (45 + 10 + 12 * len(all_tools) + 8))

    for s in scenarios:
        sid = s["scenario_id"]
        expected = s.get("expected_verdict", "?")
        print(f"{sid:<45} {expected:<10}", end="")

        verdicts_for_parity: dict[str, str] = {}
        for t in all_tools:
            tr = s.get("tool_results", {}).get(t, {})
            status = tr.get("status", "?")
            verdict = tr.get("normalized_verdict", "?")
            mode = tr.get("execution_mode", "?")
            display = f"{verdict}({mode[0]})" if mode != "?" else verdict
            print(f" {display:<12}", end="")

            # Only include tools with ok status for parity check
            if status == "ok":
                verdicts_for_parity[t] = verdict

        # Check parity: all ok tools should agree
        unique_verdicts = set(verdicts_for_parity.values())
        if len(unique_verdicts) <= 1:
            agree_str = "yes" if len(verdicts_for_parity) >= 2 else "n/a"
        else:
            agree_str = "NO"
            # Only fail for non-mock disagreements
            non_mock_verdicts: dict[str, str] = {}
            for t, v in verdicts_for_parity.items():
                tr = s.get("tool_results", {}).get(t, {})
                if tr.get("execution_mode") != "mock":
                    non_mock_verdicts[t] = v
            if len(set(non_mock_verdicts.values())) > 1:
                failures.append(
                    f"{sid}: non-mock tools disagree: "
                    + ", ".join(f"{t}={v}" for t, v in non_mock_verdicts.items())
                )

        print(f" {agree_str:<8}")

    print()
    if failures:
        print("VERDICT PARITY CHECK FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("Verdict parity check passed.")


if __name__ == "__main__":
    main()
