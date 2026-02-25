#!/usr/bin/env python3
"""Validate cross-tool external execution report.

Contract:
- Report must include at least one scenario.
- For every scenario, both external tools (`bymc`, `spin`) must run with status=ok.
- Scenario must be apples-to-apples comparable (`tools_agree` is boolean).
- Normalized assumptions must include core fields.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def fail(msg: str) -> int:
    print(f"Cross-tool external execution check FAILED: {msg}")
    return 1


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_cross_tool_external_execution.py <report.json>")
        return 2

    report_path = Path(sys.argv[1])
    if not report_path.exists():
        return fail(f"report file does not exist: {report_path}")

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return fail(f"invalid JSON in {report_path}: {exc}")

    scenarios = report.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        return fail("report.scenarios must be a non-empty list")

    for entry in scenarios:
        sid = entry.get("scenario_id", "<unknown>")
        tool_results = entry.get("tool_results", {})
        for tool in ("bymc", "spin"):
            tool_entry = tool_results.get(tool)
            if not isinstance(tool_entry, dict):
                return fail(f"scenario {sid} missing tool_results.{tool}")
            if tool_entry.get("status") != "ok":
                return fail(
                    f"scenario {sid} tool {tool} status must be ok, got {tool_entry.get('status')!r}"
                )

        tools_agree = entry.get("tools_agree")
        if not isinstance(tools_agree, bool):
            return fail(
                f"scenario {sid} tools_agree must be boolean when two external verdicts exist"
            )

        assumptions = entry.get("normalized_assumptions", {})
        for key in ("fault_model", "fault_bound", "network_model", "message_loss", "property"):
            if key not in assumptions:
                return fail(f"scenario {sid} missing normalized_assumptions.{key}")

    print(
        "Cross-tool external execution check passed "
        f"({len(scenarios)} scenarios with bymc+spin status=ok)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
