#!/usr/bin/env python3
"""Validate cross-tool external execution report.

Contract:
- Report must include at least one scenario.
- For every scenario, all required tools must run with status=ok.
- Selected tools may be required to run with `execution_mode=real`.
- Scenario must be apples-to-apples comparable (`tools_agree` is boolean).
- Normalized assumptions must include core fields.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def fail(msg: str) -> int:
    print(f"Cross-tool external execution check FAILED: {msg}")
    return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate cross-tool external execution report contract."
    )
    parser.add_argument("report", help="Path to cross-tool benchmark report JSON.")
    parser.add_argument(
        "--required-tools",
        default="bymc,spin",
        help="Comma-separated tools that must be present with status=ok in each scenario.",
    )
    parser.add_argument(
        "--require-real-tools",
        default="",
        help="Comma-separated tools that must report execution_mode=real in each scenario.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report_path = Path(args.report)
    if not report_path.exists():
        return fail(f"report file does not exist: {report_path}")

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return fail(f"invalid JSON in {report_path}: {exc}")

    scenarios = report.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        return fail("report.scenarios must be a non-empty list")

    required_tools = [t.strip() for t in args.required_tools.split(",") if t.strip()]
    require_real_tools = [t.strip() for t in args.require_real_tools.split(",") if t.strip()]
    for tool in require_real_tools:
        if tool not in required_tools:
            required_tools.append(tool)

    for entry in scenarios:
        sid = entry.get("scenario_id", "<unknown>")
        tool_results = entry.get("tool_results", {})
        for tool in required_tools:
            tool_entry = tool_results.get(tool)
            if not isinstance(tool_entry, dict):
                return fail(f"scenario {sid} missing tool_results.{tool}")
            if tool_entry.get("status") != "ok":
                return fail(
                    f"scenario {sid} tool {tool} status must be ok, got {tool_entry.get('status')!r}"
                )
            if tool in require_real_tools and tool_entry.get("execution_mode") != "real":
                return fail(
                    f"scenario {sid} tool {tool} must run in execution_mode=real, got "
                    f"{tool_entry.get('execution_mode')!r}"
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
        f"({len(scenarios)} scenarios, required_tools={required_tools}, "
        f"require_real_tools={require_real_tools})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
