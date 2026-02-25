#!/usr/bin/env python3
"""
CI gate for dynamic ample-set POR diagnostics.

This script reads an `analyze --format json` report and enforces an upper bound
on the dynamic-ample UNSAT recheck SAT rate:

    unsat_recheck_sat_rate = total_unsat_recheck_sat / total_unsat_rechecks

The metric is only enforced when `total_unsat_rechecks >= min_unsat_rechecks`,
so small/no-signal runs do not fail spuriously.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _gather_totals(report: dict[str, Any]) -> tuple[int, int, int, int]:
    total_queries = 0
    total_fast_sat = 0
    total_unsat_rechecks = 0
    total_unsat_recheck_sat = 0

    for layer in report.get("layers", []):
        details = layer.get("details") or {}
        abstractions = details.get("abstractions") or {}
        summary = abstractions.get("por_dynamic_ample")
        if isinstance(summary, dict):
            total_queries += int(summary.get("total_queries", 0) or 0)
            total_fast_sat += int(summary.get("total_fast_sat", 0) or 0)
            total_unsat_rechecks += int(summary.get("total_unsat_rechecks", 0) or 0)
            total_unsat_recheck_sat += int(summary.get("total_unsat_recheck_sat", 0) or 0)
            continue

        # Fallback for older reports without the summary object.
        for profile in abstractions.get("smt_profiles", []):
            total_queries += int(profile.get("por_dynamic_ample_queries", 0) or 0)
            total_fast_sat += int(profile.get("por_dynamic_ample_fast_sat", 0) or 0)
            total_unsat_rechecks += int(profile.get("por_dynamic_ample_unsat_rechecks", 0) or 0)
            total_unsat_recheck_sat += int(
                profile.get("por_dynamic_ample_unsat_recheck_sat", 0) or 0
            )

    return (
        total_queries,
        total_fast_sat,
        total_unsat_rechecks,
        total_unsat_recheck_sat,
    )


def _ratio(num: int, den: int) -> float:
    if den <= 0:
        return 0.0
    return float(num) / float(den)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="Path to analyze JSON report")
    parser.add_argument(
        "--max-unsat-recheck-sat-rate",
        type=float,
        default=0.20,
        help=(
            "Fail when unsat_recheck_sat_rate exceeds this threshold and "
            "the minimum unsat-recheck count is met."
        ),
    )
    parser.add_argument(
        "--min-unsat-rechecks",
        type=int,
        default=1,
        help="Minimum unsat rechecks required before enforcing the rate gate.",
    )
    args = parser.parse_args()

    report_path = args.report.resolve()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    queries, fast_sat, unsat_rechecks, unsat_recheck_sat = _gather_totals(report)

    fast_sat_rate = _ratio(fast_sat, queries)
    unsat_recheck_rate = _ratio(unsat_rechecks, queries)
    unsat_recheck_sat_rate = _ratio(unsat_recheck_sat, unsat_rechecks)

    print(
        "Dynamic ample summary: "
        f"queries={queries}, fast_sat={fast_sat} ({fast_sat_rate:.3f}), "
        f"unsat_rechecks={unsat_rechecks} ({unsat_recheck_rate:.3f}), "
        f"unsat_recheck_sat={unsat_recheck_sat} ({unsat_recheck_sat_rate:.3f})"
    )

    if unsat_rechecks < args.min_unsat_rechecks:
        print(
            "Dynamic ample gate: SKIP "
            f"(unsat_rechecks={unsat_rechecks} < min_unsat_rechecks={args.min_unsat_rechecks})"
        )
        return 0

    if unsat_recheck_sat_rate > args.max_unsat_recheck_sat_rate:
        print(
            "Dynamic ample gate: FAIL "
            f"(unsat_recheck_sat_rate={unsat_recheck_sat_rate:.3f} > "
            f"max={args.max_unsat_recheck_sat_rate:.3f})"
        )
        return 1

    print(
        "Dynamic ample gate: PASS "
        f"(unsat_recheck_sat_rate={unsat_recheck_sat_rate:.3f} <= "
        f"max={args.max_unsat_recheck_sat_rate:.3f})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
