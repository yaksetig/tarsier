#!/usr/bin/env python3
"""Tests for statistical performance regression gating (P1-13).

Validates:
- AC1: CI perf gate uses statistical thresholding, not single-run noise.
- AC2: Regression report includes baseline, delta, confidence decision.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Import the benchmark module's statistical functions directly.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_library_bench import (
    bootstrap_median_delta_ci,
    bootstrap_total_delta_ci,
    evaluate_perf_budget,
    median,
    quantile,
)


# ---------------------------------------------------------------------------
# AC1: Statistical thresholding (not single-run noise)
# ---------------------------------------------------------------------------


def test_bootstrap_ci_returns_confidence_interval():
    """Bootstrap CI produces (low, high) bounds for median delta."""
    current = [100.0, 105.0, 110.0, 108.0, 102.0]
    baseline = [90.0, 92.0, 95.0, 88.0, 91.0]
    low, high = bootstrap_median_delta_ci(current, baseline, 0.95, 2000, 1337)
    assert isinstance(low, float)
    assert isinstance(high, float)
    assert low <= high, f"CI must satisfy low <= high: {low} vs {high}"
    # Median delta is ~13ms; both bounds should be positive for this clear gap
    assert low > 0, f"With clear regression, CI low should be positive: {low}"


def test_bootstrap_ci_deterministic_with_seed():
    """Same seed produces identical CI bounds (deterministic)."""
    current = [100.0, 110.0, 105.0]
    baseline = [90.0, 95.0, 92.0]
    a = bootstrap_median_delta_ci(current, baseline, 0.95, 2000, 42)
    b = bootstrap_median_delta_ci(current, baseline, 0.95, 2000, 42)
    assert a == b, f"Same seed must produce identical results: {a} vs {b}"


def test_bootstrap_ci_empty_samples():
    """Empty samples produce (0, 0) without crashing."""
    assert bootstrap_median_delta_ci([], [1.0], 0.95, 200, 0) == (0.0, 0.0)
    assert bootstrap_median_delta_ci([1.0], [], 0.95, 200, 0) == (0.0, 0.0)


def test_bootstrap_ci_no_regression_includes_zero():
    """When current ≈ baseline, CI should include zero."""
    same = [100.0, 101.0, 99.0, 100.5, 100.2]
    low, high = bootstrap_median_delta_ci(same, same, 0.95, 2000, 1337)
    assert low <= 0.0 <= high, f"No-regression CI should include zero: [{low}, {high}]"


def test_statistics_enabled_in_budget():
    """Budget files declare statistics.enabled = true for CI gates."""
    budgets_dir = Path(__file__).resolve().parent / "budgets"
    for budget_file in budgets_dir.glob("*.json"):
        budget = json.loads(budget_file.read_text(encoding="utf-8"))
        stats = budget.get("statistics", {})
        assert stats.get("enabled") is True, (
            f"{budget_file.name}: statistics.enabled must be true"
        )
        assert isinstance(stats.get("confidence"), (int, float)), (
            f"{budget_file.name}: statistics.confidence must be numeric"
        )
        assert isinstance(stats.get("bootstrap_samples"), int), (
            f"{budget_file.name}: statistics.bootstrap_samples must be int"
        )


# ---------------------------------------------------------------------------
# AC2: Regression report includes baseline, delta, confidence decision
# ---------------------------------------------------------------------------


def test_perf_gate_report_structure():
    """evaluate_perf_budget returns report with baseline, delta, confidence fields."""
    budget = {
        "statistics": {
            "enabled": True,
            "confidence": 0.95,
            "bootstrap_samples": 500,
            "min_samples": 3,
            "seed": 1337,
        },
        "baseline": {
            "total_elapsed_ms": 300.0,
            "protocol_elapsed_ms": {
                "proto_a": 100.0,
                "proto_b": 200.0,
            },
            "protocol_elapsed_samples_ms": {
                "proto_a": [98.0, 100.0, 102.0],
                "proto_b": [195.0, 200.0, 205.0],
            },
        },
        "thresholds": {
            "per_protocol_regression_pct": 50.0,
            "per_protocol_regression_ms": 100.0,
            "min_regressed_protocols": 1,
            "total_elapsed_regression_pct": 40.0,
            "total_elapsed_regression_ms": 500.0,
        },
        "hard_limits": {},
    }
    runs = [
        {"protocol": "proto_a", "elapsed_ms": 105.0, "samples_ms": [103.0, 105.0, 107.0]},
        {"protocol": "proto_b", "elapsed_ms": 210.0, "samples_ms": [208.0, 210.0, 212.0]},
    ]
    report = evaluate_perf_budget(runs, budget)

    # Structure: enabled, passed, baseline, current, statistics, regressed_protocols
    assert report["enabled"] is True
    assert "passed" in report
    assert "baseline" in report
    assert "current" in report
    assert "statistics" in report
    assert "regressed_protocols" in report
    assert "total_regression" in report

    # Baseline fields
    assert report["baseline"]["total_elapsed_ms"] == 300.0
    assert report["baseline"]["protocols_with_baseline"] == 2

    # Current fields
    assert report["current"]["protocols_measured"] == 2
    assert report["current"]["total_elapsed_ms"] > 0

    # Statistics fields
    assert report["statistics"]["enabled"] is True
    assert report["statistics"]["confidence"] == 0.95
    assert report["statistics"]["bootstrap_samples"] == 500
    assert isinstance(report["statistics"]["checked_protocols"], int)
    assert isinstance(report["statistics"]["significant_protocols"], int)

    # Total regression includes delta + statistics
    assert "delta_ms" in report["total_regression"]
    assert "delta_pct" in report["total_regression"]
    assert "significant" in report["total_regression"]
    assert "statistics" in report["total_regression"]
    total_stats = report["total_regression"]["statistics"]
    assert total_stats["used"] is True
    assert "delta_ci_ms" in total_stats


def test_perf_gate_no_regression_passes():
    """When current ≈ baseline, gate should pass."""
    budget = {
        "statistics": {"enabled": True, "confidence": 0.95, "bootstrap_samples": 500, "min_samples": 3, "seed": 1337},
        "baseline": {
            "total_elapsed_ms": 100.0,
            "protocol_elapsed_ms": {"p": 100.0},
            "protocol_elapsed_samples_ms": {"p": [98.0, 100.0, 102.0]},
        },
        "thresholds": {
            "per_protocol_regression_pct": 50.0,
            "per_protocol_regression_ms": 100.0,
            "min_regressed_protocols": 1,
            "total_elapsed_regression_pct": 40.0,
            "total_elapsed_regression_ms": 200.0,
        },
        "hard_limits": {},
    }
    runs = [{"protocol": "p", "elapsed_ms": 101.0, "samples_ms": [99.0, 101.0, 103.0]}]
    report = evaluate_perf_budget(runs, budget)
    assert report["passed"] is True, f"No regression should pass: {report['reasons']}"


def test_perf_gate_large_regression_fails():
    """When current >> baseline and statistically significant, gate should fail."""
    budget = {
        "statistics": {"enabled": True, "confidence": 0.95, "bootstrap_samples": 500, "min_samples": 3, "seed": 1337},
        "baseline": {
            "total_elapsed_ms": 100.0,
            "protocol_elapsed_ms": {"p": 100.0},
            "protocol_elapsed_samples_ms": {"p": [98.0, 100.0, 102.0]},
        },
        "thresholds": {
            "per_protocol_regression_pct": 50.0,
            "per_protocol_regression_ms": 100.0,
            "min_regressed_protocols": 1,
            "total_elapsed_regression_pct": 40.0,
            "total_elapsed_regression_ms": 100.0,
        },
        "hard_limits": {},
    }
    # 3x regression
    runs = [{"protocol": "p", "elapsed_ms": 300.0, "samples_ms": [295.0, 300.0, 305.0]}]
    report = evaluate_perf_budget(runs, budget)
    assert report["passed"] is False, "3x regression should fail"
    assert len(report["regressed_protocols"]) >= 1
    proto = report["regressed_protocols"][0]
    assert proto["baseline_ms"] > 0
    assert proto["delta_ms"] > 0
    assert proto["delta_pct"] > 0
    assert proto["statistics"]["used"] is True
    assert proto["statistics"]["significant"] is True
    assert "delta_ci_ms" in proto["statistics"]
    assert len(proto["statistics"]["delta_ci_ms"]) == 2


def test_perf_gate_regressed_protocol_has_confidence_fields():
    """Each regressed protocol entry includes per-protocol confidence decision."""
    budget = {
        "statistics": {"enabled": True, "confidence": 0.90, "bootstrap_samples": 300, "min_samples": 3, "seed": 42},
        "baseline": {
            "total_elapsed_ms": 50.0,
            "protocol_elapsed_ms": {"q": 50.0},
            "protocol_elapsed_samples_ms": {"q": [48.0, 50.0, 52.0]},
        },
        "thresholds": {
            "per_protocol_regression_pct": 30.0,
            "per_protocol_regression_ms": 20.0,
            "min_regressed_protocols": 1,
            "total_elapsed_regression_pct": 30.0,
            "total_elapsed_regression_ms": 20.0,
        },
        "hard_limits": {},
    }
    runs = [{"protocol": "q", "elapsed_ms": 200.0, "samples_ms": [195.0, 200.0, 205.0]}]
    report = evaluate_perf_budget(runs, budget)
    assert len(report["regressed_protocols"]) >= 1
    proto = report["regressed_protocols"][0]
    stats = proto["statistics"]
    assert stats["used"] is True
    assert "confidence" in stats
    assert stats["confidence"] == 0.90
    assert "delta_ci_ms" in stats
    assert isinstance(stats["delta_ci_ms"], list)
    assert "significant" in stats


def test_total_regression_uses_bootstrap_ci():
    """Total regression decision uses bootstrap CI, not raw delta."""
    budget = {
        "statistics": {"enabled": True, "confidence": 0.95, "bootstrap_samples": 500, "min_samples": 3, "seed": 1337},
        "baseline": {
            "total_elapsed_ms": 200.0,
            "protocol_elapsed_ms": {"a": 100.0, "b": 100.0},
            "protocol_elapsed_samples_ms": {
                "a": [98.0, 100.0, 102.0],
                "b": [98.0, 100.0, 102.0],
            },
        },
        "thresholds": {
            "per_protocol_regression_pct": 200.0,
            "per_protocol_regression_ms": 500.0,
            "min_regressed_protocols": 1,
            "total_elapsed_regression_pct": 40.0,
            "total_elapsed_regression_ms": 100.0,
        },
        "hard_limits": {},
    }
    # 3x total regression — clearly significant
    runs = [
        {"protocol": "a", "elapsed_ms": 300.0, "samples_ms": [295.0, 300.0, 305.0]},
        {"protocol": "b", "elapsed_ms": 300.0, "samples_ms": [295.0, 300.0, 305.0]},
    ]
    report = evaluate_perf_budget(runs, budget)
    total = report["total_regression"]
    assert total["statistics"]["used"] is True, "total regression must use bootstrap CI"
    assert total["statistics"]["significant"] is True
    assert "delta_ci_ms" in total["statistics"]
    assert len(total["statistics"]["delta_ci_ms"]) == 2
    assert total["statistics"]["confidence"] == 0.95


def test_total_regression_no_regression_ci_not_significant():
    """When total is near baseline, bootstrap CI should not flag it as significant."""
    budget = {
        "statistics": {"enabled": True, "confidence": 0.95, "bootstrap_samples": 500, "min_samples": 3, "seed": 1337},
        "baseline": {
            "total_elapsed_ms": 200.0,
            "protocol_elapsed_ms": {"a": 100.0, "b": 100.0},
            "protocol_elapsed_samples_ms": {
                "a": [98.0, 100.0, 102.0],
                "b": [98.0, 100.0, 102.0],
            },
        },
        "thresholds": {
            "per_protocol_regression_pct": 200.0,
            "per_protocol_regression_ms": 500.0,
            "min_regressed_protocols": 1,
            "total_elapsed_regression_pct": 40.0,
            "total_elapsed_regression_ms": 100.0,
        },
        "hard_limits": {},
    }
    # Tiny delta — should NOT be significant
    runs = [
        {"protocol": "a", "elapsed_ms": 101.0, "samples_ms": [99.0, 101.0, 103.0]},
        {"protocol": "b", "elapsed_ms": 101.0, "samples_ms": [99.0, 101.0, 103.0]},
    ]
    report = evaluate_perf_budget(runs, budget)
    total = report["total_regression"]
    assert total["statistics"]["used"] is True, "total regression should use bootstrap"
    assert total["significant"] is False, (
        f"No-regression total should not be significant: {total}"
    )


def test_bootstrap_total_delta_ci_basic():
    """bootstrap_total_delta_ci returns valid CI for sum-of-medians delta."""
    pairs = [
        ([100.0, 105.0, 110.0], [90.0, 92.0, 95.0]),
        ([200.0, 210.0, 205.0], [190.0, 195.0, 192.0]),
    ]
    low, high = bootstrap_total_delta_ci(pairs, 0.95, 2000, 1337)
    assert low <= high, f"CI bounds inverted: {low} > {high}"
    # Total point delta is ~(105-92) + (205-192) = 26; CI should include it
    assert low > 0, f"Clear regression total CI low should be positive: {low}"


def test_bootstrap_total_delta_ci_empty():
    """Empty pairs produce (0, 0)."""
    assert bootstrap_total_delta_ci([], 0.95, 200, 0) == (0.0, 0.0)


def test_statistics_disabled_skips_bootstrap():
    """When statistics.enabled is false, bootstrap is not used."""
    budget = {
        "statistics": {"enabled": False},
        "baseline": {
            "total_elapsed_ms": 100.0,
            "protocol_elapsed_ms": {"p": 100.0},
        },
        "thresholds": {
            "per_protocol_regression_pct": 50.0,
            "per_protocol_regression_ms": 100.0,
            "min_regressed_protocols": 1,
            "total_elapsed_regression_pct": 40.0,
            "total_elapsed_regression_ms": 100.0,
        },
        "hard_limits": {},
    }
    runs = [{"protocol": "p", "elapsed_ms": 300.0, "samples_ms": [295.0, 300.0, 305.0]}]
    report = evaluate_perf_budget(runs, budget)
    assert report["statistics"]["enabled"] is False
    assert report["statistics"]["checked_protocols"] == 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_quantile_basic():
    assert quantile([1.0, 2.0, 3.0, 4.0, 5.0], 0.5) == 3.0
    assert quantile([10.0], 0.5) == 10.0


def test_median_basic():
    assert median([3.0, 1.0, 2.0]) == 2.0
    assert median([]) == 0.0


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def main() -> int:
    tests = [
        test_bootstrap_ci_returns_confidence_interval,
        test_bootstrap_ci_deterministic_with_seed,
        test_bootstrap_ci_empty_samples,
        test_bootstrap_ci_no_regression_includes_zero,
        test_statistics_enabled_in_budget,
        test_perf_gate_report_structure,
        test_perf_gate_no_regression_passes,
        test_perf_gate_large_regression_fails,
        test_perf_gate_regressed_protocol_has_confidence_fields,
        test_total_regression_uses_bootstrap_ci,
        test_total_regression_no_regression_ci_not_significant,
        test_bootstrap_total_delta_ci_basic,
        test_bootstrap_total_delta_ci_empty,
        test_statistics_disabled_skips_bootstrap,
        test_quantile_basic,
        test_median_basic,
    ]
    passed = 0
    failed = 0
    for test_fn in tests:
        try:
            test_fn()
            print(f"  PASS  {test_fn.__name__}")
            passed += 1
        except Exception as exc:
            print(f"  FAIL  {test_fn.__name__}: {exc}")
            failed += 1
    print(f"\n{passed}/{passed + failed} tests passed.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
