#!/usr/bin/env python3
"""Run deterministic analysis benchmarks across the protocol library."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import random
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run `tarsier analyze` over a protocol list and write a JSON benchmark report."
    )
    parser.add_argument(
        "--manifest",
        default="examples/library/cert_suite.json",
        help="Path to cert-suite manifest (relative to repo root). Used unless --protocols is set.",
    )
    parser.add_argument(
        "--protocols",
        default="",
        help="Optional newline-separated protocol list (relative to repo root). Overrides --manifest.",
    )
    parser.add_argument(
        "--mode",
        default="standard",
        choices=["quick", "standard", "proof", "audit"],
        help="analyze mode.",
    )
    parser.add_argument("--solver", default="z3", help="Primary solver for analyze.")
    parser.add_argument("--depth", type=int, default=8, help="Bounded depth.")
    parser.add_argument("--k", type=int, default=12, help="Unbounded proof frame/depth bound.")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout (seconds) per layer.")
    parser.add_argument(
        "--soundness",
        default="strict",
        choices=["strict", "permissive"],
        help="Soundness profile for analyze.",
    )
    parser.add_argument(
        "--fairness",
        default="weak",
        choices=["weak", "strong"],
        help="Fairness profile for analyze.",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Output report path. Default: benchmarks/results/library-bench-<timestamp>.json",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip `cargo build -p tarsier-cli` before running.",
    )
    parser.add_argument(
        "--require-pass",
        action="store_true",
        help="Fail when any protocol does not return overall=pass (default only checks run integrity).",
    )
    parser.add_argument(
        "--require-expectations",
        action="store_true",
        help="Fail when manifest expectations (verify/liveness/prove/...) do not match reported layer results.",
    )
    parser.add_argument(
        "--perf-budget",
        default="",
        help=(
            "Optional performance budget JSON. When set, benchmark fails on "
            "configured significant regressions/limits."
        ),
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=1,
        help="Number of timing samples per protocol (median is reported).",
    )
    return parser.parse_args()


def load_protocols(repo_root: Path, protocol_file: Path) -> list[Path]:
    items: list[Path] = []
    raw = protocol_file.read_text(encoding="utf-8")
    for line in raw.splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#"):
            continue
        protocol_path = (repo_root / trimmed).resolve()
        if not protocol_path.exists():
            raise FileNotFoundError(f"Protocol path does not exist: {trimmed}")
        items.append(protocol_path)
    if not items:
        raise ValueError("No protocols found in list.")
    return items


def load_protocol_entries_from_manifest(
    repo_root: Path, manifest_file: Path
) -> list[dict[str, Any]]:
    manifest_obj = json.loads(manifest_file.read_text(encoding="utf-8"))
    entries = manifest_obj.get("entries")
    if not isinstance(entries, list):
        raise ValueError("Manifest does not contain an 'entries' list.")

    out: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Manifest entry must be an object.")
        raw_file = entry.get("file")
        if not isinstance(raw_file, str) or not raw_file.strip():
            raise ValueError("Manifest entry is missing a valid 'file'.")
        protocol_path = (manifest_file.parent / raw_file).resolve()
        if not protocol_path.exists():
            raise FileNotFoundError(f"Protocol path does not exist: {raw_file}")
        configured_checks = [
            name
            for name in ("verify", "liveness", "fair_liveness", "prove", "prove_fair")
            if entry.get(name) is not None
        ]
        expectations = {
            name: str(entry[name]).strip()
            for name in ("verify", "liveness", "fair_liveness", "prove", "prove_fair")
            if isinstance(entry.get(name), str) and str(entry.get(name)).strip()
        }
        proof_engine = (
            str(entry.get("proof_engine", "kinduction")).strip() or "kinduction"
        ).lower()
        out.append(
            {
                "path": protocol_path,
                "file": raw_file,
                "family": entry.get("family"),
                "class": entry.get("class"),
                "checks": configured_checks,
                "expectations": expectations,
                "proof_engine": proof_engine,
            }
        )
    if not out:
        raise ValueError("No protocols found in manifest.")
    return out


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def as_float_list(raw: Any) -> list[float]:
    if not isinstance(raw, list):
        return []
    out: list[float] = []
    for item in raw:
        try:
            out.append(float(item))
        except (TypeError, ValueError):
            continue
    return out


def quantile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    if q <= 0.0:
        return sorted_values[0]
    if q >= 1.0:
        return sorted_values[-1]
    position = (len(sorted_values) - 1) * q
    lo = int(math.floor(position))
    hi = int(math.ceil(position))
    if lo == hi:
        return sorted_values[lo]
    frac = position - lo
    return sorted_values[lo] * (1.0 - frac) + sorted_values[hi] * frac


def median(values: list[float]) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    return quantile(sorted_values, 0.5)


def bootstrap_median_delta_ci(
    current_samples: list[float],
    baseline_samples: list[float],
    confidence: float,
    bootstrap_samples: int,
    seed: int,
) -> tuple[float, float]:
    if not current_samples or not baseline_samples:
        return (0.0, 0.0)
    bootstrap_n = max(200, bootstrap_samples)
    conf = min(max(confidence, 0.50), 0.999)
    rng = random.Random(seed)
    current_len = len(current_samples)
    baseline_len = len(baseline_samples)
    deltas: list[float] = []
    for _ in range(bootstrap_n):
        current_draw = [
            current_samples[rng.randrange(current_len)] for _ in range(current_len)
        ]
        baseline_draw = [
            baseline_samples[rng.randrange(baseline_len)] for _ in range(baseline_len)
        ]
        deltas.append(median(current_draw) - median(baseline_draw))
    deltas.sort()
    alpha = 1.0 - conf
    low = quantile(deltas, alpha / 2.0)
    high = quantile(deltas, 1.0 - (alpha / 2.0))
    return (low, high)


def extract_layer_results(report_obj: dict[str, Any] | None) -> dict[str, str]:
    if not isinstance(report_obj, dict):
        return {}
    layers = report_obj.get("layers")
    if not isinstance(layers, list):
        return {}
    out: dict[str, str] = {}
    for layer in layers:
        if not isinstance(layer, dict):
            continue
        layer_name = layer.get("layer")
        if not isinstance(layer_name, str) or not layer_name:
            continue
        details = layer.get("details")
        if not isinstance(details, dict):
            continue
        result = details.get("result")
        if isinstance(result, str) and result:
            out[layer_name] = result
    return out


def pick_observed_result(
    layer_results: dict[str, str], check_name: str, proof_engine: str
) -> tuple[str | None, str]:
    if check_name == "verify":
        candidates = ["verify", "verify[quick]"]
    elif check_name == "liveness":
        candidates = ["liveness[bounded]"]
    elif check_name == "fair_liveness":
        candidates = ["liveness[fair_lasso]"]
    elif check_name == "prove":
        normalized_engine = proof_engine if proof_engine in ("kinduction", "pdr") else "kinduction"
        candidates = [f"prove[{normalized_engine}]"]
        if normalized_engine != "kinduction":
            candidates.append("prove[kinduction]")
    elif check_name == "prove_fair":
        candidates = ["prove[fair_pdr]"]
    else:
        return None, ""

    for layer_name in candidates:
        observed = layer_results.get(layer_name)
        if observed is not None:
            return observed, layer_name
    return None, candidates[0] if candidates else ""


def evaluate_expectations(
    report_obj: dict[str, Any] | None, entry: dict[str, Any]
) -> dict[str, Any]:
    expectations = entry.get("expectations")
    if not isinstance(expectations, dict) or not expectations:
        return {
            "checked": 0,
            "passed": 0,
            "failed": 0,
            "checks": [],
        }

    layer_results = extract_layer_results(report_obj)
    proof_engine = str(entry.get("proof_engine", "kinduction")).lower()

    checks: list[dict[str, Any]] = []
    failed = 0
    for check_name, expected in expectations.items():
        if not isinstance(expected, str) or not expected:
            continue
        observed, layer = pick_observed_result(layer_results, check_name, proof_engine)
        matched = observed == expected
        if not matched:
            failed += 1
        checks.append(
            {
                "check": check_name,
                "layer": layer,
                "expected": expected,
                "observed": observed,
                "matched": matched,
                "reason": (
                    None
                    if matched
                    else ("layer_missing" if observed is None else "result_mismatch")
                ),
            }
        )

    checked = len(checks)
    return {
        "checked": checked,
        "passed": checked - failed,
        "failed": failed,
        "checks": checks,
    }


def evaluate_perf_budget(
    runs: list[dict[str, Any]], perf_budget: dict[str, Any]
) -> dict[str, Any]:
    thresholds = perf_budget.get("thresholds", {}) if isinstance(perf_budget, dict) else {}
    baseline = perf_budget.get("baseline", {}) if isinstance(perf_budget, dict) else {}
    hard_limits = perf_budget.get("hard_limits", {}) if isinstance(perf_budget, dict) else {}
    statistics_cfg = (
        perf_budget.get("statistics", {}) if isinstance(perf_budget, dict) else {}
    )
    baseline_protocol = (
        baseline.get("protocol_elapsed_ms", {}) if isinstance(baseline, dict) else {}
    )
    baseline_protocol_samples = (
        baseline.get("protocol_elapsed_samples_ms", {}) if isinstance(baseline, dict) else {}
    )
    if not isinstance(baseline_protocol, dict):
        baseline_protocol = {}
    if not isinstance(baseline_protocol_samples, dict):
        baseline_protocol_samples = {}

    per_protocol_pct = float(thresholds.get("per_protocol_regression_pct", 0.0) or 0.0)
    per_protocol_abs_ms = float(thresholds.get("per_protocol_regression_ms", 0.0) or 0.0)
    min_regressed_protocols = int(thresholds.get("min_regressed_protocols", 1) or 1)
    total_pct = float(thresholds.get("total_elapsed_regression_pct", 0.0) or 0.0)
    total_abs_ms = float(thresholds.get("total_elapsed_regression_ms", 0.0) or 0.0)
    statistics_enabled = bool(statistics_cfg.get("enabled", False))
    statistics_confidence = float(statistics_cfg.get("confidence", 0.95) or 0.95)
    statistics_bootstrap_samples = int(
        statistics_cfg.get("bootstrap_samples", 2000) or 2000
    )
    statistics_min_samples = int(statistics_cfg.get("min_samples", 3) or 3)
    statistics_seed = int(statistics_cfg.get("seed", 1337) or 1337)

    baseline_total = float(baseline.get("total_elapsed_ms", 0.0) or 0.0)
    current_total = float(
        sum(
            (
                median(samples)
                if (samples := as_float_list(run.get("samples_ms")))
                else float(run.get("elapsed_ms", 0.0) or 0.0)
            )
            for run in runs
        )
    )

    regressed_protocols: list[dict[str, Any]] = []
    stats_checked = 0
    stats_significant = 0
    for run in runs:
        protocol = str(run.get("protocol", ""))
        if not protocol or (
            protocol not in baseline_protocol and protocol not in baseline_protocol_samples
        ):
            continue
        current_samples = as_float_list(run.get("samples_ms"))
        if not current_samples:
            current_samples = [float(run.get("elapsed_ms", 0.0) or 0.0)]

        baseline_samples = as_float_list(baseline_protocol_samples.get(protocol))
        if not baseline_samples and protocol in baseline_protocol:
            baseline_samples = [float(baseline_protocol.get(protocol, 0.0) or 0.0)]

        current_ms = median(current_samples)
        baseline_ms = median(baseline_samples)
        delta_ms = current_ms - baseline_ms
        pct = 0.0 if baseline_ms <= 0.0 else (delta_ms / baseline_ms) * 100.0

        statistics_entry: dict[str, Any] = {
            "used": False,
            "significant": False,
        }

        significant = delta_ms >= per_protocol_abs_ms and pct >= per_protocol_pct
        if (
            statistics_enabled
            and len(current_samples) >= statistics_min_samples
            and len(baseline_samples) >= statistics_min_samples
        ):
            stats_checked += 1
            protocol_seed = statistics_seed + int(
                hashlib.sha256(protocol.encode("utf-8")).hexdigest()[:8], 16
            )
            ci_low, ci_high = bootstrap_median_delta_ci(
                current_samples=current_samples,
                baseline_samples=baseline_samples,
                confidence=statistics_confidence,
                bootstrap_samples=statistics_bootstrap_samples,
                seed=protocol_seed,
            )
            ci_low_pct = 0.0 if baseline_ms <= 0.0 else (ci_low / baseline_ms) * 100.0
            significant = ci_low >= per_protocol_abs_ms and ci_low_pct >= per_protocol_pct
            if significant:
                stats_significant += 1
            statistics_entry = {
                "used": True,
                "confidence": statistics_confidence,
                "bootstrap_samples": statistics_bootstrap_samples,
                "delta_ci_ms": [ci_low, ci_high],
                "delta_ci_low_pct": ci_low_pct,
                "significant": significant,
            }

        if significant:
            regressed_protocols.append(
                {
                    "protocol": protocol,
                    "baseline_ms": baseline_ms,
                    "current_ms": current_ms,
                    "delta_ms": delta_ms,
                    "delta_pct": pct,
                    "statistics": statistics_entry,
                }
            )

    significant_protocol_regression = len(regressed_protocols) >= min_regressed_protocols
    total_delta_ms = current_total - baseline_total
    total_delta_pct = 0.0 if baseline_total <= 0.0 else (total_delta_ms / baseline_total) * 100.0
    significant_total_regression = (
        total_delta_ms >= total_abs_ms and total_delta_pct >= total_pct
    )

    max_protocol_elapsed_ms = hard_limits.get("max_protocol_elapsed_ms")
    max_total_elapsed_ms = hard_limits.get("max_total_elapsed_ms")
    hard_failures: list[str] = []
    if max_protocol_elapsed_ms is not None:
        max_protocol_elapsed_ms = float(max_protocol_elapsed_ms)
        offenders = [
            {
                "protocol": str(run.get("protocol", "")),
                "elapsed_ms": float(run.get("elapsed_ms", 0.0) or 0.0),
            }
            for run in runs
            if float(run.get("elapsed_ms", 0.0) or 0.0) > max_protocol_elapsed_ms
        ]
        if offenders:
            hard_failures.append(
                f"protocol_elapsed_ms exceeded hard limit ({max_protocol_elapsed_ms})"
            )
    else:
        offenders = []
    if max_total_elapsed_ms is not None and current_total > float(max_total_elapsed_ms):
        hard_failures.append(
            f"total_elapsed_ms exceeded hard limit ({float(max_total_elapsed_ms)})"
        )

    passed = not (
        significant_protocol_regression or significant_total_regression or hard_failures
    )
    reasons: list[str] = []
    if significant_protocol_regression:
        reasons.append(
            "significant per-protocol regression threshold crossed"
        )
    if significant_total_regression:
        reasons.append("significant total elapsed regression threshold crossed")
    reasons.extend(hard_failures)

    return {
        "enabled": True,
        "passed": passed,
        "reasons": reasons,
        "statistics": {
            "enabled": statistics_enabled,
            "confidence": statistics_confidence,
            "bootstrap_samples": statistics_bootstrap_samples,
            "min_samples": statistics_min_samples,
            "checked_protocols": stats_checked,
            "significant_protocols": stats_significant,
        },
        "thresholds": {
            "per_protocol_regression_pct": per_protocol_pct,
            "per_protocol_regression_ms": per_protocol_abs_ms,
            "min_regressed_protocols": min_regressed_protocols,
            "total_elapsed_regression_pct": total_pct,
            "total_elapsed_regression_ms": total_abs_ms,
        },
        "baseline": {
            "total_elapsed_ms": baseline_total,
            "protocols_with_baseline": len(baseline_protocol),
            "protocols_with_sample_baseline": len(baseline_protocol_samples),
        },
        "current": {
            "total_elapsed_ms": current_total,
            "protocols_measured": len(runs),
        },
        "regressed_protocol_count": len(regressed_protocols),
        "regressed_protocols": sorted(
            regressed_protocols, key=lambda item: float(item["delta_ms"]), reverse=True
        ),
        "total_regression": {
            "delta_ms": total_delta_ms,
            "delta_pct": total_delta_pct,
            "significant": significant_total_regression,
        },
        "hard_limit_offenders": offenders,
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    protocol_entries: list[dict[str, Any]]
    source_label: str
    if args.protocols:
        protocol_list_file = (repo_root / args.protocols).resolve()
        protocols = load_protocols(repo_root, protocol_list_file)
        protocol_entries = [
            {"path": path, "file": path.relative_to(repo_root).as_posix()}
            for path in protocols
        ]
        source_label = str(Path(args.protocols))
    else:
        manifest_file = (repo_root / args.manifest).resolve()
        protocol_entries = load_protocol_entries_from_manifest(repo_root, manifest_file)
        source_label = str(Path(args.manifest))

    if not args.skip_build:
        build = run(["cargo", "build", "-q", "-p", "tarsier-cli"], repo_root)
        if build.returncode != 0:
            sys.stderr.write("Failed to build tarsier-cli.\n")
            if build.stdout:
                sys.stderr.write(build.stdout)
            if build.stderr:
                sys.stderr.write(build.stderr)
            return 1

    binary = (repo_root / "target" / "debug" / "tarsier").resolve()
    if not binary.exists():
        sys.stderr.write(f"Expected binary not found: {binary}\n")
        return 1

    started_utc = dt.datetime.now(dt.timezone.utc)
    runs: list[dict[str, Any]] = []
    ok_count = 0
    expectation_checked_total = 0
    expectation_failed_total = 0

    family_summary: dict[str, dict[str, int]] = {}
    class_summary: dict[str, dict[str, int]] = {}

    for entry in protocol_entries:
        protocol = Path(entry["path"])
        rel_protocol = protocol.relative_to(repo_root).as_posix()
        sample_count = max(1, int(args.samples))
        sample_elapsed_ms: list[float] = []
        sample_exit_codes: list[int] = []
        sample_overalls: list[str | None] = []
        sample_stderr: list[str] = []
        sample_parse_errors: list[str] = []
        sample_validity: list[bool] = []
        representative_report: dict[str, Any] | None = None

        for _ in range(sample_count):
            cmd = [
                str(binary),
                "analyze",
                rel_protocol,
                "--mode",
                args.mode,
                "--solver",
                args.solver,
                "--depth",
                str(args.depth),
                "--k",
                str(args.k),
                "--timeout",
                str(args.timeout),
                "--soundness",
                args.soundness,
                "--fairness",
                args.fairness,
                "--format",
                "json",
            ]
            t0 = time.perf_counter()
            proc = run(cmd, repo_root)
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            sample_elapsed_ms.append(elapsed_ms)
            sample_exit_codes.append(proc.returncode)
            if proc.stderr.strip():
                sample_stderr.append(proc.stderr.strip())

            report_obj: dict[str, Any] | None = None
            parse_error: str | None = None
            stdout = proc.stdout.strip()
            if stdout:
                try:
                    parsed = json.loads(stdout)
                    if isinstance(parsed, dict):
                        report_obj = parsed
                except json.JSONDecodeError as exc:
                    parse_error = f"json_parse_error: {exc}"
            if parse_error is not None:
                sample_parse_errors.append(parse_error)
            if representative_report is None and report_obj is not None:
                representative_report = report_obj

            overall = report_obj.get("overall") if report_obj else None
            sample_overalls.append(overall if isinstance(overall, str) else None)
            sample_validity.append(proc.returncode in (0, 2) and overall in ("pass", "fail"))

        elapsed_ms = round(median(sample_elapsed_ms), 3)
        report_obj = representative_report
        parse_error = "; ".join(sorted(set(sample_parse_errors))) if sample_parse_errors else None
        unique_sample_overalls = sorted(
            {value for value in sample_overalls if value is not None}
        )
        overall = unique_sample_overalls[0] if len(unique_sample_overalls) == 1 else None
        sample_consistent = len(unique_sample_overalls) <= 1
        if not sample_consistent:
            consistency_note = (
                f"sample_overall_mismatch: {','.join(unique_sample_overalls)}"
            )
            parse_error = (
                consistency_note
                if parse_error is None
                else f"{parse_error}; {consistency_note}"
            )
        run_is_valid = all(sample_validity) and sample_consistent
        expectation_eval = evaluate_expectations(report_obj, entry)
        expectation_checked_total += expectation_eval["checked"]
        expectation_failed_total += expectation_eval["failed"]

        all_samples_pass = (
            sample_consistent
            and overall == "pass"
            and all(code == 0 for code in sample_exit_codes)
        )
        base_ok = all_samples_pass if args.require_pass else run_is_valid
        expectations_required = args.require_expectations and expectation_eval["checked"] > 0
        ok = base_ok and (expectation_eval["failed"] == 0 if expectations_required else True)
        if ok:
            ok_count += 1

        stderr_summary = ""
        if sample_stderr:
            stderr_summary = "\n---\n".join(sample_stderr)

        runs.append(
            {
                "protocol": rel_protocol,
                "manifest_file": entry.get("file"),
                "family": entry.get("family"),
                "class": entry.get("class"),
                "checks": entry.get("checks", []),
                "mode": args.mode,
                "exit_code": sample_exit_codes[0] if sample_exit_codes else 1,
                "sample_exit_codes": sample_exit_codes,
                "sample_overalls": sample_overalls,
                "sample_consistent": sample_consistent,
                "sample_count": sample_count,
                "samples_ms": sample_elapsed_ms,
                "elapsed_ms": elapsed_ms,
                "overall": overall,
                "ok": ok,
                "run_is_valid": run_is_valid,
                "expectations": expectation_eval,
                "json_parse_error": parse_error,
                "stderr": stderr_summary,
                "report": report_obj,
            }
        )
        status = "PASS" if ok and args.require_pass else ("OK" if ok else "FAIL")
        suffix = f"overall={overall}" if overall is not None else "overall=n/a"
        exp_suffix = ""
        if expectation_eval["checked"] > 0:
            exp_suffix = (
                f", expectations={expectation_eval['passed']}/{expectation_eval['checked']}"
            )
        print(
            f"[{status}] {rel_protocol} ({suffix}{exp_suffix}, median={elapsed_ms} ms, samples={sample_count})"
        )

        family = entry.get("family")
        if isinstance(family, str) and family:
            bucket = family_summary.setdefault(family, {"total": 0, "ok": 0, "failed": 0})
            bucket["total"] += 1
            bucket["ok" if ok else "failed"] += 1
        cls = entry.get("class")
        if isinstance(cls, str) and cls:
            bucket = class_summary.setdefault(cls, {"total": 0, "ok": 0, "failed": 0})
            bucket["total"] += 1
            bucket["ok" if ok else "failed"] += 1

    finished_utc = dt.datetime.now(dt.timezone.utc)
    perf_gate: dict[str, Any] = {"enabled": False, "passed": True, "reasons": []}
    if args.perf_budget:
        perf_budget_file = (repo_root / args.perf_budget).resolve()
        perf_budget = json.loads(perf_budget_file.read_text(encoding="utf-8"))
        perf_gate = evaluate_perf_budget(runs, perf_budget)

    report: dict[str, Any] = {
        "schema_version": 1,
        "started_at_utc": started_utc.isoformat(),
        "finished_at_utc": finished_utc.isoformat(),
        "config": {
            "mode": args.mode,
            "solver": args.solver,
            "depth": args.depth,
            "k": args.k,
            "timeout_secs": args.timeout,
            "samples": max(1, int(args.samples)),
            "soundness": args.soundness,
            "fairness": args.fairness,
            "protocol_source": source_label,
            "manifest_mode": not bool(args.protocols),
        },
        "summary": {
            "total": len(runs),
            "ok": ok_count,
            "failed": len(runs) - ok_count,
            "require_pass": args.require_pass,
            "require_expectations": args.require_expectations,
            "expectation_checks_total": expectation_checked_total,
            "expectation_checks_failed": expectation_failed_total,
            "by_family": family_summary,
            "by_class": class_summary,
        },
        "performance_gate": perf_gate,
        "runs": runs,
    }

    out_path = Path(args.out).resolve() if args.out else None
    if out_path is None:
        stamp = started_utc.strftime("%Y%m%d-%H%M%S")
        out_path = (repo_root / "benchmarks" / "results" / f"library-bench-{stamp}.json").resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("")
    print(f"Wrote report: {out_path}")
    print(f"OK: {ok_count}/{len(runs)}")
    if perf_gate.get("enabled"):
        print(
            f"Performance gate: {'PASS' if perf_gate.get('passed') else 'FAIL'}"
        )
        for reason in perf_gate.get("reasons", []):
            print(f"  - {reason}")
    all_passed = ok_count == len(runs) and bool(perf_gate.get("passed", True))
    return 0 if all_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
