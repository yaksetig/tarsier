#!/usr/bin/env python3
"""Manifest-driven liveness PDR regression checks.

Tracks:
- wall-clock runtime per scenario
- convergence frontier frame (when available)
- result-kind stability

Exits non-zero when a scenario violates its expected result or performance bounds.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class EntryResult:
    id: str
    file: str
    fairness: str
    k: int
    expected_result: str | None
    expected_outcome: str | None
    max_runtime_ms: int | None
    min_frontier_frame: int | None
    max_frontier_frame: int | None
    actual_result: str | None
    actual_outcome: str | None
    frontier_frame: int | None
    runtime_ms: int | None
    status: str
    failure_reason: str | None


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    return None


def run_entry(root: Path, entry: dict[str, Any]) -> EntryResult:
    ident = str(entry["id"])
    rel_file = str(entry["file"])
    fairness = str(entry.get("fairness", "weak"))
    k = int(entry.get("k", 12))
    expected_result = entry.get("expected_result")
    expected_outcome = entry.get("expected_outcome")
    max_runtime_ms = _int_or_none(entry.get("max_runtime_ms"))
    min_frontier = _int_or_none(entry.get("min_frontier_frame"))
    max_frontier = _int_or_none(entry.get("max_frontier_frame"))

    cmd = [
        "cargo",
        "run",
        "-q",
        "-p",
        "tarsier-cli",
        "--",
        "prove-fair",
        rel_file,
        "--k",
        str(k),
        "--fairness",
        fairness,
        "--format",
        "json",
    ]

    started = time.perf_counter()
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    runtime_ms = int((time.perf_counter() - started) * 1000)

    if proc.returncode != 0:
        return EntryResult(
            id=ident,
            file=rel_file,
            fairness=fairness,
            k=k,
            expected_result=expected_result,
            expected_outcome=expected_outcome,
            max_runtime_ms=max_runtime_ms,
            min_frontier_frame=min_frontier,
            max_frontier_frame=max_frontier,
            actual_result=None,
            actual_outcome=None,
            frontier_frame=None,
            runtime_ms=runtime_ms,
            status="fail",
            failure_reason=(proc.stderr.strip() or f"command exited {proc.returncode}"),
        )

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return EntryResult(
            id=ident,
            file=rel_file,
            fairness=fairness,
            k=k,
            expected_result=expected_result,
            expected_outcome=expected_outcome,
            max_runtime_ms=max_runtime_ms,
            min_frontier_frame=min_frontier,
            max_frontier_frame=max_frontier,
            actual_result=None,
            actual_outcome=None,
            frontier_frame=None,
            runtime_ms=runtime_ms,
            status="fail",
            failure_reason=f"invalid JSON output: {exc}",
        )

    actual_result = payload.get("result")
    details = payload.get("details") or {}
    convergence = details.get("convergence") or {}
    actual_outcome = convergence.get("outcome")
    frontier_frame = _int_or_none(convergence.get("frontier_frame"))

    failures: list[str] = []
    if expected_result is not None and actual_result != expected_result:
        failures.append(
            f"result mismatch: expected={expected_result} actual={actual_result}"
        )
    if expected_outcome is not None and actual_outcome != expected_outcome:
        failures.append(
            f"outcome mismatch: expected={expected_outcome} actual={actual_outcome}"
        )
    if max_runtime_ms is not None and runtime_ms > max_runtime_ms:
        failures.append(f"runtime_ms {runtime_ms} exceeds budget {max_runtime_ms}")

    if min_frontier is not None or max_frontier is not None:
        if frontier_frame is None:
            failures.append("frontier_frame missing")
        else:
            if min_frontier is not None and frontier_frame < min_frontier:
                failures.append(
                    f"frontier_frame {frontier_frame} below minimum {min_frontier}"
                )
            if max_frontier is not None and frontier_frame > max_frontier:
                failures.append(
                    f"frontier_frame {frontier_frame} above maximum {max_frontier}"
                )

    return EntryResult(
        id=ident,
        file=rel_file,
        fairness=fairness,
        k=k,
        expected_result=(str(expected_result) if expected_result is not None else None),
        expected_outcome=(str(expected_outcome) if expected_outcome is not None else None),
        max_runtime_ms=max_runtime_ms,
        min_frontier_frame=min_frontier,
        max_frontier_frame=max_frontier,
        actual_result=(str(actual_result) if actual_result is not None else None),
        actual_outcome=(str(actual_outcome) if actual_outcome is not None else None),
        frontier_frame=frontier_frame,
        runtime_ms=runtime_ms,
        status="pass" if not failures else "fail",
        failure_reason="; ".join(failures) if failures else None,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run liveness prove-fair regression checks from a manifest."
    )
    parser.add_argument("--manifest", required=True, help="Path to scenario manifest JSON")
    parser.add_argument(
        "--report-out",
        required=True,
        help="Path to write machine-readable regression report JSON",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = (root / manifest_path).resolve()

    payload = json.loads(manifest_path.read_text())
    entries = payload.get("entries")
    if not isinstance(entries, list) or not entries:
        print(f"Manifest has no entries: {manifest_path}", file=sys.stderr)
        return 2

    build = subprocess.run(
        ["cargo", "build", "-q", "-p", "tarsier-cli"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        stderr = build.stderr.strip() or f"command exited {build.returncode}"
        print(f"Failed to prebuild tarsier-cli: {stderr}", file=sys.stderr)
        return 1

    results = [run_entry(root, entry) for entry in entries]
    passed = sum(1 for r in results if r.status == "pass")
    failed = len(results) - passed

    report = {
        "schema_version": 1,
        "suite": "liveness-pdr-regression",
        "manifest": str(manifest_path.relative_to(root)),
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "entries": [r.__dict__ for r in results],
    }

    report_out = Path(args.report_out)
    if not report_out.is_absolute():
        report_out = (root / report_out).resolve()
    report_out.parent.mkdir(parents=True, exist_ok=True)
    report_out.write_text(json.dumps(report, indent=2) + "\n")

    for result in results:
        prefix = "pass" if result.status == "pass" else "fail"
        detail = (
            f"result={result.actual_result} outcome={result.actual_outcome} "
            f"frontier={result.frontier_frame} runtime_ms={result.runtime_ms}"
        )
        print(f"[{prefix}] {result.id}: {detail}")
        if result.failure_reason:
            print(f"  reason: {result.failure_reason}")

    print(f"Wrote report: {report_out}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
