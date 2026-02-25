#!/usr/bin/env python3
"""Check benchmark format docs/schema/harness contract consistency."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "BENCHMARK_FORMAT.md"
SCHEMA = ROOT / "docs" / "benchmark-report-schema-v1.json"
HARNESS = ROOT / "benchmarks" / "replay_library_bench.py"
RUNNER = ROOT / "benchmarks" / "run_library_bench.py"
README = ROOT / "benchmarks" / "README.md"


def main() -> int:
    errors: list[str] = []

    for required in (DOC, SCHEMA, HARNESS, RUNNER, README):
        if not required.exists():
            errors.append(f"missing required file: {required.relative_to(ROOT)}")

    if errors:
        print("Benchmark format contract check FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    required_top = {
        "schema_version",
        "config",
        "environment",
        "summary",
        "performance_gate",
        "scale_band_gate",
        "replay",
        "runs",
    }
    required = set(schema.get("required", []))
    missing_top = sorted(required_top - required)
    if missing_top:
        errors.append(
            "benchmark-report-schema-v1.json missing required top-level keys: "
            + ", ".join(missing_top)
        )

    doc = DOC.read_text(encoding="utf-8")
    for marker in (
        "## Deterministic Replay Contract",
        "## Reproducibility Requirements",
        "## Pinned Environment Requirements",
        "benchmark-report-schema-v1.json",
        "replay_library_bench.py",
    ):
        if marker not in doc:
            errors.append(f"BENCHMARK_FORMAT.md missing marker: {marker}")

    readme = README.read_text(encoding="utf-8")
    for marker in (
        "docs/BENCHMARK_FORMAT.md",
        "docs/benchmark-report-schema-v1.json",
        "replay_library_bench.py",
    ):
        if marker not in readme:
            errors.append(f"benchmarks/README.md missing marker: {marker}")

    runner_src = RUNNER.read_text(encoding="utf-8")
    for marker in (
        '"protocol_sha256"',
        '"environment"',
        '"replay"',
        "compute_replay_plan_sha256",
        "compute_replay_result_sha256",
    ):
        if marker not in runner_src:
            errors.append(f"run_library_bench.py missing marker: {marker}")

    harness_src = HARNESS.read_text(encoding="utf-8")
    for marker in (
        "validate_report",
        "canonical_projection",
        "verify_protocol_hashes",
        "allow-env-mismatch",
    ):
        if marker not in harness_src:
            errors.append(f"replay_library_bench.py missing marker: {marker}")

    if errors:
        print("Benchmark format contract check FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("Benchmark format contract check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
