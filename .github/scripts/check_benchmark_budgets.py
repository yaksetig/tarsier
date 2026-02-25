#!/usr/bin/env python3
"""Check consistency of benchmark budget manifests.

Enforces:
  1. Budget JSON files parse correctly.
  2. scale_bands section is present with valid band definitions.
  3. All bands have non-overlapping ranges with min_ms < max_ms.
  4. Every protocol in baseline.protocol_elapsed_ms has a scale_band assignment.
  5. Every protocol's baseline median falls within its declared scale band.
  6. No orphan scale_band entries (every classified protocol has a baseline).

Exits with code 1 on any violation.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUDGET_DIR = ROOT / "benchmarks" / "budgets"

BUDGET_FILES = [
    "ci-quick-smoke-budget.json",
    "large-smoke-budget.json",
]


def median(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    if n % 2 == 1:
        return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) / 2.0


def check_budget(path: Path, errors: list[str]) -> None:
    name = path.name
    try:
        budget = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        errors.append(f"{name}: failed to load: {exc}")
        return

    # Check scale_bands section exists
    scale_bands = budget.get("scale_bands")
    if not isinstance(scale_bands, dict):
        errors.append(f"{name}: missing or invalid 'scale_bands' section")
        return

    bands = scale_bands.get("bands", {})
    protocol_bands = scale_bands.get("protocol_bands", {})

    if not isinstance(bands, dict) or not bands:
        errors.append(f"{name}: scale_bands.bands is missing or empty")
        return
    if not isinstance(protocol_bands, dict) or not protocol_bands:
        errors.append(f"{name}: scale_bands.protocol_bands is missing or empty")
        return

    # Validate band definitions
    band_ranges: list[tuple[str, float, float]] = []
    for band_name, band_def in bands.items():
        if not isinstance(band_def, dict):
            errors.append(f"{name}: band '{band_name}' is not an object")
            continue
        min_ms = band_def.get("min_ms")
        max_ms = band_def.get("max_ms")
        if not isinstance(min_ms, (int, float)) or not isinstance(max_ms, (int, float)):
            errors.append(f"{name}: band '{band_name}' missing min_ms or max_ms")
            continue
        if min_ms >= max_ms:
            errors.append(f"{name}: band '{band_name}' has min_ms >= max_ms ({min_ms} >= {max_ms})")
        band_ranges.append((band_name, float(min_ms), float(max_ms)))

    # Check for overlapping bands
    band_ranges.sort(key=lambda x: x[1])
    for i in range(len(band_ranges) - 1):
        _, _, prev_max = band_ranges[i]
        next_name, next_min, _ = band_ranges[i + 1]
        if prev_max > next_min:
            errors.append(
                f"{name}: bands overlap: '{band_ranges[i][0]}' max={prev_max} > "
                f"'{next_name}' min={next_min}"
            )

    # Check protocol_bands entries reference valid bands
    for protocol, band_name in protocol_bands.items():
        if band_name not in bands:
            errors.append(f"{name}: protocol '{protocol}' assigned to unknown band '{band_name}'")

    # Check all baseline protocols have band assignments
    baseline = budget.get("baseline", {})
    baseline_protocols = set(baseline.get("protocol_elapsed_ms", {}).keys())
    classified_protocols = set(protocol_bands.keys())

    unclassified = baseline_protocols - classified_protocols
    for protocol in sorted(unclassified):
        errors.append(f"{name}: baseline protocol '{protocol}' has no scale_band assignment")

    orphans = classified_protocols - baseline_protocols
    for protocol in sorted(orphans):
        errors.append(f"{name}: scale_band protocol '{protocol}' has no baseline entry")

    # Check baselines fall within declared bands
    baseline_ms = baseline.get("protocol_elapsed_ms", {})
    baseline_samples = baseline.get("protocol_elapsed_samples_ms", {})
    for protocol, band_name in protocol_bands.items():
        band_def = bands.get(band_name)
        if not isinstance(band_def, dict):
            continue

        # Use median of samples if available, otherwise single baseline
        samples = baseline_samples.get(protocol)
        if isinstance(samples, list) and samples:
            try:
                value = median([float(s) for s in samples])
            except (TypeError, ValueError):
                value = float(baseline_ms.get(protocol, 0.0))
        elif protocol in baseline_ms:
            value = float(baseline_ms[protocol])
        else:
            continue

        band_min = float(band_def.get("min_ms", 0.0))
        band_max = float(band_def.get("max_ms", float("inf")))
        if not (band_min <= value <= band_max):
            errors.append(
                f"{name}: protocol '{protocol}' baseline median {value:.1f} ms "
                f"outside declared band '{band_name}' [{band_min}-{band_max} ms]"
            )


def main() -> int:
    errors: list[str] = []

    for budget_file in BUDGET_FILES:
        path = BUDGET_DIR / budget_file
        if not path.exists():
            errors.append(f"{budget_file}: required file missing")
            continue
        check_budget(path, errors)

    if errors:
        print("Benchmark budget consistency check FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print(
        f"Benchmark budget consistency check passed "
        f"({len(BUDGET_FILES)} budgets, all scale bands valid)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
