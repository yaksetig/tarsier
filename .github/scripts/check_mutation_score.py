#!/usr/bin/env python3
"""Check mutation testing score against a minimum threshold.

Reads the outcomes.json produced by cargo-mutants and computes:
    score = caught / (caught + missed) * 100

Exits non-zero when the score falls below the threshold configured via
the MUTATION_SCORE_MIN environment variable (default: 70).

Timeouts are counted as "caught" because the mutant was detected (the
test suite behaved differently), even though it was killed rather than
failing an assertion.  Unviable mutants are excluded from the
denominator entirely since they never compiled.
"""

from __future__ import annotations

import json
import os
import sys
from glob import glob
from pathlib import Path


def discover_outcome_paths() -> list[Path]:
    outcomes_glob = os.environ.get("MUTATION_OUTCOMES_GLOB")
    if outcomes_glob:
        return sorted(Path(path) for path in glob(outcomes_glob, recursive=True))

    outcomes_path = Path(
        os.environ.get("MUTATION_OUTCOMES_PATH", "mutants.out/outcomes.json")
    )
    if outcomes_path.is_dir():
        return sorted(outcomes_path.rglob("outcomes.json"))
    return [outcomes_path]


def extract_counts(data: dict) -> dict[str, int]:
    counts = {
        "caught": int(data.get("caught", 0)),
        "missed": int(data.get("missed", 0)),
        "timeout": int(data.get("timeout", 0)),
        "unviable": int(data.get("unviable", 0)),
        "total_mutants": int(data.get("total_mutants", 0)),
    }

    # Fallback: if top-level counts are missing (older cargo-mutants
    # versions), count from the per-outcome array.
    if counts["total_mutants"] == 0 and "outcomes" in data:
        for outcome in data["outcomes"]:
            summary = outcome.get("summary", "")
            if summary == "CaughtMutant":
                counts["caught"] += 1
            elif summary == "MissedMutant":
                counts["missed"] += 1
            elif summary == "Timeout":
                counts["timeout"] += 1
            elif summary == "Unviable":
                counts["unviable"] += 1
        counts["total_mutants"] = (
            counts["caught"]
            + counts["missed"]
            + counts["timeout"]
            + counts["unviable"]
        )

    return counts


def main() -> int:
    outcomes_paths = discover_outcome_paths()

    threshold = float(os.environ.get("MUTATION_SCORE_MIN", "70"))
    expected_outcome_files = int(os.environ.get("MUTATION_EXPECTED_OUTCOME_FILES", "0"))

    # ------------------------------------------------------------------
    # Load outcomes
    # ------------------------------------------------------------------
    missing_paths = [path for path in outcomes_paths if not path.exists()]
    if not outcomes_paths or missing_paths:
        paths = ", ".join(str(path) for path in missing_paths or outcomes_paths)
        print(f"ERROR: outcomes file not found: {paths}", file=sys.stderr)
        return 1
    if expected_outcome_files and len(outcomes_paths) != expected_outcome_files:
        print(
            f"ERROR: expected {expected_outcome_files} outcomes files, "
            f"found {len(outcomes_paths)}",
            file=sys.stderr,
        )
        return 1

    caught = 0
    missed = 0
    timeout = 0
    unviable = 0
    total_mutants = 0
    for outcomes_path in outcomes_paths:
        with open(outcomes_path) as fh:
            counts = extract_counts(json.load(fh))
        caught += counts["caught"]
        missed += counts["missed"]
        timeout += counts["timeout"]
        unviable += counts["unviable"]
        total_mutants += counts["total_mutants"]

    # Timeouts count as detected (the mutant changed observable behaviour).
    detected = caught + timeout
    # Denominator excludes unviable mutants (they never compiled).
    testable = caught + missed + timeout

    if testable == 0:
        print("WARNING: no testable mutants found (all unviable or none generated)")
        print("Treating this as a pass since there is nothing to score.")
        return 0

    score = detected / testable * 100.0

    # ------------------------------------------------------------------
    # Summary table
    # ------------------------------------------------------------------
    print("=" * 56)
    print("  MUTATION TESTING QUALITY GATE")
    print("=" * 56)
    print(f"  Outcome files read     : {len(outcomes_paths):>6}")
    print(f"  Total mutants generated : {total_mutants:>6}")
    print(f"  Caught (tests failed)   : {caught:>6}")
    print(f"  Missed (tests passed)   : {missed:>6}")
    print(f"  Timeout (killed)        : {timeout:>6}")
    print(f"  Unviable (didn't build) : {unviable:>6}")
    print("-" * 56)
    print(f"  Testable (caught+missed+timeout) : {testable:>6}")
    print(f"  Detected (caught+timeout)        : {detected:>6}")
    print(f"  Mutation score           : {score:>6.1f}%")
    print(f"  Required minimum         : {threshold:>6.1f}%")
    print("=" * 56)

    if score < threshold:
        print(
            f"\nFAILED: mutation score {score:.1f}% is below "
            f"the required threshold of {threshold:.1f}%"
        )
        return 1

    print(f"\nPASSED: mutation score {score:.1f}% meets the threshold of {threshold:.1f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
