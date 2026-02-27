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
from pathlib import Path


def main() -> int:
    outcomes_path = Path(os.environ.get(
        "MUTATION_OUTCOMES_PATH", "mutants.out/outcomes.json"
    ))

    threshold = float(os.environ.get("MUTATION_SCORE_MIN", "70"))

    # ------------------------------------------------------------------
    # Load outcomes
    # ------------------------------------------------------------------
    if not outcomes_path.exists():
        print(f"ERROR: outcomes file not found: {outcomes_path}", file=sys.stderr)
        return 1

    with open(outcomes_path) as fh:
        data = json.load(fh)

    # ------------------------------------------------------------------
    # Extract counts - use top-level summary fields from LabOutcome
    # ------------------------------------------------------------------
    caught = data.get("caught", 0)
    missed = data.get("missed", 0)
    timeout = data.get("timeout", 0)
    unviable = data.get("unviable", 0)
    total_mutants = data.get("total_mutants", 0)

    # Fallback: if top-level counts are missing (older cargo-mutants
    # versions), count from the per-outcome array.
    if total_mutants == 0 and "outcomes" in data:
        for outcome in data["outcomes"]:
            summary = outcome.get("summary", "")
            if summary == "CaughtMutant":
                caught += 1
            elif summary == "MissedMutant":
                missed += 1
            elif summary == "Timeout":
                timeout += 1
            elif summary == "Unviable":
                unviable += 1
        total_mutants = caught + missed + timeout + unviable

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
