#!/usr/bin/env python3
"""Enforce required corpus-maintenance policy contract.

The policy document must exist and include explicit ownership, review cadence,
update cadence/SLA, and enforcement references to CI/release corpus gates.
"""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "docs" / "CORPUS_MAINTENANCE_POLICY.md"


REQUIRED_SNIPPETS = [
    "# Protocol Corpus Maintenance Policy",
    "## Ownership",
    "## Review Cadence",
    "## Update Cadence and SLA",
    "## Enforcement",
    "Primary owner:",
    "Backup owner:",
    "within 24 hours",
    "within 48 hours",
    "scripts/certify-corpus.sh",
    ".github/workflows/ci.yml",
    ".github/workflows/release-certification.yml",
    ".github/scripts/check_corpus_policy_contract.py",
]


def main() -> int:
    if not POLICY.exists():
        print(f"missing policy file: {POLICY}")
        return 1

    text = POLICY.read_text(encoding="utf-8")
    missing = [needle for needle in REQUIRED_SNIPPETS if needle not in text]
    if missing:
        print("Corpus maintenance policy contract violations:")
        for needle in missing:
            print(f"  - missing snippet: {needle}")
        return 1

    print("Corpus maintenance policy contract OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
