#!/usr/bin/env python3
"""Check semantic consistency of documentation files.

Enforces:
  1. Canonical terminology is used consistently across docs.
  2. Cross-references between docs point to files that exist.
  3. INTERPRETATION_MATRIX.md exists and contains required sections.
  4. No contradictory soundness claims across docs.
  5. Network mode names match canonical enum values.

Exits with code 1 on any violation.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
DOCS_DIR = ROOT / "docs"

# Canonical network mode terms — these must be used consistently.
CANONICAL_MODES = {
    "classic",
    "identity_selective",
    "cohort_selective",
    "process_selective",
}

# The interpretation matrix must exist and contain these section headings.
MATRIX_REQUIRED_SECTIONS = [
    "Network Mode Comparison",
    "Soundness Transfer Rules",
    "Counter-Abstraction Limitations",
    "Worked Examples",
    "Choosing the Right Mode",
]

# Soundness claims that must not appear in contradictory forms.
# Each entry is (claim_regex, contradiction_regex, description).
SOUNDNESS_RULES: list[tuple[str, str, str]] = [
    # classic SAFE transfers conditionally, never unconditionally
    (
        r"classic.*SAFE.*unconditionally\s+transfers",
        r".",  # any match of the claim is itself a violation
        "classic SAFE transfer is conditional (monotone guards, equivocation: full, no received distinct)",
    ),
    # process_selective is instance-exact, not an over-approximation
    (
        r"process.selective.*over.approximat",
        r".",
        "process_selective is instance-exact, not an over-approximation",
    ),
]

# Cross-reference patterns in markdown: `docs/FILENAME.md` or `FILENAME.md`
DOC_REF_PATTERN = re.compile(r"`(docs/[A-Z_]+\.md)`")


def load_docs() -> dict[str, str]:
    """Load all .md files from docs/ directory."""
    result: dict[str, str] = {}
    for path in sorted(DOCS_DIR.glob("*.md")):
        result[str(path.relative_to(ROOT))] = path.read_text(encoding="utf-8")
    return result


def check_terminology(docs: dict[str, str], errors: list[str]) -> None:
    """Check that deprecated or inconsistent terminology is flagged."""
    for doc_name, text in docs.items():
        # "legacy mode" without "classic" nearby is ambiguous — should use "classic (legacy)"
        # We check if "legacy" is used to describe the network mode without "classic" context.
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            lower = line.lower()
            # Flag "legacy mode" or "legacy network" without mentioning "classic"
            if re.search(r"\blegacy\s+(mode|network|semantics)\b", lower):
                # Check if "classic" appears within 3 lines
                context = "\n".join(lines[max(0, i - 4) : i + 3]).lower()
                if "classic" not in context:
                    errors.append(
                        f"{doc_name}:{i}: uses 'legacy' without 'classic' context — "
                        f"use 'classic (legacy)' or 'classic' for consistency"
                    )


def check_cross_references(docs: dict[str, str], errors: list[str]) -> None:
    """Check that doc cross-references point to existing files."""
    for doc_name, text in docs.items():
        for match in DOC_REF_PATTERN.finditer(text):
            ref = match.group(1)
            if not (ROOT / ref).exists():
                errors.append(
                    f"{doc_name}: cross-reference `{ref}` does not exist"
                )


def check_interpretation_matrix(errors: list[str]) -> None:
    """Check that INTERPRETATION_MATRIX.md exists and has required sections."""
    matrix_path = DOCS_DIR / "INTERPRETATION_MATRIX.md"
    if not matrix_path.exists():
        errors.append("docs/INTERPRETATION_MATRIX.md: required file missing")
        return

    text = matrix_path.read_text(encoding="utf-8")
    for section in MATRIX_REQUIRED_SECTIONS:
        if section not in text:
            errors.append(
                f"docs/INTERPRETATION_MATRIX.md: missing required section '{section}'"
            )


def check_soundness_claims(docs: dict[str, str], errors: list[str]) -> None:
    """Check for contradictory soundness claims."""
    for doc_name, text in docs.items():
        for claim_re, _, description in SOUNDNESS_RULES:
            if re.search(claim_re, text, re.IGNORECASE):
                errors.append(
                    f"{doc_name}: contradictory soundness claim — {description}"
                )


def check_mode_consistency(docs: dict[str, str], errors: list[str]) -> None:
    """Check that network mode names use canonical underscore form."""
    # Non-canonical forms that people might use
    non_canonical = {
        "identity-selective": "identity_selective",
        "cohort-selective": "cohort_selective",
        "process-selective": "process_selective",
    }
    for doc_name, text in docs.items():
        for wrong, right in non_canonical.items():
            # Only flag if used as a technical term (not in prose like "process-selective approach")
            pattern = rf"`{re.escape(wrong)}`"
            if re.search(pattern, text):
                errors.append(
                    f"{doc_name}: uses non-canonical mode name `{wrong}` — "
                    f"use `{right}` (underscore form)"
                )


def main() -> int:
    errors: list[str] = []

    docs = load_docs()
    if not docs:
        errors.append("no .md files found in docs/")
        print("Doc consistency check FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    check_terminology(docs, errors)
    check_cross_references(docs, errors)
    check_interpretation_matrix(errors)
    check_soundness_claims(docs, errors)
    check_mode_consistency(docs, errors)

    if errors:
        print("Doc consistency check FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print(f"Doc consistency check passed ({len(docs)} docs scanned).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
