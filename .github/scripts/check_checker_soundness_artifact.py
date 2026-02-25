#!/usr/bin/env python3
"""Validate the checker soundness artifact stays explicit and test-linked.

Enforces:
  1. docs/CHECKER_SOUNDNESS_ARGUMENT.md exists and contains required sections.
  2. Machine-checked subset proof test names are documented.
  3. Documented subset proof tests exist in tarsier-proof-kernel source.
  4. Documented replay-boundary tests exist in tarsier-certcheck integration tests.
  5. CI enforcement hooks are explicitly named in the artifact document.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "CHECKER_SOUNDNESS_ARGUMENT.md"
KERNEL_SRC = ROOT / "crates" / "tarsier-proof-kernel" / "src" / "lib.rs"
CERTCHECK_INTEGRATION = ROOT / "crates" / "tarsier-certcheck" / "tests" / "integration.rs"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def require_contains(haystack: str, needle: str, errors: list[str], context: str) -> None:
    if needle not in haystack:
        errors.append(f"{context}: missing required text `{needle}`")


def require_test_exists(src: str, test_name: str, errors: list[str], context: str) -> None:
    pattern = rf"fn\s+{re.escape(test_name)}\s*\("
    if re.search(pattern, src) is None:
        errors.append(f"{context}: missing test function `{test_name}`")


def main() -> int:
    errors: list[str] = []

    if not DOC.exists():
        errors.append("docs/CHECKER_SOUNDNESS_ARGUMENT.md: required artifact file missing")
    if not KERNEL_SRC.exists():
        errors.append("crates/tarsier-proof-kernel/src/lib.rs: required source file missing")
    if not CERTCHECK_INTEGRATION.exists():
        errors.append("crates/tarsier-certcheck/tests/integration.rs: required integration tests file missing")

    if errors:
        print("Checker soundness artifact check FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    doc = read(DOC)
    kernel_src = read(KERNEL_SRC)
    certcheck_src = read(CERTCHECK_INTEGRATION)

    required_sections = [
        "## Soundness Claim",
        "## Machine-Checked Subset Proof",
        "## Assumptions (Explicit + Test-Linked)",
        "## Explicit Non-Goals (Boundary + Test-Linked)",
        "## CI Enforcement",
    ]
    for section in required_sections:
        require_contains(doc, section, errors, "docs/CHECKER_SOUNDNESS_ARGUMENT.md")

    required_doc_markers = [
        "soundness_subset_profile_validator_matches_reference_spec",
        "soundness_subset_bundle_hash_matches_spec_vectors",
        "certcheck_passes_valid_bundle_with_mock_solver",
        "certcheck_fails_on_tampered_obligation",
        "check_checker_soundness_artifact.py",
        "Checker Soundness Subset Gate",
    ]
    for marker in required_doc_markers:
        require_contains(doc, marker, errors, "docs/CHECKER_SOUNDNESS_ARGUMENT.md")

    require_test_exists(
        kernel_src,
        "soundness_subset_profile_validator_matches_reference_spec",
        errors,
        "crates/tarsier-proof-kernel/src/lib.rs",
    )
    require_test_exists(
        kernel_src,
        "soundness_subset_bundle_hash_matches_spec_vectors",
        errors,
        "crates/tarsier-proof-kernel/src/lib.rs",
    )
    require_test_exists(
        certcheck_src,
        "certcheck_passes_valid_bundle_with_mock_solver",
        errors,
        "crates/tarsier-certcheck/tests/integration.rs",
    )
    require_test_exists(
        certcheck_src,
        "certcheck_fails_on_tampered_obligation",
        errors,
        "crates/tarsier-certcheck/tests/integration.rs",
    )

    if errors:
        print("Checker soundness artifact check FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("Checker soundness artifact check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
