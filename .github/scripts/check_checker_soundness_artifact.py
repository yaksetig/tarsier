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
KERNEL_SOURCES = [
    ROOT / "crates" / "tarsier-proof-kernel" / "src" / "lib.rs",
    ROOT / "crates" / "tarsier-proof-kernel" / "src" / "tests.rs",
]
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


def check_checker_soundness_artifact(
    doc: Path,
    kernel_sources: list[Path],
    certcheck_integration: Path,
    root: Path,
) -> list[str]:
    errors: list[str] = []

    if not doc.exists():
        errors.append("docs/CHECKER_SOUNDNESS_ARGUMENT.md: required artifact file missing")
    missing_kernel_sources = [path for path in kernel_sources if not path.exists()]
    if missing_kernel_sources:
        for path in missing_kernel_sources:
            errors.append(f"{path.relative_to(root)}: required source file missing")
    if not certcheck_integration.exists():
        errors.append("crates/tarsier-certcheck/tests/integration.rs: required integration tests file missing")

    if errors:
        return errors

    doc_text = read(doc)
    kernel_src = "\n".join(read(path) for path in kernel_sources)
    certcheck_src = read(certcheck_integration)

    required_sections = [
        "## Soundness Claim",
        "## Machine-Checked Subset Proof",
        "## Assumptions (Explicit + Test-Linked)",
        "## Explicit Non-Goals (Boundary + Test-Linked)",
        "## CI Enforcement",
    ]
    for section in required_sections:
        require_contains(doc_text, section, errors, "docs/CHECKER_SOUNDNESS_ARGUMENT.md")

    required_doc_markers = [
        "soundness_subset_profile_validator_matches_reference_spec",
        "soundness_subset_bundle_hash_matches_spec_vectors",
        "certcheck_passes_valid_bundle_with_mock_solver",
        "certcheck_fails_on_tampered_obligation",
        "check_checker_soundness_artifact.py",
        "Checker Soundness Subset Gate",
    ]
    for marker in required_doc_markers:
        require_contains(doc_text, marker, errors, "docs/CHECKER_SOUNDNESS_ARGUMENT.md")

    require_test_exists(
        kernel_src,
        "soundness_subset_profile_validator_matches_reference_spec",
        errors,
        "crates/tarsier-proof-kernel/src",
    )
    require_test_exists(
        kernel_src,
        "soundness_subset_bundle_hash_matches_spec_vectors",
        errors,
        "crates/tarsier-proof-kernel/src",
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

    return errors


def main() -> int:
    errors = check_checker_soundness_artifact(
        DOC,
        KERNEL_SOURCES,
        CERTCHECK_INTEGRATION,
        ROOT,
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
