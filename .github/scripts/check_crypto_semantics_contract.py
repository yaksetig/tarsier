#!/usr/bin/env python3
"""Validate crypto-object operational semantics docs stay explicit and test-linked.

Enforces:
  1. docs/SEMANTICS.md contains required crypto semantics sections.
  2. The IR/SMT mapping section references required regression tests.
  3. Referenced regression tests exist in lowering/encoder/engine test suites.
"""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SEMANTICS_DOC = ROOT / "docs" / "SEMANTICS.md"
LOWERING_SRC = ROOT / "crates" / "tarsier-ir" / "src" / "lowering.rs"
ENCODER_SRC = ROOT / "crates" / "tarsier-smt" / "src" / "encoder.rs"
ENGINE_INTEGRATION = ROOT / "crates" / "tarsier-engine" / "tests" / "integration_tests.rs"


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

    required_files = [
        SEMANTICS_DOC,
        LOWERING_SRC,
        ENCODER_SRC,
        ENGINE_INTEGRATION,
    ]
    for path in required_files:
        if not path.exists():
            errors.append(f"{path.relative_to(ROOT)}: required file missing")

    if errors:
        print("Crypto semantics contract check FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    doc = read(SEMANTICS_DOC)
    lowering_src = read(LOWERING_SRC)
    encoder_src = read(ENCODER_SRC)
    integration_src = read(ENGINE_INTEGRATION)

    required_sections = [
        "## 2.5 Crypto Object Operational Semantics",
        "### `form C(...)`",
        "### `lock C(...)`",
        "### `justify C(...)`",
        "### `certificate` vs `threshold_signature`",
        "### IR and SMT Mapping (Test-Linked)",
    ]
    for section in required_sections:
        require_contains(doc, section, errors, "docs/SEMANTICS.md")

    required_doc_markers = [
        "lower_crypto_object_form_lock_justify",
        "lower_threshold_signature_form_filters_witnesses_to_signer_role",
        "lower_rejects_threshold_signature_without_signer_role",
        "lower_lock_adds_implicit_has_threshold_guard",
        "lower_justify_sets_justify_flag_not_lock_flag",
        "lower_crypto_object_conflicts_exclusive_adds_admissibility_guard",
        "forging_crypto_object_family_is_unsat_even_with_byzantine_budget",
        "valid_crypto_object_formation_path_is_sat",
        "exclusive_crypto_policy_blocks_conflicting_variants_in_same_state",
        "crypto_justify_independent_of_lock",
    ]
    for marker in required_doc_markers:
        require_contains(doc, marker, errors, "docs/SEMANTICS.md")

    lowering_tests = [
        "lower_crypto_object_form_lock_justify",
        "lower_threshold_signature_form_filters_witnesses_to_signer_role",
        "lower_rejects_threshold_signature_without_signer_role",
        "lower_lock_adds_implicit_has_threshold_guard",
        "lower_justify_sets_justify_flag_not_lock_flag",
        "lower_crypto_object_conflicts_exclusive_adds_admissibility_guard",
    ]
    for test_name in lowering_tests:
        require_test_exists(lowering_src, test_name, errors, "crates/tarsier-ir/src/lowering.rs")

    encoder_tests = [
        "forging_crypto_object_family_is_unsat_even_with_byzantine_budget",
        "valid_crypto_object_formation_path_is_sat",
        "exclusive_crypto_policy_blocks_conflicting_variants_in_same_state",
    ]
    for test_name in encoder_tests:
        require_test_exists(encoder_src, test_name, errors, "crates/tarsier-smt/src/encoder.rs")

    integration_tests = [
        "crypto_justify_independent_of_lock",
    ]
    for test_name in integration_tests:
        require_test_exists(
            integration_src,
            test_name,
            errors,
            "crates/tarsier-engine/tests/integration_tests.rs",
        )

    if errors:
        print("Crypto semantics contract check FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("Crypto semantics contract check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
