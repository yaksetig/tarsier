#!/usr/bin/env python3
"""Check consistency between KERNEL_SPEC.md and tarsier-proof-kernel implementation.

Enforces:
  1. Every error code in the Rust source appears in KERNEL_SPEC.md.
  2. Every error code in KERNEL_SPEC.md appears in the Rust source.
  3. Obligation profiles in KERNEL_SPEC.md match the Rust source.
  4. Governance profiles in KERNEL_SPEC.md match the Rust source.
  5. KERNEL_SPEC.md cross-references point to files that exist.
  6. KERNEL_SPEC.md is referenced from CERTIFICATE_SCHEMA.md and TRUST_BOUNDARY.md.

Exits with code 1 on any violation.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
KERNEL_SPEC = ROOT / "docs" / "KERNEL_SPEC.md"
KERNEL_SRC = ROOT / "crates" / "tarsier-proof-kernel" / "src" / "lib.rs"
CERT_SCHEMA = ROOT / "docs" / "CERTIFICATE_SCHEMA.md"
TRUST_BOUNDARY = ROOT / "docs" / "TRUST_BOUNDARY.md"


def extract_error_codes_from_rust(src: str) -> set[str]:
    """Extract all error code string literals from BundleCheckIssue constructions."""
    # Match: code: "error_code_name"
    pattern = re.compile(r'code:\s*"([a-z_]+)"')
    return set(pattern.findall(src))


def extract_error_codes_from_spec(spec: str) -> set[str]:
    """Extract all error codes from KERNEL_SPEC.md Sections 4.1-4.6 tables.

    Only looks at the Obligation-to-Check Mapping section (Section 4) to avoid
    picking up non-error-code backtick words from other tables.
    """
    codes: set[str] = set()

    # Extract from Section 4 tables only (subsections 4.1-4.6)
    section_start = spec.find("## 4. Obligation-to-Check Mapping")
    if section_start < 0:
        return codes
    section = spec[section_start:]
    section_end = section.find("\n## 5.")
    if section_end > 0:
        section = section[:section_end]

    # Match: | `error_code_name` | at the start of table rows
    # Error codes are always the first column in these tables
    pattern = re.compile(r'\|\s*`([a-z_]+)`\s*\|')
    codes = set(pattern.findall(section))
    return codes


def extract_obligation_profiles_from_rust(src: str) -> dict[tuple[str, str], list[str]]:
    """Extract obligation profiles from the Rust source.

    Handles multi-line Rust patterns like:
        ("safety_proof", "pdr") => {
            profile = Some(
                &[
                    "init_implies_inv",
                    ...
                ][..],
            );
        }
    """
    profiles: dict[tuple[str, str], list[str]] = {}
    # Match the kind/engine pair, then capture everything until the closing ];
    pattern = re.compile(
        r'\("(\w+)",\s*"(\w+)"\)\s*=>\s*\{[^}]*?profile\s*=\s*Some\(\s*&\[(.*?)\]\[?\.\.\]?',
        re.DOTALL
    )
    for m in pattern.finditer(src):
        kind, engine = m.group(1), m.group(2)
        names_raw = m.group(3)
        names = re.findall(r'"(\w+)"', names_raw)
        if names:
            profiles[(kind, engine)] = names
    return profiles


def extract_obligation_profiles_from_spec(spec: str) -> dict[tuple[str, str], list[str]]:
    """Extract obligation profiles from KERNEL_SPEC.md Section 5 table."""
    profiles: dict[tuple[str, str], list[str]] = {}
    # Match table rows: | `kind` | `engine` | `name1`, `name2`, ... | count |
    pattern = re.compile(
        r'\|\s*`(\w+)`\s*\|\s*`(\w+)`\s*\|\s*([^|]+)\s*\|\s*\d+\s*\|'
    )
    section_start = spec.find("## 5. Obligation Profiles")
    if section_start < 0:
        return profiles
    section = spec[section_start:]
    section_end = section.find("\n## ")
    if section_end > 0:
        section = section[:section_end]
    for m in pattern.finditer(section):
        kind, engine = m.group(1), m.group(2)
        names_raw = m.group(3)
        names = re.findall(r'`(\w+)`', names_raw)
        profiles[(kind, engine)] = names
    return profiles


def extract_governance_profiles_from_rust(src: str) -> set[str]:
    """Extract governance profile display names from the Rust source."""
    # Match: GovernanceProfile::Xxx => write!(f, "name")
    pattern = re.compile(r'GovernanceProfile::\w+\s*=>\s*write!\(f,\s*"([^"]+)"\)')
    return set(pattern.findall(src))


def extract_governance_profiles_from_spec(spec: str) -> set[str]:
    """Extract governance profile names from KERNEL_SPEC.md Section 7."""
    profiles: set[str] = set()
    section_start = spec.find("## 7. Governance Profiles")
    if section_start < 0:
        return profiles
    section = spec[section_start:]
    section_end = section.find("\n## ")
    if section_end > 0:
        section = section[:section_end]
    # Match: | `profile_name` | in table rows
    pattern = re.compile(r'\|\s*`([a-z-]+)`\s*\|')
    return set(pattern.findall(section))


def check_cross_references(spec: str, errors: list[str]) -> None:
    """Verify cross-references in KERNEL_SPEC.md point to existing files."""
    pattern = re.compile(r'`((?:docs|crates)/[A-Za-z0-9_/./-]+)`')
    for m in pattern.finditer(spec):
        ref = m.group(1)
        if not (ROOT / ref).exists():
            errors.append(f"KERNEL_SPEC.md: cross-reference `{ref}` does not exist")


def check_back_references(errors: list[str]) -> None:
    """Verify that CERTIFICATE_SCHEMA.md and TRUST_BOUNDARY.md reference KERNEL_SPEC.md."""
    for doc_path, doc_name in [
        (CERT_SCHEMA, "CERTIFICATE_SCHEMA.md"),
        (TRUST_BOUNDARY, "TRUST_BOUNDARY.md"),
    ]:
        if doc_path.exists():
            content = doc_path.read_text(encoding="utf-8")
            if "KERNEL_SPEC.md" not in content:
                errors.append(
                    f"{doc_name}: missing cross-reference to docs/KERNEL_SPEC.md"
                )


def main() -> int:
    errors: list[str] = []

    if not KERNEL_SPEC.exists():
        errors.append("docs/KERNEL_SPEC.md: required file missing")
        print("Kernel spec consistency check FAILED (missing file):")
        for err in errors:
            print(f"  - {err}")
        return 1

    if not KERNEL_SRC.exists():
        errors.append("crates/tarsier-proof-kernel/src/lib.rs: required file missing")
        print("Kernel spec consistency check FAILED (missing source):")
        for err in errors:
            print(f"  - {err}")
        return 1

    spec = KERNEL_SPEC.read_text(encoding="utf-8")
    src = KERNEL_SRC.read_text(encoding="utf-8")

    # 1. Error code consistency
    rust_codes = extract_error_codes_from_rust(src)
    spec_codes = extract_error_codes_from_spec(spec)

    missing_from_spec = rust_codes - spec_codes
    missing_from_rust = spec_codes - rust_codes

    for code in sorted(missing_from_spec):
        errors.append(
            f"KERNEL_SPEC.md: missing error code `{code}` (present in Rust source)"
        )
    for code in sorted(missing_from_rust):
        errors.append(
            f"KERNEL_SPEC.md: documents error code `{code}` not found in Rust source"
        )

    # 2. Obligation profile consistency
    rust_profiles = extract_obligation_profiles_from_rust(src)
    spec_profiles = extract_obligation_profiles_from_spec(spec)

    for key in rust_profiles:
        if key not in spec_profiles:
            errors.append(
                f"KERNEL_SPEC.md: missing obligation profile for {key}"
            )
        elif sorted(rust_profiles[key]) != sorted(spec_profiles[key]):
            errors.append(
                f"KERNEL_SPEC.md: obligation profile mismatch for {key}: "
                f"Rust={sorted(rust_profiles[key])}, Spec={sorted(spec_profiles[key])}"
            )

    for key in spec_profiles:
        if key not in rust_profiles:
            errors.append(
                f"KERNEL_SPEC.md: documents obligation profile {key} not in Rust source"
            )

    # 3. Governance profile consistency
    rust_gov = extract_governance_profiles_from_rust(src)
    spec_gov = extract_governance_profiles_from_spec(spec)

    for p in rust_gov - spec_gov:
        errors.append(
            f"KERNEL_SPEC.md: missing governance profile `{p}` (present in Rust source)"
        )
    for p in spec_gov - rust_gov:
        errors.append(
            f"KERNEL_SPEC.md: documents governance profile `{p}` not in Rust source"
        )

    # 4. Cross-references
    check_cross_references(spec, errors)

    # 5. Back-references
    check_back_references(errors)

    if errors:
        print("Kernel spec consistency check FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print(
        f"Kernel spec consistency check passed "
        f"({len(rust_codes)} error codes, "
        f"{len(rust_profiles)} obligation profiles, "
        f"{len(rust_gov)} governance profiles)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
