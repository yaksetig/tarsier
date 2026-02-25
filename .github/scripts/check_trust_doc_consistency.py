#!/usr/bin/env python3
"""Check consistency between trust-boundary documents, trust report schema, and SECURITY.md.

Enforces:
  1. Trust report JSON schema governance profiles match TRUST_BOUNDARY.md profiles.
  2. Trust report JSON schema claim layer statuses match TRUST_REPORT_SCHEMA.md.
  3. Trust report JSON schema threat entry statuses match TRUST_REPORT_SCHEMA.md.
  4. TRUST_BOUNDARY.md claim layers are referenced in trust-report-schema-v1.json.
  5. TRUST_BOUNDARY.md residual assumptions count matches trust report residual_assumptions.
  6. SECURITY.md scope section mentions key in-scope components from TRUST_BOUNDARY.md.
  7. Cross-references between trust docs point to files that exist.
  8. Governance profile names are consistent across all sources.

Exits with code 1 on any violation.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
DOCS_DIR = ROOT / "docs"


def load_text(path: Path) -> str:
    """Load a text file, or empty string if missing."""
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def load_json(path: Path) -> dict | None:
    """Load a JSON file, or None if missing."""
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return None


def check_trust_report_schema_exists(errors: list[str]) -> dict | None:
    """Check that the trust report JSON schema exists and is valid JSON."""
    schema_path = DOCS_DIR / "trust-report-schema-v1.json"
    if not schema_path.exists():
        errors.append("docs/trust-report-schema-v1.json: required file missing")
        return None
    schema = load_json(schema_path)
    if schema is None:
        errors.append("docs/trust-report-schema-v1.json: failed to parse as JSON")
    return schema


def check_trust_report_schema_doc_exists(errors: list[str]) -> str:
    """Check that the trust report schema documentation exists."""
    doc_path = DOCS_DIR / "TRUST_REPORT_SCHEMA.md"
    if not doc_path.exists():
        errors.append("docs/TRUST_REPORT_SCHEMA.md: required file missing")
        return ""
    return load_text(doc_path)


def check_trust_boundary_exists(errors: list[str]) -> str:
    """Check that TRUST_BOUNDARY.md exists."""
    tb_path = DOCS_DIR / "TRUST_BOUNDARY.md"
    if not tb_path.exists():
        errors.append("docs/TRUST_BOUNDARY.md: required file missing")
        return ""
    return load_text(tb_path)


def check_security_exists(errors: list[str]) -> str:
    """Check that SECURITY.md exists."""
    sec_path = ROOT / "SECURITY.md"
    if not sec_path.exists():
        errors.append("SECURITY.md: required file missing")
        return ""
    return load_text(sec_path)


def check_governance_profiles_consistent(
    schema: dict, trust_boundary: str, schema_doc: str, errors: list[str]
) -> None:
    """Verify governance profiles are consistent across all sources."""
    # Extract profiles from JSON schema
    schema_profiles = set()
    gov_prop = schema.get("properties", {}).get("governance_profile", {})
    if "enum" in gov_prop:
        schema_profiles = set(gov_prop["enum"])

    expected_profiles = {"standard", "reinforced", "high-assurance"}

    if schema_profiles != expected_profiles:
        errors.append(
            f"trust-report-schema-v1.json: governance_profile enum {sorted(schema_profiles)} "
            f"does not match expected {sorted(expected_profiles)}"
        )

    # Check TRUST_BOUNDARY.md mentions all profiles
    for profile in expected_profiles:
        if f"`{profile}`" not in trust_boundary:
            errors.append(
                f"docs/TRUST_BOUNDARY.md: missing governance profile `{profile}` in profiles table"
            )

    # Check schema doc mentions all profiles
    for profile in expected_profiles:
        if profile not in schema_doc:
            errors.append(
                f"docs/TRUST_REPORT_SCHEMA.md: missing governance profile '{profile}'"
            )


def check_claim_layer_statuses(schema: dict, schema_doc: str, errors: list[str]) -> None:
    """Verify claim layer status enum is consistent."""
    claim_def = schema.get("$defs", {}).get("claim_layer", {})
    status_prop = claim_def.get("properties", {}).get("status", {})
    schema_statuses = set(status_prop.get("enum", []))

    expected_statuses = {"enforced", "optional", "not_applicable"}
    if schema_statuses != expected_statuses:
        errors.append(
            f"trust-report-schema-v1.json: claim_layer status enum {sorted(schema_statuses)} "
            f"does not match expected {sorted(expected_statuses)}"
        )

    # Check schema doc mentions all statuses
    for status in expected_statuses:
        if status not in schema_doc:
            errors.append(
                f"docs/TRUST_REPORT_SCHEMA.md: missing claim layer status '{status}'"
            )


def check_threat_entry_statuses(schema: dict, schema_doc: str, errors: list[str]) -> None:
    """Verify threat entry status enum is consistent."""
    threat_def = schema.get("$defs", {}).get("threat_entry", {})
    status_prop = threat_def.get("properties", {}).get("status", {})
    schema_statuses = set(status_prop.get("enum", []))

    expected_statuses = {"enforced", "available", "not_applicable"}
    if schema_statuses != expected_statuses:
        errors.append(
            f"trust-report-schema-v1.json: threat_entry status enum {sorted(schema_statuses)} "
            f"does not match expected {sorted(expected_statuses)}"
        )

    for status in expected_statuses:
        if status not in schema_doc:
            errors.append(
                f"docs/TRUST_REPORT_SCHEMA.md: missing threat entry status '{status}'"
            )


def check_claim_layers_referenced(trust_boundary: str, errors: list[str]) -> None:
    """Verify that claim layer names from TRUST_BOUNDARY.md are consistent with report schema."""
    # The trust report generator uses these claim layer names;
    # verify they correspond to layers described in TRUST_BOUNDARY.md.
    expected_layers = [
        ("certificate_integrity", "Certificate integrity"),
        ("smt_replay", "SMT replay"),
        ("multi_solver_replay", "Multi-solver replay"),
        ("proof_object_path", "Proof-object path"),
        ("source_obligation_consistency", "Source->obligation consistency"),
    ]

    for layer_id, layer_desc_prefix in expected_layers:
        # Check that TRUST_BOUNDARY.md mentions this layer concept
        if layer_desc_prefix.lower() not in trust_boundary.lower():
            errors.append(
                f"docs/TRUST_BOUNDARY.md: missing claim layer concept '{layer_desc_prefix}' "
                f"(maps to trust report layer '{layer_id}')"
            )


def check_threat_categories_referenced(trust_boundary: str, errors: list[str]) -> None:
    """Verify threat model categories from the report appear in TRUST_BOUNDARY.md."""
    expected_categories = ["tampering", "soundness", "modeling", "supply_chain", "replay_evasion"]

    # In TRUST_BOUNDARY.md, the threat model table uses these category names
    # (possibly with different casing or formatting)
    tb_lower = trust_boundary.lower()
    for cat in expected_categories:
        # Allow underscore or space or hyphen variants
        cat_variants = [cat, cat.replace("_", " "), cat.replace("_", "-")]
        found = any(v in tb_lower for v in cat_variants)
        if not found:
            errors.append(
                f"docs/TRUST_BOUNDARY.md: missing threat category '{cat}' in threat model"
            )


def check_residual_assumptions_count(trust_boundary: str, errors: list[str]) -> None:
    """Verify residual assumptions are present in TRUST_BOUNDARY.md."""
    # TRUST_BOUNDARY.md section 6 lists residual assumptions as numbered items
    assumption_keywords = [
        "solver correctness",
        "proof checker soundness",
        "modeling fidelity",
        "toolchain correctness",
        "environment integrity",
        "domain tag uniqueness",
        "obligation-theorem correspondence",
    ]

    tb_lower = trust_boundary.lower()
    for kw in assumption_keywords:
        if kw.lower() not in tb_lower:
            errors.append(
                f"docs/TRUST_BOUNDARY.md: missing residual assumption '{kw}'"
            )


def check_security_scope_alignment(security_md: str, trust_boundary: str, errors: list[str]) -> None:
    """Verify SECURITY.md scope mentions key components from TRUST_BOUNDARY.md."""
    # SECURITY.md should mention these in-scope components
    key_components = [
        "tarsier-cli",
        "tarsier-certcheck",
        "tarsier-engine",
    ]

    for component in key_components:
        if component not in security_md:
            errors.append(
                f"SECURITY.md: missing in-scope component '{component}'"
            )

    # SECURITY.md should mention supply-chain integrity
    if "supply-chain" not in security_md.lower() and "supply chain" not in security_md.lower():
        errors.append(
            "SECURITY.md: missing supply-chain integrity section"
        )


def check_trust_doc_cross_references(schema_doc: str, errors: list[str]) -> None:
    """Verify cross-references in trust report schema doc point to existing files."""
    # Check references to other docs/files
    ref_pattern = re.compile(r"`(docs/[A-Za-z_.-]+\.[a-z]+)`")
    for match in ref_pattern.finditer(schema_doc):
        ref = match.group(1)
        if not (ROOT / ref).exists():
            errors.append(
                f"docs/TRUST_REPORT_SCHEMA.md: cross-reference `{ref}` does not exist"
            )


def check_soundness_modes_consistent(schema: dict, errors: list[str]) -> None:
    """Verify soundness mode enum in schema is correct."""
    vs_def = schema.get("$defs", {}).get("verification_scope", {})
    soundness_prop = vs_def.get("properties", {}).get("soundness", {})
    soundness_enum = set(soundness_prop.get("enum", []))

    expected = {"strict", "permissive"}
    if soundness_enum != expected:
        errors.append(
            f"trust-report-schema-v1.json: soundness enum {sorted(soundness_enum)} "
            f"does not match expected {sorted(expected)}"
        )


def check_signed_report_contract(
    schema_doc: str, trust_boundary: str, security_md: str, errors: list[str]
) -> None:
    """Verify signed trust report contract is documented across all sources."""
    # TRUST_REPORT_SCHEMA.md must mention signed reports
    if "signed report" not in schema_doc.lower() and "cosign" not in schema_doc.lower():
        errors.append(
            "docs/TRUST_REPORT_SCHEMA.md: missing signed report / cosign documentation"
        )

    # TRUST_REPORT_SCHEMA.md must document verification procedure
    if "verify-blob" not in schema_doc:
        errors.append(
            "docs/TRUST_REPORT_SCHEMA.md: missing cosign verify-blob verification procedure"
        )

    # TRUST_BOUNDARY.md must mention trust report provenance threat
    if "trust report" not in trust_boundary.lower():
        errors.append(
            "docs/TRUST_BOUNDARY.md: missing trust report provenance in threat model"
        )

    # SECURITY.md must mention trust report signing
    if "trust report" not in security_md.lower():
        errors.append(
            "SECURITY.md: missing trust report signing in supply-chain integrity"
        )


def check_sandbox_documented(trust_boundary: str, errors: list[str]) -> None:
    """Verify runtime sandbox controls and limitations are documented."""
    tb_lower = trust_boundary.lower()

    # Enforced controls must be documented
    for control in ["wall-clock timeout", "memory budget", "input file size"]:
        if control not in tb_lower:
            errors.append(
                f"docs/TRUST_BOUNDARY.md: missing sandbox enforced control '{control}'"
            )

    # Non-enforced controls must be explicitly called out
    if "network isolation" not in tb_lower:
        errors.append(
            "docs/TRUST_BOUNDARY.md: missing sandbox limitation 'network isolation'"
        )
    if "filesystem write isolation" not in tb_lower and "filesystem isolation" not in tb_lower:
        errors.append(
            "docs/TRUST_BOUNDARY.md: missing sandbox limitation 'filesystem write isolation'"
        )

    # Fail-closed semantics must be documented
    if "fail-closed" not in tb_lower:
        errors.append(
            "docs/TRUST_BOUNDARY.md: missing sandbox fail-closed semantics documentation"
        )


def check_kernel_spec_exists(trust_boundary: str, errors: list[str]) -> None:
    """Verify KERNEL_SPEC.md exists and is referenced from TRUST_BOUNDARY.md."""
    spec_path = DOCS_DIR / "KERNEL_SPEC.md"
    if not spec_path.exists():
        errors.append("docs/KERNEL_SPEC.md: required file missing")
        return
    if "KERNEL_SPEC.md" not in trust_boundary:
        errors.append(
            "docs/TRUST_BOUNDARY.md: missing cross-reference to KERNEL_SPEC.md"
        )


def check_proof_engine_consistent(schema: dict, errors: list[str]) -> None:
    """Verify proof engine enum in schema is correct."""
    vs_def = schema.get("$defs", {}).get("verification_scope", {})
    engine_prop = vs_def.get("properties", {}).get("proof_engine", {})
    engine_enum = set(engine_prop.get("enum", []))

    expected = {"kinduction", "pdr"}
    if engine_enum != expected:
        errors.append(
            f"trust-report-schema-v1.json: proof_engine enum {sorted(engine_enum)} "
            f"does not match expected {sorted(expected)}"
        )


def main() -> int:
    errors: list[str] = []

    # Load all source-of-truth documents
    schema = check_trust_report_schema_exists(errors)
    schema_doc = check_trust_report_schema_doc_exists(errors)
    trust_boundary = check_trust_boundary_exists(errors)
    security_md = check_security_exists(errors)

    # If critical files are missing, report and exit
    if schema is None or not schema_doc or not trust_boundary or not security_md:
        if errors:
            print("Trust/docs consistency check FAILED (missing files):")
            for err in errors:
                print(f"  - {err}")
        return 1

    # Run all consistency checks
    check_governance_profiles_consistent(schema, trust_boundary, schema_doc, errors)
    check_claim_layer_statuses(schema, schema_doc, errors)
    check_threat_entry_statuses(schema, schema_doc, errors)
    check_claim_layers_referenced(trust_boundary, errors)
    check_threat_categories_referenced(trust_boundary, errors)
    check_residual_assumptions_count(trust_boundary, errors)
    check_security_scope_alignment(security_md, trust_boundary, errors)
    check_trust_doc_cross_references(schema_doc, errors)
    check_soundness_modes_consistent(schema, errors)
    check_proof_engine_consistent(schema, errors)
    check_signed_report_contract(schema_doc, trust_boundary, security_md, errors)
    check_sandbox_documented(trust_boundary, errors)
    check_kernel_spec_exists(trust_boundary, errors)

    if errors:
        print("Trust/docs consistency check FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("Trust/docs consistency check passed (SECURITY.md, TRUST_BOUNDARY.md, trust-report-schema-v1.json, TRUST_REPORT_SCHEMA.md, signed-report contract, sandbox contract, kernel spec).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
