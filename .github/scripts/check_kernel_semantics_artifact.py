#!/usr/bin/env python3
"""Validate kernel-semantics artifact structure and source parity."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "artifacts" / "kernel-semantics" / "kernel_semantics_v1.json"
SCHEMA = ROOT / "docs" / "kernel-semantics-schema-v1.json"
KERNEL_SRC = ROOT / "crates" / "tarsier-proof-kernel" / "src" / "lib.rs"


def load_json(path: Path) -> dict:
    if not path.exists():
        raise RuntimeError(f"missing required file: {path.relative_to(ROOT)}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{path.relative_to(ROOT)} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return data


def extract_kernel_error_codes(src: str) -> list[str]:
    match = re.search(
        r"pub const KERNEL_ERROR_CODES:\s*&\[\s*&str\s*\]\s*=\s*&\[(.*?)\];",
        src,
        re.DOTALL,
    )
    if not match:
        raise RuntimeError("unable to find KERNEL_ERROR_CODES in proof-kernel source")
    return re.findall(r'"([a-z_]+)"', match.group(1))


def validate_against_schema_shape(schema: dict, artifact: dict) -> list[str]:
    errors: list[str] = []
    required = schema.get("required", [])
    for key in required:
        if key not in artifact:
            errors.append(f"artifact missing required field `{key}`")

    props = set(schema.get("properties", {}).keys())
    extras = sorted(set(artifact.keys()) - props)
    if extras:
        errors.append(f"artifact has unknown fields: {extras}")

    if artifact.get("schema_version") != 1:
        errors.append("artifact schema_version must be 1")

    if not isinstance(artifact.get("obligation_profiles"), list) or not artifact["obligation_profiles"]:
        errors.append("artifact.obligation_profiles must be a non-empty array")
    if not isinstance(artifact.get("governance_profiles"), list) or not artifact["governance_profiles"]:
        errors.append("artifact.governance_profiles must be a non-empty array")
    if not isinstance(artifact.get("issue_codes"), list) or not artifact["issue_codes"]:
        errors.append("artifact.issue_codes must be a non-empty array")
    if isinstance(artifact.get("issue_codes"), list):
        if len(set(artifact["issue_codes"])) != len(artifact["issue_codes"]):
            errors.append("artifact.issue_codes must be unique")

    return errors


def main() -> int:
    errors: list[str] = []

    schema = load_json(SCHEMA)
    artifact = load_json(ARTIFACT)

    errors.extend(validate_against_schema_shape(schema, artifact))

    src = KERNEL_SRC.read_text(encoding="utf-8")
    kernel_codes = extract_kernel_error_codes(src)
    artifact_codes = artifact.get("issue_codes", [])
    if artifact_codes != kernel_codes:
        errors.append(
            "artifact issue_codes drift from KERNEL_ERROR_CODES source constant"
        )

    expected_profiles = {
        ("safety_proof", "kinduction"),
        ("safety_proof", "pdr"),
        ("fair_liveness_proof", "pdr"),
    }
    got_profiles = {
        (row.get("kind"), row.get("proof_engine"))
        for row in artifact.get("obligation_profiles", [])
        if isinstance(row, dict)
    }
    if got_profiles != expected_profiles:
        errors.append(
            f"artifact obligation profile keys mismatch: expected {sorted(expected_profiles)}, got {sorted(got_profiles)}"
        )

    expected_gov = {"standard", "reinforced", "high-assurance"}
    got_gov = {
        row.get("name")
        for row in artifact.get("governance_profiles", [])
        if isinstance(row, dict)
    }
    if got_gov != expected_gov:
        errors.append(
            f"artifact governance profiles mismatch: expected {sorted(expected_gov)}, got {sorted(got_gov)}"
        )

    if errors:
        print("Kernel semantics artifact check FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("Kernel semantics artifact check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
