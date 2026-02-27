#!/usr/bin/env python3
"""Backward-compatibility contract test for proof certificate JSON artifacts.

Validates that:
1. The JSON schema at schemas/proof_certificate.schema.json is well-formed.
2. All existing certificate.json artifacts conform to the schema.
3. Required fields, types, and enum values match the contract defined by
   CertificateMetadata in tarsier-proof-kernel/src/lib.rs.
4. The cert-suite entry.json files conform to their expected structure.

This script uses only the Python standard library (no jsonschema package)
and performs structural validation equivalent to what the schema describes.

Run: python .github/scripts/check_proof_certificate_schema.py
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schemas" / "proof_certificate.schema.json"

# -- Schema constants that must stay in sync with tarsier-proof-kernel --
CERTIFICATE_SCHEMA_VERSION = 2
VALID_KINDS = {"safety_proof", "fair_liveness_proof"}
VALID_PROOF_ENGINES = {"kinduction", "pdr"}
VALID_SOLVERS = {"z3", "cvc5"}
VALID_SOUNDNESS = {"strict", "permissive"}
VALID_FAIRNESS = {"weak", "strong", None}
VALID_EXPECTED = {"unsat", "sat", "unknown"}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def errors_in_obligation(obj: Any, idx: int) -> list[str]:
    """Validate a single obligation entry."""
    errs: list[str] = []
    prefix = f"obligations[{idx}]"

    if not isinstance(obj, dict):
        return [f"{prefix}: expected object, got {type(obj).__name__}"]

    # Required fields
    for field in ("name", "expected", "file"):
        if field not in obj:
            errs.append(f"{prefix}: missing required field '{field}'")

    if "name" in obj:
        if not isinstance(obj["name"], str) or not obj["name"]:
            errs.append(f"{prefix}.name: must be a non-empty string")

    if "expected" in obj:
        if obj["expected"] not in VALID_EXPECTED:
            errs.append(
                f"{prefix}.expected: '{obj['expected']}' not in {VALID_EXPECTED}"
            )

    if "file" in obj:
        if not isinstance(obj["file"], str) or not obj["file"].endswith(".smt2"):
            errs.append(f"{prefix}.file: must be a string ending with .smt2")

    if "sha256" in obj and obj["sha256"] is not None:
        if not isinstance(obj["sha256"], str) or not SHA256_PATTERN.match(obj["sha256"]):
            errs.append(f"{prefix}.sha256: must be a 64-char lowercase hex string or null")

    if "proof_file" in obj:
        if not isinstance(obj["proof_file"], str):
            errs.append(f"{prefix}.proof_file: must be a string")

    if "proof_sha256" in obj:
        if not isinstance(obj["proof_sha256"], str) or not SHA256_PATTERN.match(
            obj["proof_sha256"]
        ):
            errs.append(f"{prefix}.proof_sha256: must be a 64-char lowercase hex string")

    # Disallow unknown fields (matching serde deny_unknown_fields)
    known_fields = {"name", "expected", "file", "sha256", "proof_file", "proof_sha256"}
    for key in obj:
        if key not in known_fields:
            errs.append(f"{prefix}: unknown field '{key}'")

    return errs


def validate_certificate(data: Any, path: str) -> list[str]:
    """Validate a parsed certificate.json against the proof certificate contract."""
    errs: list[str] = []
    ctx = f"[{path}]"

    if not isinstance(data, dict):
        return [f"{ctx}: top-level value must be an object"]

    # Required fields
    required = [
        "schema_version",
        "kind",
        "protocol_file",
        "proof_engine",
        "solver_used",
        "soundness",
        "committee_bounds",
        "obligations",
    ]
    for field in required:
        if field not in data:
            errs.append(f"{ctx}: missing required field '{field}'")

    # schema_version
    if "schema_version" in data:
        if data["schema_version"] != CERTIFICATE_SCHEMA_VERSION:
            errs.append(
                f"{ctx}: schema_version must be {CERTIFICATE_SCHEMA_VERSION}, "
                f"got {data['schema_version']}"
            )

    # kind
    if "kind" in data:
        if data["kind"] not in VALID_KINDS:
            errs.append(f"{ctx}: kind '{data['kind']}' not in {VALID_KINDS}")

    # protocol_file
    if "protocol_file" in data:
        if not isinstance(data["protocol_file"], str) or not data["protocol_file"]:
            errs.append(f"{ctx}: protocol_file must be a non-empty string")

    # proof_engine
    if "proof_engine" in data:
        if data["proof_engine"] not in VALID_PROOF_ENGINES:
            errs.append(
                f"{ctx}: proof_engine '{data['proof_engine']}' not in {VALID_PROOF_ENGINES}"
            )

    # induction_k (optional, integer or null)
    if "induction_k" in data:
        val = data["induction_k"]
        if val is not None and (not isinstance(val, int) or val < 0):
            errs.append(f"{ctx}: induction_k must be a non-negative integer or null")

    # solver_used
    if "solver_used" in data:
        if data["solver_used"] not in VALID_SOLVERS:
            errs.append(
                f"{ctx}: solver_used '{data['solver_used']}' not in {VALID_SOLVERS}"
            )

    # soundness
    if "soundness" in data:
        if data["soundness"] not in VALID_SOUNDNESS:
            errs.append(
                f"{ctx}: soundness '{data['soundness']}' not in {VALID_SOUNDNESS}"
            )

    # fairness (optional, string or null)
    if "fairness" in data:
        val = data["fairness"]
        if val not in VALID_FAIRNESS:
            errs.append(
                f"{ctx}: fairness '{val}' not in {VALID_FAIRNESS}"
            )

    # committee_bounds
    if "committee_bounds" in data:
        if not isinstance(data["committee_bounds"], list):
            errs.append(f"{ctx}: committee_bounds must be an array")
        else:
            for i, entry in enumerate(data["committee_bounds"]):
                if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                    errs.append(
                        f"{ctx}: committee_bounds[{i}] must be a [string, integer] pair"
                    )
                    continue
                if not isinstance(entry[0], str):
                    errs.append(
                        f"{ctx}: committee_bounds[{i}][0] must be a string"
                    )
                if not isinstance(entry[1], int) or entry[1] < 0:
                    errs.append(
                        f"{ctx}: committee_bounds[{i}][1] must be a non-negative integer"
                    )

    # bundle_sha256 (optional)
    if "bundle_sha256" in data and data["bundle_sha256"] is not None:
        if not isinstance(data["bundle_sha256"], str) or not SHA256_PATTERN.match(
            data["bundle_sha256"]
        ):
            errs.append(f"{ctx}: bundle_sha256 must be a 64-char lowercase hex string or null")

    # obligations
    if "obligations" in data:
        if not isinstance(data["obligations"], list):
            errs.append(f"{ctx}: obligations must be an array")
        elif len(data["obligations"]) == 0:
            errs.append(f"{ctx}: obligations must have at least one entry")
        else:
            for i, obligation in enumerate(data["obligations"]):
                errs.extend(errors_in_obligation(obligation, i))

    # Disallow unknown top-level fields (matching serde deny_unknown_fields)
    known_top = {
        "schema_version",
        "kind",
        "protocol_file",
        "proof_engine",
        "induction_k",
        "solver_used",
        "soundness",
        "fairness",
        "committee_bounds",
        "bundle_sha256",
        "obligations",
    }
    for key in data:
        if key not in known_top:
            errs.append(f"{ctx}: unknown top-level field '{key}'")

    return errs


def validate_cert_suite_entry(data: Any, path: str) -> list[str]:
    """Validate a cert-suite entry.json against its expected structure."""
    errs: list[str] = []
    ctx = f"[{path}]"

    if not isinstance(data, dict):
        return [f"{ctx}: top-level value must be an object"]

    # Required top-level fields
    required = ["file", "family", "class", "verdict", "status", "checks", "errors"]
    for field in required:
        if field not in data:
            errs.append(f"{ctx}: missing required field '{field}'")

    if "status" in data:
        if data["status"] not in {"pass", "fail", "error", "skip"}:
            errs.append(f"{ctx}: status must be pass/fail/error/skip")

    if "verdict" in data:
        if data["verdict"] not in {"pass", "fail", "error", "skip"}:
            errs.append(f"{ctx}: verdict must be pass/fail/error/skip")

    if "checks" in data:
        if not isinstance(data["checks"], list):
            errs.append(f"{ctx}: checks must be an array")
        else:
            for i, check in enumerate(data["checks"]):
                if not isinstance(check, dict):
                    errs.append(f"{ctx}: checks[{i}] must be an object")
                    continue
                for field in ("check", "expected", "actual", "status"):
                    if field not in check:
                        errs.append(f"{ctx}: checks[{i}] missing required field '{field}'")

    if "assumptions" in data:
        if not isinstance(data["assumptions"], dict):
            errs.append(f"{ctx}: assumptions must be an object")
        else:
            assumptions = data["assumptions"]
            for field in ("solver", "soundness", "depth"):
                if field not in assumptions:
                    errs.append(f"{ctx}: assumptions missing expected field '{field}'")

    return errs


def find_certificate_jsons(root: Path) -> list[Path]:
    """Find all certificate.json files under artifacts/."""
    artifacts_dir = root / "artifacts"
    if not artifacts_dir.exists():
        return []
    found = []
    for dirpath, _dirnames, filenames in os.walk(artifacts_dir):
        for fname in filenames:
            if fname == "certificate.json":
                found.append(Path(dirpath) / fname)
    found.sort()
    return found


def find_cert_suite_entries(root: Path) -> list[Path]:
    """Find all cert-suite entry.json files."""
    cert_suite = root / "artifacts" / "cert-suite"
    if not cert_suite.exists():
        return []
    found = []
    for dirpath, _dirnames, filenames in os.walk(cert_suite):
        for fname in filenames:
            if fname == "entry.json":
                found.append(Path(dirpath) / fname)
    found.sort()
    return found


def main() -> int:
    all_errors: list[str] = []

    # 1. Validate that the JSON schema file itself is well-formed JSON.
    if not SCHEMA_PATH.exists():
        all_errors.append(f"Schema file not found: {SCHEMA_PATH}")
    else:
        try:
            schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
            if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
                all_errors.append("Schema file missing or wrong $schema field.")
            if "properties" not in schema:
                all_errors.append("Schema file missing 'properties' key.")
            # Verify schema requires the same fields as CertificateMetadata
            schema_required = set(schema.get("required", []))
            code_required = {
                "schema_version",
                "kind",
                "protocol_file",
                "proof_engine",
                "solver_used",
                "soundness",
                "committee_bounds",
                "obligations",
            }
            if schema_required != code_required:
                all_errors.append(
                    f"Schema 'required' fields mismatch. "
                    f"Schema: {sorted(schema_required)}, "
                    f"Expected: {sorted(code_required)}"
                )
            # Verify schema_version const matches
            sv_prop = schema.get("properties", {}).get("schema_version", {})
            if sv_prop.get("const") != CERTIFICATE_SCHEMA_VERSION:
                all_errors.append(
                    f"Schema schema_version const should be {CERTIFICATE_SCHEMA_VERSION}, "
                    f"got {sv_prop.get('const')}"
                )
            print(f"[PASS] Schema file is well-formed JSON: {SCHEMA_PATH}")
        except json.JSONDecodeError as exc:
            all_errors.append(f"Schema file is not valid JSON: {exc}")

    # 2. Validate all existing certificate.json artifacts.
    cert_files = find_certificate_jsons(ROOT)
    if not cert_files:
        print("[WARN] No certificate.json artifacts found. Skipping artifact validation.")
    else:
        for cert_path in cert_files:
            rel = cert_path.relative_to(ROOT)
            try:
                data = json.loads(cert_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                all_errors.append(f"[{rel}]: invalid JSON: {exc}")
                continue

            errs = validate_certificate(data, str(rel))
            if errs:
                all_errors.extend(errs)
            else:
                print(f"[PASS] Certificate artifact validates: {rel}")

    # 3. Validate cert-suite entry.json files.
    entry_files = find_cert_suite_entries(ROOT)
    if not entry_files:
        print("[WARN] No cert-suite entry.json files found.")
    else:
        validated = 0
        for entry_path in entry_files:
            rel = entry_path.relative_to(ROOT)
            try:
                data = json.loads(entry_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                all_errors.append(f"[{rel}]: invalid JSON: {exc}")
                continue

            errs = validate_cert_suite_entry(data, str(rel))
            if errs:
                all_errors.extend(errs)
            else:
                validated += 1

        if validated == len(entry_files):
            print(f"[PASS] All {validated} cert-suite entry.json files validate.")
        else:
            print(
                f"[PARTIAL] {validated}/{len(entry_files)} cert-suite entries passed."
            )

    # 4. Cross-check schema version constant against tarsier-proof-kernel source.
    kernel_lib = ROOT / "crates" / "tarsier-proof-kernel" / "src" / "lib.rs"
    if kernel_lib.exists():
        kernel_src = kernel_lib.read_text(encoding="utf-8")
        match = re.search(
            r"pub const CERTIFICATE_SCHEMA_VERSION:\s*u32\s*=\s*(\d+);", kernel_src
        )
        if match:
            code_version = int(match.group(1))
            if code_version != CERTIFICATE_SCHEMA_VERSION:
                all_errors.append(
                    f"CERTIFICATE_SCHEMA_VERSION in proof-kernel ({code_version}) "
                    f"does not match contract test constant ({CERTIFICATE_SCHEMA_VERSION})"
                )
            else:
                print(
                    f"[PASS] Schema version {CERTIFICATE_SCHEMA_VERSION} matches proof-kernel."
                )
        else:
            all_errors.append(
                "Could not find CERTIFICATE_SCHEMA_VERSION in tarsier-proof-kernel/src/lib.rs"
            )
    else:
        all_errors.append(f"Missing file: {kernel_lib}")

    # Report
    if all_errors:
        print("\nProof certificate schema contract violations:")
        for err in all_errors:
            print(f"  - {err}")
        return 1

    print("\nAll proof certificate schema contract checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
