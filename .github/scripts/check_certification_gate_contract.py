#!/usr/bin/env python3
"""Enforce the certification gate contract in CI/release workflows.

This is a lightweight text-based contract check (no external YAML deps).
It prevents accidental drift from:
  - one-command corpus certification entrypoint (`./scripts/certify-corpus.sh`)
  - pinned-environment verification
  - release gating on pinned workflow
"""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release-certification.yml"
CERT_SCRIPT = ROOT / "scripts" / "certify-corpus.sh"

PIN_LINES = [
    'EXPECTED_RUSTC: "1.92.0"',
    'EXPECTED_Z3: "4.12.5"',
    'EXPECTED_CVC5: "1.1.2"',
    'EXPECTED_OS: "ubuntu-22.04"',
]


def fail(errors: list[str]) -> int:
    if not errors:
        return 0
    print("Certification gate contract violations:")
    for err in errors:
        print(f"  - {err}")
    return 1


def load(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f"missing file: {path}")
    return path.read_text(encoding="utf-8")


def job_block(text: str, job_name: str) -> str:
    lines = text.splitlines()
    start = None
    marker = f"  {job_name}:"
    for i, line in enumerate(lines):
        if line == marker:
            start = i
            break
    if start is None:
        return ""

    end = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line):
            end = i
            break
    return "\n".join(lines[start:end])


def ensure_contains(errors: list[str], block: str, needle: str, ctx: str) -> None:
    if needle not in block:
        errors.append(f"{ctx}: missing `{needle}`")


def ensure_not_contains(errors: list[str], block: str, needle: str, ctx: str) -> None:
    if needle in block:
        errors.append(f"{ctx}: forbidden direct command `{needle}` (use ./scripts/certify-corpus.sh)")


def main() -> int:
    errors: list[str] = []

    ci = load(CI_WORKFLOW)
    release = load(RELEASE_WORKFLOW)
    cert_script = load(CERT_SCRIPT)

    if "cargo run -p tarsier-cli -- cert-suite" not in cert_script:
        errors.append("scripts/certify-corpus.sh no longer invokes `cargo run -p tarsier-cli -- cert-suite`.")

    # CI gate contract
    ci_gate = job_block(ci, "corpus-certification-gate")
    if not ci_gate:
        errors.append("ci.yml: missing `corpus-certification-gate` job.")
    else:
        ensure_contains(errors, ci_gate, "runs-on: ubuntu-22.04", "ci.yml corpus-certification-gate")
        for pin in PIN_LINES:
            ensure_contains(errors, ci_gate, pin, "ci.yml corpus-certification-gate")
        ensure_contains(
            errors,
            ci_gate,
            "run: ./.github/scripts/verify_pinned_env.sh",
            "ci.yml corpus-certification-gate",
        )
        ensure_contains(
            errors,
            ci_gate,
            "./scripts/certify-corpus.sh",
            "ci.yml corpus-certification-gate",
        )
        ensure_not_contains(
            errors,
            ci_gate,
            "cargo run -p tarsier-cli -- cert-suite",
            "ci.yml corpus-certification-gate",
        )

    # Ensure downstream proof/certification jobs depend on corpus gate.
    for dep_job in [
        "certificate-check",
        "certificate-check-fair-liveness",
        "certificate-proof-object-validation",
    ]:
        block = job_block(ci, dep_job)
        if not block:
            errors.append(f"ci.yml: missing `{dep_job}` job.")
            continue
        ensure_contains(errors, block, "- corpus-certification-gate", f"ci.yml {dep_job}")

    # High-assurance proof replay contract for CI.
    ci_proof_gate = job_block(ci, "proof-mode-independent-gate")
    if not ci_proof_gate:
        errors.append("ci.yml: missing `proof-mode-independent-gate` job.")
    else:
        ensure_contains(
            errors,
            ci_proof_gate,
            "TARSIER_REQUIRE_CARCARA: \"1\"",
            "ci.yml proof-mode-independent-gate",
        )
        ensure_contains(
            errors,
            ci_proof_gate,
            "--profile high-assurance",
            "ci.yml proof-mode-independent-gate",
        )
        ensure_contains(
            errors,
            ci_proof_gate,
            "--proof-checker ./.github/scripts/check_proof_object.py",
            "ci.yml proof-mode-independent-gate",
        )

    # Release gate contract
    release_gate = job_block(release, "release-corpus-certification-gate")
    if not release_gate:
        errors.append("release-certification.yml: missing `release-corpus-certification-gate` job.")
    else:
        ensure_contains(
            errors,
            release_gate,
            "runs-on: ubuntu-22.04",
            "release-certification.yml release-corpus-certification-gate",
        )
        for pin in PIN_LINES:
            ensure_contains(
                errors,
                release_gate,
                pin,
                "release-certification.yml release-corpus-certification-gate",
            )
        ensure_contains(
            errors,
            release_gate,
            "run: ./.github/scripts/verify_pinned_env.sh",
            "release-certification.yml release-corpus-certification-gate",
        )
        ensure_contains(
            errors,
            release_gate,
            "./scripts/certify-corpus.sh",
            "release-certification.yml release-corpus-certification-gate",
        )
        ensure_not_contains(
            errors,
            release_gate,
            "cargo run -p tarsier-cli -- cert-suite",
            "release-certification.yml release-corpus-certification-gate",
        )

    release_proof_gate = job_block(release, "release-proof-independent-gate")
    if not release_proof_gate:
        errors.append("release-certification.yml: missing `release-proof-independent-gate` job.")
    else:
        ensure_contains(
            errors,
            release_proof_gate,
            "needs:",
            "release-certification.yml release-proof-independent-gate",
        )
        ensure_contains(
            errors,
            release_proof_gate,
            "- release-corpus-certification-gate",
            "release-certification.yml release-proof-independent-gate",
        )
        ensure_contains(
            errors,
            release_proof_gate,
            "TARSIER_REQUIRE_CARCARA: \"1\"",
            "release-certification.yml release-proof-independent-gate",
        )
        ensure_contains(
            errors,
            release_proof_gate,
            "--profile high-assurance",
            "release-certification.yml release-proof-independent-gate",
        )
        ensure_contains(
            errors,
            release_proof_gate,
            "--proof-checker ./.github/scripts/check_proof_object.py",
            "release-certification.yml release-proof-independent-gate",
        )

    # Release workflow must gate on version tags.
    if 'tags:\n      - "v*"' not in release:
        errors.append("release-certification.yml must trigger on tags `v*`.")

    # V2-09: Verify beginner-ux-gate job exists, calls smoke script, and depends on build-test.
    ci_beginner_gate = job_block(ci, "beginner-ux-gate")
    if not ci_beginner_gate:
        errors.append("ci.yml: missing `beginner-ux-gate` job.")
    else:
        ensure_contains(
            errors,
            ci_beginner_gate,
            "./scripts/beginner-ux-smoke.sh",
            "ci.yml beginner-ux-gate",
        )
        if "build-test" not in ci_beginner_gate:
            errors.append("ci.yml beginner-ux-gate: must depend on `build-test`")

    # V2-09: Verify proof-mode-independent-gate depends on build-test.
    if ci_proof_gate:
        if "build-test" not in ci_proof_gate:
            errors.append("ci.yml proof-mode-independent-gate: must depend on `build-test`")

    # Supply-chain audit gate contract.
    ci_supply_chain = job_block(ci, "supply-chain-audit")
    if not ci_supply_chain:
        errors.append("ci.yml: missing `supply-chain-audit` job.")
    else:
        ensure_contains(
            errors,
            ci_supply_chain,
            "cargo deny check",
            "ci.yml supply-chain-audit",
        )

    # Release binaries: verify job must exist and gate the release job.
    release_binaries_path = ROOT / ".github" / "workflows" / "release-binaries.yml"
    if release_binaries_path.exists():
        release_binaries = load(release_binaries_path)
        release_verify = job_block(release_binaries, "verify")
        if not release_verify:
            errors.append("release-binaries.yml: missing `verify` job.")
        else:
            ensure_contains(
                errors,
                release_verify,
                "cosign verify-blob",
                "release-binaries.yml verify",
            )
        release_release = job_block(release_binaries, "release")
        if release_release:
            ensure_contains(
                errors,
                release_release,
                "verify",
                "release-binaries.yml release (must depend on verify)",
            )
    else:
        errors.append("release-binaries.yml: missing workflow file.")

    # Release doc sync contracts must be enforced in CI.
    ci_build = job_block(ci, "build-test")
    if ci_build:
        ensure_contains(
            errors,
            ci_build,
            "check_release_doc_sync.py",
            "ci.yml build-test",
        )
        ensure_contains(
            errors,
            ci_build,
            "check_release_doc_refs.py",
            "ci.yml build-test",
        )
        ensure_contains(
            errors,
            ci_build,
            "check_doc_consistency.py",
            "ci.yml build-test",
        )

    # V2-09: Verify schema version consistency between schema doc and main.rs.
    schema_path = ROOT / "docs" / "analysis-report-schema-v1.json"
    main_rs_path = ROOT / "crates" / "tarsier-cli" / "src" / "main.rs"
    if schema_path.exists() and main_rs_path.exists():
        schema_text = schema_path.read_text(encoding="utf-8")
        main_text = main_rs_path.read_text(encoding="utf-8")
        if '"const": "v1"' not in schema_text:
            errors.append(
                "docs/analysis-report-schema-v1.json: schema_version const should be 'v1'."
            )
        if 'schema_version: "v1".to_string()' not in main_text:
            errors.append(
                "main.rs: schema_version should be set to 'v1'."
            )
    elif not schema_path.exists():
        errors.append("docs/analysis-report-schema-v1.json: missing schema file.")

    return fail(errors)


if __name__ == "__main__":
    sys.exit(main())
