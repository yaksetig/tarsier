#!/usr/bin/env python3
"""Validate release documentation is in sync with workflows and repo state.

Checks:
  1. rust-toolchain.toml exists and its channel matches workflow pins.
  2. Pinned versions in docs match workflow env vars.
  3. Required infrastructure files exist.
  4. Release workflows trigger on v* tags.
  5. RELEASE_PROCESS.md and RELEASE_CHECKLIST.md are consistent with each other.

Exits with code 1 on any violation.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]

# --- File paths ---
RUST_TOOLCHAIN = ROOT / "rust-toolchain.toml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_CERT_WORKFLOW = ROOT / ".github" / "workflows" / "release-certification.yml"
RELEASE_BIN_WORKFLOW = ROOT / ".github" / "workflows" / "release-binaries.yml"
RELEASE_CHECKLIST = ROOT / "docs" / "RELEASE_CHECKLIST.md"
RELEASE_PROCESS = ROOT / "docs" / "RELEASE_PROCESS.md"

# Files that must exist for a valid release infrastructure.
REQUIRED_FILES = [
    ROOT / "rust-toolchain.toml",
    ROOT / "docs" / "CHANGELOG.md",
    ROOT / "SECURITY.md",
    ROOT / "deny.toml",
    ROOT / "docs" / "RELEASE_CHECKLIST.md",
    ROOT / "docs" / "RELEASE_PROCESS.md",
    ROOT / ".github" / "scripts" / "verify_pinned_env.sh",
    ROOT / ".github" / "scripts" / "install_solvers.sh",
    ROOT / ".github" / "scripts" / "install_proof_checkers.sh",
    ROOT / ".github" / "scripts" / "check_certification_gate_contract.py",
    ROOT / "scripts" / "certify-corpus.sh",
    ROOT / "scripts" / "verify-release-artifacts.sh",
    ROOT / "docs" / "INTERPRETATION_MATRIX.md",
]


def load(path: Path) -> str:
    """Read file contents, raising on missing files."""
    if not path.exists():
        raise FileNotFoundError(f"missing: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def extract_toolchain_channel(text: str) -> str | None:
    """Extract channel value from rust-toolchain.toml."""
    m = re.search(r'^channel\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return m.group(1) if m else None


def extract_workflow_rustc_pin(text: str) -> str | None:
    """Extract EXPECTED_RUSTC value from a workflow file."""
    m = re.search(r'EXPECTED_RUSTC:\s*"([^"]+)"', text)
    return m.group(1) if m else None


def extract_workflow_toolchain_pin(text: str) -> str | None:
    """Extract toolchain: value from dtolnay/rust-toolchain@master step."""
    m = re.search(r'toolchain:\s*(\S+)', text)
    return m.group(1) if m else None


def extract_doc_rust_version(text: str) -> str | None:
    """Extract Rust version mentioned in release docs."""
    # Match patterns like "Rust toolchain: `1.92.0`" or "1.92.0"
    m = re.search(r'Rust toolchain:?\s*`?(\d+\.\d+\.\d+)', text)
    return m.group(1) if m else None


def extract_doc_z3_version(text: str) -> str | None:
    m = re.search(r'Z3:?\s*`?(\d+\.\d+\.\d+)', text)
    return m.group(1) if m else None


def extract_doc_cvc5_version(text: str) -> str | None:
    m = re.search(r'cvc5:?\s*`?(\d+\.\d+\.\d+)', text)
    return m.group(1) if m else None


def extract_workflow_z3_pin(text: str) -> str | None:
    m = re.search(r'EXPECTED_Z3:\s*"([^"]+)"', text)
    return m.group(1) if m else None


def extract_workflow_cvc5_pin(text: str) -> str | None:
    m = re.search(r'EXPECTED_CVC5:\s*"([^"]+)"', text)
    return m.group(1) if m else None


def main() -> int:
    errors: list[str] = []

    # 1. Check required files exist.
    for path in REQUIRED_FILES:
        if not path.exists():
            errors.append(f"required file missing: {path.relative_to(ROOT)}")

    # Early exit if critical files are missing.
    critical_missing = not RUST_TOOLCHAIN.exists() or not RELEASE_CERT_WORKFLOW.exists()
    if critical_missing:
        print("Release doc sync check FAILED (critical files missing):")
        for err in errors:
            print(f"  - {err}")
        return 1

    # Load all files.
    toolchain_text = load(RUST_TOOLCHAIN)
    ci_text = load(CI_WORKFLOW)
    release_cert_text = load(RELEASE_CERT_WORKFLOW)
    checklist_text = load(RELEASE_CHECKLIST)
    process_text = load(RELEASE_PROCESS)

    # 2. rust-toolchain.toml channel must match workflow pins.
    tc_channel = extract_toolchain_channel(toolchain_text)
    if tc_channel is None:
        errors.append("rust-toolchain.toml: missing `channel` field")
    else:
        # Check against release-certification.yml EXPECTED_RUSTC
        wf_rustc = extract_workflow_rustc_pin(release_cert_text)
        if wf_rustc and wf_rustc != tc_channel:
            errors.append(
                f"version mismatch: rust-toolchain.toml channel={tc_channel} "
                f"vs release-certification.yml EXPECTED_RUSTC={wf_rustc}"
            )

        # Check against release-certification.yml toolchain: pin
        wf_toolchain = extract_workflow_toolchain_pin(release_cert_text)
        if wf_toolchain and wf_toolchain != tc_channel:
            errors.append(
                f"version mismatch: rust-toolchain.toml channel={tc_channel} "
                f"vs release-certification.yml toolchain={wf_toolchain}"
            )

        # Check against CI corpus-certification-gate EXPECTED_RUSTC
        ci_rustc = extract_workflow_rustc_pin(ci_text)
        if ci_rustc and ci_rustc != tc_channel:
            errors.append(
                f"version mismatch: rust-toolchain.toml channel={tc_channel} "
                f"vs ci.yml EXPECTED_RUSTC={ci_rustc}"
            )

    # 3. Doc versions must match workflow versions.
    doc_rust = extract_doc_rust_version(process_text)
    if doc_rust and tc_channel and doc_rust != tc_channel:
        errors.append(
            f"version mismatch: RELEASE_PROCESS.md Rust={doc_rust} "
            f"vs rust-toolchain.toml channel={tc_channel}"
        )

    wf_z3 = extract_workflow_z3_pin(release_cert_text)
    doc_z3 = extract_doc_z3_version(process_text)
    if wf_z3 and doc_z3 and wf_z3 != doc_z3:
        errors.append(
            f"version mismatch: RELEASE_PROCESS.md Z3={doc_z3} "
            f"vs release-certification.yml EXPECTED_Z3={wf_z3}"
        )

    wf_cvc5 = extract_workflow_cvc5_pin(release_cert_text)
    doc_cvc5 = extract_doc_cvc5_version(process_text)
    if wf_cvc5 and doc_cvc5 and wf_cvc5 != doc_cvc5:
        errors.append(
            f"version mismatch: RELEASE_PROCESS.md cvc5={doc_cvc5} "
            f"vs release-certification.yml EXPECTED_CVC5={wf_cvc5}"
        )

    # 4. Release workflows must trigger on v* tags.
    if RELEASE_CERT_WORKFLOW.exists():
        if 'tags:\n      - "v*"' not in release_cert_text:
            errors.append("release-certification.yml: must trigger on tags v*")

    if RELEASE_BIN_WORKFLOW.exists():
        release_bin_text = load(RELEASE_BIN_WORKFLOW)
        if 'tags:\n      - "v*"' not in release_bin_text:
            errors.append("release-binaries.yml: must trigger on tags v*")

    # 5. RELEASE_CHECKLIST.md should reference docs/CHANGELOG.md (not bare CHANGELOG.md).
    if "Update `CHANGELOG.md`" in checklist_text:
        errors.append(
            "RELEASE_CHECKLIST.md: references bare `CHANGELOG.md` — should be `docs/CHANGELOG.md`"
        )

    # 6. Both docs should mention the same Rust version.
    checklist_rust = extract_doc_rust_version(checklist_text)
    if checklist_rust and tc_channel and checklist_rust != tc_channel:
        errors.append(
            f"version mismatch: RELEASE_CHECKLIST.md Rust={checklist_rust} "
            f"vs rust-toolchain.toml channel={tc_channel}"
        )

    # 7. Proof replay protocol files in checklist must match release workflow.
    # The checklist and release workflow must both reference the same protocol files.
    for protocol in [
        "examples/reliable_broadcast.trs",
        "examples/library/pbft_liveness_safe_ci.trs",
    ]:
        if protocol not in checklist_text:
            errors.append(f"RELEASE_CHECKLIST.md: missing proof replay protocol `{protocol}`")
        if protocol not in release_cert_text:
            errors.append(
                f"release-certification.yml: missing proof replay protocol `{protocol}`"
            )

    # 8. Key certcheck flags must appear in both checklist and release workflow.
    for flag in ["--profile high-assurance", "--solvers z3,cvc5", "--json-report"]:
        if flag not in checklist_text:
            errors.append(f"RELEASE_CHECKLIST.md: missing certcheck flag `{flag}`")
        if flag not in release_cert_text:
            errors.append(
                f"release-certification.yml: missing certcheck flag `{flag}`"
            )

    if errors:
        print("Release doc sync check FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("Release doc sync check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
