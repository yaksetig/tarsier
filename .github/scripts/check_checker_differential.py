#!/usr/bin/env python3
"""Differential checker regression gate.

Compares outcome parity between:
  - Legacy checker path: `tarsier check-certificate`
  - Tiny standalone checker: `tarsier-certcheck`

Any divergence fails unless explicitly allowlisted with rationale.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CORPUS_DEFAULT = ROOT / "docs" / "checker-differential-corpus-v1.json"
ALLOWLIST_DEFAULT = ROOT / "docs" / "checker-differential-allowlist-v1.json"
DOMAIN_TAG = "tarsier-certificate-v2\n"


@dataclass
class CaseResult:
    case_id: str
    fixture: str
    options: list[str]
    legacy_exit: int
    tiny_exit: int
    legacy_status: str
    tiny_status: str
    legacy_stdout: str
    legacy_stderr: str
    tiny_stdout: str
    tiny_stderr: str
    diverged: bool
    allowlisted: bool
    allowlist_rationale: str | None


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_bundle_sha256(metadata: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(DOMAIN_TAG.encode("utf-8"))
    h.update(metadata["kind"].encode("utf-8"))
    h.update(b"\n")
    h.update(metadata["protocol_file"].encode("utf-8"))
    h.update(b"\n")
    h.update(metadata["proof_engine"].encode("utf-8"))
    h.update(b"\n")
    induction_k = metadata.get("induction_k")
    if induction_k is None:
        h.update(b"none")
    else:
        h.update(str(induction_k).encode("utf-8"))
    h.update(b"\n")
    h.update(metadata["solver_used"].encode("utf-8"))
    h.update(b"\n")
    h.update(metadata["soundness"].encode("utf-8"))
    h.update(b"\n")
    h.update((metadata.get("fairness") or "").encode("utf-8"))
    h.update(b"\n")
    for bound in metadata.get("committee_bounds", []):
        h.update(str(bound[0]).encode("utf-8"))
        h.update(b"=")
        h.update(str(bound[1]).encode("utf-8"))
        h.update(b"\n")
    for obligation in metadata.get("obligations", []):
        h.update(obligation["name"].encode("utf-8"))
        h.update(b"|")
        h.update(obligation["expected"].encode("utf-8"))
        h.update(b"|")
        h.update(obligation["file"].encode("utf-8"))
        h.update(b"|")
        h.update(obligation.get("sha256", "").encode("utf-8"))
        h.update(b"|")
        h.update(obligation.get("proof_file", "").encode("utf-8"))
        h.update(b"|")
        h.update(obligation.get("proof_sha256", "").encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_valid_kinduction_bundle(bundle_dir: Path) -> None:
    script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n"
    script_hash = sha256_hex(script.encode("utf-8"))
    (bundle_dir / "base_case.smt2").write_text(script, encoding="utf-8")
    (bundle_dir / "inductive_step.smt2").write_text(script, encoding="utf-8")
    metadata: dict[str, Any] = {
        "schema_version": 2,
        "kind": "safety_proof",
        "protocol_file": "protocol.trs",
        "proof_engine": "kinduction",
        "induction_k": 2,
        "solver_used": "z3",
        "soundness": "strict",
        "fairness": None,
        "committee_bounds": [],
        "bundle_sha256": None,
        "obligations": [
            {
                "name": "base_case",
                "expected": "unsat",
                "file": "base_case.smt2",
                "sha256": script_hash,
            },
            {
                "name": "inductive_step",
                "expected": "unsat",
                "file": "inductive_step.smt2",
                "sha256": script_hash,
            },
        ],
    }
    metadata["bundle_sha256"] = compute_bundle_sha256(metadata)
    write_json(bundle_dir / "certificate.json", metadata)


def write_tampered_kinduction_obligation_bundle(bundle_dir: Path) -> None:
    write_valid_kinduction_bundle(bundle_dir)
    # Tamper after metadata hash is sealed.
    tampered = "(set-logic QF_LIA)\n(assert true)\n(check-sat)\n(exit)\n"
    (bundle_dir / "base_case.smt2").write_text(tampered, encoding="utf-8")


def write_valid_fair_liveness_bundle(bundle_dir: Path) -> None:
    script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n"
    script_hash = sha256_hex(script.encode("utf-8"))
    (bundle_dir / "init_implies_inv.smt2").write_text(script, encoding="utf-8")
    (bundle_dir / "inv_and_transition_implies_inv_prime.smt2").write_text(
        script, encoding="utf-8"
    )
    (bundle_dir / "inv_implies_no_fair_bad.smt2").write_text(script, encoding="utf-8")
    metadata: dict[str, Any] = {
        "schema_version": 2,
        "kind": "fair_liveness_proof",
        "protocol_file": "protocol.trs",
        "proof_engine": "pdr",
        "induction_k": 5,
        "solver_used": "z3",
        "soundness": "strict",
        "fairness": "weak",
        "committee_bounds": [],
        "bundle_sha256": None,
        "obligations": [
            {
                "name": "init_implies_inv",
                "expected": "unsat",
                "file": "init_implies_inv.smt2",
                "sha256": script_hash,
            },
            {
                "name": "inv_and_transition_implies_inv_prime",
                "expected": "unsat",
                "file": "inv_and_transition_implies_inv_prime.smt2",
                "sha256": script_hash,
            },
            {
                "name": "inv_implies_no_fair_bad",
                "expected": "unsat",
                "file": "inv_implies_no_fair_bad.smt2",
                "sha256": script_hash,
            },
        ],
    }
    metadata["bundle_sha256"] = compute_bundle_sha256(metadata)
    write_json(bundle_dir / "certificate.json", metadata)


def write_invalid_fair_missing_obligation_bundle(bundle_dir: Path) -> None:
    script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n"
    script_hash = sha256_hex(script.encode("utf-8"))
    (bundle_dir / "init_implies_inv.smt2").write_text(script, encoding="utf-8")
    (bundle_dir / "inv_and_transition_implies_inv_prime.smt2").write_text(
        script, encoding="utf-8"
    )
    # Missing inv_implies_no_fair_bad on purpose.
    metadata: dict[str, Any] = {
        "schema_version": 2,
        "kind": "fair_liveness_proof",
        "protocol_file": "protocol.trs",
        "proof_engine": "pdr",
        "induction_k": 5,
        "solver_used": "z3",
        "soundness": "strict",
        "fairness": "weak",
        "committee_bounds": [],
        "bundle_sha256": None,
        "obligations": [
            {
                "name": "init_implies_inv",
                "expected": "unsat",
                "file": "init_implies_inv.smt2",
                "sha256": script_hash,
            },
            {
                "name": "inv_and_transition_implies_inv_prime",
                "expected": "unsat",
                "file": "inv_and_transition_implies_inv_prime.smt2",
                "sha256": script_hash,
            },
        ],
    }
    metadata["bundle_sha256"] = compute_bundle_sha256(metadata)
    write_json(bundle_dir / "certificate.json", metadata)


def build_fixture(bundle_dir: Path, fixture: str) -> None:
    if fixture == "valid_kinduction":
        write_valid_kinduction_bundle(bundle_dir)
        return
    if fixture == "tampered_kinduction_obligation":
        write_tampered_kinduction_obligation_bundle(bundle_dir)
        return
    if fixture == "valid_fair_liveness":
        write_valid_fair_liveness_bundle(bundle_dir)
        return
    if fixture == "invalid_fair_missing_obligation":
        write_invalid_fair_missing_obligation_bundle(bundle_dir)
        return
    raise ValueError(f"Unknown fixture '{fixture}'")


def write_mock_solver(path: Path) -> None:
    script = "#!/usr/bin/env bash\necho unsat\n"
    path.write_text(script, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def run_command(cmd: list[str], cwd: Path) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def classify_status(code: int) -> str:
    return "pass" if code == 0 else "fail"


def validate_corpus(corpus: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if corpus.get("schema_version") != 1:
        errors.append("corpus schema_version must be 1")
    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append("corpus cases must be a non-empty list")
        return errors
    seen: set[str] = set()
    for idx, case in enumerate(cases):
        cid = case.get("id")
        fixture = case.get("fixture")
        if not isinstance(cid, str) or not cid.strip():
            errors.append(f"cases[{idx}].id must be non-empty string")
        elif cid in seen:
            errors.append(f"duplicate case id '{cid}'")
        else:
            seen.add(cid)
        if fixture not in {
            "valid_kinduction",
            "tampered_kinduction_obligation",
            "valid_fair_liveness",
            "invalid_fair_missing_obligation",
        }:
            errors.append(
                f"cases[{idx}].fixture must be one of known fixtures; got {fixture!r}"
            )
        options = case.get("options", [])
        if not isinstance(options, list) or not all(
            isinstance(opt, str) and opt.strip() for opt in options
        ):
            errors.append(f"cases[{idx}].options must be a list of non-empty strings")
    return errors


def validate_allowlist(allowlist: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if allowlist.get("schema_version") != 1:
        errors.append("allowlist schema_version must be 1")
    entries = allowlist.get("divergences")
    if not isinstance(entries, list):
        errors.append("allowlist divergences must be a list")
        return errors
    for idx, entry in enumerate(entries):
        if not isinstance(entry.get("case_id"), str) or not entry["case_id"].strip():
            errors.append(f"divergences[{idx}].case_id must be non-empty string")
        if entry.get("legacy") not in {"pass", "fail"}:
            errors.append(f"divergences[{idx}].legacy must be pass/fail")
        if entry.get("tiny") not in {"pass", "fail"}:
            errors.append(f"divergences[{idx}].tiny must be pass/fail")
        rationale = entry.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            errors.append(f"divergences[{idx}].rationale must be non-empty string")
    return errors


def lookup_allowlist(
    allowlist: dict[str, Any], case_id: str, legacy: str, tiny: str
) -> str | None:
    for entry in allowlist.get("divergences", []):
        if (
            entry.get("case_id") == case_id
            and entry.get("legacy") == legacy
            and entry.get("tiny") == tiny
        ):
            return entry.get("rationale")
    return None


def ensure_binaries() -> tuple[Path, Path]:
    build_cmd = ["cargo", "build", "-p", "tarsier-cli", "-p", "tarsier-certcheck"]
    print("[info] building checker binaries:", " ".join(build_cmd))
    rc, out, err = run_command(build_cmd, ROOT)
    if rc != 0:
        sys.stderr.write(out)
        sys.stderr.write(err)
        raise RuntimeError("failed to build checker binaries")
    suffix = ".exe" if sys.platform.startswith("win") else ""
    legacy = ROOT / "target" / "debug" / f"tarsier{suffix}"
    tiny = ROOT / "target" / "debug" / f"tarsier-certcheck{suffix}"
    if not legacy.exists():
        raise RuntimeError(f"missing legacy checker binary: {legacy}")
    if not tiny.exists():
        raise RuntimeError(f"missing tiny checker binary: {tiny}")
    return legacy, tiny


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS_DEFAULT)
    parser.add_argument("--allowlist", type=Path, default=ALLOWLIST_DEFAULT)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    corpus = load_json(args.corpus)
    allowlist = load_json(args.allowlist)
    errors = validate_corpus(corpus) + validate_allowlist(allowlist)
    if errors:
        print("Checker differential corpus validation FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    try:
        legacy_bin, tiny_bin = ensure_binaries()
    except RuntimeError as exc:
        print(f"Checker differential gate FAILED: {exc}")
        return 1

    temp_root = Path(tempfile.mkdtemp(prefix="tarsier_checker_diff_"))
    results: list[CaseResult] = []
    case_errors: list[str] = []
    observed_divergence_keys: set[tuple[str, str, str]] = set()
    try:
        for case in corpus["cases"]:
            case_id = case["id"]
            fixture = case["fixture"]
            options = case.get("options", [])
            case_dir = temp_root / case_id
            bundle_dir = case_dir / "bundle"
            bundle_dir.mkdir(parents=True, exist_ok=True)
            build_fixture(bundle_dir, fixture)
            solver_path = case_dir / "mock_solver.sh"
            write_mock_solver(solver_path)

            legacy_cmd = [
                str(legacy_bin),
                "check-certificate",
                str(bundle_dir),
                "--solvers",
                str(solver_path),
            ] + options
            tiny_cmd = [str(tiny_bin), str(bundle_dir), "--solvers", str(solver_path)] + options

            legacy_exit, legacy_stdout, legacy_stderr = run_command(legacy_cmd, ROOT)
            tiny_exit, tiny_stdout, tiny_stderr = run_command(tiny_cmd, ROOT)
            legacy_status = classify_status(legacy_exit)
            tiny_status = classify_status(tiny_exit)
            diverged = legacy_status != tiny_status
            allowlisted = False
            rationale: str | None = None
            if diverged:
                rationale = lookup_allowlist(allowlist, case_id, legacy_status, tiny_status)
                if rationale is None:
                    case_errors.append(
                        f"unexpected checker divergence for case '{case_id}': "
                        f"legacy={legacy_status}, tiny={tiny_status}"
                    )
                else:
                    allowlisted = True
                    observed_divergence_keys.add((case_id, legacy_status, tiny_status))

            results.append(
                CaseResult(
                    case_id=case_id,
                    fixture=fixture,
                    options=options,
                    legacy_exit=legacy_exit,
                    tiny_exit=tiny_exit,
                    legacy_status=legacy_status,
                    tiny_status=tiny_status,
                    legacy_stdout=legacy_stdout,
                    legacy_stderr=legacy_stderr,
                    tiny_stdout=tiny_stdout,
                    tiny_stderr=tiny_stderr,
                    diverged=diverged,
                    allowlisted=allowlisted,
                    allowlist_rationale=rationale,
                )
            )

        # Reject stale allowlist entries without a currently observed divergence.
        for entry in allowlist.get("divergences", []):
            key = (entry["case_id"], entry["legacy"], entry["tiny"])
            if key not in observed_divergence_keys:
                case_errors.append(
                    "stale allowlist entry without matching divergence: "
                    f"case_id={entry['case_id']} legacy={entry['legacy']} tiny={entry['tiny']}"
                )

        report = {
            "schema_version": 1,
            "corpus": str(args.corpus),
            "allowlist": str(args.allowlist),
            "cases": [
                {
                    "id": r.case_id,
                    "fixture": r.fixture,
                    "options": r.options,
                    "legacy_exit": r.legacy_exit,
                    "tiny_exit": r.tiny_exit,
                    "legacy_status": r.legacy_status,
                    "tiny_status": r.tiny_status,
                    "diverged": r.diverged,
                    "allowlisted": r.allowlisted,
                    "allowlist_rationale": r.allowlist_rationale,
                }
                for r in results
            ],
            "errors": case_errors,
        }
        if args.out is not None:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            write_json(args.out, report)

        for r in results:
            tag = "PASS" if not r.diverged or r.allowlisted else "FAIL"
            print(
                f"[{tag}] {r.case_id}: legacy={r.legacy_status} tiny={r.tiny_status}"
                + (
                    f" (allowlisted: {r.allowlist_rationale})"
                    if r.allowlisted and r.allowlist_rationale
                    else ""
                )
            )

        if case_errors:
            print("Checker differential gate FAILED:")
            for err in case_errors:
                print(f"  - {err}")
            return 1

        print(
            f"Checker differential gate passed ({len(results)} cases, "
            f"{sum(1 for r in results if r.diverged)} divergences, "
            f"{sum(1 for r in results if r.allowlisted)} allowlisted)."
        )
        return 0
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
