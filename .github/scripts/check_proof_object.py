#!/usr/bin/env python3
"""Proof-object checker used in CI and trusted certificate replay.

Validation layers:
- structural proof-object sanity checks (all solvers)
- solver-backed proof replay checks (all solvers)
- optional external Alethe checking via Carcara (cvc5)

Environment knobs:
- TARSIER_CARCARA_BIN: explicit `carcara` path
- TARSIER_REQUIRE_CARCARA=1: fail cvc5 checks if Carcara is unavailable
"""

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

SUPPORTED_SOLVERS = {"z3", "cvc5"}


def normalize_token(token: str) -> str:
    return "".join(ch for ch in token if ch.isalpha()).lower()


def first_nonempty_token(text: str) -> str:
    for line in text.splitlines():
        for token in line.split():
            if token:
                return token
    return ""


def parse_result_prefix(text: str) -> str:
    token = normalize_token(first_nonempty_token(text))
    if token in {"sat", "unsat", "unknown"}:
        return token
    return ""


def balanced_parentheses(text: str) -> bool:
    balance = 0
    for ch in text:
        if ch == "(":
            balance += 1
        elif ch == ")":
            balance -= 1
            if balance < 0:
                return False
    return balance == 0


def fail(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 2


def run(
    cmd: list[str], *, stdin_text: str | None = None, timeout_secs: int = 120
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            input=stdin_text,
            text=True,
            capture_output=True,
            timeout=timeout_secs,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"command not found: {cmd[0]}") from exc


def augment_query_for_proof(script: str) -> str:
    # Obligations already include (check-sat) and (exit); strip exit and add get-proof.
    body = script.replace("(exit)\n", "").replace("(exit)", "")
    out = "(set-option :produce-proofs true)\n"
    out += body
    if "(check-sat)" not in body:
        out += "\n(check-sat)\n"
    out += "(get-proof)\n"
    out += "(exit)\n"
    return out


def extract_proof_payload(proof_text: str) -> str:
    # Proof streams are expected to start with `unsat` and then a proof s-expression.
    first_paren = proof_text.find("(")
    if first_paren < 0:
        return ""
    return proof_text[first_paren:].strip()


def check_structural_proof_object(proof_text: str) -> tuple[bool, str]:
    if not proof_text.strip():
        return False, "proof text is empty"

    result = parse_result_prefix(proof_text)
    if result != "unsat":
        return False, f"expected UNSAT proof output prefix, got '{result or 'empty'}'"

    lowered = proof_text.lower()
    if "error" in lowered or "unsupported" in lowered:
        return False, "proof text contains solver error markers"

    payload = extract_proof_payload(proof_text)
    if not payload:
        return False, "proof text does not contain an s-expression payload"
    if not balanced_parentheses(payload):
        return False, "proof payload is not a balanced s-expression"
    return True, ""


def resolve_carcara() -> pathlib.Path | None:
    explicit = os.environ.get("TARSIER_CARCARA_BIN")
    if explicit:
        path = pathlib.Path(explicit)
        if path.exists():
            return path
        return None
    which = shutil.which("carcara")
    return pathlib.Path(which) if which else None


def require_carcara() -> bool:
    raw = os.environ.get("TARSIER_REQUIRE_CARCARA", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def check_with_z3_solver_validation(smt2_path: pathlib.Path) -> tuple[bool, str]:
    script = smt2_path.read_text(encoding="utf-8")
    proof_script = augment_query_for_proof(script)

    # z3 can self-check generated proofs with solver.proof.check=true.
    cmd = [
        "z3",
        "-smt2",
        "-in",
        "sat.euf=true",
        "tactic.default_tactic=smt",
        "solver.proof.check=true",
    ]
    try:
        out = run(cmd, stdin_text=proof_script)
    except RuntimeError as exc:
        return False, str(exc)
    if out.returncode != 0:
        return False, f"z3 replay failed: {out.stderr.strip() or out.stdout.strip()}"

    prefix = parse_result_prefix(out.stdout)
    if prefix != "unsat":
        return False, f"z3 replay expected unsat, got '{prefix or 'empty'}'"
    payload = extract_proof_payload(out.stdout)
    if not payload or not balanced_parentheses(payload):
        return False, "z3 replay returned malformed proof payload"
    return True, ""


def check_with_cvc5_solver_validation(smt2_path: pathlib.Path) -> tuple[bool, str]:
    script = smt2_path.read_text(encoding="utf-8")
    proof_script = augment_query_for_proof(script)

    # cvc5 can internally validate generated proofs with --check-proofs.
    cmd = [
        "cvc5",
        "--lang",
        "smt2",
        "--check-proofs",
        "--proof-format-mode=alethe",
        "--proof-granularity=theory-rewrite",
        "--proof-alethe-res-pivots",
        "-",
    ]
    try:
        out = run(cmd, stdin_text=proof_script)
    except RuntimeError as exc:
        return False, str(exc)
    if out.returncode != 0:
        return False, f"cvc5 replay failed: {out.stderr.strip() or out.stdout.strip()}"

    prefix = parse_result_prefix(out.stdout)
    if prefix != "unsat":
        return False, f"cvc5 replay expected unsat, got '{prefix or 'empty'}'"
    payload = extract_proof_payload(out.stdout)
    if not payload or not balanced_parentheses(payload):
        return False, "cvc5 replay returned malformed proof payload"
    return True, ""


def check_cvc5_with_carcara(
    smt2_path: pathlib.Path, proof_text: str
) -> tuple[bool, str, bool]:
    carcara = resolve_carcara()
    if not carcara:
        if require_carcara():
            return (
                False,
                "Carcara required but not found (set TARSIER_CARCARA_BIN or add `carcara` to PATH)",
                False,
            )
        return True, "Carcara unavailable; skipped external Alethe proof check", False

    payload = extract_proof_payload(proof_text)
    if not payload:
        return False, "proof text does not contain an Alethe payload for Carcara", True

    with tempfile.TemporaryDirectory(prefix="tarsier-proof-check-") as tmp:
        proof_file = pathlib.Path(tmp) / "proof.alethe"
        proof_file.write_text(payload + "\n", encoding="utf-8")
        cmd = [
            str(carcara),
            "check",
            "--strict",
            "--lia-via-cvc5",
            str(proof_file),
            str(smt2_path),
        ]
        try:
            out = run(cmd)
        except RuntimeError as exc:
            return False, str(exc), True
        if out.returncode != 0:
            return (
                False,
                f"Carcara rejected cvc5 proof: {out.stderr.strip() or out.stdout.strip()}",
                True,
            )
    return True, "Carcara validated cvc5 Alethe proof", True


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate SMT solver proof objects")
    parser.add_argument("--solver", required=True)
    parser.add_argument("--smt2", required=True)
    parser.add_argument("--proof", required=True)
    args = parser.parse_args()

    solver = args.solver.strip()
    if solver not in SUPPORTED_SOLVERS:
        return fail(f"unsupported solver '{solver}' (supported: z3,cvc5)")

    smt2_path = pathlib.Path(args.smt2)
    proof_path = pathlib.Path(args.proof)
    if not smt2_path.exists():
        return fail(f"missing smt2 file: {smt2_path}")
    if not proof_path.exists():
        return fail(f"missing proof file: {proof_path}")

    try:
        proof_text = proof_path.read_text(encoding="utf-8")
    except Exception as exc:  # pragma: no cover - defensive
        return fail(f"could not read proof file {proof_path}: {exc}")

    ok, msg = check_structural_proof_object(proof_text)
    if not ok:
        return fail(msg)

    if solver == "z3":
        ok, msg = check_with_z3_solver_validation(smt2_path)
        if not ok:
            return fail(msg)
        print(
            f"proof-check ok solver={solver} mode=structural+z3-self-check smt2={smt2_path} proof={proof_path}"
        )
        return 0

    if solver == "cvc5":
        # Strongest path: external Alethe checker + cvc5 internal proof checking.
        ok, msg, used_carcara = check_cvc5_with_carcara(smt2_path, proof_text)
        if not ok:
            return fail(msg)
        if used_carcara:
            print(msg, file=sys.stderr)
        elif require_carcara():
            return fail(msg)
        else:
            print(msg, file=sys.stderr)

        ok, msg = check_with_cvc5_solver_validation(smt2_path)
        if not ok:
            return fail(msg)
        mode = (
            "structural+carcara+cvc5-self-check"
            if used_carcara
            else "structural+cvc5-self-check"
        )
        print(
            f"proof-check ok solver={solver} mode={mode} smt2={smt2_path} proof={proof_path}"
        )
        return 0

    return fail(f"unsupported solver '{solver}'")


if __name__ == "__main__":
    raise SystemExit(main())
