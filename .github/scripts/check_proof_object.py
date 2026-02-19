#!/usr/bin/env python3
"""Minimal proof-object checker used in CI and trusted certificate replay.

This checker intentionally stays small and solver-focused:
- supports z3 and cvc5 proof objects emitted by `(get-proof)`
- validates expected UNSAT prefix and basic structural sanity
"""

from __future__ import annotations

import argparse
import pathlib
import sys

SUPPORTED_SOLVERS = {"z3", "cvc5"}


def normalize_token(token: str) -> str:
    return "".join(ch for ch in token if ch.isalpha()).lower()


def first_token(text: str) -> str:
    for line in text.splitlines():
        for token in line.split():
            if token:
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

    if not proof_text.strip():
        return fail("proof text is empty")

    result = normalize_token(first_token(proof_text))
    if result != "unsat":
        return fail(f"expected UNSAT proof output prefix, got '{result or 'empty'}'")

    lowered = proof_text.lower()
    if "error" in lowered or "unsupported" in lowered:
        return fail("proof text contains solver error markers")

    if "(" not in proof_text or not balanced_parentheses(proof_text):
        return fail("proof text is not a balanced s-expression")

    print(f"proof-check ok solver={solver} smt2={smt2_path} proof={proof_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
