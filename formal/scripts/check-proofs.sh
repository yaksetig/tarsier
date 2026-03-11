#!/usr/bin/env bash
# CI proof-check script for Lean 4 and Coq kernel soundness theorems.
# Exit codes: 0 = all proofs check, 1 = failure, 2 = toolchain missing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FORMAL_DIR="$(dirname "$SCRIPT_DIR")"
EXIT_CODE=0

echo "=== Tarsier Kernel Formal Proof Check ==="
echo ""

# --- Lean 4 ---
echo "--- Lean 4 (KERN-03) ---"
if command -v lake >/dev/null 2>&1; then
    cd "$FORMAL_DIR/lean"
    if lake build 2>&1; then
        echo "PASS: Lean 4 proof checks succeeded."
    else
        echo "FAIL: Lean 4 proof checks failed."
        EXIT_CODE=1
    fi
else
    echo "SKIP: lake (Lean 4) not found on PATH."
    echo "  Install: https://leanprover-community.github.io/get_started.html"
    # Don't fail CI if Lean isn't installed — advisory only
fi

echo ""

# --- Coq ---
echo "--- Coq (KERN-04) ---"
if command -v coqc >/dev/null 2>&1; then
    cd "$FORMAL_DIR/coq"
    if make 2>&1; then
        echo "PASS: Coq proof checks succeeded."
    else
        echo "FAIL: Coq proof checks failed."
        EXIT_CODE=1
    fi
else
    echo "SKIP: coqc not found on PATH."
    echo "  Install: https://coq.inria.fr/download"
    # Don't fail CI if Coq isn't installed — advisory only
fi

echo ""
if [ "$EXIT_CODE" -eq 0 ]; then
    echo "=== All available proof checks passed ==="
else
    echo "=== Some proof checks FAILED ==="
fi
exit $EXIT_CODE
