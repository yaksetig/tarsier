#!/usr/bin/env bash
set -euo pipefail

# Cross-check quantitative formulas against known analytic baselines.
# These tests intentionally use exact names so CI fails if they are removed/renamed.
tests=(
  "cross_check_pbft_message_complexity_is_quadratic"
  "cross_check_reliable_broadcast_message_complexity"
  "cross_check_geometric_finality_formula"
  "cross_check_hypergeometric_committee_b_max"
  "cross_check_crash_fault_model_has_zero_adversary_injection"
)

for test_name in "${tests[@]}"; do
  echo ">>> Running quantitative baseline: ${test_name}"
  cargo test -p tarsier-engine "${test_name}" -- --exact --nocapture
done

echo "Quantitative baseline cross-checks passed (${#tests[@]} tests)."
