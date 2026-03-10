#!/usr/bin/env bash
# CI guardrail: ban panic!/unwrap()/expect() in tarsier-engine production code.
# Allowlist: test modules, test files, and the single unreachable!() in cegar.rs.
#
# Usage: scripts/check-engine-no-panic.sh
# Exit code: 0 if clean, 1 if violations found.

set -euo pipefail

ENGINE_SRC="crates/tarsier-engine/src"

# Known allowlist entries (file:line patterns that are acceptable).
# Each entry is a grep -F pattern matched against "file:line" output.
ALLOWLIST=(
  "pipeline/verification/cegar.rs:1435"  # unreachable!() in dead match arm
)

# Search for panic-family calls, excluding test files entirely.
violations=$(
  grep -rn \
    -e '\.unwrap()' \
    -e '\.expect(' \
    -e 'panic!(' \
    -e 'unreachable!(' \
    -e 'unimplemented!(' \
    -e 'todo!(' \
    "$ENGINE_SRC" \
    --include='*.rs' \
  | grep -v 'tests\.rs:' \
  | grep -v '_tests\.rs:' \
  | grep -v 'test_.*\.rs:' \
  | grep -v 'property_pipeline_unit_tests' \
  | grep -v '#\[cfg(test)\]' \
  | grep -v '#\[test\]' \
  | grep -v '\.unwrap_or' \
  | grep -v '\.unwrap_or_else' \
  | grep -v '\.unwrap_or_default' \
  | grep -v 'unwrap_none' \
  | grep -v '// ' \
  || true
)

if [ -z "$violations" ]; then
  echo "✓ No panic-family calls in tarsier-engine production code."
  exit 0
fi

# Filter out allowlisted entries.
filtered=""
while IFS= read -r line; do
  allowed=false
  for pattern in "${ALLOWLIST[@]}"; do
    if echo "$line" | grep -qF "$pattern"; then
      allowed=true
      break
    fi
  done
  if [ "$allowed" = false ]; then
    # Extra check: is this line inside a #[cfg(test)] module?
    # We do a rough heuristic: check if there's a #[cfg(test)] above in the same file.
    file=$(echo "$line" | cut -d: -f1)
    lineno=$(echo "$line" | cut -d: -f2)
    # Check if we're inside a test module by looking for #[cfg(test)] before this line.
    test_mod_line=$(grep -n '#\[cfg(test)\]' "$file" 2>/dev/null | tail -1 | cut -d: -f1 || echo "99999")
    if [ "$lineno" -gt "$test_mod_line" ] 2>/dev/null; then
      # This line is after the last #[cfg(test)], likely in a test module.
      continue
    fi
    filtered="${filtered}${line}\n"
  fi
done <<< "$violations"

# Remove trailing newline
filtered=$(echo -e "$filtered" | sed '/^$/d')

if [ -z "$filtered" ]; then
  echo "✓ No panic-family calls in tarsier-engine production code (allowlist applied)."
  exit 0
fi

echo "✗ Found panic-family calls in tarsier-engine production code:"
echo ""
echo "$filtered"
echo ""
echo "If these are intentional, add them to the ALLOWLIST in scripts/check-engine-no-panic.sh"
exit 1
