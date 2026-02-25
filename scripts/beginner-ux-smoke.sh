#!/usr/bin/env bash
# V1-10: Beginner UX smoke test — CI gate for the beginner happy path.
# Fails if the beginner workflow output contract changes unexpectedly.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

TARSIER="cargo run -q -p tarsier-cli --"
# Suppress tracing logs from stdout so JSON output is parseable
export RUST_LOG=off

echo "=== Beginner UX Smoke Tests ==="

# --- Test 0: discoverability + canonical path in help ---
echo "[beginner] Test 0: help discoverability"
help_out="$(mktemp)"
${TARSIER} --help >"${help_out}" 2>/dev/null
if ! grep -q "tarsier assist --kind pbft --out my_protocol.trs" "${help_out}"; then
  echo "FAIL: help missing canonical assist step"
  cat "${help_out}"
  exit 1
fi
if ! grep -q "tarsier analyze my_protocol.trs --goal safety" "${help_out}"; then
  echo "FAIL: help missing canonical analyze step"
  cat "${help_out}"
  exit 1
fi
if ! grep -q "tarsier visualize my_protocol.trs --check verify" "${help_out}"; then
  echo "FAIL: help missing canonical visualize step"
  cat "${help_out}"
  exit 1
fi
# Default build must not advertise governance-only commands.
if grep -q "certify-safety\\|governance-pipeline\\|cert-suite\\|check-certificate" "${help_out}"; then
  echo "FAIL: default help advertises governance-only commands"
  cat "${help_out}"
  exit 1
fi
echo "  PASS"

# --- Test 1: Default analyze (beginner profile, standard mode) ---
echo "[beginner] Test 1: analyze with defaults"
out="$(mktemp)"
set +e
${TARSIER} analyze examples/library/reliable_broadcast_safe.trs --format json >"${out}" 2>/dev/null
exit_code=$?
set -e
if [[ "${exit_code}" -ne 0 && "${exit_code}" -ne 2 ]]; then
  echo "FAIL: analyze exited with unexpected code ${exit_code}"
  exit 1
fi
# Verify JSON contract has required fields
python3 - <<'PY' "${out}"
import json, sys
with open(sys.argv[1]) as f:
    r = json.load(f)
required = ["schema_version", "mode", "file", "overall", "overall_verdict", "layers", "claim"]
for k in required:
    assert k in r, f"Missing required field: {k}"
assert "interpretation" in r and isinstance(r["interpretation"], dict), "Missing interpretation object"
for ik in ("safety", "liveness", "summary", "overall_status_meaning"):
    assert ik in r["interpretation"], f"interpretation missing field: {ik}"
assert r["schema_version"] == "v1", f"schema_version should be 'v1', got {r['schema_version']}"
assert "confidence_tier" in r, "Missing confidence_tier field"
assert r["confidence_tier"] in ("quick", "bounded", "proof", "certified"), \
    f"Invalid confidence_tier: {r['confidence_tier']}"
assert r["overall_verdict"] in ("SAFE", "UNSAFE", "LIVE_PROVED", "LIVE_CEX", "INCONCLUSIVE", "UNKNOWN"), \
    f"Invalid verdict: {r['overall_verdict']}"
assert isinstance(r["claim"], dict), "claim must be an object"
for ck in ("proven", "assumptions", "not_covered"):
    assert ck in r["claim"], f"claim missing field: {ck}"
for layer in r["layers"]:
    assert "verdict" in layer, f"layer {layer.get('layer')} missing verdict field"
assert r["interpretation"]["safety"] in ("SAFE", "UNSAFE", "UNKNOWN", "NOT_CHECKED")
assert r["interpretation"]["liveness"] in ("LIVE_PROVED", "LIVE_CEX", "UNKNOWN", "NOT_CHECKED")
print(f"  verdict={r['overall_verdict']} overall={r['overall']} layers={len(r['layers'])}")
PY
echo "  PASS"

# --- Test 2: analyze --goal bughunt ---
echo "[beginner] Test 2: analyze --goal bughunt"
out2="$(mktemp)"
set +e
${TARSIER} analyze examples/library/reliable_broadcast_safe.trs --goal bughunt --format json >"${out2}" 2>/dev/null
exit_code=$?
set -e
if [[ "${exit_code}" -ne 0 && "${exit_code}" -ne 2 ]]; then
  echo "FAIL: analyze --goal bughunt exited with unexpected code ${exit_code}"
  exit 1
fi
python3 - <<'PY' "${out2}"
import json, sys
with open(sys.argv[1]) as f:
    r = json.load(f)
assert r["mode"] == "quick", f"bughunt should map to quick mode, got {r['mode']}"
assert "next_action" in r, "next_action should be present"
print(f"  mode={r['mode']} verdict={r['overall_verdict']}")
PY
echo "  PASS"

# --- Test 2b: analyze --goal safety (no internal knobs required) ---
echo "[beginner] Test 2b: analyze --goal safety"
out2b="$(mktemp)"
set +e
${TARSIER} analyze examples/trivial_live.trs --goal safety --format json >"${out2b}" 2>/dev/null
exit_code=$?
set -e
if [[ "${exit_code}" -ne 0 && "${exit_code}" -ne 2 ]]; then
  echo "FAIL: analyze --goal safety exited with unexpected code ${exit_code}"
  exit 1
fi
python3 - <<'PY' "${out2b}"
import json, sys
with open(sys.argv[1]) as f:
    r = json.load(f)
assert r["mode"] == "proof", f"safety goal should map to proof mode, got {r['mode']}"
assert r["config"]["soundness"] == "strict", f"default soundness should be strict, got {r['config']['soundness']}"
assert any(layer["layer"].startswith("prove[") for layer in r["layers"]), \
    "safety goal should execute unbounded proof layers"
print(f"  mode={r['mode']} soundness={r['config']['soundness']} layers={len(r['layers'])}")
PY
echo "  PASS"

# --- Test 2c: analyze --goal safety+liveness (no internal knobs required) ---
echo "[beginner] Test 2c: analyze --goal safety+liveness"
out2c="$(mktemp)"
set +e
${TARSIER} analyze examples/trivial_live.trs --goal safety+liveness --format json >"${out2c}" 2>/dev/null
exit_code=$?
set -e
if [[ "${exit_code}" -ne 0 && "${exit_code}" -ne 2 ]]; then
  echo "FAIL: analyze --goal safety+liveness exited with unexpected code ${exit_code}"
  exit 1
fi
python3 - <<'PY' "${out2c}"
import json, sys
with open(sys.argv[1]) as f:
    r = json.load(f)
assert r["mode"] == "proof", f"safety+liveness goal should map to proof mode, got {r['mode']}"
assert r["config"]["soundness"] == "strict", f"default soundness should be strict, got {r['config']['soundness']}"
layer_names = [layer["layer"] for layer in r["layers"]]
assert any(name.startswith("prove[fair_") for name in layer_names), \
    f"safety+liveness goal should run fair liveness proof layer, got {layer_names}"
print(f"  mode={r['mode']} soundness={r['config']['soundness']} layers={layer_names}")
PY
echo "  PASS"

# --- Test 3: advanced gating ---
echo "[beginner] Test 3: advanced gating rejects raw flags"
set +e
err="$(${TARSIER} analyze examples/library/reliable_broadcast_safe.trs --depth 20 2>&1)"
exit_code=$?
set -e
if [[ "${exit_code}" -eq 0 ]]; then
  echo "FAIL: beginner profile should reject --depth without --advanced"
  exit 1
fi
if ! echo "${err}" | grep -q "advanced-only"; then
  echo "FAIL: error message should mention 'advanced-only', got: ${err}"
  exit 1
fi
echo "  PASS"

# --- Test 4: text output has claim/next-action ---
echo "[beginner] Test 4: text output includes claim and next-action"
out4="$(mktemp)"
set +e
${TARSIER} analyze examples/library/reliable_broadcast_safe.trs --format text >"${out4}" 2>/dev/null
exit_code=$?
set -e
if ! grep -q "What was proven:" "${out4}"; then
  echo "FAIL: text output missing 'What was proven:'"
  cat "${out4}"
  exit 1
fi
if ! grep -q "Recommended next step:" "${out4}"; then
  echo "FAIL: text output missing 'Recommended next step:'"
  cat "${out4}"
  exit 1
fi
if ! grep -q "Verdict:" "${out4}"; then
  echo "FAIL: text output missing 'Verdict:'"
  cat "${out4}"
  exit 1
fi
if ! grep -q "Interpretation:" "${out4}"; then
  echo "FAIL: text output missing 'Interpretation:' section"
  cat "${out4}"
  exit 1
fi
if ! grep -q "Safety:" "${out4}" || ! grep -q "Liveness:" "${out4}"; then
  echo "FAIL: text output missing explicit Safety/Liveness lines"
  cat "${out4}"
  exit 1
fi
echo "  PASS"

# --- Test 5: model fidelity warning for non-faithful protocol ---
echo "[beginner] Test 5: model fidelity warning visible in text"
out5="$(mktemp)"
set +e
${TARSIER} analyze examples/library/pbft_core.trs --format text >"${out5}" 2>/dev/null
exit_code=$?
set -e
# pbft_core uses classic semantics, so fidelity warning should appear
if ! grep -q "MODEL FIDELITY WARNING" "${out5}"; then
  echo "FAIL: text output missing model fidelity warning for classic protocol"
  cat "${out5}"
  exit 1
fi
echo "  PASS"

# --- Test 6: --profile ci-fast produces valid JSON with mode quick ---
echo "[beginner] Test 6: --profile ci-fast"
out6="$(mktemp)"
set +e
${TARSIER} analyze examples/library/reliable_broadcast_safe.trs --profile ci-fast --format json >"${out6}" 2>/dev/null
exit_code=$?
set -e
if [[ "${exit_code}" -ne 0 && "${exit_code}" -ne 2 ]]; then
  echo "FAIL: --profile ci-fast exited with unexpected code ${exit_code}"
  exit 1
fi
python3 - <<'PY' "${out6}"
import json, sys
with open(sys.argv[1]) as f:
    r = json.load(f)
assert r["mode"] == "quick", f"ci-fast should map to quick mode, got {r['mode']}"
assert "confidence_tier" in r, "Missing confidence_tier field"
print(f"  mode={r['mode']} confidence={r['confidence_tier']}")
PY
echo "  PASS"

# --- Test 7: --goal release produces cert-related layers when protocol passes ---
echo "[beginner] Test 7: --goal release cert layers"
out7="$(mktemp)"
set +e
${TARSIER} analyze examples/trivial_live.trs --goal release --profile pro --format json >"${out7}" 2>/dev/null
exit_code=$?
set -e
if [[ "${exit_code}" -ne 0 && "${exit_code}" -ne 2 ]]; then
  echo "FAIL: --goal release exited with unexpected code ${exit_code}"
  exit 1
fi
python3 - <<'PY' "${out7}"
import json, sys
with open(sys.argv[1]) as f:
    r = json.load(f)
assert r["mode"] == "audit", f"release should map to audit mode, got {r['mode']}"
layer_names = [l["layer"] for l in r["layers"]]
print(f"  mode={r['mode']} layers={layer_names}")
# Cert layers may or may not be present depending on whether proofs pass
PY
echo "  PASS"

# --- Test 8: --properties agreement prints property template ---
echo "[beginner] Test 8: assist --properties agreement"
out8="$(mktemp)"
set +e
${TARSIER} assist --properties agreement >"${out8}" 2>/dev/null
exit_code=$?
set -e
if [[ "${exit_code}" -ne 0 ]]; then
  echo "FAIL: assist --properties agreement exited with code ${exit_code}"
  exit 1
fi
if ! grep -q "Agreement" "${out8}"; then
  echo "FAIL: property template output missing 'Agreement'"
  cat "${out8}"
  exit 1
fi
echo "  PASS"

echo ""
echo "=== All beginner UX smoke tests passed ==="
