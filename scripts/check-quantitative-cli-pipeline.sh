#!/usr/bin/env bash
set -euo pipefail

# Reproducibility gate for the quantitative CLI pipeline.
# Runs `tarsier-cli comm` twice and verifies stable provenance anchors.

MODEL="examples/pbft_simple.trs"
DEPTH="8"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

report_a="$workdir/comm-a.json"
report_b="$workdir/comm-b.json"

cargo run -q -p tarsier-cli -- comm "$MODEL" --depth "$DEPTH" --format json --out "$report_a" >/dev/null
cargo run -q -p tarsier-cli -- comm "$MODEL" --depth "$DEPTH" --format json --out "$report_b" >/dev/null

python3 - "$report_a" "$report_b" "$DEPTH" <<'PY'
import json
import sys

path_a, path_b, expected_depth_raw = sys.argv[1], sys.argv[2], sys.argv[3]
expected_depth = int(expected_depth_raw)

with open(path_a, "r", encoding="utf-8") as f:
    a = json.load(f)
with open(path_b, "r", encoding="utf-8") as f:
    b = json.load(f)

for idx, report in enumerate((a, b), start=1):
    if report.get("schema_version") != 2:
        raise SystemExit(f"report {idx}: schema_version must be 2")
    meta = report.get("model_metadata", {})
    if meta.get("analysis_depth") != expected_depth:
        raise SystemExit(f"report {idx}: analysis_depth mismatch")
    opts = meta.get("analysis_options", {})
    if opts.get("command") != "comm":
        raise SystemExit(f"report {idx}: analysis_options.command must be 'comm'")
    if opts.get("depth") != expected_depth:
        raise SystemExit(f"report {idx}: analysis_options.depth mismatch")
    fp = meta.get("reproducibility_fingerprint", "")
    if not (isinstance(fp, str) and len(fp) == 64 and all(c in "0123456789abcdef" for c in fp.lower())):
        raise SystemExit(f"report {idx}: reproducibility_fingerprint must be 64-char hex")

meta_a = a["model_metadata"]
meta_b = b["model_metadata"]
if meta_a["source_hash"] != meta_b["source_hash"]:
    raise SystemExit("source_hash changed across identical runs")
if meta_a["reproducibility_fingerprint"] != meta_b["reproducibility_fingerprint"]:
    raise SystemExit("reproducibility_fingerprint changed across identical runs")

print("Quantitative CLI reproducibility gate passed.")
PY
