#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${ROOT_DIR}/examples/example_matrix_fast.json"
REPORT_OUT=""

usage() {
  cat <<'EOF'
Usage: scripts/example-matrix-fast.sh [--manifest <path>] [--report-out <path>]

Runs a fast verify regression subset over the example coverage matrix.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST="$2"
      shift 2
      ;;
    --report-out)
      REPORT_OUT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "$MANIFEST" ]]; then
  echo "Manifest not found: $MANIFEST" >&2
  exit 2
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tarsier-example-matrix-fast.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

ENTRIES_TSV="${TMP_DIR}/entries.tsv"
RESULTS_TSV="${TMP_DIR}/results.tsv"

python3 - "$MANIFEST" > "$ENTRIES_TSV" <<'PY'
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
data = json.loads(manifest_path.read_text())
entries = data.get("entries", [])
if not entries:
    raise SystemExit(f"Manifest {manifest_path} has no entries")
for entry in entries:
    ident = entry["id"]
    file = entry["file"]
    expected = entry["expected"]
    depth = int(entry.get("depth", 4))
    soundness = entry.get("soundness", "strict")
    print(f"{ident}\t{file}\t{expected}\t{depth}\t{soundness}")
PY

total=0
passed=0
failed=0

echo "Running fast example matrix from ${MANIFEST}"
echo "-------------------------------------------"

while IFS=$'\t' read -r ident file expected depth soundness; do
  [[ -z "${ident}" ]] && continue
  total=$((total + 1))
  out_json="${TMP_DIR}/${ident}.json"
  err_log="${TMP_DIR}/${ident}.err"

  cmd=(
    cargo run -q -p tarsier-cli -- verify "$file"
    --depth "$depth"
    --soundness "$soundness"
    --format json
  )

  actual="error"
  status="fail"

  if "${cmd[@]}" >"$out_json" 2>"$err_log"; then
    actual="$(python3 - "$out_json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text())
print(data.get("result", "unknown"))
PY
)"
    if [[ "$actual" == "$expected" ]]; then
      status="pass"
      passed=$((passed + 1))
    else
      failed=$((failed + 1))
    fi
  else
    failed=$((failed + 1))
  fi

  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$ident" "$file" "$expected" "$actual" "$status" "$depth" "$soundness" >> "$RESULTS_TSV"

  echo "[$status] $ident expected=$expected actual=$actual file=$file"
done < "$ENTRIES_TSV"

echo "-------------------------------------------"
echo "Matrix summary: total=$total passed=$passed failed=$failed"

if [[ -n "$REPORT_OUT" ]]; then
  mkdir -p "$(dirname "$REPORT_OUT")"
  python3 - "$RESULTS_TSV" "$REPORT_OUT" "$total" "$passed" "$failed" <<'PY'
import json
import sys
from pathlib import Path

results_tsv = Path(sys.argv[1])
report_out = Path(sys.argv[2])
total = int(sys.argv[3])
passed = int(sys.argv[4])
failed = int(sys.argv[5])

entries = []
for line in results_tsv.read_text().splitlines():
    ident, file, expected, actual, status, depth, soundness = line.split("\t")
    entries.append(
        {
            "id": ident,
            "file": file,
            "expected": expected,
            "actual": actual,
            "status": status,
            "depth": int(depth),
            "soundness": soundness,
        }
    )

report = {
    "schema_version": 1,
    "suite": "example-matrix-fast",
    "total": total,
    "passed": passed,
    "failed": failed,
    "entries": entries,
}
report_out.write_text(json.dumps(report, indent=2) + "\n")
print(f"Wrote report: {report_out}")
PY
fi

if [[ "$failed" -gt 0 ]]; then
  exit 1
fi

exit 0
