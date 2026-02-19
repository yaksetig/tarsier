#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MANIFEST="${MANIFEST:-$ROOT_DIR/examples/library/cert_suite.json}"
ENGINE="${ENGINE:-kinduction}"
SOLVER="${SOLVER:-z3}"
K="${K:-8}"
TIMEOUT="${TIMEOUT:-120}"
FORMAT="${FORMAT:-json}"
OUT="${OUT:-$ROOT_DIR/artifacts/cert-suite.json}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$ROOT_DIR/artifacts/cert-suite}"
CHECK_HASHES="${CHECK_HASHES:-1}"

if [[ "$FORMAT" != "json" && "$FORMAT" != "text" ]]; then
  echo "Unsupported FORMAT '$FORMAT'. Use 'json' or 'text'." >&2
  exit 2
fi

if [[ "$FORMAT" == "json" ]]; then
  mkdir -p "$(dirname "$OUT")"
fi
mkdir -p "$ARTIFACTS_DIR"

CMD=(
  cargo run -p tarsier-cli -- cert-suite
  --manifest "$MANIFEST"
  --engine "$ENGINE"
  --k "$K"
  --timeout "$TIMEOUT"
  --solver "$SOLVER"
  --format "$FORMAT"
  --artifacts-dir "$ARTIFACTS_DIR"
)

if [[ "$FORMAT" == "json" ]]; then
  CMD+=(--out "$OUT")
fi

echo "Running corpus certification:"
echo "  manifest=$MANIFEST"
echo "  engine=$ENGINE solver=$SOLVER k=$K timeout=$TIMEOUT format=$FORMAT"
if [[ "$FORMAT" == "json" ]]; then
  echo "  out=$OUT"
fi
echo "  artifacts_dir=$ARTIFACTS_DIR"
echo "  check_hashes=$CHECK_HASHES"

if [[ "$CHECK_HASHES" == "1" ]]; then
  python3 "$ROOT_DIR/scripts/update-cert-suite-hashes.py" --manifest "$MANIFEST" --check
fi

(
  cd "$ROOT_DIR"
  "${CMD[@]}"
)
