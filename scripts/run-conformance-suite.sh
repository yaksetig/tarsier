#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MANIFEST="${MANIFEST:-$ROOT_DIR/examples/conformance/conformance_suite.json}"
FORMAT="${FORMAT:-json}"
OUT="${OUT:-$ROOT_DIR/artifacts/conformance-suite.json}"

if [[ "$FORMAT" != "json" && "$FORMAT" != "text" ]]; then
  echo "Unsupported FORMAT '$FORMAT'. Use 'json' or 'text'." >&2
  exit 2
fi

if [[ "$FORMAT" == "json" ]]; then
  mkdir -p "$(dirname "$OUT")"
fi

CMD=(
  cargo run -p tarsier-cli -- conformance-suite
  --manifest "$MANIFEST"
  --format "$FORMAT"
)

if [[ "$FORMAT" == "json" ]]; then
  CMD+=(--out "$OUT")
fi

echo "Running conformance suite:"
echo "  manifest=$MANIFEST"
echo "  format=$FORMAT"
if [[ "$FORMAT" == "json" ]]; then
  echo "  out=$OUT"
fi

(
  cd "$ROOT_DIR"
  "${CMD[@]}"
)
