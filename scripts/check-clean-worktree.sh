#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"

if [[ $# -gt 0 ]]; then
  "$@"
fi

# Refresh index entries so status reflects filesystem changes accurately.
git update-index -q --refresh || true

status_output="$(git status --porcelain=v1 --untracked-files=all)"
if [[ -n "$status_output" ]]; then
  echo "ERROR: working tree is not clean after deterministic checks."
  echo
  echo "$status_output"
  echo
  echo "Hint: run deterministic update/check scripts locally and commit resulting changes."
  exit 1
fi

echo "Working tree is clean."
