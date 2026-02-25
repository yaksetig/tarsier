#!/usr/bin/env bash
set -euo pipefail

# Pinned external proof checker tooling for CI reproducibility.
CARCARA_TAG="carcara-1.1.0"
CARCARA_REPO="https://github.com/ufmg-smite/carcara.git"

ROOT_DIR="${RUNNER_TEMP:-/tmp}/tarsier-proof-checkers"
BIN_DIR="${ROOT_DIR}/bin"
mkdir -p "${BIN_DIR}"

echo "Installing Carcara (${CARCARA_TAG})..."
cargo install \
  --git "${CARCARA_REPO}" \
  --tag "${CARCARA_TAG}" \
  --locked \
  carcara-cli \
  --root "${ROOT_DIR}" \
  --force

if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${BIN_DIR}" >> "${GITHUB_PATH}"
else
  export PATH="${BIN_DIR}:${PATH}"
fi

echo "Installed proof checker tooling in ${BIN_DIR}"
"${BIN_DIR}/carcara" --version
