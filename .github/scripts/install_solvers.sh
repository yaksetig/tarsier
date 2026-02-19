#!/usr/bin/env bash
set -euo pipefail

# Pinned solver versions for deterministic certificate checking in CI.
Z3_VERSION="4.12.5"
Z3_ARCHIVE="z3-${Z3_VERSION}-x64-glibc-2.35.zip"
Z3_URL="https://github.com/Z3Prover/z3/releases/download/z3-${Z3_VERSION}/${Z3_ARCHIVE}"
Z3_SHA256="f036574d5e2029c9204fff3503cfe68ddf41fa6fdebb39beed99e1bf355b7fee"

CVC5_VERSION="1.1.2"
CVC5_ARCHIVE="cvc5-Linux-static.zip"
CVC5_URL="https://github.com/cvc5/cvc5/releases/download/cvc5-${CVC5_VERSION}/${CVC5_ARCHIVE}"
CVC5_SHA256="cf291aef67da8eaa8d425a51f67f3f72f36db8b1040655dc799b64e3d69e6086"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This installer currently supports Linux CI runners only." >&2
  exit 1
fi

if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "This installer currently supports x86_64 CI runners only." >&2
  exit 1
fi

ROOT_DIR="${RUNNER_TEMP:-/tmp}/tarsier-solvers"
BIN_DIR="${ROOT_DIR}/bin"
mkdir -p "${BIN_DIR}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "Installing Z3 ${Z3_VERSION}..."
curl -fsSL -o "${TMP_DIR}/${Z3_ARCHIVE}" "${Z3_URL}"
echo "${Z3_SHA256}  ${TMP_DIR}/${Z3_ARCHIVE}" | sha256sum -c -
unzip -q "${TMP_DIR}/${Z3_ARCHIVE}" -d "${TMP_DIR}"
cp "${TMP_DIR}/z3-${Z3_VERSION}-x64-glibc-2.35/bin/z3" "${BIN_DIR}/z3"
chmod +x "${BIN_DIR}/z3"

echo "Installing cvc5 ${CVC5_VERSION}..."
curl -fsSL -o "${TMP_DIR}/${CVC5_ARCHIVE}" "${CVC5_URL}"
echo "${CVC5_SHA256}  ${TMP_DIR}/${CVC5_ARCHIVE}" | sha256sum -c -
unzip -q "${TMP_DIR}/${CVC5_ARCHIVE}" -d "${TMP_DIR}"
cp "${TMP_DIR}/cvc5-Linux-static/bin/cvc5" "${BIN_DIR}/cvc5"
chmod +x "${BIN_DIR}/cvc5"

if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${BIN_DIR}" >> "${GITHUB_PATH}"
else
  export PATH="${BIN_DIR}:${PATH}"
fi

echo "Installed solvers in ${BIN_DIR}"
"${BIN_DIR}/z3" --version
"${BIN_DIR}/cvc5" --version
