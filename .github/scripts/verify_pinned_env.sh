#!/usr/bin/env bash
set -euo pipefail

EXPECTED_RUSTC="${EXPECTED_RUSTC:-1.92.0}"
EXPECTED_Z3="${EXPECTED_Z3:-4.12.5}"
EXPECTED_CVC5="${EXPECTED_CVC5:-1.1.2}"
EXPECTED_OS="${EXPECTED_OS:-ubuntu-22.04}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Pinned environment check failed: expected Linux runner." >&2
  exit 1
fi

if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  OS_ID_VERSION="${ID}-${VERSION_ID}"
  if [[ "${OS_ID_VERSION}" != "${EXPECTED_OS}" ]]; then
    echo "Pinned environment check failed: expected ${EXPECTED_OS}, got ${OS_ID_VERSION}." >&2
    exit 1
  fi
fi

RUSTC_VERSION="$(rustc --version | awk '{print $2}')"
if [[ "${RUSTC_VERSION}" != "${EXPECTED_RUSTC}" ]]; then
  echo "Pinned environment check failed: expected rustc ${EXPECTED_RUSTC}, got ${RUSTC_VERSION}." >&2
  exit 1
fi

Z3_VERSION="$(z3 --version | awk '{print $3}')"
if [[ "${Z3_VERSION}" != "${EXPECTED_Z3}" ]]; then
  echo "Pinned environment check failed: expected Z3 ${EXPECTED_Z3}, got ${Z3_VERSION}." >&2
  exit 1
fi

CVC5_VERSION="$(cvc5 --version | grep -Eo '[0-9]+\\.[0-9]+\\.[0-9]+' | head -n1)"
if [[ "${CVC5_VERSION}" != "${EXPECTED_CVC5}" ]]; then
  echo "Pinned environment check failed: expected cvc5 ${EXPECTED_CVC5}, got ${CVC5_VERSION}." >&2
  exit 1
fi

echo "Pinned environment verified:"
echo "  os=${EXPECTED_OS}"
echo "  rustc=${RUSTC_VERSION}"
echo "  z3=${Z3_VERSION}"
echo "  cvc5=${CVC5_VERSION}"
