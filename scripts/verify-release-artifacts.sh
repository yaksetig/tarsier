#!/usr/bin/env bash
# Verify integrity of Tarsier release artifacts.
#
# Usage:
#   ./scripts/verify-release-artifacts.sh v0.1.0
#   ./scripts/verify-release-artifacts.sh v0.1.0 --download-dir /tmp/tarsier-release
#
# Prerequisites:
#   - cosign (https://docs.sigstore.dev/cosign/system_config/installation/)
#   - gh CLI (https://cli.github.com/) — or manual download
#   - shasum
#
# What this script verifies:
#   1. SHA256 checksums match downloaded artifacts.
#   2. Cosign signatures are valid (keyless, tied to GitHub Actions OIDC).
#   3. Trust report signature is valid (keyless, tied to GitHub Actions OIDC).
#   4. SBOMs are present and structurally valid SPDX.
#   5. GitHub Artifact Attestations are retrievable for each artifact.
#
# Exit codes:
#   0 — all verifications passed
#   1 — verification failure (explicit error printed)
#   2 — missing prerequisite tool

set -euo pipefail

REPO="${TARSIER_REPO:-myaksetig/tarsier}"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <tag> [--download-dir <dir>]"
  echo "Example: $0 v0.1.0"
  exit 2
fi

TAG="$1"
shift

DOWNLOAD_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --download-dir)
      DOWNLOAD_DIR="$2"
      shift 2
      ;;
    *)
      echo "ERROR: unknown argument: $1"
      exit 2
      ;;
  esac
done

if [ -z "${DOWNLOAD_DIR}" ]; then
  DOWNLOAD_DIR="$(mktemp -d)"
  echo "Using temporary download directory: ${DOWNLOAD_DIR}"
fi

# Check prerequisites
for cmd in cosign gh shasum python3; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "ERROR: required tool '${cmd}' not found in PATH"
    exit 2
  fi
done

echo "=== Tarsier Release Artifact Verification ==="
echo "Tag:  ${TAG}"
echo "Repo: ${REPO}"
echo "Dir:  ${DOWNLOAD_DIR}"
echo ""

# Download release assets
echo "[1/6] Downloading release assets..."
mkdir -p "${DOWNLOAD_DIR}"
gh release download "${TAG}" \
  --repo "${REPO}" \
  --dir "${DOWNLOAD_DIR}" \
  --pattern "*.tar.gz" \
  --pattern "*.sha256" \
  --pattern "*.sig" \
  --pattern "*.pem" \
  --pattern "*.sbom.spdx.json" \
  --pattern "trust-report.json" \
  --clobber

# Verify checksums
echo ""
echo "[2/6] Verifying SHA256 checksums..."
failed=0
for sha_file in "${DOWNLOAD_DIR}"/*.sha256; do
  if [ ! -f "${sha_file}" ]; then
    echo "WARNING: no .sha256 files found"
    break
  fi
  echo "  Checking $(basename "${sha_file}")..."
  if ! (cd "${DOWNLOAD_DIR}" && shasum -a 256 -c "$(basename "${sha_file}")"); then
    echo "  ERROR: checksum mismatch for $(basename "${sha_file}")"
    failed=1
  fi
done
if [ "${failed}" -ne 0 ]; then
  echo "ERROR: checksum verification failed"
  exit 1
fi
echo "  Checksums OK"

# Verify cosign signatures
echo ""
echo "[3/6] Verifying Cosign signatures..."
failed=0
for tarball in "${DOWNLOAD_DIR}"/*.tar.gz; do
  if [ ! -f "${tarball}" ]; then
    echo "WARNING: no .tar.gz files found"
    break
  fi
  base="$(basename "${tarball}")"
  sig="${DOWNLOAD_DIR}/${base}.sig"
  cert="${DOWNLOAD_DIR}/${base}.pem"
  if [ ! -f "${sig}" ] || [ ! -f "${cert}" ]; then
    echo "  ERROR: missing signature or certificate for ${base}"
    failed=1
    continue
  fi
  echo "  Verifying ${base}..."
  if ! cosign verify-blob \
    --signature "${sig}" \
    --certificate "${cert}" \
    --certificate-identity-regexp "github\\.com" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "${tarball}" 2>&1; then
    echo "  ERROR: signature verification failed for ${base}"
    failed=1
  else
    echo "  OK: ${base}"
  fi
done
if [ "${failed}" -ne 0 ]; then
  echo "ERROR: signature verification failed"
  exit 1
fi
echo "  All signatures verified"

# Verify trust report signature
echo ""
echo "[4/6] Verifying trust report signature..."
tr="${DOWNLOAD_DIR}/trust-report.json"
sig="${DOWNLOAD_DIR}/trust-report.json.sig"
cert="${DOWNLOAD_DIR}/trust-report.json.pem"
if [ ! -f "${tr}" ]; then
  echo "  WARNING: trust-report.json not found in release assets (skipping)"
else
  if [ ! -f "${sig}" ] || [ ! -f "${cert}" ]; then
    echo "  ERROR: trust-report.json present but missing .sig or .pem sidecar"
    exit 1
  fi
  if ! cosign verify-blob \
    --signature "${sig}" \
    --certificate "${cert}" \
    --certificate-identity-regexp "github\\.com" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "${tr}" 2>&1; then
    echo "  ERROR: trust report signature verification failed"
    exit 1
  fi
  echo "  OK: trust-report.json"
fi

# Verify SBOMs
echo ""
echo "[5/6] Verifying SBOMs..."
failed=0
for tarball in "${DOWNLOAD_DIR}"/*.tar.gz; do
  base="$(basename "${tarball}" .tar.gz)"
  sbom="${DOWNLOAD_DIR}/${base}.sbom.spdx.json"
  if [ ! -f "${sbom}" ]; then
    echo "  ERROR: missing SBOM for ${base}"
    failed=1
    continue
  fi
  if ! python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
assert 'spdxVersion' in d, 'not a valid SPDX document'
assert 'name' in d, 'SPDX document missing name'
print(f'  OK: {sys.argv[1]} (SPDX {d[\"spdxVersion\"]})')
" "${sbom}"; then
    echo "  ERROR: invalid SBOM for ${base}"
    failed=1
  fi
done
if [ "${failed}" -ne 0 ]; then
  echo "ERROR: SBOM verification failed"
  exit 1
fi

# Verify attestations
echo ""
echo "[6/6] Verifying GitHub Artifact Attestations..."
failed=0
for tarball in "${DOWNLOAD_DIR}"/*.tar.gz; do
  base="$(basename "${tarball}")"
  echo "  Checking attestation for ${base}..."
  if ! gh attestation verify "${tarball}" \
    --repo "${REPO}" 2>&1; then
    echo "  ERROR: attestation verification failed for ${base}"
    failed=1
  else
    echo "  OK: ${base}"
  fi
done
if [ "${failed}" -ne 0 ]; then
  echo "ERROR: attestation verification failed"
  exit 1
fi

echo ""
echo "=== All verifications passed ==="
echo "Artifacts in: ${DOWNLOAD_DIR}"
