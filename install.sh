#!/bin/sh
# Tarsier installer — downloads the latest release binary for your platform.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/tarsier-verify/tarsier/main/install.sh | sh
#
# Environment variables:
#   TARSIER_INSTALL_DIR  — installation directory (default: ~/.local/bin)
#   TARSIER_VERSION      — specific version to install (default: latest)

set -eu

REPO="tarsier-verify/tarsier"
INSTALL_DIR="${TARSIER_INSTALL_DIR:-$HOME/.local/bin}"

# Detect OS
OS="$(uname -s)"
case "$OS" in
  Linux)  os="unknown-linux-gnu" ;;
  Darwin) os="apple-darwin" ;;
  *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) arch="x86_64" ;;
  aarch64|arm64) arch="aarch64" ;;
  *)             echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

TARGET="${arch}-${os}"

# Determine version
if [ -n "${TARSIER_VERSION:-}" ]; then
  VERSION="$TARSIER_VERSION"
  TAG="v${VERSION}"
else
  echo "Fetching latest release..."
  TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
  if [ -z "$TAG" ]; then
    echo "Error: could not determine latest release. Set TARSIER_VERSION manually."
    exit 1
  fi
  VERSION="${TAG#v}"
fi

TARBALL="tarsier-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${TARBALL}"

echo "Installing tarsier ${VERSION} for ${TARGET}..."
echo "  Download: ${URL}"
echo "  Install:  ${INSTALL_DIR}/tarsier"

# Create install directory
mkdir -p "$INSTALL_DIR"

# Download and extract
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

curl -fsSL "$URL" -o "${TMPDIR}/${TARBALL}"
tar xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"

# Install binary
if [ -f "${TMPDIR}/tarsier" ]; then
  cp "${TMPDIR}/tarsier" "${INSTALL_DIR}/tarsier"
  chmod +x "${INSTALL_DIR}/tarsier"
else
  # Some release archives put the binary in a subdirectory
  BINARY=$(find "$TMPDIR" -name "tarsier" -type f | head -1)
  if [ -z "$BINARY" ]; then
    echo "Error: tarsier binary not found in archive"
    exit 1
  fi
  cp "$BINARY" "${INSTALL_DIR}/tarsier"
  chmod +x "${INSTALL_DIR}/tarsier"
fi

# Verify cosign signature if available
if command -v cosign >/dev/null 2>&1; then
  SIG_URL="${URL}.sig"
  CERT_URL="${URL}.pem"
  if curl -fsSL "$SIG_URL" -o "${TMPDIR}/sig" 2>/dev/null && \
     curl -fsSL "$CERT_URL" -o "${TMPDIR}/cert" 2>/dev/null; then
    echo "Verifying cosign signature..."
    cosign verify-blob --signature "${TMPDIR}/sig" --certificate "${TMPDIR}/cert" \
      --certificate-identity-regexp "github\\.com" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      "${TMPDIR}/${TARBALL}" 2>/dev/null && echo "  Signature verified." || \
      echo "  Warning: signature verification failed (continuing anyway)."
  fi
fi

echo ""
echo "Tarsier ${VERSION} installed to ${INSTALL_DIR}/tarsier"

# Check if install dir is in PATH
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo ""
    echo "Add ${INSTALL_DIR} to your PATH:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    echo ""
    echo "Or add it to your shell profile (~/.bashrc, ~/.zshrc, etc.)."
    ;;
esac

echo ""
echo "Get started:"
echo "  tarsier --help"
echo "  tarsier verify examples/library/reliable_broadcast_safe.trs"
