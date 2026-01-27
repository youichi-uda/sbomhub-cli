#!/bin/sh
set -e

REPO="youichi-uda/sbomhub-cli"
BINARY="sbomhub"
INSTALL_DIR="/usr/local/bin"

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  armv7l) ARCH="arm" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

# Get latest version
echo "Fetching latest version..."
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep tag_name | cut -d '"' -f 4)

if [ -z "$LATEST" ]; then
  echo "Failed to get latest version"
  exit 1
fi

echo "Installing ${BINARY} ${LATEST} for ${OS}/${ARCH}..."

# Download URL
URL="https://github.com/${REPO}/releases/download/${LATEST}/${BINARY}_${OS}_${ARCH}.tar.gz"

# Create temp directory
TMP_DIR=$(mktemp -d)
trap "rm -rf ${TMP_DIR}" EXIT

# Download and extract
echo "Downloading from ${URL}..."
curl -fsSL "$URL" | tar xz -C "$TMP_DIR"

# Install
if [ -w "$INSTALL_DIR" ]; then
  mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/"
else
  echo "Installing to ${INSTALL_DIR} requires sudo..."
  sudo mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/"
fi

# Verify installation
if command -v ${BINARY} >/dev/null 2>&1; then
  echo ""
  echo "✓ ${BINARY} ${LATEST} installed successfully!"
  echo ""
  echo "Get started:"
  echo "  ${BINARY} login      # Configure API key"
  echo "  ${BINARY} scan .     # Scan current directory"
  echo ""
else
  echo "Installation completed, but ${BINARY} is not in PATH"
  echo "Add ${INSTALL_DIR} to your PATH"
fi
