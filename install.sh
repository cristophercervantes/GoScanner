#!/usr/bin/env bash

set -e

REPO="cristophercervantes/GoScanner"
BINARY_NAME="goscanner"
INSTALL_DIR="/usr/local/bin"
MODULE="github.com/cristophercervantes/GoScanner/cmd/goscanner"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[x]${NC} $1"; exit 1; }

echo ""
echo "  GoScanner v2.0 - Installer"
echo "  By Tensor Security Academy"
echo ""

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  armv7l)  ARCH="arm" ;;
  *)       warn "Unknown arch: $ARCH" ;;
esac

if command -v go &>/dev/null; then
  info "Go found: $(go version)"
  info "Installing via go install..."
  go install "${MODULE}@latest"
  info "Installed successfully. Run: goscanner -version"
  exit 0
fi

warn "Go not found, trying binary release..."

LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
if [ -z "$LATEST" ]; then
  error "Could not fetch latest release. Install Go from https://go.dev/dl and retry."
fi

info "Latest release: $LATEST"

ASSET="${BINARY_NAME}_${OS}_${ARCH}"
URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET}"

info "Downloading from $URL..."
TMP=$(mktemp)
if ! curl -fsSL -o "$TMP" "$URL"; then
  error "Download failed. Visit https://github.com/${REPO}/releases or install Go."
fi

chmod +x "$TMP"

if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP" "${INSTALL_DIR}/${BINARY_NAME}"
else
  warn "Need sudo to write to $INSTALL_DIR"
  sudo mv "$TMP" "${INSTALL_DIR}/${BINARY_NAME}"
fi

info "Installed to ${INSTALL_DIR}/${BINARY_NAME}"
info "Run: goscanner -version"
