#!/bin/bash
# TEST FIXTURE — LEGITIMATE INSTALL SCRIPT
# This should pass LLM-Butcher checks with no findings

set -euo pipefail

echo "Installing mytool v2.1.0..."

INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR"

ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

echo "Detected: ${OS}/${ARCH}"
echo "Downloading binary..."

curl -fsSL "https://releases.mytool.dev/v2.1.0/mytool-${OS}-${ARCH}.tar.gz" -o /tmp/mytool.tar.gz
tar xzf /tmp/mytool.tar.gz -C "$INSTALL_DIR"
rm /tmp/mytool.tar.gz

echo "mytool installed to ${INSTALL_DIR}/mytool"
echo "Add ${INSTALL_DIR} to your PATH if not already present."
