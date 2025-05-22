#!/bin/bash
set -euo pipefail

# Change to the abi directory
cd "$(dirname "$0")"

# Generate individual ABI files
echo "Generating IGasSponsor ABI..."
forge inspect ../src/libraries/interfaces/IGasSponsor.sol:IGasSponsor abi --json > IGasSponsor.json

echo "Generating IDarkpool ABI..."
forge inspect ../src/libraries/interfaces/IDarkpool.sol:IDarkpool abi --json > IDarkpool.json

# Combine the ABI files
echo "Combining ABI files into ICombined.json..."
jq -s 'add' IGasSponsor.json IDarkpool.json > ICombined.json

# Clean up individual ABI files
echo "Cleaning up individual ABI files..."
rm IGasSponsor.json IDarkpool.json

echo "Done! Generated combined ABI file: ICombined.json" 