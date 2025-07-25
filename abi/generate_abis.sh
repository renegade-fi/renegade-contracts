#!/bin/bash
set -euo pipefail

# Change to the abi directory
cd "$(dirname "$0")"

# Generate individual ABI files
echo "Generating IGasSponsor ABI..."
forge inspect ../src/libraries/interfaces/IGasSponsor.sol:IGasSponsor abi --json > IGasSponsor.json

echo "Generating IDarkpool ABI..."
forge inspect ../src/libraries/interfaces/IDarkpool.sol:IDarkpool abi --json > IDarkpool.json

echo "Generating IDarkpoolExecutor ABI (filtering duplicates)..."
# Generate full ABI then strip the two signatures that are already
# present in other interfaces (owner() and initialize(address,address,address))
#
# This is necessary because the ABI crate will not build if the combined ABI
# contains duplicate selectors.
forge inspect ../src/libraries/interfaces/IDarkpoolExecutor.sol:IDarkpoolExecutor abi --json \
  | jq '[ .[] | select( (.name != "owner") and ((.name == "initialize" and ((.inputs|map(.type)|join(",")) == "address,address,address")) | not) ) ]' \
  > IDarkpoolExecutor.json

echo "Combining ABI files into ICombined.json..."

jq -s 'add' IGasSponsor.json IDarkpool.json IDarkpoolExecutor.json > ICombined.json

# Clean up individual ABI files
echo "Cleaning up individual ABI files..."
rm IGasSponsor.json IDarkpool.json IDarkpoolExecutor.json

echo "Done! Generated combined ABI file: ICombined.json" 