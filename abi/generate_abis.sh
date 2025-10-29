#!/bin/bash
set -euo pipefail

# Get directories
ABI_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$ABI_DIR/.." && pwd)"

# Change to the abi directory for output files
cd "$ABI_DIR"

# Generate individual ABI files
# Note: forge inspect must run from project root to resolve remappings
echo "Generating IGasSponsor ABI..."
(cd "$PROJECT_ROOT" && forge inspect src/darkpool/v1/interfaces/IGasSponsor.sol:IGasSponsor abi --json) > IGasSponsor.json

echo "Generating IDarkpool ABI..."
(cd "$PROJECT_ROOT" && forge inspect src/darkpool/v1/interfaces/IDarkpool.sol:IDarkpool abi --json) > IDarkpool.json

echo "Generating IDarkpoolExecutor ABI (filtering duplicates)..."
# Generate full ABI then strip the two signatures that are already
# present in other interfaces (owner() and initialize(address,address,address))
#
# This is necessary because the ABI crate will not build if the combined ABI
# contains duplicate selectors.
(cd "$PROJECT_ROOT" && forge inspect src/darkpool/v1/interfaces/IDarkpoolUniswapExecutor.sol:IDarkpoolUniswapExecutor abi --json) \
  | jq '[ .[] | select( (.name != "owner") and ((.name == "initialize" and ((.inputs|map(.type)|join(",")) == "address,address,address")) | not) ) ]' \
  > IDarkpoolExecutor.json

echo "Generating IMalleableMatchConnector ABI..."
(cd "$PROJECT_ROOT" && forge inspect src/darkpool/v1/interfaces/IMalleableMatchConnector.sol:IMalleableMatchConnector abi --json) > IMalleableMatchConnector.json

echo "Combining ABI files into ICombined.json..."

# Merge and deduplicate entries while respecting their type signatures. We treat entries with the
# same ABI signature (function/event/error/constructor) as duplicates, but allow items with the same
# name and different kinds (e.g. a struct tuple vs an event) to coexist.
jq -s '
  def sig:
    if .type == "function" then
      "function:" + (.name // "") + "(" + ((.inputs // []) | map(.type) | join(",")) + ")" +
      "->" + ((.outputs // []) | map(.type) | join(",")) + "|" + (.stateMutability // "")
    elif .type == "event" then
      "event:" + (.name // "") + "(" + ((.inputs // []) | map(.type + ":" + ((.indexed // false)|tostring)) | join(",")) + ")"
    elif .type == "error" then
      "error:" + (.name // "") + "(" + ((.inputs // []) | map(.type) | join(",")) + ")"
    elif .type == "constructor" then
      "constructor(" + ((.inputs // []) | map(.type) | join(",")) + ")"
    elif .type == "receive" or .type == "fallback" then
      .type
    else
      (.type // "") + ":" + (.name // "")
    end;

  def dedup($items):
    reduce $items[] as $item (
      [];
      if any(.[]; .__sig == ($item | sig)) then .
      else . + [ $item + { "__sig": ($item | sig) } ]
      end
    ) | map(del(.__sig));

  def rename_conflicts($items):
    $items
    | ( [ $items[] | select(.type == "event") | .name ] ) as $eventNames
    | walk(
        if type == "object" and ((.internalType? // null) | type) == "string" and (.internalType | startswith("struct ")) then
          (.internalType | split(" ") | .[1]) as $structName
          | if ($eventNames | index($structName)) != null then
              .internalType = "struct " + $structName + "Struct"
            else .
            end
        else .
        end
      );

  add as $combined
  | dedup($combined) as $deduped
  | rename_conflicts($deduped)
' IGasSponsor.json IDarkpool.json IDarkpoolExecutor.json IMalleableMatchConnector.json > ICombined.json

# Clean up individual ABI files
echo "Cleaning up individual ABI files..."
rm IGasSponsor.json IDarkpool.json IDarkpoolExecutor.json IMalleableMatchConnector.json

echo "Done! Generated combined ABI file: ICombined.json" 