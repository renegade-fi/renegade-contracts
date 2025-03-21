#!/bin/bash

# Default anvil private key
ANVIL_PKEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Function to cleanup anvil process
cleanup() {
    echo "Cleaning up anvil process..."
    if [ ! -z "$ANVIL_PID" ]; then
        kill $ANVIL_PID
    fi
}

# Set up trap for cleanup on script exit
trap cleanup EXIT

# Start anvil in the background
echo "Starting anvil node..."
anvil &
ANVIL_PID=$!

# Wait for anvil to start
sleep 2

# Run the deployment script
echo "Running deployment script..."
forge script script/DeployDev.s.sol \
    --ffi \
    --rpc-url http://localhost:8545 \
    --private-key $ANVIL_PKEY \
    --broadcast

# Keep the script running until interrupted
echo "Deployment complete. Press Ctrl+C to exit..."
while true; do
    sleep 1
done 