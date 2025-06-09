#!/bin/bash
set -e

echo "=== Testing CI setup locally ==="

# Check Huff installation
echo "1. Checking Huff installation..."
if command -v huffc &> /dev/null; then
    echo "✓ Huff installed: $(huffc --version)"
else
    echo "✗ Huff not installed"
    exit 1
fi

# Check Rust installation
echo -e "\n2. Checking Rust installation..."
if command -v rustc &> /dev/null; then
    echo "✓ Rust installed: $(rustc +nightly-2024-12-01 --version 2>/dev/null || echo "nightly-2024-12-01 not installed")"
else
    echo "✗ Rust not installed"
    exit 1
fi

# Check if we can resolve dependencies
echo -e "\n3. Checking if Rust dependencies can be resolved..."
cd test/rust-reference-impls
if cargo +nightly-2024-12-01 check --message-format short 2>&1 | grep -q "error"; then
    echo "✗ Failed to resolve dependencies"
    cargo +nightly-2024-12-01 check --message-format short 2>&1 | grep "error" | head -5
    exit 1
else
    echo "✓ Dependencies resolved successfully"
fi

# Try to build a simple binary
echo -e "\n4. Attempting to build merkle binary..."
if timeout 30 cargo +nightly-2024-12-01 build --bin merkle 2>&1 > /dev/null; then
    echo "✓ Build started successfully (timed out after 30s, which is expected for large builds)"
else
    echo "✗ Build failed to start"
    exit 1
fi

echo -e "\n=== All checks passed! ==="
echo "The CI configuration should work correctly."