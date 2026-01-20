#!/bin/bash
set -e

# Navigate to the project root
cd "$(dirname "$0")/../../"
cargo +nightly-2025-11-25 run --manifest-path tools/deploy/Cargo.toml -- "$@"
