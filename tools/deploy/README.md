# Renegade Contract Deployment Tool

This is a CLI tool for deploying Renegade contracts to an EVM network.

## Prerequisites

- Rust toolchain
- Foundry (forge)

## Building

From the `tools/deploy` directory, run:

```bash
cargo build
```

## Usage

You can use the tool directly:

```bash
cargo run -- --help
```

### Example Commands

#### Mainnet Deployment

```bash
cargo run -- \
  --rpc-url https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY \
  --permit2 0x000000000022D473030F116dDEE9F6B43aC78BA3 \
  --weth 0x4200000000000000000000000000000000000006 \
  --fee-recipient 0xYourFeeRecipientAddress \
  --protocol-fee-rate 0.02 \
  --pkey YOUR_PRIVATE_KEY
```

## Environment Variables

You can use environment variables instead of some command-line arguments:

```bash
# Set RPC URL
export RPC_URL=https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY

# Set private key
export PKEY=your_private_key_here

# Run with environment variables
cargo run -- \
  --permit2 0x000000000022D473030F116dDEE9F6B43aC78BA3 \
  --weth 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 \
  --fee-recipient 0xYourFeeRecipientAddress \
  --protocol-fee-rate 0.02
```

## Options

- `-r, --rpc-url` - RPC URL to deploy to (default: http://localhost:8545), can be set with RPC_URL env var
- `--permit2` - Permit2 contract address
- `--weth` - WETH contract address
- `--protocol-fee-rate` - Protocol fee rate (between 0.0 and 1.0)
- `--fee-recipient` - Protocol fee recipient address
- `--pkey` - Private key for signing transactions, can be set with PKEY env var
- `--verbosity` - Verbosity level (v, vv, vvv) (default: v) 