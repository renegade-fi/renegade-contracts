<div align="center">
  <img
    alt="Renegade Logo"
    width="60%"
    src="./img/logo_light_contract.svg#gh-light-mode-only"
  />
  <img
    alt="Renegade Logo"
    width="60%"
    src="./img/logo_dark_contract.svg#gh-dark-mode-only"
  />
</div>

---

<div>
  <a href="https://twitter.com/renegade_fi" target="_blank">
    <img src="https://img.shields.io/twitter/follow/renegade_fi?style=social" />
  </a>
  <a href="https://discord.gg/renegade-fi" target="_blank">
    <img src="https://img.shields.io/discord/1032770899675463771?label=Join%20Discord&logo=discord&style=social" />
  </a>
</div>

This repository contains the [Arbitrum Stylus](https://arbitrum.io/stylus) code for Renegade's settlement layer. This includes managing the system-global state, verifying Plonk proofs, and emitting events that are consumed by the p2p network.

Please refer to our [whitepaper](https://www.renegade.fi/whitepaper.pdf) and [docs](https://docs.renegade.fi/) for an introduction the Renegade protocol as a whole, and see [here](./docs/specification.md) for a high-level specification of the contracts' functionality.

## Contract Development Setup

Given we are using Stylus, our contracts are written in Rust, and as such we use a combination of the Rust toolchain and a local Arbitrum Nitro devnet for development.

To set up your machine for Renegade contract development:

### Clone the repo
``` shell
git clone https://github.com/renegade-fi/renegade-contracts
```

### Install Rust toolchain

Make sure you have Rust toolchain installed, using e.g. [`rustup`](https://rustup.rs/).

You'll also need to have the nightly toolchain, the Rust standard library source, and the `wasm32-unknown-unknown` target (since Stylus contracts are compiled to WASM):

```shell
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
rustup target add wasm32-unknown-unknown
```

### Install the Stylus CLI

You'll need the Stylus CLI to deploy the Renegade contracts for the integrationt tests:

```shell
RUSTFLAGS="-C link-args=-rdynamic" cargo install --force cargo-stylus
```

### Install `wasm-opt`

We use [`wasm-opt`](https://github.com/brson/wasm-opt-rs) to optimize the compiled WASM binaries of our contracts. Install it by running:

```shell
cargo install wasm-opt --locked
```

### Set up the Arbitrum Nitro devnet

Our integration tests require a Stylus-compatible network to be accessible. The simplest way to do this is to run a devnet locally.

Follow the instructions [here](https://docs.arbitrum.io/stylus/how-tos/local-stylus-dev-node) to set up a local Arbitrum Nitro devnet capable of supporting Stylus contracts.

## Running unit tests

Some of our functionality, for example the [Plonk verifier](./contracts-core/src/verifier/mod.rs), is defined agnostically of running in the Stylus VM (this is not the case for other functionality, e.g. the [Merkle tree](./contracts-stylus/src/contracts/merkle.rs), which depends on accessing VM state). For such functionality, we have pure-Rust unit tests, which can be invoked using `cargo`:

```shell
# Unit-tests common utilities used both in the Stylus contracts and auxiliary tooling
cargo test -p contracts-common

# Unit-tests core contract logic defined agnostically of the Stylus VM
cargo test -p contracts-core
```

_Note: since the `contracts-stylus` crate is intended only to be compiled to WASM that runs in the Stylus VM, running a simple `cargo test` at the workspace root will error when it attempts to compile the `contracts-stylus` crate (by default targeting the native maching architecture)_

## Running integration tests

### Running the devnet

Our integration tests run against deployed Stylus contracts. You'll first need to run a local Arbitrum Nitro devnet, you can follow the instructions [here](https://docs.arbitrum.io/stylus/how-tos/local-stylus-dev-node) to do so.

_Note: It may take some time for the devnet to finish its setup if it's being initialized._

### Deploying the contracts

#### Using the `scripts` crate

Next, you'll need to deploy our contracts to it. This can be done by running the scripts defined in our `scripts` crate.

It's worth getting an overview of the `scripts` CLI functionality by running:

```shell
cargo run -p scripts -- -h
```

Which will show:

```shell
Scripts for deploying & upgrading the Renegade Stylus contracts

Usage: scripts --priv-key <PRIV_KEY> --rpc-url <RPC_URL> --deployments-path <DEPLOYMENTS_PATH> <COMMAND>

Commands:
  deploy-test-contracts  Deploy all the testing contracts (includes generating testing verification keys)
  deploy-proxy           Deploy the `TransparentUpgradeableProxy` and `ProxyAdmin` contracts
  deploy-stylus          Deploy a Stylus contract
  upgrade                Upgrade the darkpool implementation
  gen-srs                Generate a structured reference string
  gen-vkeys              Generate verification keys for the protocol circuits
  help                   Print this message or the help of the given subcommand(s)

Options:
  -p, --priv-key <PRIV_KEY>                  Private key of the deployer
  -r, --rpc-url <RPC_URL>                    Network RPC URL
  -d, --deployments-path <DEPLOYMENTS_PATH>  Path to a `deployments.json` file
  -h, --help
```

For interacting with the devnet, you can define the following shell variables:

```shell
# The private key of the predeployed, prefunded dev account on the devnet
PRIV_KEY=0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659

# The URL at which the devnet RPC endpoint is accessible by default
RPC_URL=http://localhost:8547

# The path at which deployed contract addresses will be saved.
# This can really be whatever you want, but `deployments.*.json` is conveniently git-ignored
DEPLOYMENTS_PATH=deployments.devnet.json
```

#### Generating a testing SRS

You'll need a structured reference string (SRS) for Plonk verification.

You can define the following shell variable for consistency:

```shell
# This can be any path, but `srs` is conveniently git-ignored
SRS_PATH=srs
```

which can be generated (note: **insecurely**, and only for testing) by running:

```shell
cargo run -p scripts -- -p $PRIV_KEY -r $RPC_URL -d $DEPLOYMENTS_PATH gen-srs -s $SRS_PATH -d <DEGREE>
```

A degree of `4096` is sufficient for `<DEGREE>`.

#### Deploying the contracts themselves

All of the contracts used in integration testing can be deployed by running the following command:
```shell
cargo run -p scripts -- -p $PRIV_KEY -r $RPC_URL -d $DEPLOYMENTS_PATH deploy-test-contracts -o 0x3f1Eae7D46d88F08fc2F8ed27FCb2AB183EB2d0E -f <FEE> -s $SRS_PATH -v contracts-stylus/vkeys/test
```
_Note: The address `0x3f1Eae7D46d88F08fc2F8ed27FCb2AB183EB2d0E` is the address associated with the predeployed dev account, whose private key we've been using._

_Be sure to use `contracts-stylus/vkeys/test` as the argument for the `-v` flag, indicating where the verification keys should be stored, as the verification keys contract expects to find them at this path._

_The `<FEE>` parameter is the initial protocol fee to set in the darkpool contract, and is largely irrelevant for testing, so you can set it to anything (other than 0)._

### Running tests

You can get an overview of the integration testing suite by running:

```shell
cargo run -p integration -- -h
```

Which will show:

```shell
CLI tool for running integration tests against a running devnet node

Usage: integration [OPTIONS] --test <TEST> --deployments-file <DEPLOYMENTS_FILE> --srs-file <SRS_FILE>

Options:
  -t, --test <TEST>
          Test to run [possible values: all, ec-add, ec-mul, ec-pairing, ec-recover, nullifier-set, merkle, verifier, upgradeable, impl-setters, initializable, ownable, pausable, external-transfer, new-wallet, update-wallet, process-match-settle]
  -d, --deployments-file <DEPLOYMENTS_FILE>
          Path to file containing contract deployment info
  -s, --srs-file <SRS_FILE>
          Path to file containing SRS
  -p, --priv-key <PRIV_KEY>
          Devnet private key, defaults to default Nitro devnet private key [default: 0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659]
  -r, --rpc-url <RPC_URL>
          Devnet RPC URL, defaults to default Nitro devnet private key [default: http://localhost:8547]
  -h, --help
          Print help (see more with '--help')
```

As you can see, `<PRIV_KEY>` and `<RPC_URL>` have their defaults set to the expected devnet values, so the `-p` and `-r` flags can be omitted.

You should use the same `$SRS_PATH` and `$DEPLOYMENTS_PATH` that you used when deploying the contracts.

From there, you can run the entire integration testing suite using:

```shell
cargo run -p integration -- -t all -s $SRS_PATH -d $DEPLOYMENTS_PATH
```
