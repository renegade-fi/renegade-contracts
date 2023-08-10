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
  <img
    src="https://github.com/renegade-fi/renegade-contracts/actions/workflows/format.yml/badge.svg"
  />
  <a href="https://twitter.com/renegade_fi" target="_blank">
    <img src="https://img.shields.io/twitter/follow/renegade_fi?style=social" />
  </a>
  <a href="https://discord.gg/renegade-fi" target="_blank">
    <img src="https://img.shields.io/discord/1032770899675463771?label=Join%20Discord&logo=discord&style=social" />
  </a>
</div>

This repository contains the Starknet Cairo code for Renegade's settlement
layer. This includes managing the system-global state, verifying bulletproofs,
and emitting events that are consumed by the p2p network.

Our contracts and tooling stack currently targets the Cairo `v2.0.1` compiler.

## Contract Development Setup

We use the following stack to support Starknet development:
- [`scarb`](https://github.com/software-mansion/scarb): For managing Cairo dependencies & builds
- [`starknet-rs`](https://github.com/xJonathanLEI/starknet-rs): For interacting with Starknet (devnet, testnet, mainnet)
- [`katana`](https://github.com/dojoengine/dojo/tree/main/crates/katana): For running a devnet node (used for integration tests)

To setup your local machine for Renegade contract development:

### Clone the repo
```
git clone https://github.com/renegade-fi/renegade-contracts
```

### Install Rust

Make sure you have Rust installed, using e.g. [`rustup`](https://rustup.rs/)

### Install Scarb

Install `scarb` version `0.5.1` by following the instructions [here](https://docs.swmansion.com/scarb/docs/install).

## Running Cairo tests

You can run the Cairo tests for the various contracts by invoking the following command:
```shell
scarb test
```
from the project root.

## Running Devnet tests

In order to run tests that require a devnet, you must first build the contracts:
```shell
scarb -P release build
```

Then, you can run our devnet tests by invoking the following command:
```shell
RUST_LOG="tests=debug,katana_core=warn" ARTIFACTS_PATH=<SCARB BUILD PATH> CAIRO_STEP_LIMIT=10000000 cargo test -p tests --lib --all-targets
```
from the project root.

The `ARTIFACTS_PATH` environment variable is **required** to be set, and is a path to folder where Scarb builds the contracts
(when using the `release` profile as above, this is typically `<PROJECT ROOT>/target/release`).

The `CAIRO_STEP_LIMIT` environment variable dictates the execution limits of the devnet node, we recommend setting it to `10000000`
(currently 10x the mainnet execution limit) as some of our code exceeds the default execution limits.

Finally, you can use the `RUST_LOG` environment variable to configure log output from the tests. We recommend `tests=debug,katana_core=warn` as above.
