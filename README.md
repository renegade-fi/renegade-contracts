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
    src="https://github.com/renegade-fi/renegade-contracts/actions/workflows/test_cairo.yml/badge.svg"
  />
  <img
    src="https://github.com/renegade-fi/renegade-contracts/actions/workflows/test_nile.yml/badge.svg"
  />
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

Our contracts and tooling stack currently targets the Cairo `v1.0.0-alpha.6` compiler.

## Contract Development Setup

We use the following stack to support Starknet development:
- [`scarb`](https://github.com/software-mansion/scarb): For managing Cairo dependencies
- [`nile-rs`](https://github.com/OpenZeppelin/nile-rs): For interacting with a devnet node
- [`starknet-devnet`](https://github.com/0xSpaceShard/starknet-devnet): For running a devnet node (used for integration tests)

This is overwhelmingly likely to change. The Starknet ecosystem, let alone the Cairo 1 ecosystem, is very nascent and the landscape
of tooling options is shifting quickly. As such, the current utilities around testing (NOT the test cases themselves) are somewhat
crude, so we don't depend on them anywhere else (e.g. in the deploy/upgrade scripts), but they get the job done.

To setup your local machine for Renegade contract development:

### Clone the repo
```
git clone https://github.com/renegade-fi/renegade-contracts
```

### Install Rust

Make sure you have Rust installed, using e.g. [`rustup`](https://rustup.rs/)

### Install the Cairo compiler

Parts of our tooling stack (namely, the Cairo test runner and the devnet node) require the compiler to be built locally.

To do this you can follow the instructions [here](https://cairo-book.github.io/ch01-01-installation.html), making sure to target `v1.0.0-alpha.6` of the compiler.

Once you've done this, set the environment variable `CAIRO_COMPILER_MANIFEST` to the path of the `Cargo.toml` manifest file in the compiler package you just built:
```shell
export CAIRO_COMPILER_MANIFEST=<PATH TO COMPILER CARGO.TOML>
```

### Install Scarb

Install `scarb` version `0.1.0` by following the instructions [here](https://docs.swmansion.com/scarb/docs/install).

Then, install `scarb-eject` (used to run Cairo tests that have Scarb dependencies) by follwoing the instructions [here](https://github.com/software-mansion-labs/scarb-eject#installation).

At this point, if you'd like, you should already be able to run our Cairo tests! You can do so by running:
```shell
scarb run test
```
from the project root.

### Install Nile-rs

Install `nile-rs` by following the instructions [here](https://github.com/OpenZeppelin/nile-rs#installation).

### Install Starknet Devnet

Install `starknet-devnet` by following the instructions [here](https://0xspaceshard.github.io/starknet-devnet/docs/intro).

This requires a Python version `>= 3.9` and `< 3.10`.

After doing this, set the environment variable `DEVNET_STATE_PATH` to some path where you'd like the devnet node to cache its state when running tests:
```shell
export DEVNET_STATE_PATH=<PATH TO DUMP FILE>.pkl
```

## Running Cairo tests

You can run the Cairo tests for the various contracts by invoking the following command:
```shell
scarb run test
```
from the project root.

## Running Devnet tests

You can run our devnet tests by invoking the following command:
```shell
nile-rs run test
```
from the project root.

Make sure the `CAIRO_COMPILER_MANIFEST` and `DEVNET_STATE_PATH` environment variables defined above are set.

Additionally, you can set the `NILE_LOG` environment variable to control the logging level from the devnet tests:
```shell
export NILE_LOG="nile_rs_scripts_module=debug"
```
You probably want to set this environment variable for the `nile_rs_scripts_module` module to avoid seeing logs from dependencies.
