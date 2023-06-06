//! Command line interface for the Starknet scripts

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Deploys and initializes the Darkpool contract.
    /// This includes declaring the Darkpool, as well as Merkle & nullifier set, classes.
    Deploy(DeployArgs),

    /// Upgrades either the Darkpool, Merkle, or nullifier set contracts.
    /// This includes declaring the contract being upgraded.
    Upgrade(UpgradeArgs),
}

#[derive(Args, Debug)]
pub struct DeployArgs {
    #[arg(short, long, long_help)]
    /// The account address of the owner of the Darkpool contract,
    /// which will be able to initialize & upgrade the contract.
    /// Assumes this is the same address as the one associated with the private key.
    pub address: String,

    #[arg(long, long_help)]
    /// The path to a folder containing the Sierra & casm artifacts of the
    /// Darkpool, Merkle, & nullifier set contracts.
    /// The files in this folder should be named:
    /// renegade_contracts_{Darkpool, Merkle, NullifierSet}.{json, casm}
    pub artifacts_path: String,

    #[arg(short, long, long_help)]
    /// Which network you'd like to use.
    /// If `localhost`, the node is expected to be running on port 5050.
    pub network: Network,

    #[arg(short, long, long_help)]
    /// The private key of the account from which to send the transactions, in hex form.
    pub private_key: String,
}

#[derive(Args, Debug)]
pub struct UpgradeArgs {
    #[arg(short, long, long_help)]
    /// The account address associated with the private key.
    pub address: String,

    #[arg(short, long, long_help)]
    /// The address of the Darkpool contract.
    pub darkpool_address: String,

    #[arg(short, long, long_help)]
    /// The contract to upgrade
    pub contract: Contract,

    #[arg(long, long_help)]
    /// The path to the Sierra & casm artifacts of the contract being upgraded.
    /// This file should be named:
    /// renegade_contracts_{Darkpool, Merkle, NullifierSet}.{json, casm}
    pub artifacts_path: String,

    #[arg(short, long, long_help)]
    /// Which network you'd like to use.
    /// If `localhost`, the node is expected to be running on port 5050.
    pub network: Network,

    #[arg(short, long, long_help)]
    /// The private key of the account from which to send the transactions, in hex form.
    pub private_key: String,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Contract {
    Darkpool,
    Merkle,
    NullifierSet,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Network {
    AlphaMainnet,
    AlphaGoerli,
    AlphaGoerli2,
    Localhost,
}
