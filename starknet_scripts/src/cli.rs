//! Command line interface for the Starknet scripts

use clap::{Args, ValueEnum};

// TODO: Move everything except for `CliArgs` and `Commands` into library crate,
// and the former into the binary crate.

#[derive(Args, Debug)]
pub struct DeployArgs {
    #[arg(short, long, long_help)]
    /// The contract to deploy
    pub contract: Contract,

    #[arg(long, long_help)]
    /// The class hash of the darkpool contract, in hex form.
    /// {n}
    /// If the darkpool contract is being deployed and this flag is not set,
    /// the darkpool contract will be declared.
    pub darkpool_class_hash: Option<String>,

    #[arg(long, long_help)]
    /// The class hash of the merkle contract, in hex form.
    /// {n}
    /// If the darkpool or merkle contract is being deployed and this flag is not set,
    /// the merkle contract will be declared.
    pub merkle_class_hash: Option<String>,

    #[arg(long, long_help)]
    /// The class hash of the nullifier set contract, in hex form.
    /// {n}
    /// If the darkpool or nullifier set contract is being deployed and this flag is not set,
    /// the nullifier set contract will be declared.
    pub nullifier_set_class_hash: Option<String>,

    #[arg(short, long, long_help)]
    /// Whether or not to initialize the contract.
    pub initialize: bool,

    #[arg(short, long, long_help)]
    /// The account address of the owner of the Darkpool contract,
    /// which will be able to initialize & upgrade the contract.
    /// {n}
    /// Assumes this is the same address as the one associated with the private key.
    pub address: String,

    #[arg(long, long_help)]
    /// The path to a folder containing the Sierra & casm artifacts of the
    /// Darkpool, Merkle, & nullifier set contracts.
    /// {n}
    /// The files in this folder should be named:
    /// {n}
    /// renegade_contracts_{Darkpool, Merkle, NullifierSet}.{sierra.json, casm}
    pub artifacts_path: String,

    #[arg(short, long, long_help)]
    /// Which network you'd like to use.
    /// {n}
    /// If `localhost`, the node is expected to be running on port 5050.
    pub network: Network,

    #[arg(short, long, long_help)]
    /// The private key of the account from which to send the transactions, in hex form.
    pub private_key: String,
}

#[derive(Args, Debug)]
pub struct UpgradeArgs {
    #[arg(long, long_help)]
    /// The class hash of the contract being upgraded, in hex form.
    /// {n}
    /// If this flag is not set, the contract will be declared.
    pub class_hash: Option<String>,

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
    /// {n}
    /// This file should be named:
    /// {n}
    /// renegade_contracts_{Darkpool, Merkle, NullifierSet}.{sierra.json, casm}
    pub artifacts_path: String,

    #[arg(short, long, long_help)]
    /// Which network you'd like to use.
    /// {n}
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
