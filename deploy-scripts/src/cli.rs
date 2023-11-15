//! Definitions of CLI arguments and commands for deploy scripts

use std::{
    fmt::{self, Display},
    sync::Arc,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use ethers::providers::Middleware;

use crate::{
    commands::deploy_proxy,
    errors::DeployError,
    utils::{build_stylus_contract, deploy_stylus_contract},
};

#[derive(Parser)]
pub struct Cli {
    /// Private key of the deployer
    // TODO: Better key management
    #[arg(short, long)]
    pub priv_key: String,

    /// Network RPC URL
    #[arg(short, long)]
    pub rpc_url: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    DeployProxy(DeployProxyArgs),
    DeployStylus(DeployStylusArgs),
}

impl Command {
    pub async fn run(
        self,
        client: Arc<impl Middleware>,
        rpc_url: &str,
        priv_key: &str,
    ) -> Result<(), DeployError> {
        match self {
            Command::DeployProxy(args) => deploy_proxy(args, client).await,
            Command::DeployStylus(args) => {
                let wasm_file_path = build_stylus_contract(args.contract)?;
                deploy_stylus_contract(wasm_file_path, rpc_url, priv_key)
            }
        }
    }
}

/// Deploy the Darkpool upgradeable proxy contract.
///
/// Concretely, this is a [`TransparentUpgradeableProxy`](https://docs.openzeppelin.com/contracts/5.x/api/proxy#transparent_proxy),
/// which itself deploys a `ProxyAdmin` contract.
///
/// Calls made directly to the `TransparentUpgradeableProxy` contract will be forwarded to the implementation contract.
/// Upgrade calls can only be made to the `TransparentUpgradeableProxy` through the `ProxyAdmin`.
#[derive(Args)]
pub struct DeployProxyArgs {
    /// Address of the owner for both the proxy admin contract
    /// and the underlying darkpool contract
    #[arg(short, long)]
    pub owner: String,

    /// Darkpool implementation contract address in hex
    #[arg(short, long)]
    pub darkpool: String,

    /// Verifier contract address in hex
    #[arg(short, long)]
    pub verifier: String,

    /// Merkle contract address in hex
    #[arg(short, long)]
    pub merkle: String,
}

#[derive(Args)]
pub struct DeployStylusArgs {
    #[arg(short, long)]
    pub contract: StylusContract,
}

#[derive(ValueEnum, Copy, Clone)]
pub enum StylusContract {
    Darkpool,
    DarkpoolTestContract,
    Merkle,
    MerkleTestContract,
    Verifier,
}

impl Display for StylusContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StylusContract::Darkpool => write!(f, "darkpool"),
            StylusContract::DarkpoolTestContract => write!(f, "darkpool-test-contract"),
            StylusContract::Merkle => write!(f, "merkle"),
            StylusContract::MerkleTestContract => write!(f, "merkle-test-contract"),
            StylusContract::Verifier => write!(f, "verifier"),
        }
    }
}
