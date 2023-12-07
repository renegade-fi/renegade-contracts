//! Definitions of CLI arguments and commands for deploy scripts

use std::{
    fmt::{self, Display},
    sync::Arc,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use ethers::providers::Middleware;

use crate::{
    commands::{build_and_deploy_stylus_contract, deploy_proxy, upgrade},
    errors::ScriptError,
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

    /// Path to a `deployments.json` file
    #[arg(short, long)]
    pub deployments_path: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    DeployProxy(DeployProxyArgs),
    DeployStylus(DeployStylusArgs),
    Upgrade(UpgradeArgs),
}

impl Command {
    pub async fn run(
        self,
        client: Arc<impl Middleware>,
        rpc_url: &str,
        priv_key: &str,
        deployments_path: &str,
    ) -> Result<(), ScriptError> {
        match self {
            Command::DeployProxy(args) => deploy_proxy(args, client, deployments_path).await,
            Command::DeployStylus(args) => {
                build_and_deploy_stylus_contract(args, rpc_url, priv_key, client, deployments_path)
                    .await
            }
            Command::Upgrade(args) => upgrade(args, client, deployments_path).await,
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

    /// Whether or not to use the testing contracts.
    /// This also informs how to generate verification keys.
    #[arg(short, long)]
    pub test: bool,
}

/// Deploy a Stylus contract
#[derive(Args)]
pub struct DeployStylusArgs {
    /// The Stylus contract to deploy
    #[arg(short, long)]
    pub contract: StylusContract,

    /// Whether or not to enable proof & ECDSA verification.
    /// This only applies to the darkpool contract.
    #[arg(long)]
    pub no_verify: bool,
}

#[derive(ValueEnum, Copy, Clone)]
pub enum StylusContract {
    Darkpool,
    DarkpoolTestContract,
    Merkle,
    MerkleTestContract,
    Verifier,
    DummyErc20,
}

impl Display for StylusContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StylusContract::Darkpool => write!(f, "darkpool"),
            StylusContract::DarkpoolTestContract => write!(f, "darkpool-test-contract"),
            StylusContract::Merkle => write!(f, "merkle"),
            StylusContract::MerkleTestContract => write!(f, "merkle-test-contract"),
            StylusContract::Verifier => write!(f, "verifier"),
            StylusContract::DummyErc20 => write!(f, "dummy-erc20"),
        }
    }
}

/// Upgrade the darkpool implementation
#[derive(Args)]
pub struct UpgradeArgs {
    /// Optional calldata, in hex form, with which to
    /// call the implementation contract when upgrading
    #[arg(short, long)]
    pub calldata: Option<String>,

    /// Whether or not to use the darkpool test contract address
    /// as the new implementation address
    #[arg(short, long)]
    pub test: bool,
}
