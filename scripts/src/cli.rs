//! Definitions of CLI arguments and commands for deploy scripts

use std::{
    fmt::{self, Display},
    sync::Arc,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use ethers::providers::Middleware;

use crate::{
    commands::{build_and_deploy_stylus_contract, deploy_proxy, upgrade, upload_vkey},
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

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    DeployProxy(DeployProxyArgs),
    DeployStylus(DeployStylusArgs),
    Upgrade(UpgradeArgs),
    UploadVkey(UploadVkeyArgs),
}

impl Command {
    pub async fn run(
        self,
        client: Arc<impl Middleware>,
        rpc_url: &str,
        priv_key: &str,
    ) -> Result<(), ScriptError> {
        match self {
            Command::DeployProxy(args) => deploy_proxy(args, client).await,
            Command::DeployStylus(args) => {
                build_and_deploy_stylus_contract(args, rpc_url, priv_key)
            }
            Command::Upgrade(args) => upgrade(args, client).await,
            Command::UploadVkey(args) => upload_vkey(args, client).await,
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

/// Deploy a Stylus contract
#[derive(Args)]
pub struct DeployStylusArgs {
    /// The Stylus contract to deploy
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

/// Upgrade the darkpool implementation
#[derive(Args)]
pub struct UpgradeArgs {
    /// Address of the proxy admin contract
    #[arg(long)]
    pub proxy_admin: String,

    /// Address of the proxy contract
    #[arg(long)]
    pub proxy: String,

    /// Address of the new implementation contract
    #[arg(short, long)]
    pub implementation: String,

    /// Optional calldata, in hex form, with which to
    /// call the implementation contract when upgrading
    #[arg(short, long)]
    pub calldata: Option<String>,
}

/// Upload a new verification key
#[derive(Args)]
pub struct UploadVkeyArgs {
    /// Which circuit to upload the verification key for
    #[arg(short, long)]
    pub circuit: Circuit,

    /// The address of the darkpool proxy contract
    #[arg(short, long)]
    pub darkpool_address: String,

    /// Whether or not to use the smaller circuit size parameters
    #[arg(short, long)]
    pub small: bool,
}

#[derive(ValueEnum, Copy, Clone)]
pub enum Circuit {
    ValidWalletCreate,
    ValidWalletUpdate,
    ValidCommitments,
    ValidReblind,
    ValidMatchSettle,
}
