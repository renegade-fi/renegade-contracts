//! Definitions of CLI arguments and commands for deploy scripts

use std::{
    fmt::{self, Display},
    sync::Arc,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use ethers::providers::Middleware;

use crate::{
    commands::{build_and_deploy_stylus_contract, deploy_proxy, gen_srs, gen_vkeys, upgrade},
    constants::DEFAULT_SRS_DEGREE,
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
    GenSrs(GenSrsArgs),
    GenVkeys(GenVkeysArgs),
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
            Command::GenSrs(args) => gen_srs(args),
            Command::GenVkeys(args) => gen_vkeys(args),
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

    /// The initial protocol fee with which to initialize the darkpool contract
    #[arg(short, long)]
    pub fee: u64,
}

/// Deploy a Stylus contract
#[derive(Args)]
pub struct DeployStylusArgs {
    /// The Stylus contract to deploy
    #[arg(short, long)]
    pub contract: StylusContract,

    /// Whether or not to enable proof & ECDSA verification.
    /// This only applies to the darkpool & Merkle contracts.
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
    Vkeys,
    TestVkeys,
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
            StylusContract::Vkeys => write!(f, "vkeys"),
            StylusContract::TestVkeys => write!(f, "test-vkeys"),
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
}

/// Generate an SRS for proving/verification keys
#[derive(Args)]
pub struct GenSrsArgs {
    /// The file path at which to write the serialized SRS
    #[arg(short, long)]
    pub srs_path: String,

    /// The degree of the SRS to generate
    #[arg(short, long, default_value_t = DEFAULT_SRS_DEGREE)]
    pub degree: usize,
}

/// Generate verification keys for the system circuits
#[derive(Args)]
pub struct GenVkeysArgs {
    /// The path to the file containing the SRS
    #[arg(short, long)]
    pub srs_path: String,

    /// The directory to which to write the verification keys
    #[arg(short, long)]
    pub vkeys_dir: String,

    /// Whether or not to create testing verification keys
    #[arg(short, long)]
    pub test: bool,
}
