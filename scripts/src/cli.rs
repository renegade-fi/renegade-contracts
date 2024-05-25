//! Definitions of CLI arguments and commands for deploy scripts

use std::sync::Arc;

use clap::{Args, Parser, Subcommand};

use crate::{
    commands::{
        build_and_deploy_stylus_contract, deploy_erc20s, deploy_permit2, deploy_proxy,
        deploy_test_contracts, gen_vkeys, upgrade,
    },
    errors::ScriptError,
    types::StylusContract,
    utils::LocalWalletHttpClient,
};

/// Scripts for deploying & upgrading the Renegade Stylus contracts
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

    /// The command to run
    #[command(subcommand)]
    pub command: Command,
}

/// The possible CLI commands
#[derive(Subcommand)]
pub enum Command {
    /// Deploy all the testing contracts (includes generating testing verification keys)
    DeployTestContracts(DeployTestContractsArgs),
    /// Deploy the `TransparentUpgradeableProxy` and `ProxyAdmin` contracts
    DeployProxy(DeployProxyArgs),
    /// Deploy the `Permit2` contract
    DeployPermit2,
    /// Deploy a Stylus contract
    DeployStylus(DeployStylusArgs),
    /// Deploy dummy ERC20s
    DeployErc20s(DeployErc20sArgs),
    /// Upgrade the darkpool implementation
    Upgrade(UpgradeArgs),
    /// Generate verification keys for the protocol circuits
    GenVkeys(GenVkeysArgs),
}

impl Command {
    /// Run the command
    pub async fn run(
        self,
        client: Arc<LocalWalletHttpClient>,
        rpc_url: &str,
        priv_key: &str,
        deployments_path: &str,
    ) -> Result<(), ScriptError> {
        match self {
            Command::DeployTestContracts(args) => {
                deploy_test_contracts(args, rpc_url, priv_key, client, deployments_path).await
            }
            Command::DeployProxy(args) => deploy_proxy(args, client, deployments_path).await,
            Command::DeployPermit2 => deploy_permit2(client, deployments_path).await,
            Command::DeployStylus(args) => {
                build_and_deploy_stylus_contract(args, rpc_url, priv_key, client, deployments_path)
                    .await
            }
            Command::DeployErc20s(args) => {
                deploy_erc20s(args, rpc_url, priv_key, client, deployments_path).await
            }
            Command::Upgrade(args) => upgrade(args, client, deployments_path).await,
            Command::GenVkeys(args) => gen_vkeys(args),
        }
    }
}

/// Deploy all the testing contracts (includes generating testing verification keys)
#[derive(Args)]
pub struct DeployTestContractsArgs {
    /// Address of the owner for both the proxy admin contract
    /// and the underlying darkpool contract
    #[arg(short, long)]
    pub owner: String,

    /// Whether or not to enable proof & ECDSA verification.
    /// This only applies to the darkpool & Merkle contracts.
    #[arg(long)]
    pub no_verify: bool,

    /// The directory to which to write the testing verification keys
    #[arg(short, long)]
    pub vkeys_dir: String,
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

    /// The initial protocol fee with which to initialize the darkpool contract.
    /// The fee is a percentage of the trade volume, represented as a fixed-point number.
    /// The `u64` used here should accommodate any fee we'd want to set.
    ///
    /// The default value here is the fixed-point representation of 0.0002 (2 bps),
    /// that is 0.0002 * 2^32
    #[arg(short, long, default_value = "858993")]
    pub fee: u64,

    /// The public EC-ElGamal encryption key for the protocol,
    /// hex-encoded in compressed form.
    /// If not provided, a random key will be generated.
    #[arg(short, long)]
    pub protocol_public_encryption_key: Option<String>,
}

/// Deploy a Stylus contract
#[derive(Args, Clone, Copy)]
pub struct DeployStylusArgs {
    /// The Stylus contract to deploy
    #[arg(short, long)]
    pub contract: StylusContract,

    /// Whether or not to enable proof & ECDSA verification.
    /// This only applies to the darkpool & Merkle contracts.
    #[arg(long)]
    pub no_verify: bool,
}

/// Deploy dummy ERC20s. Assumes the darkpool contract has already been deployed.
#[derive(Args)]
pub struct DeployErc20sArgs {
    /// The tickers for the ERC20s to deploy
    #[arg(short, long, value_parser, num_args = 1.., value_delimiter = ' ')]
    pub tickers: Vec<String>,

    /// The amount with which to fund each account
    #[arg(short, long)]
    pub funding_amount: u128,

    /// A space-separated list of private keys corresponding to the accounts
    /// which will be funded with the ERC20s and
    /// for which the darkpool will be approved to transfer ERC20s
    #[arg(short, long, value_parser, num_args = 0.., value_delimiter = ' ')]
    pub account_skeys: Vec<String>,
}

/// Upgrade the darkpool implementation
#[derive(Args)]
pub struct UpgradeArgs {
    /// Optional calldata, in hex form, with which to
    /// call the implementation contract when upgrading
    #[arg(short, long)]
    pub calldata: Option<String>,
}

/// Generate verification keys for the system circuits
#[derive(Args)]
pub struct GenVkeysArgs {
    /// The directory to which to write the verification keys
    #[arg(short, long)]
    pub vkeys_dir: String,

    /// Whether or not to create testing verification keys
    #[arg(short, long)]
    pub test: bool,
}
