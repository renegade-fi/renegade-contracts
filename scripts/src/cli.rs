//! Definitions of CLI arguments and commands for deploy scripts

use clap::{Args, Parser, Subcommand};

use crate::{
    commands::{
        build_and_deploy_stylus_contract, deploy_darkpool_proxy, deploy_erc20,
        deploy_gas_sponsor_proxy, deploy_permit2, deploy_test_contracts,
        gen_set_all_delegate_addresses_calldata_hex, gen_vkeys, upgrade,
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
    #[arg(short, long, env = "PKEY")]
    pub priv_key: String,

    /// Network RPC URL
    #[arg(short, long, env = "RPC_URL")]
    pub rpc_url: String,

    /// Path to a `deployments.json` file
    #[arg(short, long, env = "DEPLOYMENTS")]
    pub deployments_path: String,

    /// The command to run
    #[command(subcommand)]
    pub command: Command,
}

/// The possible CLI commands
#[derive(Subcommand)]
pub enum Command {
    /// Deploy all the testing contracts (includes generating testing
    /// verification keys)
    DeployTestContracts(DeployTestContractsArgs),
    /// Deploy the proxy contracts for
    /// the darkpool
    DeployDarkpoolProxy(DeployDarkpoolProxyArgs),
    /// Deploy the proxy contracts for
    /// the gas sponsor
    DeployGasSponsorProxy(DeployGasSponsorProxyArgs),
    /// Deploy the `Permit2` contract
    DeployPermit2,
    /// Deploy a Stylus contract
    DeployStylus(DeployStylusArgs),
    /// Deploy a dummy ERC20
    DeployErc20(DeployErc20Args),
    /// Upgrade the darkpool implementation
    Upgrade(UpgradeArgs),
    /// Generate the calldata for invoking `setAllDelegateAddresses`
    // TODO: REMOVE AFTER DEPLOY
    SetAllDelegateAddressesCalldata(SetAllDelegateAddressesCalldataArgs),
    /// Generate verification keys for the protocol circuits
    GenVkeys(GenVkeysArgs),
}

impl Command {
    /// Run the command
    pub async fn run(
        self,
        client: LocalWalletHttpClient,
        rpc_url: &str,
        priv_key: &str,
        deployments_path: &str,
    ) -> Result<(), ScriptError> {
        match self {
            Command::DeployTestContracts(args) => {
                deploy_test_contracts(&args, rpc_url, priv_key, client, deployments_path).await
            },
            Command::DeployDarkpoolProxy(args) => {
                deploy_darkpool_proxy(&args, client, deployments_path).await
            },
            Command::DeployGasSponsorProxy(args) => {
                deploy_gas_sponsor_proxy(&args, client, deployments_path).await
            },
            Command::DeployPermit2 => deploy_permit2(client, deployments_path).await,
            Command::DeployStylus(args) => {
                build_and_deploy_stylus_contract(&args, rpc_url, priv_key, client, deployments_path)
                    .await
                    .map(|_| ())
            },
            Command::DeployErc20(args) => {
                deploy_erc20(&args, rpc_url, priv_key, client, deployments_path).await.map(|_| ())
            },
            Command::Upgrade(args) => upgrade(&args, client, deployments_path).await,
            Command::SetAllDelegateAddressesCalldata(args) => {
                gen_set_all_delegate_addresses_calldata_hex(&args, deployments_path)
            },
            Command::GenVkeys(args) => gen_vkeys(&args),
        }
    }
}

/// Deploy all the testing contracts (includes generating testing verification
/// keys)
#[derive(Args)]
pub struct DeployTestContractsArgs {
    /// The directory to which to write the testing verification keys
    #[arg(short, long)]
    pub vkeys_dir: String,
}

/// Deploy the Darkpool upgradeable proxy contract.
///
/// Concretely, this is a [`TransparentUpgradeableProxy`](https://docs.openzeppelin.com/contracts/5.x/api/proxy#transparent_proxy),
/// which itself deploys a `ProxyAdmin` contract.
///
/// Calls made directly to the `TransparentUpgradeableProxy` contract will be
/// forwarded to the implementation contract. Upgrade calls can only be made to
/// the `TransparentUpgradeableProxy` through the `ProxyAdmin`.
#[derive(Args)]
pub struct DeployDarkpoolProxyArgs {
    /// The initial protocol fee with which to initialize the darkpool contract.
    /// The fee is a percentage of the trade volume, represented as a
    /// fixed-point number. The `u64` used here should accommodate any fee
    /// we'd want to set.
    ///
    /// The default value here is the fixed-point representation of 0.0002 (2
    /// bps), that is 0.0002 * 2^63
    #[arg(short, long, default_value = "1844674407370955")]
    pub fee: u64,

    /// The public EC-ElGamal encryption key for the protocol,
    /// hex-encoded in compressed form.
    /// If not provided, a random key will be generated.
    #[arg(short, long)]
    pub protocol_public_encryption_key: Option<String>,

    /// The address of the protocol external fee collection wallet
    #[arg(long)]
    pub protocol_external_fee_collection_address: Option<String>,

    /// Whether or not to use the test contracts
    #[arg(short, long)]
    pub test: bool,
}

/// Deploy the gas sponsor upgradeable proxy contract, similar to the darkpool
/// proxy contract.
///
/// Assumes the gas sponsor contract & darkpool proxy contract have already been
/// deployed by referencing their addresses in the `deployments.json` file.
#[derive(Args)]
pub struct DeployGasSponsorProxyArgs {
    /// The address pertaining to the auth pubkey for gas sponsorship
    #[arg(short, long)]
    pub auth_address: String,
}

/// Deploy a Stylus contract
#[derive(Args, Clone)]
pub struct DeployStylusArgs {
    /// The Stylus contract to deploy
    #[arg(short, long)]
    pub contract: StylusContract,
}

/// Deploy a dummy ERC20. Assumes the darkpool contract has already been
/// deployed.
#[derive(Args)]
pub struct DeployErc20Args {
    /// The symbol for the ERC20 to deploy
    #[arg(short, long)]
    pub symbol: String,

    /// The name for the ERC20 to deploy
    #[arg(short, long)]
    pub name: String,

    /// The number of decimals for the ERC20 to deploy
    #[arg(short, long)]
    pub decimals: u8,

    /// Whether or not to deploy the native asset wrapper erc20 (WETH)
    #[arg(long)]
    pub as_wrapper: bool,

    /// The amount with which to fund each account
    #[arg(short, long)]
    pub funding_amount: Option<u128>,

    /// A space-separated list of private keys corresponding to the accounts
    /// which will be funded with the ERC20 and for which the Permit2 contract
    /// will be approved to transfer the ERC20
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

    /// Whether or not to upgrade the darkpool test contract
    #[arg(short, long)]
    pub test: bool,
}

/// Generate the calldata for invoking `setAllDelegateAddresses`
#[derive(Args)]
pub struct SetAllDelegateAddressesCalldataArgs {
    /// Whether or not to use the test contracts
    #[arg(short, long)]
    pub test: bool,
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
