//! Definitions of CLI arguments and commands for deploy scripts

use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use ethers::providers::Middleware;

use crate::{commands::deploy_proxy, errors::DeployError};

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
}

#[derive(Args)]
pub struct DeployProxyArgs {
    /// Path to the proxy contract ABI
    #[arg(short, long)]
    pub abi: String,

    /// Path to the proxy contract bytecode
    #[arg(short, long)]
    pub bytecode: String,

    /// Implementation contract address in hex
    #[arg(short, long)]
    pub implementation: String,

    /// Proxy admin contract owner address in hex
    #[arg(short, long)]
    pub owner: String,

    /// Implementation contract calldata in hex
    #[arg(short, long)]
    pub calldata: Option<String>,
}

impl Command {
    pub async fn run(self, client: Arc<impl Middleware>) -> Result<(), DeployError> {
        match self {
            Command::DeployProxy(args) => deploy_proxy(args, client).await,
        }
    }
}
