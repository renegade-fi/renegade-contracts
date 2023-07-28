use clap::{Parser, Subcommand};
use eyre::Result;
use starknet_scripts::{
    cli::{DeployArgs, UpgradeArgs},
    commands::{deploy::deploy_and_initialize, upgrade::upgrade},
};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Deploys and initializes one of the contracts (darkpool, merkle, nullifier set).
    Deploy(DeployArgs),

    /// Upgrades one of the contracts (darkpool, merkle, nullifier set).
    Upgrade(UpgradeArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    match CliArgs::parse().command {
        Commands::Deploy(args) => deploy_and_initialize(args).await?,
        Commands::Upgrade(args) => upgrade(args).await?,
    };

    Ok(())
}
