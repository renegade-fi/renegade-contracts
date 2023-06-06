mod cli;
mod commands;

use clap::Parser;
use commands::{deploy::deploy_and_initialize, upgrade::upgrade};
use eyre::Result;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use cli::{CliArgs, Commands};

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
