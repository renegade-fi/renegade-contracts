use clap::Parser;
use scripts::{cli::Cli, errors::ScriptError, utils::setup_client};

#[tokio::main]
async fn main() -> Result<(), ScriptError> {
    let Cli {
        priv_key,
        rpc_url,
        command,
        deployments_path,
    } = Cli::parse();

    tracing_subscriber::fmt().pretty().init();

    let client = setup_client(&priv_key, &rpc_url).await?;

    command
        .run(client, &rpc_url, &priv_key, &deployments_path)
        .await
}
