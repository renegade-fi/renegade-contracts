use clap::Parser;
use deploy_scripts::{cli::Cli, errors::DeployError, utils::setup_client};

#[tokio::main]
async fn main() -> Result<(), DeployError> {
    let Cli {
        priv_key,
        rpc_url,
        command,
    } = Cli::parse();

    let client = setup_client(&priv_key, &rpc_url).await?;

    command.run(client, &rpc_url, &priv_key).await
}
