use clap::Parser;
use deploy_scripts::{cli::Cli, utils::setup_client};

#[tokio::main]
async fn main() {
    let Cli { priv_key, rpc_url, command } = Cli::parse();

    let client = setup_client(priv_key, rpc_url).await.unwrap();

    command.run(client).await.unwrap();
}
