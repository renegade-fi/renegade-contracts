// Auto-generated file. Don't edit directly.

use eyre::Result;

// Requires a devnet node running
async fn run() -> Result<()> {
    debug!("Compiling contracts...");
    utils::devnet_utils::compile()?;

    merkle::tests::run().await?;
    // nullifier_set::tests::run().await?;

    Ok(())
}
pub mod merkle;
pub mod nullifier_set;
pub mod utils;
use std::process::exit;
use tokio::runtime::Builder;
use tracing::log::{debug, error};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

fn main() {
    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();

    let res = runtime.block_on(async {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_env("NILE_LOG"))
            .init();

        let mut devnet = utils::devnet_utils::spawn_devnet().await;
        let res = run().await;
        debug!("Killing devnet...");
        devnet.kill()?;
        res
    });

    match res {
        Ok(_) => exit(0),
        Err(e) => {
            error!("{}", e);
            exit(1)
        }
    }
}
