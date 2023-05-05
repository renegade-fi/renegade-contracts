use eyre::Result;

// Requires a devnet node running
async fn run() -> Result<()> {

    debug!("Compiling contracts...");
    utils::devnet_utils::compile()?;

    merkle::tests::run().await?;
    nullifier_set::tests::run().await?;

    Ok(())
}