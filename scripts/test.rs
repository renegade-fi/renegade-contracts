use eyre::Result;

// Requires a devnet node running
async fn run() -> Result<()> {

    // warn!("SKIPPING contract compilation");
    debug!("Compiling contracts...");
    utils::devnet_utils::compile("./Scarb.toml")?;

    utils::common_utils::init_devnet_state(None).await?;

    nullifier_set::tests::run().await?;
    merkle::tests::run().await?;
    darkpool::tests::run().await?;

    Ok(())
}