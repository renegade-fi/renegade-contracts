// Requires a devnet node running
async fn run(nre: NileRuntimeEnvironment) {
    println!("Running");

    let accounts = nre.get_predeployed_accounts().await;
    println!("Predeployed accounts: {:?}", accounts);
}
