use eyre::Result;

// Requires a devnet node running
async fn run(_nre: NileRuntimeEnvironment) -> Result<()> {
    println!("Compiling contracts...");
    utils::compile()?;

    let contract = "HelloStarknet";
    println!("Declaring {contract} contract...");
    utils::declare(contract)?;

    println!("Deploying {contract} contract...");
    let contract_address = utils::deploy("HelloStarknet")?;

    let function = "get_balance";
    println!("Calling {function} on {contract} at address {contract_address}");
    let res = utils::call(&contract_address, function, vec![])?;
    println!("Balance: {res:#?}");

    let function = "increase_balance";
    let calldata = vec!["0", "1"];
    println!("Calling {function} on {contract} at address {contract_address} with calldata {calldata:?}");
    utils::send(&contract_address, function, calldata)?;

    let function = "get_balance";
    println!("Calling {function} on {contract} at address {contract_address}");
    let res = utils::call(&contract_address, function, vec![])?;
    println!("Balance: {res:#?}");

    Ok(())
}
