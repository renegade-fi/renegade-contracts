// Auto-generated file. Don't edit directly.

use eyre::Result;

// Requires a devnet node running
async fn run(_nre: NileRuntimeEnvironment) -> Result<()> {
    panic!("test")
    // println!("Compiling contracts...");
    // utils::compile()?;

    // let contract = "HelloStarknet";
    // println!("Declaring {contract} contract...");
    // utils::declare(contract)?;

    // println!("Deploying {contract} contract...");
    // let contract_address = utils::deploy("HelloStarknet")?;

    // let function = "get_balance";
    // println!("Calling {function} on {contract} at address {contract_address}");
    // let res = utils::call(&contract_address, function, vec![])?;
    // println!("Balance: {res:#?}");

    // let function = "increase_balance";
    // let calldata = vec!["0", "1"];
    // println!("Calling {function} on {contract} at address {contract_address} with calldata {calldata:?}");
    // utils::send(&contract_address, function, calldata)?;

    // let function = "get_balance";
    // println!("Calling {function} on {contract} at address {contract_address}");
    // let res = utils::call(&contract_address, function, vec![])?;
    // println!("Balance: {res:#?}");

    // Ok(())
}

pub mod utils;
extern crate nile_rs;
use nile_rs::nre::NileRuntimeEnvironment;

#[tokio::main]
async fn main() {
    let nre = NileRuntimeEnvironment::new("localhost").unwrap();
    let mut devnet = utils::spawn_devnet().await;
    match run(nre).await {
        Ok(_) => {}
        Err(e) => {
            eprintln!("An error occurred: {}", e);
        }
    }
    println!("killing devnet");
    devnet.kill().unwrap();
}
