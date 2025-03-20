//! Basic integration tests for the Renegade contracts

use alloy::providers::Provider;
use eyre::Result;
use test_helpers::integration_test_async;

use crate::TestArgs;

/// Test fetching the block number for the config
async fn test_get_block_number(args: TestArgs) -> Result<()> {
    let block_number = args.wallet.get_block_number().await?;
    println!("Block number: {}", block_number);
    Ok(())
}
integration_test_async!(test_get_block_number);

/// Test fetching the Merkle root for the darkpool
async fn test_get_merkle_root(args: TestArgs) -> Result<()> {
    let merkle_root = args.darkpool.getMerkleRoot().call().await?._0;
    println!("Merkle root: {}", merkle_root);
    Ok(())
}
integration_test_async!(test_get_merkle_root);
