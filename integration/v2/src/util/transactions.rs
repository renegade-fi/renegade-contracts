//! Utilities for sending and waiting on transactions

use std::time::Duration;

use alloy::{
    contract::{CallBuilder, CallDecoder},
    network::Ethereum,
    providers::{DynProvider, Provider},
    rpc::types::TransactionReceipt,
};
use eyre::Result;
use test_helpers::assert_eq_result;

/// The call builder type for the tests
pub type TestCallBuilder<'a, C> = CallBuilder<&'a DynProvider, C, Ethereum>;

// ----------------
// | Transactions |
// ----------------

/// Wait for a transaction receipt and ensure it was successful
pub async fn wait_for_tx_success<C: CallDecoder>(
    tx: TestCallBuilder<'_, C>,
) -> Result<TransactionReceipt> {
    let receipt = send_tx(tx).await?;
    assert_eq_result!(receipt.status(), true)?;
    Ok(receipt)
}

/// Send a transaction and wait for it to succeed or fail
pub async fn send_tx<C: CallDecoder>(tx: TestCallBuilder<'_, C>) -> Result<TransactionReceipt> {
    let pending_tx = tx.send().await?;
    let tx_hash = *pending_tx.tx_hash();

    // Retry fetching the receipt up to 10 times
    // The current version of alloy has issues watching the pending transaction directly, so we patch this here
    let mut remaining_attempts = 10;
    let provider = tx.provider;
    while remaining_attempts > 0 {
        match provider.get_transaction_receipt(tx_hash).await? {
            Some(receipt) => return Ok(receipt),
            None => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                remaining_attempts -= 1;
            }
        }
    }

    eyre::bail!("no tx receipt found after retries");
}
