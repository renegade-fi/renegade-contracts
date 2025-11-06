//! Utilities for sending and waiting on transactions

use alloy::{
    contract::{CallBuilder, CallDecoder},
    network::Ethereum,
    providers::DynProvider,
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
    let receipt = pending_tx.get_receipt().await?;
    Ok(receipt)
}
