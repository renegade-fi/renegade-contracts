//! Utilities for integration tests

use alloy::{
    network::Ethereum,
    primitives::{TxHash, U256},
    providers::{DynProvider, Provider},
    rpc::types::TransactionReceipt,
};
use alloy_contract::{CallBuilder, CallDecoder};
use eyre::Result;
use itertools::Itertools;
use num_bigint::BigUint;
use renegade_common::types::merkle::MerkleAuthenticationPath;
use renegade_constants::{Scalar, MERKLE_HEIGHT};
use test_helpers::assert_eq_result;

use crate::{
    contracts::{
        darkpool::MerkleOpeningNode,
        type_conversion::{scalar_to_u256, size_vec, u256_to_scalar},
    },
    Darkpool,
};

/// The call builder type for the tests
pub type TestCallBuilder<'a, C> = CallBuilder<(), &'a DynProvider, C, Ethereum>;

// -----------------
// | Merkle Proofs |
// -----------------

/// Fetch a Merkle opening for a given wallet in a tx
///
/// Takes the wallet commitment and returns the sibling path used to hash the commitment into the
/// merkle tree
pub async fn fetch_merkle_opening(
    commitment: Scalar,
    darkpool: &Darkpool,
) -> Result<MerkleAuthenticationPath> {
    // 1. Find the public blinder in the darkpool logs
    let (merkle_index, tx_hash) = find_commitment(commitment, darkpool).await?;

    // 2. Fetch all Merkle opening logs for the tx
    let siblings = fetch_merkle_openings(tx_hash, darkpool).await?;

    // 3. Construct the authentication path
    let leaf_index = BigUint::from(merkle_index);
    let path_siblings = size_vec(
        siblings
            .into_iter()
            .map(|(_, v)| u256_to_scalar(v))
            .collect_vec(),
    );

    Ok(MerkleAuthenticationPath {
        path_siblings,
        leaf_index,
        value: commitment,
    })
}

/// Find the given public blinder in the Merkle insertion logs
///
/// Returns the index of the commitment in the Merkle tree, and the tx hash
async fn find_commitment(commitment: Scalar, darkpool: &Darkpool) -> Result<(u128, TxHash)> {
    let commitment_u256 = scalar_to_u256(commitment);
    let logs = darkpool
        .MerkleInsertion_filter()
        .topic2(commitment_u256)
        .query()
        .await?;

    let (data, log) = logs.last().expect("no logs found for MerkleInsertion");
    Ok((data.index, log.transaction_hash.unwrap()))
}

/// Fetch the Merkle opening logs for a given tx hash
///
/// Returns the logs in order of increasing height (decreasing depth)
async fn fetch_merkle_openings(tx_hash: TxHash, darkpool: &Darkpool) -> Result<Vec<(u128, U256)>> {
    let tx_receipt = darkpool
        .provider()
        .get_transaction_receipt(tx_hash)
        .await?
        .expect("no tx receipt");

    let mut opening_nodes = Vec::with_capacity(MERKLE_HEIGHT);
    for log in tx_receipt.logs() {
        if let Ok(decoded) = log
            .log_decode::<MerkleOpeningNode>()
            .map(|l| l.into_inner())
        {
            opening_nodes.push((decoded.depth, decoded.index, decoded.new_value));
        }
    }

    // Sort by decreasing depth
    opening_nodes.sort_by_key(|s| -(s.0 as i8));
    let siblings = opening_nodes.into_iter().map(|(_, i, v)| (i, v)).collect();
    Ok(siblings)
}

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

/// Send a call and return the result
pub async fn call_helper<C: CallDecoder + Unpin>(
    call: TestCallBuilder<'_, C>,
) -> Result<C::CallOutput> {
    let res = call.call().await?;
    Ok(res)
}

// ----------
// | Errors |
// ----------

/// A trait with auto-implementation that makes it easier to convert errors to `eyre::Result`
pub trait WrapEyre {
    /// The type of the value being wrapped
    type Value;

    /// Convert the error to an eyre::Result
    fn to_eyre(self) -> Result<Self::Value>;
}

impl<R, E: ToString> WrapEyre for core::result::Result<R, E> {
    type Value = R;

    fn to_eyre(self) -> Result<R> {
        match self {
            Ok(r) => Ok(r),
            Err(e) => Err(eyre::eyre!(e.to_string())),
        }
    }
}
