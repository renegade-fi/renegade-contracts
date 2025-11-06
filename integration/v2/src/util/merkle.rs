//! Utils for fetching and operating on Merkle openings

use alloy::{
    primitives::{TxHash, U256},
    providers::Provider,
};
use eyre::{eyre, Result};
use itertools::Itertools;
use num_bigint::BigUint;
use renegade_common::types::merkle::MerkleAuthenticationPath;
use renegade_constants::{Scalar, MERKLE_HEIGHT};
use renegade_crypto::fields::{scalar_to_u256, u256_to_scalar};

use crate::util::darkpool::Darkpool;

// Helper function to size a vector (copied from proof_bundles since it's private)
fn size_vec<const N: usize, T>(vec: Vec<T>) -> [T; N] {
    let size = vec.len();
    if size != N {
        panic!("vector is not the correct size: expected {N}, got {size}");
    }
    vec.try_into().map_err(|_| ()).unwrap()
}

// -----------------
// | Merkle Proofs |
// -----------------

/// Fetch a Merkle opening for a given commitment in a tx
///
/// Takes the commitment and returns the sibling path used to hash the commitment into the
/// merkle tree
pub async fn fetch_merkle_opening(
    commitment: Scalar,
    darkpool: &Darkpool,
) -> Result<MerkleAuthenticationPath> {
    // 1. Find the commitment in the darkpool logs
    let (merkle_index, tx_hash) = find_commitment(commitment, darkpool).await?;

    // 2. Fetch all Merkle opening logs for the tx
    let siblings = fetch_merkle_openings(tx_hash, darkpool).await?;

    // 3. Construct the authentication path
    let leaf_index = BigUint::from(merkle_index);
    let path_siblings = size_vec(
        siblings
            .into_iter()
            .map(|(_, v)| u256_to_scalar(&v))
            .collect_vec(),
    );

    Ok(MerkleAuthenticationPath {
        path_siblings,
        leaf_index,
        value: commitment,
    })
}

/// Find the given commitment in the Merkle insertion logs
///
/// Returns the index of the commitment in the Merkle tree, and the tx hash
async fn find_commitment(commitment: Scalar, darkpool: &Darkpool) -> Result<(u128, TxHash)> {
    let commitment_u256 = scalar_to_u256(&commitment);
    let block = darkpool.provider().get_block_number().await?;
    let from_block = block.saturating_sub(1000);
    let logs = darkpool
        .MerkleInsertion_filter()
        .topic2(commitment_u256)
        .from_block(from_block)
        .to_block(block)
        .query()
        .await?;

    let (data, log) = logs
        .last()
        .ok_or(eyre!("no logs found for MerkleInsertion"))?;
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
            .log_decode::<renegade_abi::v2::IDarkpoolV2::MerkleOpeningNode>()
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
