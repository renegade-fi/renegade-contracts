//! Integration testing utilities for contract interaction

use alloy::signers::local::PrivateKeySigner;
use alloy_contract::CallDecoder;
use alloy_sol_types::SolCall;
use ark_crypto_primitives::merkle_tree::MerkleTree as ArkMerkleTree;
use circuit_types::elgamal::EncryptionKey;
use constants::Scalar;
use contracts_common::types::ScalarField;
use contracts_core::crypto::poseidon::compute_poseidon_hash;
use contracts_utils::merkle::MerkleConfig;
use eyre::{eyre, Result};
use scripts::utils::{EthereumCall, LocalWalletHttpClient};

use crate::DarkpoolTestInstance;

use super::u256_to_scalar;

// ---------------------------------------
// | Client Setup & Contract Interaction |
// ---------------------------------------

/// Sets up a dummy client with a random private key
/// targeting the same RPC endpoint
pub fn setup_dummy_client(client: LocalWalletHttpClient) -> LocalWalletHttpClient {
    let signer = PrivateKeySigner::random();
    let endpoint = client.url();
    LocalWalletHttpClient::new(signer, endpoint)
}

/// Fetches the protocol public encryption key from the darkpool contract
pub async fn get_protocol_pubkey(
    darkpool_contract: &DarkpoolTestInstance,
) -> Result<EncryptionKey> {
    let [x, y] = darkpool_contract.getPubkey().call().await?._0;
    let x_scalar = Scalar::new(u256_to_scalar(x));
    let y_scalar = Scalar::new(u256_to_scalar(y));
    Ok(EncryptionKey { x: x_scalar, y: y_scalar })
}

/// Computes a commitment to the given wallet shares, inserts them
/// into the given Arkworks Merkle tree, and returns the new root
pub(crate) fn insert_shares_and_get_root(
    ark_merkle: &mut ArkMerkleTree<MerkleConfig>,
    private_shares_commitment: ScalarField,
    public_shares: &[ScalarField],
    index: usize,
) -> Result<Scalar> {
    let mut shares = vec![private_shares_commitment];
    shares.extend(public_shares);
    let commitment = compute_poseidon_hash(&shares);
    ark_merkle
        .update(index, &commitment)
        .map_err(|_| eyre!("Failed to update Arkworks Merkle tree"))?;

    Ok(Scalar::new(ark_merkle.root()))
}

// -----------------------
// | Contract Assertions |
// -----------------------

/// Asserts that the given method can only be called by the owner of the
/// darkpool contract
pub async fn assert_only_owner<C: SolCall>(
    call: C,
    contract: &DarkpoolTestInstance,
    contract_with_dummy_owner: &DarkpoolTestInstance,
) -> Result<()> {
    let sig = C::SIGNATURE;

    let non_owner_err = contract_with_dummy_owner.call_builder(&call).send().await.is_err();
    assert!(non_owner_err, "Called {sig} as non-owner");

    let owner_err = contract.call_builder(&call).send().await.is_err();
    assert!(!owner_err, "Failed to call {sig} as owner");

    Ok(())
}

/// Asserts that all the given transactions revert
pub async fn assert_revert<'a, C: CallDecoder + Unpin>(call: EthereumCall<'_, C>) -> Result<()> {
    let pending_res = call.send().await;
    assert!(pending_res.is_err(), "Expected transaction to revert, but it succeeded");
    Ok(())
}

/// Asserts that all of the given transactions successfully execute
pub async fn assert_success<'a, C: CallDecoder + Unpin>(call: EthereumCall<'_, C>) -> Result<()> {
    let pending_res = call.send().await;
    assert!(pending_res.is_ok(), "Expected transaction to succeed, but it reverted");
    Ok(())
}
