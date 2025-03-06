//! Integration testing utilities for contract interaction

use std::{future::Future, sync::Arc};

use ark_crypto_primitives::merkle_tree::MerkleTree as ArkMerkleTree;
use circuit_types::elgamal::EncryptionKey;
use constants::Scalar;
use contracts_common::types::ScalarField;
use contracts_core::crypto::poseidon::compute_poseidon_hash;
use contracts_utils::merkle::MerkleConfig;
use ethers::{
    abi::{Detokenize, Tokenize},
    contract::ContractError,
    providers::{JsonRpcClient, Middleware, PendingTransaction},
    signers::{LocalWallet, Signer},
};
use eyre::{eyre, Result};
use rand::thread_rng;
use scripts::utils::LocalWalletHttpClient;

use crate::abis::DarkpoolTestContract;

use super::u256_to_scalar;

// ---------------------------------------
// | Client Setup & Contract Interaction |
// ---------------------------------------

/// Sets up a dummy client with a random private key
/// targeting the same RPC endpoint
pub async fn setup_dummy_client(
    client: Arc<LocalWalletHttpClient>,
) -> Result<Arc<LocalWalletHttpClient>> {
    let mut rng = thread_rng();
    Ok(Arc::new(client.with_signer(
        LocalWallet::new(&mut rng).with_chain_id(client.get_chainid().await?.as_u64()),
    )))
}

/// Fetches the protocol public encryption key from the darkpool contract
pub async fn get_protocol_pubkey(
    darkpool_contract: &DarkpoolTestContract<LocalWalletHttpClient>,
) -> Result<EncryptionKey> {
    let [x, y] = darkpool_contract.get_pubkey().call().await?;
    Ok(EncryptionKey { x: Scalar::new(u256_to_scalar(x)?), y: Scalar::new(u256_to_scalar(y)?) })
}

/// Computes a commitment to the given wallet shares, inserts them
/// into the given Arkworks Merkle tree, and returns the new root
pub(crate) fn insert_shares_and_get_root(
    ark_merkle: &mut ArkMerkleTree<MerkleConfig>,
    private_shares_commitment: ScalarField,
    public_shares: &[ScalarField],
    index: usize,
) -> Result<ScalarField> {
    let mut shares = vec![private_shares_commitment];
    shares.extend(public_shares);
    let commitment = compute_poseidon_hash(&shares);
    ark_merkle
        .update(index, &commitment)
        .map_err(|_| eyre!("Failed to update Arkworks Merkle tree"))?;

    Ok(ark_merkle.root())
}

// -----------------------
// | Contract Assertions |
// -----------------------

/// Asserts that the given method can only be called by the owner of the
/// darkpool contract
pub async fn assert_only_owner<T: Tokenize + Clone, D: Detokenize>(
    contract: &DarkpoolTestContract<LocalWalletHttpClient>,
    contract_with_dummy_owner: &DarkpoolTestContract<LocalWalletHttpClient>,
    method: &str,
    args: T,
) -> Result<()> {
    assert!(
        contract_with_dummy_owner.method::<T, D>(method, args.clone())?.send().await.is_err(),
        "Called {} as non-owner",
        method
    );

    assert!(
        contract.method::<T, D>(method, args)?.send().await.is_ok(),
        "Failed to call {} as owner",
        method
    );

    Ok(())
}

/// Asserts that all the given transactions revert
pub async fn assert_all_revert<'a>(
    txs: Vec<
        impl Future<
            Output = Result<
                PendingTransaction<'a, impl JsonRpcClient + 'a>,
                ContractError<LocalWalletHttpClient>,
            >,
        >,
    >,
) -> Result<()> {
    for tx in txs {
        assert!(tx.await.is_err(), "Expected transaction to revert, but it succeeded");
    }

    Ok(())
}

/// Asserts that all of the given transactions successfully execute
pub async fn assert_all_succeed<'a>(
    txs: Vec<
        impl Future<
            Output = Result<
                PendingTransaction<'a, impl JsonRpcClient + 'a>,
                ContractError<LocalWalletHttpClient>,
            >,
        >,
    >,
) -> Result<()> {
    for tx in txs {
        assert!(tx.await.is_ok(), "Expected transaction to succeed, but it reverted");
    }

    Ok(())
}
