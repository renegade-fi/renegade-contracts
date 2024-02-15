//! Utilities for running integration tests

use std::future::Future;

use alloy_primitives::{keccak256, Address as AlloyAddress, B256, U256 as AlloyU256};
use alloy_sol_types::{
    eip712_domain,
    sol_data::{Address as SolAddress, Uint as SolUint},
    Eip712Domain, SolStruct, SolType,
};
use ark_crypto_primitives::merkle_tree::MerkleTree as ArkMerkleTree;
use contracts_common::{
    constants::NUM_BYTES_FELT,
    custom_serde::{BytesDeserializable, BytesSerializable},
    solidity::{PermitTransferFrom, TokenPermissions},
    types::{
        ExternalTransfer, MatchLinkingProofs, MatchLinkingVkeys, MatchProofs, MatchPublicInputs,
        MatchVkeys, Proof, PublicInputs, PublicSigningKey, ScalarField, TransferAuxData,
        VerificationKey,
    },
};
use contracts_core::crypto::poseidon::compute_poseidon_hash;
use contracts_utils::{crypto::hash_and_sign_message, merkle::MerkleConfig};
use ethers::{
    abi::{Address, Detokenize, Tokenize},
    contract::ContractError,
    core::k256::ecdsa::SigningKey,
    providers::{JsonRpcClient, Middleware, PendingTransaction},
    types::{Bytes, H256, U256},
};
use eyre::{eyre, Result};
use rand::{thread_rng, RngCore};
use scripts::{
    constants::{PERMIT2_CONTRACT_KEY, TEST_FUNDING_AMOUNT},
    utils::{parse_addr_from_deployments_file, LocalWalletProvider},
};
use serde::Serialize;

use crate::{
    abis::{DarkpoolTestContract, DummyErc20Contract},
    constants::PERMIT2_EIP712_DOMAIN_NAME,
};

/// Asserts that the given method can only be called by the owner of the darkpool contract
pub async fn assert_only_owner<T: Tokenize + Clone, D: Detokenize>(
    contract: &DarkpoolTestContract<LocalWalletProvider<impl Middleware + 'static>>,
    contract_with_dummy_owner: &DarkpoolTestContract<
        LocalWalletProvider<impl Middleware + 'static>,
    >,
    method: &str,
    args: T,
) -> Result<()> {
    assert!(
        contract_with_dummy_owner
            .method::<T, D>(method, args.clone())?
            .send()
            .await
            .is_err(),
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
                ContractError<LocalWalletProvider<impl Middleware + 'static>>,
            >,
        >,
    >,
) -> Result<()> {
    for tx in txs {
        assert!(
            tx.await.is_err(),
            "Expected transaction to revert, but it succeeded"
        );
    }

    Ok(())
}

/// Asserts that all of the given transactions successfully execute
pub async fn assert_all_suceed<'a>(
    txs: Vec<
        impl Future<
            Output = Result<
                PendingTransaction<'a, impl JsonRpcClient + 'a>,
                ContractError<LocalWalletProvider<impl Middleware + 'static>>,
            >,
        >,
    >,
) -> Result<()> {
    for tx in txs {
        assert!(
            tx.await.is_ok(),
            "Expected transaction to succeed, but it reverted"
        );
    }

    Ok(())
}

/// Converts a [`ScalarField`] to a [`ethers::types::U256`]
pub fn scalar_to_u256(scalar: ScalarField) -> U256 {
    U256::from_big_endian(&scalar.serialize_to_bytes())
}

/// Converts a [`ethers::types::U256`] to a [`ScalarField`]
pub fn u256_to_scalar(u256: U256) -> Result<ScalarField> {
    let mut scalar_bytes = [0_u8; NUM_BYTES_FELT];
    u256.to_big_endian(&mut scalar_bytes);
    ScalarField::deserialize_from_bytes(&scalar_bytes)
        .map_err(|_| eyre!("failed converting U256 to scalar"))
}

/// Serialiez the given serializable type into a [`Bytes`] object
/// that can be passed in as calldata
pub fn serialize_to_calldata<T: Serialize>(t: &T) -> Result<Bytes> {
    Ok(postcard::to_allocvec(t)?.into())
}

/// Serializes the given bundle of verification key, proof, and public inputs
/// into a [`Bytes`] object that can be passed in as calldata
pub fn serialize_verification_bundle(
    vkey: &VerificationKey,
    proof: &Proof,
    public_inputs: &PublicInputs,
) -> Result<Bytes> {
    let vkey_ser: Vec<u8> = postcard::to_allocvec(vkey)?;
    let proof_ser: Vec<u8> = postcard::to_allocvec(proof)?;
    let public_inputs_ser: Vec<u8> = postcard::to_allocvec(public_inputs)?;

    let bundle_bytes = [vkey_ser, proof_ser, public_inputs_ser].concat();

    Ok(bundle_bytes.into())
}

/// Serializes the given bundle of verification key, proof, and public inputs
/// used in a match into a [`Bytes`] object that can be passed in as calldata
pub fn serialize_match_verification_bundle(
    match_vkeys: &MatchVkeys,
    match_linking_vkeys: &MatchLinkingVkeys,
    match_proofs: &MatchProofs,
    match_public_inputs: &MatchPublicInputs,
    match_linking_proofs: &MatchLinkingProofs,
) -> Result<Bytes> {
    let match_vkeys_ser: Vec<u8> = postcard::to_allocvec(match_vkeys)?;
    let match_linking_vkeys_ser: Vec<u8> = postcard::to_allocvec(match_linking_vkeys)?;
    let match_proofs_ser: Vec<u8> = postcard::to_allocvec(match_proofs)?;
    let match_public_inputs_ser: Vec<u8> = postcard::to_allocvec(match_public_inputs)?;
    let match_linking_proofs_ser: Vec<u8> = postcard::to_allocvec(match_linking_proofs)?;

    let bundle_bytes = [
        match_vkeys_ser,
        match_linking_vkeys_ser,
        match_proofs_ser,
        match_public_inputs_ser,
        match_linking_proofs_ser,
    ]
    .concat();

    Ok(bundle_bytes.into())
}

/// Creates an [`ExternalTransfer`] object for the given account address,
/// mint address, and transfer direction
fn dummy_erc20_external_transfer(
    account_addr: Address,
    mint: Address,
    is_withdrawal: bool,
) -> ExternalTransfer {
    ExternalTransfer {
        account_addr: AlloyAddress::from_slice(account_addr.as_bytes()),
        mint: AlloyAddress::from_slice(mint.as_bytes()),
        amount: AlloyU256::from(TEST_FUNDING_AMOUNT),
        is_withdrawal,
    }
}

/// Creates an [`ExternalTransfer`] object representing a deposit
pub(crate) fn dummy_erc20_deposit(account_addr: Address, mint: Address) -> ExternalTransfer {
    dummy_erc20_external_transfer(account_addr, mint, false)
}

/// Creates an [`ExternalTransfer`] object representing a withdrawal
pub(crate) fn dummy_erc20_withdrawal(account_addr: Address, mint: Address) -> ExternalTransfer {
    dummy_erc20_external_transfer(account_addr, mint, true)
}

/// Executes the given transfer and returns the resulting balances of the darkpool and user
pub(crate) async fn execute_transfer_and_get_balances(
    darkpool_test_contract: &DarkpoolTestContract<LocalWalletProvider<impl Middleware + 'static>>,
    dummy_erc20_contract: &DummyErc20Contract<LocalWalletProvider<impl Middleware + 'static>>,
    signing_key: &SigningKey,
    pk_root: &PublicSigningKey,
    transfer: &ExternalTransfer,
    account_address: Address,
    deployments_path: &str,
) -> Result<(U256, U256)> {
    let transfer_aux_data = gen_transfer_aux_data(
        signing_key,
        transfer,
        deployments_path,
        darkpool_test_contract,
    )
    .await?;

    darkpool_test_contract
        .execute_external_transfer(
            serialize_to_calldata(pk_root)?,
            serialize_to_calldata(transfer)?,
            serialize_to_calldata(&transfer_aux_data)?,
        )
        .send()
        .await?
        .await?;
    let darkpool_balance = dummy_erc20_contract
        .balance_of(darkpool_test_contract.address())
        .call()
        .await?;
    let user_balance = dummy_erc20_contract
        .balance_of(account_address)
        .call()
        .await?;

    Ok((darkpool_balance, user_balance))
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

/// Generates the auxiliary data fpr the given external transfer,
/// including the Permit2 data & a signature over the transfer
pub(crate) async fn gen_transfer_aux_data(
    signing_key: &SigningKey,
    transfer: &ExternalTransfer,
    deployments_path: &str,
    darkpool_test_contract: &DarkpoolTestContract<LocalWalletProvider<impl Middleware + 'static>>,
) -> Result<TransferAuxData> {
    let (permit_nonce, permit_deadline, permit_signature) = gen_permit_payload(
        transfer.mint,
        transfer.amount,
        deployments_path,
        darkpool_test_contract,
    )
    .await?;

    let transfer_bytes = serialize_to_calldata(transfer)?;
    let transfer_signature = hash_and_sign_message(signing_key, &transfer_bytes).to_vec();

    Ok(TransferAuxData {
        permit_nonce: Some(permit_nonce),
        permit_deadline: Some(permit_deadline),
        permit_signature: Some(permit_signature),
        transfer_signature: Some(transfer_signature),
    })
}

/// Generates a permit payload for the given token and amount
pub(crate) async fn gen_permit_payload(
    token: AlloyAddress,
    amount: AlloyU256,
    deployments_path: &str,
    darkpool_test_contract: &DarkpoolTestContract<LocalWalletProvider<impl Middleware + 'static>>,
) -> Result<(AlloyU256, AlloyU256, Vec<u8>)> {
    let client = darkpool_test_contract.client();

    let permitted = TokenPermissions { token, amount };

    // Generate a random nonce
    let mut nonce_bytes = [0_u8; 32];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = AlloyU256::from_be_slice(&nonce_bytes);

    // Set an effectively infinite deadline
    let deadline = AlloyU256::from(u64::MAX);

    let spender = AlloyAddress::from_slice(darkpool_test_contract.address().as_bytes());

    let signable_permit = PermitTransferFrom {
        permitted,
        spender,
        nonce,
        deadline,
    };

    // Construct the EIP712 domain
    let permit2_address = AlloyAddress::from_slice(
        parse_addr_from_deployments_file(deployments_path, PERMIT2_CONTRACT_KEY)?.as_bytes(),
    );
    let chain_id = client.get_chainid().await?.try_into().unwrap();
    let permit_domain = eip712_domain!(
        name: PERMIT2_EIP712_DOMAIN_NAME,
        chain_id: chain_id,
        verifying_contract: permit2_address,
    );

    let msg_hash =
        H256::from_slice(permit_signing_hash(&signable_permit, &permit_domain).as_slice());

    let signature = client.signer().sign_hash(msg_hash)?.to_vec();

    Ok((nonce, deadline, signature))
}

/// This is a re-implementation of `eip712_signing_hash` (https://github.com/alloy-rs/core/blob/v0.3.1/crates/sol-types/src/types/struct.rs#L117)
/// which correctly encodes the data for the nested `TokenPermissions` struct.
///
/// We do so by mirroring the functionality implemented in the `sol!` macro (https://github.com/alloy-rs/core/blob/v0.3.1/crates/sol-macro/src/expand/struct.rs#L56)
/// but avoiding the (unintended) extra hash of the `TokenPermissions` struct's EIP-712 struct hash.
///
/// This is fixed here: https://github.com/alloy-rs/core/pull/258
/// But the version of `alloy` used by `stylus-sdk` is not updated to include this fix.
///
/// TODO: Remove this function when `stylus-sdk` uses `alloy >= 0.4.0`
fn permit_signing_hash(permit: &PermitTransferFrom, domain: &Eip712Domain) -> B256 {
    let domain_separator = domain.hash_struct();

    let mut type_hash = permit.eip712_type_hash().to_vec();
    let encoded_data = [
        permit.permitted.eip712_hash_struct().0,
        SolAddress::eip712_data_word(&permit.spender).0,
        SolUint::<256>::eip712_data_word(&permit.nonce).0,
        SolUint::<256>::eip712_data_word(&permit.deadline).0,
    ]
    .concat();
    type_hash.extend(encoded_data);
    let struct_hash = keccak256(&type_hash);

    let mut digest_input = [0u8; 2 + 32 + 32];
    digest_input[0] = 0x19;
    digest_input[1] = 0x01;
    digest_input[2..34].copy_from_slice(&domain_separator[..]);
    digest_input[34..66].copy_from_slice(&struct_hash[..]);
    keccak256(digest_input)
}
