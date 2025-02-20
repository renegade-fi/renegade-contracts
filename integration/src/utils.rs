//! Utilities for running integration tests

use std::{future::Future, str::FromStr, sync::Arc};

use alloy_primitives::{keccak256, Address as AlloyAddress, B256, U256 as AlloyU256};
use alloy_sol_types::{
    eip712_domain,
    sol_data::{Address as SolAddress, Uint as SolUint},
    Eip712Domain, SolStruct, SolType,
};
use ark_crypto_primitives::merkle_tree::MerkleTree as ArkMerkleTree;
use ark_std::UniformRand;
use circuit_types::{
    elgamal::EncryptionKey,
    fixed_point::FixedPoint,
    r#match::{ExternalMatchResult, FeeTake},
};
use constants::Scalar;
use contracts_common::{
    constants::{NUM_BYTES_ADDRESS, NUM_BYTES_FELT, NUM_BYTES_U256},
    custom_serde::{pk_to_u256s, BytesDeserializable, BytesSerializable},
    solidity::{DepositWitness, PermitWitnessTransferFrom, TokenPermissions},
    types::{
        ExternalTransfer, MatchLinkingProofs, MatchLinkingVkeys, MatchProofs, MatchPublicInputs,
        MatchVkeys, Proof, PublicInputs, PublicSigningKey, ScalarField, TransferAuxData,
        VerificationKey, VerifyMatchCalldata,
    },
};
use contracts_core::crypto::poseidon::compute_poseidon_hash;
use contracts_stylus::NATIVE_ETH_ADDRESS;
use contracts_utils::{
    crypto::hash_and_sign_message,
    merkle::MerkleConfig,
    proof_system::test_data::{
        address_to_biguint, gen_atomic_match_with_match_and_fees, ProcessAtomicMatchSettleData,
        SponsoredAtomicMatchSettleData,
    },
};
use ethers::{
    abi::{Address, Detokenize, Tokenize},
    contract::ContractError,
    core::k256::ecdsa::SigningKey,
    providers::{JsonRpcClient, Middleware, PendingTransaction},
    signers::{LocalWallet, Signer},
    types::{Bytes, H256, U256},
    utils::parse_ether,
};
use eyre::{eyre, Result};
use num_bigint::BigUint;
use rand::{thread_rng, RngCore};
use scripts::{constants::TEST_FUNDING_AMOUNT, utils::LocalWalletHttpClient};
use serde::Serialize;

use crate::{
    abis::{DarkpoolTestContract, DummyErc20Contract, TransferExecutorContract},
    constants::PERMIT2_EIP712_DOMAIN_NAME,
    TestContext,
};

// --------------------
// | Type Conversions |
// --------------------

/// Convert an ethers `Address` to an alloy `Address`
pub fn ethers_address_to_alloy_address(address: &Address) -> AlloyAddress {
    let bytes = &address.0;
    AlloyAddress::from_slice(bytes.as_slice())
}

/// Convert an alloy `Address` to an ethers `Address`
pub fn alloy_address_to_ethers_address(address: &AlloyAddress) -> Address {
    let bytes = address.to_vec();
    Address::from_slice(&bytes)
}

/// Convert an ethers `Address` to a `BigUint`
///
/// Call out to the alloy helper to ensure that address formats are the same
/// throughout test helpers
pub fn ethers_address_to_biguint(address: &Address) -> BigUint {
    let alloy_address = ethers_address_to_alloy_address(address);
    address_to_biguint(alloy_address)
}

/// Converts a `BigUint` to an ethers `Address`
pub fn biguint_to_ethers_address(biguint: &BigUint) -> Address {
    let bytes = biguint.to_bytes_be();
    Address::from_slice(&bytes)
}

/// Get the native ETH address
pub fn native_eth_address() -> AlloyAddress {
    AlloyAddress::from_str(NATIVE_ETH_ADDRESS).unwrap()
}

/// Converts an [`ethers::types::U256`] to an [`alloy_primitives::U256`]
pub fn u256_to_alloy_u256(u256: U256) -> AlloyU256 {
    let mut buf = [0_u8; 32];
    u256.to_big_endian(&mut buf);
    AlloyU256::from_be_slice(&buf)
}

/// Converts an [`alloy_primitives::U256`] to an [`ethers::types::U256`]
pub fn alloy_u256_to_ethers_u256(alloy_u256: AlloyU256) -> U256 {
    U256::from_big_endian(&alloy_u256.to_be_bytes_vec())
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

/// Serialize the given serializable type into a [`Bytes`] object
/// that can be passed in as calldata
pub fn serialize_to_calldata<T: Serialize>(t: &T) -> Result<Bytes> {
    Ok(postcard::to_allocvec(t)?.into())
}

// ---------------------------
// | ERC20 Utils & Transfers |
// ---------------------------

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

/// Executes the given transfer and returns the resulting balances of the
/// darkpool and user
pub(crate) async fn execute_transfer_and_get_balances(
    transfer_executor_contract: &TransferExecutorContract<LocalWalletHttpClient>,
    dummy_erc20_contract: &DummyErc20Contract<LocalWalletHttpClient>,
    permit2_address: Address,
    signing_key: &SigningKey,
    pk_root: PublicSigningKey,
    transfer: &ExternalTransfer,
    account_address: Address,
) -> Result<(U256, U256)> {
    let transfer_aux_data = gen_transfer_aux_data(
        signing_key,
        pk_root,
        transfer,
        permit2_address,
        transfer_executor_contract,
    )
    .await?;

    transfer_executor_contract
        .execute_external_transfer(
            serialize_to_calldata(&pk_root)?,
            serialize_to_calldata(transfer)?,
            serialize_to_calldata(&transfer_aux_data)?,
        )
        .send()
        .await?
        .await?;

    let darkpool_balance =
        dummy_erc20_contract.balance_of(transfer_executor_contract.address()).call().await?;

    let user_balance = dummy_erc20_contract.balance_of(account_address).call().await?;

    Ok((darkpool_balance, user_balance))
}

/// Generates the auxiliary data fpr the given external transfer,
/// including the Permit2 data & a signature over the transfer
pub(crate) async fn gen_transfer_aux_data(
    signing_key: &SigningKey,
    pk_root: PublicSigningKey,
    transfer: &ExternalTransfer,
    permit2_address: Address,
    transfer_executor_contract: &TransferExecutorContract<LocalWalletHttpClient>,
) -> Result<TransferAuxData> {
    let (permit_nonce, permit_deadline, permit_signature) = gen_permit_payload(
        transfer.mint,
        transfer.amount,
        pk_root,
        permit2_address,
        transfer_executor_contract,
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
    pk_root: PublicSigningKey,
    permit2_address: Address,
    transfer_executor_contract: &TransferExecutorContract<LocalWalletHttpClient>,
) -> Result<(AlloyU256, AlloyU256, Vec<u8>)> {
    let client = transfer_executor_contract.client();

    let permitted = TokenPermissions { token, amount };

    // Generate a random nonce
    let mut nonce_bytes = [0_u8; 32];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = AlloyU256::from_be_slice(&nonce_bytes);

    // Set an effectively infinite deadline
    let deadline = AlloyU256::from(u64::MAX);

    let spender = AlloyAddress::from_slice(transfer_executor_contract.address().as_bytes());

    let witness = DepositWitness {
        pkRoot: pk_to_u256s(&pk_root).map_err(|_| eyre!("Failed to convert pk_root to u256s"))?,
    };

    let signable_permit =
        PermitWitnessTransferFrom { permitted, spender, nonce, deadline, witness };

    // Construct the EIP712 domain
    let permit2_address = AlloyAddress::from_slice(permit2_address.as_bytes());
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

/// Mint dummy ERC20 tokens for testing
///
/// Mint to both the user and the darkpool so that both are sufficiently
/// capitalized
pub async fn mint_dummy_erc20s(mint: Address, amount: U256, test_args: &TestContext) -> Result<()> {
    let address = test_args.client.address();
    let darkpool_address = test_args.darkpool_proxy_address;
    let contract = DummyErc20Contract::new(mint, test_args.client.clone());
    contract.mint(address, amount).send().await?.await?;
    contract.mint(darkpool_address, amount).send().await?.await?;

    Ok(())
}

/// Setup the token approvals for an atomic match
pub async fn setup_external_match_token_approvals(
    buy_side: bool,
    use_gas_sponsor: bool,
    match_result: &ExternalMatchResult,
    test_args: &TestContext,
) -> Result<()> {
    let mint = if buy_side { &match_result.quote_mint } else { &match_result.base_mint };

    let mint = biguint_to_ethers_address(mint);
    let contract = DummyErc20Contract::new(mint, test_args.client.clone());
    let amount = TEST_FUNDING_AMOUNT;

    let spender = if use_gas_sponsor {
        test_args.gas_sponsor_proxy_address
    } else {
        test_args.darkpool_proxy_address
    };

    contract.approve(spender, amount.into()).send().await?.await?;

    Ok(())
}

/// This is a re-implementation of `eip712_signing_hash` (https://github.com/alloy-rs/core/blob/v0.3.1/crates/sol-types/src/types/struct.rs#L117)
/// which correctly encodes the data for the nested `TokenPermissions` struct.
///
/// We do so by mirroring the functionality implemented in the `sol!` macro (https://github.com/alloy-rs/core/blob/v0.3.1/crates/sol-macro/src/expand/struct.rs#L56)
/// but avoiding the (unintended) extra hash of the `TokenPermissions` struct's
/// EIP-712 struct hash.
///
/// This is fixed here: https://github.com/alloy-rs/core/pull/258
/// But the version of `alloy` used by `stylus-sdk` is not updated to include
/// this fix.
///
/// TODO: Remove this function when `stylus-sdk` uses `alloy >= 0.4.0`
fn permit_signing_hash(permit: &PermitWitnessTransferFrom, domain: &Eip712Domain) -> B256 {
    let domain_separator = domain.hash_struct();

    let mut type_hash = permit.eip712_type_hash().to_vec();
    let encoded_data = [
        permit.permitted.eip712_hash_struct().0,
        SolAddress::eip712_data_word(&permit.spender).0,
        SolUint::<256>::eip712_data_word(&permit.nonce).0,
        SolUint::<256>::eip712_data_word(&permit.deadline).0,
        permit.witness.eip712_hash_struct().0,
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

// ------------------------
// | External Match Setup |
// ------------------------

/// Get a dummy `ExternalMatchResult` and `FeeTake` for an atomic match
pub async fn dummy_external_match_result_and_fees(
    buy_side: bool,
    use_gas_sponsor: bool,
    ctx: &TestContext,
) -> Result<(ExternalMatchResult, FeeTake)> {
    let base_mint = ctx.test_erc20_address1;
    let quote_mint = ctx.test_erc20_address2;
    let base_amount = TEST_FUNDING_AMOUNT;
    let quote_amount = TEST_FUNDING_AMOUNT;

    // Ensure that the client has sufficient balances and approvals
    mint_dummy_erc20s(base_mint, base_amount.into(), ctx).await?;
    mint_dummy_erc20s(quote_mint, quote_amount.into(), ctx).await?;

    // The price here does not matter for testing, so we just trade the default
    // funding amount
    let match_result = ExternalMatchResult {
        base_mint: ethers_address_to_biguint(&base_mint),
        quote_mint: ethers_address_to_biguint(&quote_mint),
        base_amount,
        quote_amount,
        direction: buy_side,
    };
    setup_external_match_token_approvals(buy_side, use_gas_sponsor, &match_result, ctx).await?;

    // Values here don't matter, but importantly are different to ensure the
    // correct fee ends in the correct address
    let fees = FeeTake {
        relayer_fee: TEST_FUNDING_AMOUNT / 100,  // 1%
        protocol_fee: TEST_FUNDING_AMOUNT / 200, // 0.5%
    };

    Ok((match_result, fees))
}

/// Setup an atomic match settle test using native ETH as the base asset
pub async fn setup_atomic_match_settle_test_native_eth(
    buy_side: bool,
    use_gas_sponsor: bool,
    ctx: &TestContext,
) -> Result<ProcessAtomicMatchSettleData> {
    let mut data = setup_atomic_match_settle_test(buy_side, use_gas_sponsor, ctx).await?;

    // Replace the base mint with the native ETH address
    let eth_addr = native_eth_address();
    data.valid_match_settle_atomic_statement.match_result.base_mint = eth_addr;
    Ok(data)
}

/// Setup a sponsored atomic match settle test
pub async fn setup_sponsored_match_test(
    buy_side: bool,
    ctx: &TestContext,
) -> Result<SponsoredAtomicMatchSettleData> {
    // Ensure that the gas sponsor is unpaused
    ctx.gas_sponsor_contract().unpause().send().await?.await?;

    let process_atomic_match_settle_data =
        setup_atomic_match_settle_test(buy_side, true /* use_gas_sponsor */, ctx).await?;

    let mut rng = thread_rng();
    let nonce = scalar_to_u256(ScalarField::rand(&mut rng));
    let mut message = [0_u8; NUM_BYTES_U256 + NUM_BYTES_ADDRESS];
    nonce.to_big_endian(&mut message[..NUM_BYTES_U256]);
    message[NUM_BYTES_U256..].copy_from_slice(Address::zero().as_bytes());

    let signature = Bytes::from(hash_and_sign_message(ctx.signing_key(), &message).to_vec());

    // Fund the gas sponsor with some ETH
    ctx.gas_sponsor_contract().receive_eth().value(parse_ether("0.1")?).send().await?.await?;

    Ok(SponsoredAtomicMatchSettleData { process_atomic_match_settle_data, nonce, signature })
}

/// Setup a sponsored atomic match settle test using native ETH as the base
/// asset
pub async fn setup_sponsored_match_test_native_eth(
    buy_side: bool,
    ctx: &TestContext,
) -> Result<SponsoredAtomicMatchSettleData> {
    let mut data = setup_sponsored_match_test(buy_side, ctx).await?;

    // Replace the base mint with the native ETH address
    let eth_addr = native_eth_address();
    data.process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .base_mint = eth_addr;

    Ok(data)
}

/// Setup an atomic match settle test
pub async fn setup_atomic_match_settle_test(
    buy_side: bool,
    use_gas_sponsor: bool,
    ctx: &TestContext,
) -> Result<ProcessAtomicMatchSettleData> {
    let darkpool_contract = ctx.darkpool_contract();

    // Clear merkle state
    darkpool_contract.clear_merkle().send().await?.await?;

    let mut rng = thread_rng();
    let contract_root = Scalar::new(u256_to_scalar(darkpool_contract.get_root().call().await?)?);
    let (match_result, fees) =
        dummy_external_match_result_and_fees(buy_side, use_gas_sponsor, ctx).await?;
    let base = biguint_to_ethers_address(&match_result.base_mint);
    let fee = darkpool_contract.get_external_match_fee_for_asset(base).call().await?;
    let protocol_fee = FixedPoint::from(Scalar::new(u256_to_scalar(fee)?));

    let data = gen_atomic_match_with_match_and_fees(
        &mut rng,
        contract_root,
        protocol_fee,
        match_result,
        fees,
    )?;

    Ok(data)
}

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

// ---------------------------
// | Serialization Utilities |
// ---------------------------

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
    verifier_address: AlloyAddress,
    match_vkeys: &MatchVkeys,
    match_linking_vkeys: &MatchLinkingVkeys,
    match_proofs: &MatchProofs,
    match_public_inputs: &MatchPublicInputs,
    match_linking_proofs: &MatchLinkingProofs,
) -> Result<Bytes> {
    let match_vkeys_ser = serialize_to_calldata(&match_vkeys)?;
    let match_linking_vkeys_ser = serialize_to_calldata(&match_linking_vkeys)?;
    let match_vkeys = [match_vkeys_ser, match_linking_vkeys_ser].concat();

    let calldata = VerifyMatchCalldata {
        verifier_address,
        match_vkeys,
        match_proofs: serialize_to_calldata(&match_proofs)?.to_vec(),
        match_public_inputs: serialize_to_calldata(&match_public_inputs)?.to_vec(),
        match_linking_proofs: serialize_to_calldata(&match_linking_proofs)?.to_vec(),
    };

    let calldata_ser: Vec<u8> = postcard::to_allocvec(&calldata)?;
    Ok(calldata_ser.into())
}
