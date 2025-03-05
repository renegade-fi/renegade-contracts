//! Integration testing utilities for external transfers & ERC20s

use alloy_primitives::{keccak256, Address as AlloyAddress, B256, U256 as AlloyU256};
use alloy_sol_types::{
    eip712_domain,
    sol_data::{Address as SolAddress, Uint as SolUint},
    Eip712Domain, SolStruct, SolType,
};
use circuit_types::r#match::ExternalMatchResult;
use contracts_common::{
    custom_serde::pk_to_u256s,
    solidity::{DepositWitness, PermitWitnessTransferFrom, TokenPermissions},
    types::{ExternalTransfer, PublicSigningKey, TransferAuxData},
};
use contracts_utils::crypto::hash_and_sign_message;
use ethers::{
    core::k256::ecdsa::SigningKey,
    providers::Middleware,
    types::{Address, H256, U256},
};
use eyre::{eyre, Result};
use rand::{thread_rng, RngCore};
use scripts::{constants::TEST_FUNDING_AMOUNT, utils::LocalWalletHttpClient};

use crate::{
    abis::{DummyErc20Contract, TransferExecutorContract},
    constants::PERMIT2_EIP712_DOMAIN_NAME,
    TestContext,
};

use super::{biguint_to_ethers_address, serialize_to_calldata};

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
