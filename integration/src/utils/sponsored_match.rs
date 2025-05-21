//! Integration testing utilities for sponsored matches

use alloy::{rpc::types::TransactionReceipt, signers::k256::ecdsa::SigningKey};
use alloy_primitives::{utils::parse_ether, Address, Bytes, U256};
use ark_std::UniformRand;
use contracts_common::types::{ScalarField, ValidMatchSettleAtomicStatement};
use contracts_utils::{
    crypto::hash_and_sign_message,
    proof_system::test_data::{
        ProcessAtomicMatchSettleData, ProcessMalleableMatchSettleAtomicData,
    },
};
use eyre::Result;
use rand::thread_rng;
use scripts::utils::send_tx;
use test_helpers::assert_eq_result;

use crate::{abis::DummyErc20Contract, constants::REFUND_AMOUNT, GasSponsorInstance, TestContext};

use super::{
    native_eth_address, scalar_to_u256, serialize_to_calldata, setup_atomic_match_settle_test,
    setup_malleable_match_test,
};

// ---------
// | Types |
// ---------

/// The options for setting up a sponsored match test
#[derive(Default, Clone, Copy)]
pub struct SponsoredMatchTestOptions {
    /// Whether or not the external party sells the base
    pub sell_side: bool,
    /// Whether to use native ETH as the base
    pub trade_native_eth: bool,
    /// The address to refund to
    pub refund_address: Address,
    /// The address to receive the tokens
    pub receiver: Address,
    /// Whether to refund through the buy-side token
    pub in_kind_refund: bool,
}

/// The inputs for the `sponsor_atomic_match_settle` darkpool method
pub struct SponsoredAtomicMatchSettleData {
    /// The data used to call `process_atomic_match_settle`
    pub process_atomic_match_settle_data: ProcessAtomicMatchSettleData,
    /// The address to refund to
    pub refund_address: Address,
    /// The address to receive the tokens
    pub receiver: Address,
    /// The sponsorship nonce
    pub nonce: U256,
    /// Whether to refund through native ETH
    pub refund_native_eth: bool,
    /// The refund amount
    pub refund_amount: U256,
    /// The signature over the nonce
    pub signature: Bytes,
}

/// The inputs for the `sponsor_malleable_match_settle_atomic` darkpool method
pub struct SponsoredMalleableMatchSettleAtomicData {
    /// The data used to call `process_malleable_match_settle_atomic`
    pub process_malleable_match_settle_atomic_data: ProcessMalleableMatchSettleAtomicData,
    /// The address to refund to
    pub refund_address: Address,
    /// The base amount swapped
    pub base_amount: U256,
    /// The quote amount swapped
    pub quote_amount: U256,
    /// The address to receive the tokens
    pub receiver: Address,
    /// The sponsorship nonce
    pub nonce: U256,
    /// Whether to refund through native ETH
    pub refund_native_eth: bool,
    /// The refund amount
    pub refund_amount: U256,
    /// The signature over the nonce
    pub signature: Bytes,
}

// -----------
// | Helpers |
// -----------

/// Create a sponsorship signature for gas refunds
fn create_sponsorship_signature(
    nonce: U256,
    refund_address: Address,
    refund_amount: U256,
    signing_key: &SigningKey,
) -> (U256, Bytes) {
    let nonce_bytes = nonce.to_be_bytes_vec();
    let refund_amount_bytes = refund_amount.to_be_bytes_vec();

    let mut message = Vec::new();
    message.extend_from_slice(&nonce_bytes);
    message.extend_from_slice(refund_address.as_ref());
    message.extend_from_slice(&refund_amount_bytes);

    let signature = Bytes::from(hash_and_sign_message(signing_key, &message).as_bytes());
    (nonce, signature)
}

/// Setup a sponsored atomic match settle test
pub async fn setup_sponsored_match_test(
    options: SponsoredMatchTestOptions,
    ctx: &TestContext,
) -> Result<SponsoredAtomicMatchSettleData> {
    // Ensure that the gas sponsor is unpaused
    send_tx(ctx.gas_sponsor_contract().unpause()).await?;

    let mut process_atomic_match_settle_data =
        setup_atomic_match_settle_test(!options.sell_side, true /* use_gas_sponsor */, ctx).await?;

    if options.trade_native_eth {
        // Replace the base mint with the native ETH address
        process_atomic_match_settle_data
            .valid_match_settle_atomic_statement
            .match_result
            .base_mint = native_eth_address();
    }

    let mut rng = thread_rng();
    let nonce = scalar_to_u256(ScalarField::rand(&mut rng));

    if options.in_kind_refund {
        // Fund the gas sponsor with some ERC20s
        let erc20_addr1 = DummyErc20Contract::new(ctx.test_erc20_address1, ctx.client.provider());
        let mint_tx1 = erc20_addr1.mint(ctx.gas_sponsor_proxy_address, REFUND_AMOUNT);
        send_tx(mint_tx1).await?;

        let erc20_addr2 = DummyErc20Contract::new(ctx.test_erc20_address2, ctx.client.provider());
        let mint_tx2 = erc20_addr2.mint(ctx.gas_sponsor_proxy_address, REFUND_AMOUNT);
        send_tx(mint_tx2).await?;
    }

    let (nonce, signature) = create_sponsorship_signature(
        nonce,
        options.refund_address,
        REFUND_AMOUNT,
        ctx.signing_key(),
    );

    // Fund the gas sponsor with some ETH
    let sponsor_contract = ctx.gas_sponsor_contract();
    let receive_eth_tx = sponsor_contract.receiveEth().value(parse_ether("0.1")?);
    send_tx(receive_eth_tx).await?;

    Ok(SponsoredAtomicMatchSettleData {
        process_atomic_match_settle_data,
        nonce,
        signature,
        refund_address: options.refund_address,
        receiver: options.receiver,
        refund_native_eth: !options.in_kind_refund,
        refund_amount: REFUND_AMOUNT,
    })
}

/// Setup a sponsored malleable match test
pub async fn setup_sponsored_malleable_match_test(
    options: SponsoredMatchTestOptions,
    ctx: &TestContext,
) -> Result<SponsoredMalleableMatchSettleAtomicData> {
    // Ensure that the gas sponsor is unpaused
    send_tx(ctx.gas_sponsor_contract().unpause()).await?;

    // Setup malleable match test data
    let (quote_amount, base_amount, process_malleable_match_settle_atomic_data) =
        setup_malleable_match_test(options.trade_native_eth, true /* use_gas_sponsor */, ctx)
            .await?;

    let mut rng = thread_rng();
    let nonce = scalar_to_u256(ScalarField::rand(&mut rng));

    if options.in_kind_refund {
        // Fund the gas sponsor with some ERC20s
        let erc20_addr1 = DummyErc20Contract::new(ctx.test_erc20_address1, ctx.client.provider());
        let mint_tx1 = erc20_addr1.mint(ctx.gas_sponsor_proxy_address, REFUND_AMOUNT);
        send_tx(mint_tx1).await?;

        let erc20_addr2 = DummyErc20Contract::new(ctx.test_erc20_address2, ctx.client.provider());
        let mint_tx2 = erc20_addr2.mint(ctx.gas_sponsor_proxy_address, REFUND_AMOUNT);
        send_tx(mint_tx2).await?;
    }

    let (nonce, signature) = create_sponsorship_signature(
        nonce,
        options.refund_address,
        REFUND_AMOUNT,
        ctx.signing_key(),
    );

    // Fund the gas sponsor with some ETH
    let sponsor_contract = ctx.gas_sponsor_contract();
    let receive_eth_tx = sponsor_contract.receiveEth().value(parse_ether("0.1")?);
    send_tx(receive_eth_tx).await?;

    Ok(SponsoredMalleableMatchSettleAtomicData {
        process_malleable_match_settle_atomic_data,
        nonce,
        signature,
        refund_address: options.refund_address,
        receiver: options.receiver,
        refund_native_eth: !options.in_kind_refund,
        refund_amount: REFUND_AMOUNT,
        base_amount,
        quote_amount,
    })
}

/// Asserts that the gas refund through native ETH matches the refund amount.
/// The `post_refund_eth_balance` is expected to be the balance after accounting
/// for gas costs & gas refund, but not factoring in any native ETH traded.
pub fn assert_native_eth_gas_refund(
    initial_eth_balance: U256,
    post_refund_eth_balance: U256,
    receipt: TransactionReceipt,
) -> Result<()> {
    let gas_cost = U256::from(receipt.gas_used as u128 * receipt.effective_gas_price);
    let eth_diff = initial_eth_balance - post_refund_eth_balance;
    assert_eq_result!(gas_cost - eth_diff, REFUND_AMOUNT)
}

/// Invoke the `sponsor_atomic_match_settle_with_refund_options` method on the
/// gas sponsor with the given test data
pub async fn sponsor_match_with_test_data(
    gas_sponsor: &GasSponsorInstance,
    data: SponsoredAtomicMatchSettleData,
) -> Result<TransactionReceipt> {
    let SponsoredAtomicMatchSettleData {
        process_atomic_match_settle_data,
        refund_address,
        receiver,
        nonce,
        refund_native_eth,
        refund_amount,
        signature,
    } = data;

    let internal_party_match_payload =
        serialize_to_calldata(&process_atomic_match_settle_data.internal_party_match_payload)?;
    let valid_match_settle_atomic_statement = serialize_to_calldata(
        &process_atomic_match_settle_data.valid_match_settle_atomic_statement,
    )?;
    let match_proofs =
        serialize_to_calldata(&process_atomic_match_settle_data.match_atomic_proofs)?;
    let match_linking_proofs =
        serialize_to_calldata(&process_atomic_match_settle_data.match_atomic_linking_proofs)?;

    let mut settle_tx = gas_sponsor.sponsorAtomicMatchSettleWithRefundOptions(
        receiver,
        internal_party_match_payload,
        valid_match_settle_atomic_statement,
        match_proofs,
        match_linking_proofs,
        refund_address,
        nonce,
        refund_native_eth,
        refund_amount,
        signature,
    );

    let match_result =
        &process_atomic_match_settle_data.valid_match_settle_atomic_statement.match_result;

    let native_eth_sell = match_result.base_mint == native_eth_address() && !match_result.direction;

    if native_eth_sell {
        settle_tx = settle_tx.value(match_result.base_amount);
    }

    let receipt = send_tx(settle_tx).await?;
    Ok(receipt)
}

/// Calculate the amount received by the external party in an atomic match
pub fn amount_received_in_match(statement: &ValidMatchSettleAtomicStatement) -> U256 {
    let base_amount = statement.match_result.base_amount;

    let fee_total = statement.external_party_fees.total();

    base_amount - fee_total
}

/// Burn the entirety of the gas sponsor's balance of the given token
pub async fn burn_gas_sponsor_token_balance(mint: Address, ctx: &TestContext) -> Result<()> {
    let sponsor_token_balance =
        ctx.get_erc20_balance_of(mint, ctx.gas_sponsor_proxy_address).await?;
    let token_contract = DummyErc20Contract::new(mint, ctx.client.provider());
    let burn_tx = token_contract.burn(ctx.gas_sponsor_proxy_address, sponsor_token_balance);
    send_tx(burn_tx).await?;

    Ok(())
}

/// Invoke the `sponsor_malleable_match_settle_atomic` method on the
/// gas sponsor with the given test data
pub async fn sponsor_malleable_match_with_test_data(
    gas_sponsor: &GasSponsorInstance,
    data: SponsoredMalleableMatchSettleAtomicData,
) -> Result<TransactionReceipt> {
    let SponsoredMalleableMatchSettleAtomicData {
        process_malleable_match_settle_atomic_data: test_data,
        refund_address,
        base_amount,
        quote_amount,
        receiver,
        nonce,
        refund_native_eth,
        refund_amount,
        signature,
    } = data;

    // Get the statement and proofs from the test data
    let internal_party_payload = serialize_to_calldata(&test_data.internal_party_match_payload)?;
    let valid_malleable_statement =
        serialize_to_calldata(&test_data.valid_malleable_match_settle_atomic_statement)?;
    let match_proofs = serialize_to_calldata(&test_data.match_atomic_proofs)?;
    let match_linking_proofs = serialize_to_calldata(&test_data.match_atomic_linking_proofs)?;

    // Determine if we need to send ETH with the transaction
    let match_result = &test_data.valid_malleable_match_settle_atomic_statement.match_result;
    let is_native = match_result.base_mint == native_eth_address();
    let native_sell = is_native && !match_result.direction;
    let value = if native_sell { base_amount } else { U256::ZERO };

    // Prepare the transaction
    let settle_tx = gas_sponsor
        .sponsorMalleableAtomicMatchSettleWithRefundOptions(
            quote_amount,
            base_amount,
            receiver,
            internal_party_payload,
            valid_malleable_statement,
            match_proofs,
            match_linking_proofs,
            refund_address,
            nonce,
            refund_native_eth,
            refund_amount,
            signature,
        )
        .value(value);

    let receipt = send_tx(settle_tx).await?;
    Ok(receipt)
}
