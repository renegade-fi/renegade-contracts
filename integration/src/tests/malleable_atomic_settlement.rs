//! Integration tests for malleable atomic settlement
use alloy::rpc::types::TransactionReceipt;
use alloy_primitives::{Address, U256};
use constants::ScalarField;
use contracts_common::types::{
    MatchAtomicLinkingProofs, MatchAtomicProofs, MatchPayload,
    ValidMalleableMatchSettleAtomicStatement,
};
use eyre::Result;
use rand::{thread_rng, Rng};
use scripts::utils::send_tx;
use test_helpers::{assert_eq_result, assert_true_result, integration_test_async};

use crate::{
    utils::{native_eth_address, serialize_to_calldata, setup_malleable_match_test},
    TestContext,
};

// ---------
// | Tests |
// ---------

// --- Valid Test Cases --- //

/// Test a basic malleable match
#[allow(non_snake_case)]
async fn test_malleable_match__basic(ctx: TestContext) -> Result<()> {
    let (base_amount, payload) = setup_malleable_match_test(false /* is_native */, &ctx).await?;
    let receiver = ctx.client.address();
    submit_and_validate_malleable_match(
        receiver,
        base_amount,
        payload.internal_party_match_payload,
        payload.valid_malleable_match_settle_atomic_statement,
        payload.match_atomic_proofs,
        payload.match_atomic_linking_proofs,
        &ctx,
    )
    .await?;

    Ok(())
}
integration_test_async!(test_malleable_match__basic);

/// Test a malleable match on the native asset
#[allow(non_snake_case)]
async fn test_malleable_match__native(ctx: TestContext) -> Result<()> {
    let (base_amount, payload) = setup_malleable_match_test(true /* is_native */, &ctx).await?;
    let receiver = ctx.client.address();
    submit_and_validate_malleable_match(
        receiver,
        base_amount,
        payload.internal_party_match_payload,
        payload.valid_malleable_match_settle_atomic_statement,
        payload.match_atomic_proofs,
        payload.match_atomic_linking_proofs,
        &ctx,
    )
    .await?;

    Ok(())
}
integration_test_async!(test_malleable_match__native);

/// Test a malleable match with a non-sender as the receiver
#[allow(non_snake_case)]
async fn test_malleable_match__non_sender_receiver(ctx: TestContext) -> Result<()> {
    let (base_amount, payload) = setup_malleable_match_test(false /* is_native */, &ctx).await?;
    let receiver = Address::random();
    submit_and_validate_malleable_match(
        receiver,
        base_amount,
        payload.internal_party_match_payload,
        payload.valid_malleable_match_settle_atomic_statement,
        payload.match_atomic_proofs,
        payload.match_atomic_linking_proofs,
        &ctx,
    )
    .await?;

    Ok(())
}
integration_test_async!(test_malleable_match__non_sender_receiver);

/// Test a malleable match with a non-sender as the receiver on the native asset
#[allow(non_snake_case)]
async fn test_malleable_match__non_sender_receiver_native(ctx: TestContext) -> Result<()> {
    let (base_amount, payload) = setup_malleable_match_test(true /* is_native */, &ctx).await?;
    let receiver = Address::random();
    submit_and_validate_malleable_match(
        receiver,
        base_amount,
        payload.internal_party_match_payload,
        payload.valid_malleable_match_settle_atomic_statement,
        payload.match_atomic_proofs,
        payload.match_atomic_linking_proofs,
        &ctx,
    )
    .await?;

    Ok(())
}
integration_test_async!(test_malleable_match__non_sender_receiver_native);

// --- Invalid Test Cases --- //

/// Test a malleable match on the native asset with an invalid ETH value (i.e.
/// greater than zero)
#[allow(non_snake_case)]
async fn test_malleable_match__non_native_invalid_value(ctx: TestContext) -> Result<()> {
    let darkpool = ctx.darkpool_contract();
    let (base_amount, payload) = setup_malleable_match_test(false /* is_native */, &ctx).await?;
    let receiver = Address::random();
    let tx = darkpool
        .processMalleableAtomicMatchSettle(
            base_amount,
            receiver,
            serialize_to_calldata(&payload.internal_party_match_payload)?,
            serialize_to_calldata(&payload.valid_malleable_match_settle_atomic_statement)?,
            serialize_to_calldata(&payload.match_atomic_proofs)?,
            serialize_to_calldata(&payload.match_atomic_linking_proofs)?,
        )
        .value(U256::from(1));
    let is_err = send_tx(tx).await.is_err();
    assert_true_result!(is_err)
}
integration_test_async!(test_malleable_match__non_native_invalid_value);

/// Test a malleable match on the native asset with an ETH value too small
#[allow(non_snake_case)]
async fn test_malleable_match__native_value_too_small(ctx: TestContext) -> Result<()> {
    let darkpool = ctx.darkpool_contract();
    let (base_amount, mut payload) = setup_malleable_match_test(true /* is_native */, &ctx).await?;
    payload.valid_malleable_match_settle_atomic_statement.match_result.direction = false; // sell

    let receiver = ctx.client.address();
    let invalid_value = base_amount - U256::from(1);
    let tx = darkpool
        .processMalleableAtomicMatchSettle(
            base_amount,
            receiver,
            serialize_to_calldata(&payload.internal_party_match_payload)?,
            serialize_to_calldata(&payload.valid_malleable_match_settle_atomic_statement)?,
            serialize_to_calldata(&payload.match_atomic_proofs)?,
            serialize_to_calldata(&payload.match_atomic_linking_proofs)?,
        )
        .value(invalid_value);
    let is_err = send_tx(tx).await.is_err();
    assert_true_result!(is_err)
}
integration_test_async!(test_malleable_match__native_value_too_small);

/// Test a malleable match with an incorrect protocol fee rate
#[allow(non_snake_case)]
async fn test_malleable_match__incorrect_protocol_fee_rate(ctx: TestContext) -> Result<()> {
    let mut rng = thread_rng();
    let darkpool = ctx.darkpool_contract();
    let (base_amount, mut payload) =
        setup_malleable_match_test(false /* is_native */, &ctx).await?;

    // Modify the fee rate
    let fee_rate = if rng.gen_bool(0.5) {
        &mut payload.valid_malleable_match_settle_atomic_statement.external_fee_rates
    } else {
        &mut payload.valid_malleable_match_settle_atomic_statement.internal_fee_rates
    };

    fee_rate.protocol_fee_rate.repr -= ScalarField::from(1);
    let receiver = ctx.client.address();

    let tx = darkpool.processMalleableAtomicMatchSettle(
        base_amount,
        receiver,
        serialize_to_calldata(&payload.internal_party_match_payload)?,
        serialize_to_calldata(&payload.valid_malleable_match_settle_atomic_statement)?,
        serialize_to_calldata(&payload.match_atomic_proofs)?,
        serialize_to_calldata(&payload.match_atomic_linking_proofs)?,
    );
    let is_err = send_tx(tx).await.is_err();
    assert_true_result!(is_err)
}
integration_test_async!(test_malleable_match__incorrect_protocol_fee_rate);

// -----------
// | Helpers |
// -----------

/// Submit a malleable match, and validate the balances of all parties before
/// and after
async fn submit_and_validate_malleable_match(
    receiver: Address,
    base_amount: U256,
    internal_party_payload: MatchPayload,
    statement: ValidMalleableMatchSettleAtomicStatement,
    proofs: MatchAtomicProofs,
    linking_proofs: MatchAtomicLinkingProofs,
    ctx: &TestContext,
) -> Result<()> {
    let darkpool = ctx.darkpool_contract();

    // Measure the balances of all parties before the match
    let base_mint = statement.match_result.base_mint;
    let relayer_recipient = statement.relayer_fee_address;
    let balances_before = get_party_balances(base_mint, receiver, relayer_recipient, ctx).await?;

    // Submit the match
    let is_native = statement.match_result.base_mint == native_eth_address();
    let native_sell = is_native && statement.match_result.is_external_party_sell();
    let value = if native_sell { base_amount } else { U256::ZERO };

    let tx = darkpool
        .processMalleableAtomicMatchSettle(
            base_amount,
            receiver,
            serialize_to_calldata(&internal_party_payload)?,
            serialize_to_calldata(&statement)?,
            serialize_to_calldata(&proofs)?,
            serialize_to_calldata(&linking_proofs)?,
        )
        .value(value);
    let tx_receipt = send_tx(tx).await?.expect("No tx receipt");

    // Measure the balances of all parties after the match, and validate that they
    // match the expected balances
    let balances_after = get_party_balances(base_mint, receiver, relayer_recipient, ctx).await?;
    let mut expected_balances = balances_before.clone();
    let sender_is_receiver = ctx.client.address() == receiver;
    update_expected_balances(
        base_amount,
        is_native,
        sender_is_receiver,
        &statement,
        &tx_receipt,
        &mut expected_balances,
    );

    assert_eq_result!(balances_after, expected_balances)
}

/// A type representing the balances of all parties in a match
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct PartyBalances {
    /// The darkpool's balance of the base token
    darkpool_base: U256,
    /// The darkpool's balance of the quote token
    darkpool_quote: U256,
    /// The tx sender's balance of the base token
    sender_base: U256,
    /// The tx sender's balance of the quote token
    sender_quote: U256,
    /// The receiver's balance of the base token
    receiver_base: U256,
    /// The receiver's balance of the quote token
    receiver_quote: U256,
    /// The relayer's fee balance of the base token
    relayer_fee_base: U256,
    /// The relayer's fee balance of the quote token
    relayer_fee_quote: U256,
    /// The protocol fee collector's balance of the base token
    protocol_fee_base: U256,
    /// The protocol fee collector's balance of the quote token
    protocol_fee_quote: U256,
}

/// Get the balances of all parties in a match
async fn get_party_balances(
    base_mint: Address,
    receiver: Address,
    relayer_fee_recipient: Address,
    ctx: &TestContext,
) -> Result<PartyBalances> {
    let sender = ctx.client.address();
    let darkpool = ctx.darkpool_contract();
    let darkpool_addr = *darkpool.address();
    let protocol_fee_addr = darkpool.getProtocolExternalFeeCollectionAddress().call().await?._0;
    let base_wrapper = ctx.test_erc20_address1;

    // Fetch balances
    let quote_mint = ctx.test_erc20_address2;
    let darkpool_base = ctx.get_erc20_balance_of(base_wrapper, darkpool_addr).await?;
    let darkpool_quote = ctx.get_erc20_balance_of(quote_mint, darkpool_addr).await?;
    let sender_base = ctx.get_erc20_balance_of(base_mint, sender).await?;
    let sender_quote = ctx.get_erc20_balance_of(quote_mint, sender).await?;
    let receiver_base = ctx.get_erc20_balance_of(base_mint, receiver).await?;
    let receiver_quote = ctx.get_erc20_balance_of(quote_mint, receiver).await?;
    let relayer_fee_base = ctx.get_erc20_balance_of(base_mint, relayer_fee_recipient).await?;
    let relayer_fee_quote = ctx.get_erc20_balance_of(quote_mint, relayer_fee_recipient).await?;
    let protocol_fee_base = ctx.get_erc20_balance_of(base_mint, protocol_fee_addr).await?;
    let protocol_fee_quote = ctx.get_erc20_balance_of(quote_mint, protocol_fee_addr).await?;

    Ok(PartyBalances {
        darkpool_base,
        darkpool_quote,
        sender_base,
        sender_quote,
        receiver_base,
        receiver_quote,
        relayer_fee_base,
        relayer_fee_quote,
        protocol_fee_base,
        protocol_fee_quote,
    })
}

/// Compute the expected balances of all parties in a match
fn update_expected_balances(
    base_amount: U256,
    is_native: bool,
    sender_is_receiver: bool,
    statement: &ValidMalleableMatchSettleAtomicStatement,
    tx_receipt: &TransactionReceipt,
    expected_balances: &mut PartyBalances,
) {
    /// Macro to conditionally apply a balance update in the case that the
    /// sender and receiver are the same
    macro_rules! if_sender_receiver {
        ($($body:tt)*) => {
            if sender_is_receiver {
                $($body)*
            }
        };
    }

    // Compute update values
    let gas_used = tx_receipt.gas_used;
    let gas_price = tx_receipt.effective_gas_price;
    let eth_gas_cost = U256::from((gas_used as u128) * gas_price);
    let quote_amount = statement.match_result.price.unsafe_fixed_point_mul(base_amount);

    // Apply the updates to the balances
    if statement.match_result.is_external_party_sell() {
        // External party sells the base and receives the quote
        let fees = statement.external_fee_rates.get_fee_take(quote_amount);
        let total_fees = fees.total();
        let net_quote_amount = quote_amount - total_fees;

        expected_balances.darkpool_base += base_amount;
        expected_balances.darkpool_quote -= quote_amount;
        expected_balances.sender_base -= base_amount;
        if_sender_receiver!(expected_balances.receiver_base -= base_amount);
        expected_balances.receiver_quote += net_quote_amount;
        if_sender_receiver!(expected_balances.sender_quote += net_quote_amount);
        expected_balances.protocol_fee_quote += fees.protocol_fee;
        expected_balances.relayer_fee_quote += fees.relayer_fee;
    } else {
        // External party buys the base and pays for the quote
        let fees = statement.external_fee_rates.get_fee_take(base_amount);
        let total_fees = fees.total();

        expected_balances.darkpool_base -= base_amount;
        expected_balances.darkpool_quote += quote_amount;
        expected_balances.receiver_base += base_amount - total_fees;
        if_sender_receiver!(expected_balances.sender_base += base_amount - total_fees);
        expected_balances.sender_quote -= quote_amount;
        if_sender_receiver!(expected_balances.receiver_quote -= quote_amount);
        expected_balances.protocol_fee_base += fees.protocol_fee;
        expected_balances.relayer_fee_base += fees.relayer_fee;
    }

    // Account for the gas cost in the native asset balance
    if is_native {
        expected_balances.sender_base -= eth_gas_cost;
        if_sender_receiver!(expected_balances.receiver_base -= eth_gas_cost);
    }
}
