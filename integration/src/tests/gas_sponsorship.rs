//! Integration tests for gas sponsorship

use alloy_primitives::{Address, U256};
use eyre::Result;
use scripts::utils::send_tx;
use test_helpers::{assert_eq_result, assert_true_result, integration_test_async};

use crate::{
    constants::REFUND_AMOUNT,
    utils::{
        amount_received_in_match, assert_native_eth_gas_refund, setup_sponsored_match_test,
        sponsor_match_with_test_data, SponsoredMatchTestOptions,
    },
    TestContext,
};

/// Test a sponsored match through the gas sponsor.
///
/// Asserts that the refunded amount is ~equal to the gas paid.
#[allow(non_snake_case)]
pub async fn test_sponsored_match_refund__simple(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let options: SponsoredMatchTestOptions = Default::default();
    let data = setup_sponsored_match_test(options, &ctx).await?;

    let initial_eth_balance = ctx.get_eth_balance().await?;

    let receipt = sponsor_match_with_test_data(&gas_sponsor_contract, data).await?;

    let final_eth_balance = ctx.get_eth_balance().await?;

    assert_native_eth_gas_refund(initial_eth_balance, final_eth_balance, receipt)
}
integration_test_async!(test_sponsored_match_refund__simple);

/// Test a sponsored match through the gas sponsor, buying the native asset.
///
/// Asserts that the refunded amount is ~equal to the gas paid.
#[allow(non_snake_case)]
pub async fn test_sponsored_match_refund__native_asset_buy(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let options = SponsoredMatchTestOptions { trade_native_eth: true, ..Default::default() };
    let data = setup_sponsored_match_test(options, &ctx).await?;

    let eth_received_in_match = amount_received_in_match(
        &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
    );

    let initial_eth_balance = ctx.get_eth_balance().await?;

    let receipt = sponsor_match_with_test_data(&gas_sponsor_contract, data).await?;

    let final_eth_balance = ctx.get_eth_balance().await?;
    let post_refund_eth_balance = final_eth_balance - eth_received_in_match;

    assert_native_eth_gas_refund(initial_eth_balance, post_refund_eth_balance, receipt)
}
integration_test_async!(test_sponsored_match_refund__native_asset_buy);

/// Test a sponsored match through the gas sponsor, selling the native asset.
///
/// Asserts that the refunded amount is ~equal to the gas paid.
#[allow(non_snake_case)]
pub async fn test_sponsored_match_refund__native_asset_sell(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let options =
        SponsoredMatchTestOptions { sell_side: true, trade_native_eth: true, ..Default::default() };

    let data = setup_sponsored_match_test(options, &ctx).await?;

    let base_amount = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .base_amount;

    let initial_eth_balance = ctx.get_eth_balance().await?;

    let receipt = sponsor_match_with_test_data(&gas_sponsor_contract, data).await?;

    let final_eth_balance = ctx.get_eth_balance().await?;
    let post_refund_eth_balance = final_eth_balance + base_amount;

    assert_native_eth_gas_refund(initial_eth_balance, post_refund_eth_balance, receipt)
}
integration_test_async!(test_sponsored_match_refund__native_asset_sell);

/// Test a sponsored match which reuses an existing nonce.
///
/// Asserts that the match w/ the duplicate nonce fails.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__duplicate_nonce(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let options: SponsoredMatchTestOptions = Default::default();
    let data1 = setup_sponsored_match_test(options, &ctx).await?;
    let mut data2 = setup_sponsored_match_test(options, &ctx).await?;

    // Ensure we reuse the signed components of the first sponsored match
    data2.nonce = data1.nonce;
    data2.refund_address = data1.refund_address;
    data2.refund_amount = data1.refund_amount;
    data2.signature = data1.signature.clone();

    sponsor_match_with_test_data(&gas_sponsor_contract, data1).await?;
    let result = sponsor_match_with_test_data(&gas_sponsor_contract, data2).await;

    assert_true_result!(result.is_err())
}
integration_test_async!(test_sponsored_match__duplicate_nonce);

/// Test a sponsored match which provides a refund address other than the
/// one that was signed.
///
/// Asserts that the match fails on account of an invalid signature.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__invalid_signature(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let options: SponsoredMatchTestOptions = Default::default();
    let mut data = setup_sponsored_match_test(options, &ctx).await?;

    // Set an incorrect refund address
    data.refund_address = Address::random();

    let result = sponsor_match_with_test_data(&gas_sponsor_contract, data).await;

    assert_true_result!(result.is_err())
}
integration_test_async!(test_sponsored_match__invalid_signature);

/// Test a sponsored match when the gas sponsor is paused.
///
/// Asserts that the match succeeds but is not sponsored.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__paused(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let options: SponsoredMatchTestOptions = Default::default();
    let data = setup_sponsored_match_test(options, &ctx).await?;

    // Pause the gas sponsor
    send_tx(gas_sponsor_contract.pause()).await?;

    let initial_eth_balance = ctx.get_eth_balance().await?;

    let receipt = sponsor_match_with_test_data(&gas_sponsor_contract, data).await?;

    let gas_cost = receipt.gas_used as u128 * receipt.effective_gas_price;
    let final_eth_balance = ctx.get_eth_balance().await?;

    assert_eq_result!(initial_eth_balance - final_eth_balance, U256::from(gas_cost))
}
integration_test_async!(test_sponsored_match__paused);

/// Test a sponsored match when the gas sponsor is underfunded.
///
/// Asserts that the match succeeds but is not sponsored.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__underfunded(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let options: SponsoredMatchTestOptions = Default::default();
    let data = setup_sponsored_match_test(options, &ctx).await?;

    // Withdraw all ETH from the gas sponsor
    let balance = ctx.get_eth_balance_of(*gas_sponsor_contract.address()).await?;
    let withdraw_tx = gas_sponsor_contract.withdrawEth(ctx.client.address(), balance);
    send_tx(withdraw_tx).await?;

    let initial_eth_balance = ctx.get_eth_balance().await?;

    let receipt = sponsor_match_with_test_data(&gas_sponsor_contract, data).await?;

    let gas_cost = receipt.gas_used as u128 * receipt.effective_gas_price;
    let final_eth_balance = ctx.get_eth_balance().await?;

    assert_eq_result!(initial_eth_balance - final_eth_balance, U256::from(gas_cost))
}
integration_test_async!(test_sponsored_match__underfunded);

/// Test a sponsored match through the gas sponsor with in-kind refunds.
///
/// Asserts that the refunded amount in the buy-side token is ~equal to the gas
/// paid.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__in_kind__simple(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let options = SponsoredMatchTestOptions { in_kind_refund: true, ..Default::default() };
    let data = setup_sponsored_match_test(options, &ctx).await?;

    let (buy_token_addr, _) = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .external_party_buy_mint_amount();

    let received_in_match = amount_received_in_match(
        &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
    );

    let initial_balance = ctx.get_erc20_balance(buy_token_addr).await?;

    sponsor_match_with_test_data(&gas_sponsor_contract, data).await?;

    let final_balance = ctx.get_erc20_balance(buy_token_addr).await?;
    let post_refund_balance = final_balance - received_in_match;

    assert_eq_result!(post_refund_balance - initial_balance, REFUND_AMOUNT)
}
integration_test_async!(test_sponsored_match__in_kind__simple);

/// Test a sponsored match through the gas sponsor with in-kind refunds when
/// buying native ETH.
///
/// Asserts that the refunded amount is ~equal to the gas paid in native ETH.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__in_kind__native_buy(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let options = SponsoredMatchTestOptions {
        in_kind_refund: true,
        trade_native_eth: true,
        ..Default::default()
    };

    let data = setup_sponsored_match_test(options, &ctx).await?;

    let eth_received_in_match = amount_received_in_match(
        &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
    );

    let initial_eth_balance = ctx.get_eth_balance().await?;

    let receipt = sponsor_match_with_test_data(&gas_sponsor_contract, data).await?;

    let final_eth_balance = ctx.get_eth_balance().await?;
    let post_refund_eth_balance = final_eth_balance - eth_received_in_match;

    assert_native_eth_gas_refund(initial_eth_balance, post_refund_eth_balance, receipt)
}
integration_test_async!(test_sponsored_match__in_kind__native_buy);

/// Test a sponsored match through the gas sponsor with a custom refund address.
///
/// Asserts that the refunded amount is sent to the specified refund address.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__refund_address__explicit(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let refund_address = Address::random();
    let options = SponsoredMatchTestOptions { refund_address, ..Default::default() };
    let data = setup_sponsored_match_test(options, &ctx).await?;

    sponsor_match_with_test_data(&gas_sponsor_contract, data).await?;

    let final_eth_balance = ctx.get_eth_balance_of(refund_address).await?;
    assert_eq_result!(final_eth_balance, REFUND_AMOUNT)
}
integration_test_async!(test_sponsored_match__refund_address__explicit);

/// Test that the gas refund is sent to tx::origin() when refund_address is zero
/// and refund_native_eth is true
#[allow(non_snake_case)]
pub async fn test_sponsored_match__refund_address__tx_origin(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();

    // Generate a random receiver address different from tx::origin to ensure
    // we can properly test that the refund goes to tx::origin and not the receiver
    let receiver = Address::random();
    let options = SponsoredMatchTestOptions { receiver, ..Default::default() };
    let data = setup_sponsored_match_test(options, &ctx).await?;

    // tx::origin() will be ctx.client.address() in this case
    let initial_eth_balance = ctx.get_eth_balance().await?;

    let receipt = sponsor_match_with_test_data(&gas_sponsor_contract, data).await?;
    let final_eth_balance = ctx.get_eth_balance().await?;

    assert_native_eth_gas_refund(initial_eth_balance, final_eth_balance, receipt)?;

    // Verify that the refund went to tx::origin and not the receiver
    let receiver_eth_balance = ctx.get_eth_balance_of(receiver).await?;
    assert_eq_result!(receiver_eth_balance, U256::ZERO)
}
integration_test_async!(test_sponsored_match__refund_address__tx_origin);

/// Test that the gas refund is sent to the receiver when refund_address is zero
/// and refund_native_eth is false
#[allow(non_snake_case)]
pub async fn test_sponsored_match__refund_address__receiver(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();

    // Generate a random receiver address different from tx::origin to ensure
    // we can properly test that the refund goes to the receiver and not tx::origin
    let receiver = Address::random();
    let options =
        SponsoredMatchTestOptions { receiver, in_kind_refund: true, ..Default::default() };

    let data = setup_sponsored_match_test(options, &ctx).await?;

    let (buy_token_addr, _) = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .external_party_buy_mint_amount();

    let received_in_match = amount_received_in_match(
        &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
    );

    // Record tx::origin's initial balance to verify it doesn't receive the refund
    let tx_origin_initial_balance = ctx.get_erc20_balance(buy_token_addr).await?;

    sponsor_match_with_test_data(&gas_sponsor_contract, data).await?;

    // Verify that tx::origin did not receive the refund by checking its balance
    // didn't change
    let tx_origin_final_balance = ctx.get_erc20_balance(buy_token_addr).await?;

    assert_eq!(
        tx_origin_final_balance, tx_origin_initial_balance,
        "tx::origin's balance changed when it should not have received the refund"
    );

    // Verify that the refund was sent to the receiver
    let receiver_balance = ctx.get_erc20_balance_of(buy_token_addr, receiver).await?;
    let post_refund_balance = receiver_balance - received_in_match;
    assert_eq_result!(post_refund_balance, REFUND_AMOUNT)?;

    Ok(())
}
integration_test_async!(test_sponsored_match__refund_address__receiver);

/// Test that the gas refund is sent to msg::sender() when refund_address is
/// zero, refund_native_eth is false, and the receiver is zero.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__refund_address__msg_sender(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();

    let options = SponsoredMatchTestOptions { in_kind_refund: true, ..Default::default() };
    let data = setup_sponsored_match_test(options, &ctx).await?;

    let (buy_token_addr, _) = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .external_party_buy_mint_amount();

    let received_in_match = amount_received_in_match(
        &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
    );

    // msg::sender() will be ctx.client.address() in this case
    let initial_balance = ctx.get_erc20_balance(buy_token_addr).await?;

    sponsor_match_with_test_data(&gas_sponsor_contract, data).await?;

    let final_balance = ctx.get_erc20_balance(buy_token_addr).await?;
    let post_refund_balance = final_balance - received_in_match;

    assert_eq_result!(post_refund_balance - initial_balance, REFUND_AMOUNT)
}
integration_test_async!(test_sponsored_match__refund_address__msg_sender);
