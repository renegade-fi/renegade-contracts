//! Integration tests for gas sponsorship

use alloy_primitives::U256;
use ethers::{abi::Address, types::TransactionReceipt};
use eyre::Result;
use ruint::uint;
use test_helpers::integration_test_async;

use crate::{
    abis::IAtomicMatchSettleContract,
    utils::{
        alloy_u256_to_ethers_u256, serialize_to_calldata, setup_sponsored_match_test,
        u256_to_alloy_u256, SponsoredMatchTestOptions,
    },
    TestContext,
};

use super::atomic_settlement::{
    _test_process_atomic_match_settle__external_party_buy_side,
    _test_process_atomic_match_settle__external_party_sell_side,
    _test_process_atomic_match_settle__native_asset_buy_side,
    _test_process_atomic_match_settle__native_asset_sell_side,
    _test_process_atomic_match_settle_with_receiver,
};

/// The gas cost tolerance, i.e. the margin of error in units of gas
/// that is permissible in our gas refund accounting
const GAS_COST_TOLERANCE: U256 = uint!(15_000U256);

/// Test an unsponsored buy through the gas
/// sponsor
#[allow(non_snake_case)]
pub async fn test_unsponsored_match__buy_side(ctx: TestContext) -> Result<()> {
    let contract =
        IAtomicMatchSettleContract::new(ctx.gas_sponsor_proxy_address, ctx.client.clone());

    _test_process_atomic_match_settle__external_party_buy_side(ctx, contract).await
}
integration_test_async!(test_unsponsored_match__buy_side);

/// Test an unsponsored sell through the gas
/// sponsor
#[allow(non_snake_case)]
pub async fn test_unsponsored_match__sell_side(ctx: TestContext) -> Result<()> {
    let contract =
        IAtomicMatchSettleContract::new(ctx.gas_sponsor_proxy_address, ctx.client.clone());

    _test_process_atomic_match_settle__external_party_sell_side(ctx, contract).await
}
integration_test_async!(test_unsponsored_match__sell_side);

/// Test an unsponsored buy through the gas sponsor with the native asset
#[allow(non_snake_case)]
pub async fn test_unsponsored_match__native_asset_buy_side(ctx: TestContext) -> Result<()> {
    let contract =
        IAtomicMatchSettleContract::new(ctx.gas_sponsor_proxy_address, ctx.client.clone());

    _test_process_atomic_match_settle__native_asset_buy_side(ctx, contract).await
}
integration_test_async!(test_unsponsored_match__native_asset_buy_side);

/// Test an unsponsored sell through the gas sponsor with the native asset
#[allow(non_snake_case)]
pub async fn test_unsponsored_match__native_asset_sell_side(ctx: TestContext) -> Result<()> {
    let contract =
        IAtomicMatchSettleContract::new(ctx.gas_sponsor_proxy_address, ctx.client.clone());

    _test_process_atomic_match_settle__native_asset_sell_side(ctx, contract).await
}
integration_test_async!(test_unsponsored_match__native_asset_sell_side);

/// Test an unsponsored match with a receiver through the gas sponsor
#[allow(non_snake_case)]
pub async fn test_unsponsored_match_with_receiver(ctx: TestContext) -> Result<()> {
    let contract =
        IAtomicMatchSettleContract::new(ctx.gas_sponsor_proxy_address, ctx.client.clone());

    _test_process_atomic_match_settle_with_receiver(ctx, contract).await
}
integration_test_async!(test_unsponsored_match_with_receiver);

/// Test a sponsored match through the gas sponsor.
///
/// Asserts that the refunded amount is ~equal to the gas paid.
#[allow(non_snake_case)]
pub async fn test_sponsored_match_refund__simple(ctx: TestContext) -> Result<()> {
    let data = setup_sponsored_match_test(Default::default() /* options */, &ctx).await?;

    let initial_eth_balance = ctx.get_eth_balance().await?;

    let receipt: TransactionReceipt = ctx
        .gas_sponsor_contract()
        .sponsor_atomic_match_settle(
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.internal_party_match_payload,
            )?,
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
            )?,
            serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.match_atomic_linking_proofs,
            )?,
            data.refund_address,
            data.nonce,
            data.signature,
        )
        .send()
        .await?
        .await?
        .expect("no tx receipt");

    let gas_price = u256_to_alloy_u256(receipt.effective_gas_price.unwrap());
    let final_eth_balance = ctx.get_eth_balance().await?;

    let eth_diff = initial_eth_balance.checked_sub(final_eth_balance).unwrap_or_default();
    let gas_diff = eth_diff / gas_price;
    assert!(gas_diff < GAS_COST_TOLERANCE, "Unrefunded gas amount of {gas_diff} is too high");

    Ok(())
}
integration_test_async!(test_sponsored_match_refund__simple);

/// Test a sponsored match through the gas sponsor, buying the native asset.
///
/// Asserts that the refunded amount is ~equal to the gas paid.
#[allow(non_snake_case)]
pub async fn test_sponsored_match_refund__native_asset_buy(ctx: TestContext) -> Result<()> {
    let data = setup_sponsored_match_test(
        SponsoredMatchTestOptions { trade_native_eth: true, ..Default::default() },
        &ctx,
    )
    .await?;

    let initial_eth_balance = ctx.get_eth_balance().await?;

    let receipt: TransactionReceipt = ctx
        .gas_sponsor_contract()
        .sponsor_atomic_match_settle(
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.internal_party_match_payload,
            )?,
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
            )?,
            serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.match_atomic_linking_proofs,
            )?,
            data.refund_address,
            data.nonce,
            data.signature,
        )
        .send()
        .await?
        .await?
        .expect("no tx receipt");

    let match_result =
        &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement.match_result;

    let fees = &data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .external_party_fees;

    let eth_received_in_match = match_result.base_amount - fees.total();

    let gas_price = u256_to_alloy_u256(receipt.effective_gas_price.unwrap());
    let final_eth_balance = ctx.get_eth_balance().await?;
    let post_refund_eth_balance = final_eth_balance - eth_received_in_match;

    let eth_diff = initial_eth_balance.checked_sub(post_refund_eth_balance).unwrap_or_default();
    let gas_diff = eth_diff / gas_price;
    assert!(gas_diff < GAS_COST_TOLERANCE, "Unrefunded gas amount of {gas_diff} is too high");

    Ok(())
}
integration_test_async!(test_sponsored_match_refund__native_asset_buy);

/// Test a sponsored match through the gas sponsor, selling the native asset.
///
/// Asserts that the refunded amount is ~equal to the gas paid.
#[allow(non_snake_case)]
pub async fn test_sponsored_match_refund__native_asset_sell(ctx: TestContext) -> Result<()> {
    let data = setup_sponsored_match_test(
        SponsoredMatchTestOptions { sell_side: true, trade_native_eth: true, ..Default::default() },
        &ctx,
    )
    .await?;

    let base_amount = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .base_amount;

    let value = alloy_u256_to_ethers_u256(base_amount);

    let initial_eth_balance = ctx.get_eth_balance().await?;

    let receipt: TransactionReceipt = ctx
        .gas_sponsor_contract()
        .sponsor_atomic_match_settle(
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.internal_party_match_payload,
            )?,
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
            )?,
            serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.match_atomic_linking_proofs,
            )?,
            data.refund_address,
            data.nonce,
            data.signature,
        )
        .value(value)
        .send()
        .await?
        .await?
        .expect("no tx receipt");

    let gas_price = u256_to_alloy_u256(receipt.effective_gas_price.unwrap());
    let final_eth_balance = ctx.get_eth_balance().await?;

    let gas_diff = (initial_eth_balance - (final_eth_balance + base_amount)) / gas_price;
    assert!(gas_diff < GAS_COST_TOLERANCE, "Unrefunded gas amount of {gas_diff} is too high");

    Ok(())
}
integration_test_async!(test_sponsored_match_refund__native_asset_sell);

/// Test a sponsored match which reuses an existing nonce.
///
/// Asserts that the match w/ the duplicate nonce fails.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__duplicate_nonce(ctx: TestContext) -> Result<()> {
    let data1 = setup_sponsored_match_test(Default::default() /* options */, &ctx).await?;
    let data2 = setup_sponsored_match_test(Default::default() /* options */, &ctx).await?;

    ctx.gas_sponsor_contract()
        .sponsor_atomic_match_settle(
            serialize_to_calldata(
                &data1.process_atomic_match_settle_data.internal_party_match_payload,
            )?,
            serialize_to_calldata(
                &data1.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
            )?,
            serialize_to_calldata(&data1.process_atomic_match_settle_data.match_atomic_proofs)?,
            serialize_to_calldata(
                &data1.process_atomic_match_settle_data.match_atomic_linking_proofs,
            )?,
            data1.refund_address,
            data1.nonce,
            data1.signature.clone(),
        )
        .send()
        .await?
        .await?
        .expect("no tx receipt");

    let call = ctx.gas_sponsor_contract().sponsor_atomic_match_settle(
        serialize_to_calldata(
            &data2.process_atomic_match_settle_data.internal_party_match_payload,
        )?,
        serialize_to_calldata(
            &data2.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
        )?,
        serialize_to_calldata(&data2.process_atomic_match_settle_data.match_atomic_proofs)?,
        serialize_to_calldata(&data2.process_atomic_match_settle_data.match_atomic_linking_proofs)?,
        // Here, we reuse the refund address + nonce + signature from the first match
        data1.refund_address,
        data1.nonce,
        data1.signature,
    );

    let result = call.send().await;

    assert!(result.is_err(), "Expected error due to duplicate nonce");

    Ok(())
}
integration_test_async!(test_sponsored_match__duplicate_nonce);

/// Test a sponsored match which provides a refund address other than the
/// one that was signed.
///
/// Asserts that the match fails on account of an invalid signature.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__invalid_signature(ctx: TestContext) -> Result<()> {
    let data = setup_sponsored_match_test(Default::default() /* options */, &ctx).await?;

    let call = ctx.gas_sponsor_contract().sponsor_atomic_match_settle(
        serialize_to_calldata(&data.process_atomic_match_settle_data.internal_party_match_payload)?,
        serialize_to_calldata(
            &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
        )?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_linking_proofs)?,
        Address::random(), // Incorrect refund address
        data.nonce,
        data.signature,
    );

    let result = call.send().await;

    assert!(result.is_err(), "Expected error due to invalid signature");

    Ok(())
}
integration_test_async!(test_sponsored_match__invalid_signature);

/// Test a sponsored match when the gas sponsor is paused.
///
/// Asserts that the match succeeds but is not sponsored.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__paused(ctx: TestContext) -> Result<()> {
    let data = setup_sponsored_match_test(Default::default() /* options */, &ctx).await?;

    // Pause the gas sponsor
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    gas_sponsor_contract.pause().send().await?.await?;

    let initial_eth_balance = ctx.get_eth_balance().await?;

    let receipt: TransactionReceipt = gas_sponsor_contract
        .sponsor_atomic_match_settle(
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.internal_party_match_payload,
            )?,
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
            )?,
            serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.match_atomic_linking_proofs,
            )?,
            data.refund_address,
            data.nonce,
            data.signature,
        )
        .send()
        .await?
        .await?
        .expect("no tx receipt");

    let gas_cost =
        u256_to_alloy_u256(receipt.gas_used.unwrap() * receipt.effective_gas_price.unwrap());
    let final_eth_balance = ctx.get_eth_balance().await?;

    assert!(
        initial_eth_balance - final_eth_balance == gas_cost,
        "Expected full gas cost to be paid"
    );

    Ok(())
}
integration_test_async!(test_sponsored_match__paused);

/// Test a sponsored match when the gas sponsor is underfunded.
///
/// Asserts that the match succeeds but is not sponsored.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__underfunded(ctx: TestContext) -> Result<()> {
    let data = setup_sponsored_match_test(Default::default() /* options */, &ctx).await?;

    // Withdraw all ETH from the gas sponsor
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let balance =
        alloy_u256_to_ethers_u256(ctx.get_eth_balance_of(gas_sponsor_contract.address()).await?);
    gas_sponsor_contract.withdraw_eth(ctx.client.address(), balance).send().await?.await?;

    let initial_eth_balance = ctx.get_eth_balance().await?;

    let receipt: TransactionReceipt = gas_sponsor_contract
        .sponsor_atomic_match_settle(
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.internal_party_match_payload,
            )?,
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
            )?,
            serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.match_atomic_linking_proofs,
            )?,
            data.refund_address,
            data.nonce,
            data.signature,
        )
        .send()
        .await?
        .await?
        .expect("no tx receipt");

    let gas_cost =
        u256_to_alloy_u256(receipt.gas_used.unwrap() * receipt.effective_gas_price.unwrap());
    let final_eth_balance = ctx.get_eth_balance().await?;

    assert!(
        initial_eth_balance - final_eth_balance == gas_cost,
        "Expected full gas cost to be paid"
    );

    Ok(())
}
integration_test_async!(test_sponsored_match__underfunded);
