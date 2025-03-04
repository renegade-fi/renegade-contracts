//! Integration tests for gas sponsorship

use ethers::types::{TransactionReceipt, U256};
use eyre::Result;
use test_helpers::integration_test_async;
use tracing::info;

use crate::{
    abis::IAtomicMatchSettleContract,
    constants::GAS_COST_TOLERANCE,
    utils::{
        alloy_address_to_ethers_address, alloy_u256_to_ethers_u256, assert_token_gas_refund,
        serialize_to_calldata, setup_sponsored_match_test, setup_sponsored_match_test_native_eth,
        u256_to_alloy_u256,
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
    let data = setup_sponsored_match_test(true /* buy_side */, &ctx).await?;

    let (alloy_buy_token_addr, _) = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .external_party_buy_mint_amount();

    let buy_token_addr = alloy_address_to_ethers_address(&alloy_buy_token_addr);

    let initial_token_balance =
        ctx.get_erc20_balance_of(buy_token_addr, ctx.gas_sponsor_proxy_address).await?;

    let receipt: TransactionReceipt = ctx
        .gas_sponsor_contract()
        .sponsor_atomic_match_settle_with_receiver(
            ctx.client.address(),
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
            data.nonce,
            data.conversion_rate,
            data.signature,
        )
        .send()
        .await?
        .await?
        .expect("no tx receipt");

    let final_token_balance =
        ctx.get_erc20_balance_of(buy_token_addr, ctx.gas_sponsor_proxy_address).await?;

    assert_token_gas_refund(
        initial_token_balance,
        final_token_balance,
        data.conversion_rate,
        receipt,
    );

    Ok(())
}
integration_test_async!(test_sponsored_match_refund__simple);

/// Test a sponsored match through the gas sponsor, buying the native asset.
///
/// Asserts that the refunded amount is ~equal to the gas paid.
#[allow(non_snake_case)]
pub async fn test_sponsored_match_refund__native_asset_buy(ctx: TestContext) -> Result<()> {
    let data = setup_sponsored_match_test_native_eth(true /* buy_side */, &ctx).await?;

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
            data.nonce,
            data.conversion_rate,
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

    info!("initial_eth_balance: {initial_eth_balance}");
    info!("post_refund_eth_balance: {post_refund_eth_balance}");

    let eth_diff = initial_eth_balance.checked_sub(post_refund_eth_balance).unwrap_or_default();
    let gas_diff = eth_diff / gas_price;

    info!("gas_diff: {gas_diff}");

    assert!(gas_diff < GAS_COST_TOLERANCE, "Unrefunded gas amount of {gas_diff} is too high");

    Ok(())
}
integration_test_async!(test_sponsored_match_refund__native_asset_buy);

/// Test a sponsored match through the gas sponsor, selling the native asset.
///
/// Asserts that the refunded amount is ~equal to the gas paid.
#[allow(non_snake_case)]
pub async fn test_sponsored_match_refund__native_asset_sell(ctx: TestContext) -> Result<()> {
    let data = setup_sponsored_match_test_native_eth(false /* buy_side */, &ctx).await?;

    let base_amount = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .base_amount;

    let value = alloy_u256_to_ethers_u256(base_amount);

    let (alloy_buy_token_addr, _) = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .external_party_buy_mint_amount();

    let buy_token_addr = alloy_address_to_ethers_address(&alloy_buy_token_addr);

    let initial_token_balance =
        ctx.get_erc20_balance_of(buy_token_addr, ctx.gas_sponsor_proxy_address).await?;

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
            data.nonce,
            data.conversion_rate,
            data.signature,
        )
        .value(value)
        .send()
        .await?
        .await?
        .expect("no tx receipt");

    let final_token_balance =
        ctx.get_erc20_balance_of(buy_token_addr, ctx.gas_sponsor_proxy_address).await?;

    assert_token_gas_refund(
        initial_token_balance,
        final_token_balance,
        data.conversion_rate,
        receipt,
    );

    Ok(())
}
integration_test_async!(test_sponsored_match_refund__native_asset_sell);

/// Test a sponsored match which reuses an existing nonce.
///
/// Asserts that the match w/ the duplicate nonce fails.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__duplicate_nonce(ctx: TestContext) -> Result<()> {
    let data1 = setup_sponsored_match_test(true /* buy_side */, &ctx).await?;
    let data2 = setup_sponsored_match_test(true /* buy_side */, &ctx).await?;

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
            data1.nonce,
            data1.conversion_rate,
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
        // Here, we reuse the nonce + conversion rate + signature from the first match
        data1.nonce,
        data1.conversion_rate,
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
    let data = setup_sponsored_match_test(true /* buy_side */, &ctx).await?;

    let call = ctx.gas_sponsor_contract().sponsor_atomic_match_settle(
        serialize_to_calldata(&data.process_atomic_match_settle_data.internal_party_match_payload)?,
        serialize_to_calldata(
            &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
        )?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_linking_proofs)?,
        U256::zero(), // incorrect nonce
        data.conversion_rate,
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
    let data = setup_sponsored_match_test(true /* buy_side */, &ctx).await?;

    // Pause the gas sponsor
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    gas_sponsor_contract.pause().send().await?.await?;

    let (alloy_buy_token_addr, _) = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .external_party_buy_mint_amount();

    let buy_token_addr = alloy_address_to_ethers_address(&alloy_buy_token_addr);

    let initial_token_balance = ctx.get_erc20_balance(buy_token_addr).await?;

    gas_sponsor_contract
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
            data.nonce,
            data.conversion_rate,
            data.signature,
        )
        .send()
        .await?
        .await?
        .expect("no tx receipt");

    let final_token_balance = ctx.get_erc20_balance(buy_token_addr).await?;

    let base_amount = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .base_amount;

    let fee_total = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .external_party_fees
        .total();

    assert!(
        final_token_balance - initial_token_balance == base_amount - fee_total,
        "Expected no surplus buy tokens"
    );

    Ok(())
}
integration_test_async!(test_sponsored_match__paused);

/// Test a sponsored match when the gas sponsor is underfunded.
///
/// Asserts that the match succeeds but is not sponsored.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__underfunded(ctx: TestContext) -> Result<()> {
    let data = setup_sponsored_match_test(true /* buy_side */, &ctx).await?;

    // Withdraw almost all token balances from the gas sponsor
    let balance1 = alloy_u256_to_ethers_u256(
        ctx.get_erc20_balance_of(ctx.test_erc20_address1, ctx.gas_sponsor_proxy_address).await?,
    );
    let balance2 = alloy_u256_to_ethers_u256(
        ctx.get_erc20_balance_of(ctx.test_erc20_address2, ctx.gas_sponsor_proxy_address).await?,
    );

    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    gas_sponsor_contract
        .withdraw_tokens(ctx.client.address(), ctx.test_erc20_address1, balance1 - 1)
        .send()
        .await?
        .await?;
    gas_sponsor_contract
        .withdraw_tokens(ctx.client.address(), ctx.test_erc20_address2, balance2 - 1)
        .send()
        .await?
        .await?;

    // Check token balance diff post-match
    let (alloy_buy_token_addr, _) = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .external_party_buy_mint_amount();

    let buy_token_addr = alloy_address_to_ethers_address(&alloy_buy_token_addr);

    let initial_token_balance = ctx.get_erc20_balance(buy_token_addr).await?;

    gas_sponsor_contract
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
            data.nonce,
            data.conversion_rate,
            data.signature,
        )
        .send()
        .await?
        .await?
        .expect("no tx receipt");

    let final_token_balance = ctx.get_erc20_balance(buy_token_addr).await?;

    let base_amount = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .base_amount;

    let fee_total = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .external_party_fees
        .total();

    assert!(
        final_token_balance - initial_token_balance == base_amount - fee_total,
        "Expected no surplus buy tokens"
    );

    Ok(())
}
integration_test_async!(test_sponsored_match__underfunded);
