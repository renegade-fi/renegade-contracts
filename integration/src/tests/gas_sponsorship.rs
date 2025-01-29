//! Integration tests for gas sponsorship

use alloy_primitives::U256;
use ethers::{abi::Address, types::TransactionReceipt};
use eyre::Result;
use ruint::uint;
use test_helpers::integration_test_async;

use crate::{
    abis::IAtomicMatchSettleContract,
    utils::{serialize_to_calldata, setup_sponsored_match_test, u256_to_alloy_u256},
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
const GAS_COST_TOLERANCE: U256 = uint!(10_000U256);

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

/// Test a sponsored buy through the gas sponsor.
///
/// This test only asserts that the refunded amount is ~equal to the gas paid.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__buy_side(ctx: TestContext) -> Result<()> {
    let data = setup_sponsored_match_test(true /* buy_side */, &ctx).await?;

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
            Address::zero(),
            data.nonce,
            data.signature,
        )
        .send()
        .await?
        .await?
        .expect("no tx receipt");

    let gas_price = u256_to_alloy_u256(receipt.effective_gas_price.unwrap());

    let final_eth_balance = ctx.get_eth_balance().await?;
    let gas_diff = (initial_eth_balance - final_eth_balance) / gas_price;
    assert!(gas_diff < GAS_COST_TOLERANCE);

    Ok(())
}
integration_test_async!(test_sponsored_match__buy_side);
