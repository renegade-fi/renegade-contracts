//! Integration tests for gas sponsorship

use eyre::Result;
use test_helpers::integration_test_async;

use crate::{abis::IAtomicMatchSettleContract, TestContext};

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
