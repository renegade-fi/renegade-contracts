//! Integration test utils for malleable matches

use alloy_primitives::U256;
use circuit_types::{
    fixed_point::FixedPoint,
    r#match::{BoundedMatchResult, ExternalMatchResult},
    Amount,
};
use constants::Scalar;
use contracts_utils::proof_system::test_data::{
    generate_malleable_match_calldata, random_fixed_point, ProcessMalleableMatchSettleAtomicData,
};
use eyre::Result;
use rand::{thread_rng, Rng};
use renegade_crypto::fields::scalar_to_u128;

use crate::TestContext;

use super::{
    address_to_biguint, biguint_to_address, mint_dummy_erc20s, native_eth_address,
    setup_external_match_token_approvals,
};

/// The maximum amount in darkpool balances and match volumes
///
/// We keep this low to avoid spending the entire native eth balance
const MAX_TRADE_SIZE: Amount = 1u128 << 15;

/// Generate the calldata for a malleable match
pub async fn setup_malleable_match_test(
    is_native: bool,
    ctx: &TestContext,
) -> Result<(U256, ProcessMalleableMatchSettleAtomicData)> {
    let mut rng = thread_rng();
    let merkle_root = ctx.get_root_scalar().await?;
    let protocol_fee = ctx.get_protocol_fee().await?;

    // Generate a random match result
    let external_party_buy = rng.gen_bool(0.5);
    let mut match_result = random_bounded_match_result(external_party_buy, ctx);
    match_result.direction = external_party_buy;
    let mut payload = generate_malleable_match_calldata(
        &mut rng,
        merkle_root,
        protocol_fee,
        match_result.clone(),
    )?;

    // Choose a base amount within the bounds
    let base_amount = sample_base_amount(&match_result);
    let quote_amount_fp = match_result.price * Scalar::from(base_amount);
    let quote_amount = scalar_to_u128(&quote_amount_fp.floor());

    // Setup ERC20 token balances
    let exact_match_res = exact_match_result(&match_result, base_amount);
    let base_mint = biguint_to_address(&match_result.base_mint);
    let quote_mint = biguint_to_address(&match_result.quote_mint);
    mint_dummy_erc20s(base_mint, U256::from(base_amount), ctx).await?;
    mint_dummy_erc20s(quote_mint, U256::from(quote_amount), ctx).await?;
    setup_external_match_token_approvals(
        external_party_buy,
        false, // use_gas_sponsor
        &exact_match_res,
        ctx,
    )
    .await?;

    if is_native {
        payload.valid_malleable_match_settle_atomic_statement.match_result.base_mint =
            native_eth_address();
    }
    Ok((U256::from(base_amount), payload))
}

/// Generate a random [`BoundedMatchResult`]
fn random_bounded_match_result(external_party_buy: bool, ctx: &TestContext) -> BoundedMatchResult {
    let mut rng = thread_rng();
    let base = ctx.test_erc20_address1;
    let quote = ctx.test_erc20_address2;
    let min_base_amount = random_amount();
    let max_base_amount = rng.gen_range(min_base_amount..MAX_TRADE_SIZE);

    BoundedMatchResult {
        direction: external_party_buy,
        quote_mint: address_to_biguint(quote),
        base_mint: address_to_biguint(base),
        price: random_price(),
        min_base_amount,
        max_base_amount,
    }
}

/// Generate a random price for an external match
fn random_price() -> FixedPoint {
    let mut rng = thread_rng();
    random_fixed_point(0.01, 1000., &mut rng)
}

/// Generate a random amount for a match
fn random_amount() -> Amount {
    let mut rng = thread_rng();
    rng.gen_range(0..MAX_TRADE_SIZE)
}

/// Choose a base amount
fn sample_base_amount(match_result: &BoundedMatchResult) -> Amount {
    let mut rng = thread_rng();
    let min = match_result.min_base_amount;
    let max = match_result.max_base_amount;
    rng.gen_range(min..max)
}

/// Get the exact match result from a bounded match result and a base amount
pub(crate) fn exact_match_result(
    match_result: &BoundedMatchResult,
    base_amount: Amount,
) -> ExternalMatchResult {
    let quote_amount_fp = match_result.price * Scalar::from(base_amount);
    let quote_amount = scalar_to_u128(&quote_amount_fp.floor());

    ExternalMatchResult {
        quote_mint: match_result.quote_mint.clone(),
        base_mint: match_result.base_mint.clone(),
        quote_amount,
        base_amount,
        direction: match_result.direction,
    }
}
