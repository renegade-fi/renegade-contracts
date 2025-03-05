//! Integration testing utilities for atomic matches

use circuit_types::{
    fixed_point::FixedPoint,
    r#match::{ExternalMatchResult, FeeTake},
};
use constants::Scalar;
use contracts_utils::proof_system::test_data::{
    gen_atomic_match_with_match_and_fees, ProcessAtomicMatchSettleData,
};
use eyre::Result;
use rand::thread_rng;
use scripts::constants::TEST_FUNDING_AMOUNT;

use crate::TestContext;

use super::{
    biguint_to_ethers_address, ethers_address_to_biguint, mint_dummy_erc20s, native_eth_address,
    setup_external_match_token_approvals, u256_to_scalar,
};

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
