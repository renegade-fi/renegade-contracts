//! External settlement tests

use crate::{
    test_args::TestArgs,
    tests::settlement::{BOUNDED_MAX_AMT, Intent, get_total_fee, random_price},
    util::transactions::wait_for_tx_success,
};
use alloy::primitives::U256;
use eyre::Result;
use rand::{Rng, thread_rng};
use renegade_circuits::test_helpers::create_bounded_match_result_with_balance;
use renegade_crypto::fields::scalar_to_u128;
use renegade_darkpool_types::bounded_match_result::BoundedMatchResult;
use renegade_darkpool_types::{fee::FeeTake, settlement_obligation::SettlementObligation};

pub mod private_intent_private_balance;
pub mod private_intent_public_balance;
pub mod public_intent_public_balance;

/// Compute the fee take for an external match
pub async fn compute_fee_take(
    internal_obligation: &SettlementObligation,
    external_obligation: &SettlementObligation,
    args: &TestArgs,
) -> Result<(FeeTake, FeeTake)> {
    let (relayer_fee_rate, protocol_fee_rate) = get_total_fee(args).await?;

    // Compute the fee take for the internal party (on their output amount)
    let internal_party_relayer_fee_take =
        relayer_fee_rate.floor_mul_int(internal_obligation.amount_out);
    let internal_party_protocol_fee_take =
        protocol_fee_rate.floor_mul_int(internal_obligation.amount_out);
    let internal_party_fee_take = FeeTake {
        relayer_fee: scalar_to_u128(&internal_party_relayer_fee_take),
        protocol_fee: scalar_to_u128(&internal_party_protocol_fee_take),
    };

    // Compute the fee take for the external party (on their output amount)
    let external_party_relayer_fee_take =
        relayer_fee_rate.floor_mul_int(external_obligation.amount_out);
    let external_party_protocol_fee_take =
        protocol_fee_rate.floor_mul_int(external_obligation.amount_out);
    let external_party_fee_take = FeeTake {
        relayer_fee: scalar_to_u128(&external_party_relayer_fee_take),
        protocol_fee: scalar_to_u128(&external_party_protocol_fee_take),
    };

    Ok((internal_party_fee_take, external_party_fee_take))
}

/// Setup function for external match tests
///
/// Funds the tx_submitter (external party) and approves the darkpool to spend tokens directly
/// (for ERC20ApprovalDeposit path).
pub async fn setup_external_match(args: &TestArgs) -> Result<()> {
    // Fund the address (ETH, tokens, permit2 approval)
    crate::fund_address(&args.tx_submitter, args).await?;

    // Approve the darkpool to spend tokens directly (ERC20ApprovalDeposit path)
    let signer = &args.tx_submitter;
    let base = args.base_token_with_signer(signer)?;
    let quote = args.quote_token_with_signer(signer)?;
    let amt = U256::from(1) << 200; // 2^200
    let darkpool = args.darkpool_addr();
    wait_for_tx_success(base.approve(darkpool, amt)).await?;
    wait_for_tx_success(quote.approve(darkpool, amt)).await?;

    Ok(())
}

/// Create an intent and bounded match result constrained by a balance amount
///
/// This ensures `max_internal_party_amount_in <= balance_amount`, satisfying
/// the circuit's capitalization constraint.
///
/// Party 0 (internal party) sells the base; Party 1 (external party) sells the quote
///
/// Returns the intent, bounded match result, and balance amount used
pub(crate) fn create_intent_and_bounded_match_result(
    args: &TestArgs,
) -> Result<(Intent, BoundedMatchResult, u128)> {
    let mut rng = thread_rng();
    // Generate balance first, then intent amount >= balance for meaningful bounded results
    let balance_amount = rng.gen_range(1..BOUNDED_MAX_AMT);
    let amount_in = rng.gen_range(balance_amount..=BOUNDED_MAX_AMT);
    let min_price = random_price();
    let internal_party_intent = Intent {
        in_token: args.base_addr()?,
        out_token: args.quote_addr()?,
        owner: args.party0_addr(),
        min_price,
        amount_in,
    };

    // Use create_bounded_match_result_with_balance to ensure max <= balance_amount
    let bounded_match_result =
        create_bounded_match_result_with_balance(&internal_party_intent, balance_amount);
    Ok((internal_party_intent, bounded_match_result, balance_amount))
}
