//! State update tests

use eyre::Result;
use renegade_abi::v2::IDarkpoolV2::ObligationBundle;
use renegade_circuit_types::{balance::DarkpoolStateBalance, intent::DarkpoolStateIntent};
use renegade_common::types::merkle::MerkleAuthenticationPath;

use crate::{
    test_args::TestArgs,
    tests::settlement::{
        compute_fee_take,
        private_intent_private_balance::{self, fund_ring0_party, fund_ring2_party},
        split_obligation,
    },
    util::{merkle::find_state_element_opening, transactions::wait_for_tx_success},
};

mod cancel_order;
pub mod create_balance;
mod deposit;
mod withdraw;

/// The state elements for a private intent and private balance
pub(crate) struct PrivateIntentPrivateBalanceElements {
    /// The intent
    intent: DarkpoolStateIntent,
    /// The opening of the intent
    intent_opening: MerkleAuthenticationPath,
    /// The input balance
    input_balance: DarkpoolStateBalance,
    /// The opening of the input balance
    input_balance_opening: MerkleAuthenticationPath,
    /// The output balance
    output_balance: DarkpoolStateBalance,
    /// The opening of the output balance
    output_balance_opening: MerkleAuthenticationPath,
}

/// Setup a private intent and private balance for tests
///
/// This is facilitated by matching an intent against a ring-0 order to create the intent and output balance
///
/// These state elements are
pub(crate) async fn setup_private_intent_private_balance(
    args: &TestArgs,
) -> Result<PrivateIntentPrivateBalanceElements> {
    // Build intents and obligations for a trade
    let (intent0, intent1, obligation0, obligation1) =
        private_intent_private_balance::create_intents_and_obligations(args)?;

    // Split the obligations
    // We want to return a set of state elements that are not completely filled or exhausted, so we only execute a first fill
    let (first_obligation0, _) = split_obligation(&obligation0);
    let (first_obligation1, _) = split_obligation(&obligation1);

    // Create the input balance
    let signer = args.party0_signer();
    let (mut input_balance, input_balance_opening) =
        fund_ring2_party(&signer, &obligation0, args).await?;

    // Fund the counterparty
    let counterparty_signer = args.party1_signer();
    fund_ring0_party(&counterparty_signer, &obligation1, args).await?;

    // Build the settlement bundles
    let obligation_bundle = ObligationBundle::new_public(
        first_obligation0.clone().into(),
        first_obligation1.clone().into(),
    );
    let (mut state_intent, mut out_balance, settlement_bundle0) =
        private_intent_private_balance::build_settlement_bundle_first_fill(
            &signer,
            &intent0,
            &first_obligation0,
            &mut input_balance,
            &input_balance_opening,
            args,
        )?;
    let settlement_bundle1 = private_intent_private_balance::build_settlement_bundle_ring0(
        &counterparty_signer,
        &intent1,
        &first_obligation1,
        args,
    )?;

    // Settle the match
    let tx = args
        .darkpool
        .settleMatch(obligation_bundle, settlement_bundle0, settlement_bundle1);
    let tx_receipt = wait_for_tx_success(tx).await?;

    // Update the state values to match their post-settlement state committed on-chain
    let fee_take = compute_fee_take(&first_obligation0, args).await?;
    state_intent.apply_settlement_obligation(&first_obligation0);
    input_balance.apply_obligation_in_balance(&first_obligation0);
    out_balance.apply_obligation_out_balance_no_fees(&first_obligation0, &fee_take);

    // Find Merkle openings for each state element
    let intent_opening = find_state_element_opening(&state_intent, &tx_receipt).await?;
    let input_balance_opening = find_state_element_opening(&input_balance, &tx_receipt).await?;
    let output_balance_opening = find_state_element_opening(&out_balance, &tx_receipt).await?;

    Ok(PrivateIntentPrivateBalanceElements {
        intent: state_intent,
        intent_opening,
        input_balance,
        input_balance_opening,
        output_balance: out_balance,
        output_balance_opening,
    })
}
