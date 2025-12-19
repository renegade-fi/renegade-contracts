//! Tests for settling a Renegade settled private fill

use alloy::primitives::U256;
use eyre::Result;
use renegade_abi::v2::IDarkpoolV2::{ObligationBundle, OutputBalanceBundle, SettlementBundle};
use renegade_circuit_types::{
    PlonkProof, ProofLinkingHint,
    balance::{DarkpoolStateBalance, PostMatchBalanceShare},
    intent::{DarkpoolStateIntent, Intent},
    settlement_obligation::SettlementObligation,
};
use renegade_circuits::{
    singleprover_prove_with_hint,
    zk_circuits::{
        proof_linking::{
            intent_and_balance::link_sized_intent_and_balance_settlement_with_party,
            output_balance::link_sized_output_balance_settlement_with_party,
        },
        settlement::intent_and_balance_private_settlement::{
            IntentAndBalancePrivateSettlementCircuit, IntentAndBalancePrivateSettlementStatement,
            IntentAndBalancePrivateSettlementWitness,
        },
        validity_proofs::{
            intent_and_balance_first_fill::IntentAndBalanceFirstFillValidityStatement,
            new_output_balance::NewOutputBalanceValidityStatement,
        },
    },
};
use renegade_common::types::merkle::MerkleAuthenticationPath;
use renegade_constants::MERKLE_HEIGHT;
use test_helpers::{assert_eq_result, integration_test_async};

use crate::{
    test_args::TestArgs,
    tests::settlement::{
        compute_fee_take,
        private_intent_private_balance::{self, create_intents_and_obligations, fund_ring2_party},
        settlement_relayer_fee, split_obligation,
    },
    util::transactions::wait_for_tx_success,
};

/// Tests settling a Renegade settled private fill
#[allow(non_snake_case)]
pub async fn test_settlement__private_fill(args: TestArgs) -> Result<()> {
    // Build the intents and obligations
    let (intent0, intent1, obligation0, obligation1) = create_intents_and_obligations(&args)?;

    // Fund both parties
    let (mut input_bal0, input_bal0_opening) =
        fund_ring2_party(&args.party0_signer(), &obligation0, &args).await?;
    let (mut input_bal1, input_bal1_opening) =
        fund_ring2_party(&args.party1_signer(), &obligation1, &args).await?;

    // Split the obligations in two for two fills
    let (first_obligation0, second_obligation0) = split_obligation(&obligation0);
    let (first_obligation1, second_obligation1) = split_obligation(&obligation1);

    // --- First Fill --- //

    // Build the settlement bundles
    let (settlement_bundle0, settlement_bundle1, obligation_bundle) = build_first_fill_bundles(
        &intent0,
        &intent1,
        &first_obligation0,
        &first_obligation1,
        &mut input_bal0,
        &mut input_bal1,
        &input_bal0_opening,
        &input_bal1_opening,
        &args,
    )
    .await?;

    // Submit the match
    let (party0_base_before, party0_quote_before) =
        args.base_and_quote_balances(args.party0_addr()).await?;
    let (party1_base_before, party1_quote_before) =
        args.base_and_quote_balances(args.party1_addr()).await?;

    let tx = args
        .darkpool
        .settleMatch(obligation_bundle, settlement_bundle0, settlement_bundle1);
    let _tx_receipt = wait_for_tx_success(tx).await?;

    let (party0_base_after, party0_quote_after) =
        args.base_and_quote_balances(args.party0_addr()).await?;
    let (party1_base_after, party1_quote_after) =
        args.base_and_quote_balances(args.party1_addr()).await?;

    // No balances should change for either party; the trade is settled entirely in darkpool state
    assert_eq_result!(party0_base_after, party0_base_before)?;
    assert_eq_result!(party0_quote_after, party0_quote_before)?;
    assert_eq_result!(party1_base_after, party1_base_before)?;
    assert_eq_result!(party1_quote_after, party1_quote_before)?;

    // TODO: Subsequent fills
    Ok(())
}
integration_test_async!(test_settlement__private_fill);

// ----------------------
// | Settlement Bundles |
// ----------------------

/// Build a settlement bundle for the first fill
#[allow(clippy::too_many_arguments)]
pub async fn build_first_fill_bundles(
    intent0: &Intent,
    intent1: &Intent,
    obligation0: &SettlementObligation,
    obligation1: &SettlementObligation,
    input_bal0: &mut DarkpoolStateBalance,
    input_bal1: &mut DarkpoolStateBalance,
    input_bal0_opening: &MerkleAuthenticationPath,
    input_bal1_opening: &MerkleAuthenticationPath,
    args: &TestArgs,
) -> Result<(SettlementBundle, SettlementBundle, ObligationBundle)> {
    // Party 0 validity proofs
    let (mut state_intent0, validity_statement0, validity_proof0, validity_hint0) =
        private_intent_private_balance::generate_validity_proof_first_fill(
            intent0,
            input_bal0,
            input_bal0_opening,
        )?;
    let (mut output_balance0, new_output_statement0, new_output_proof0, new_output_hint0) =
        private_intent_private_balance::generate_new_output_balance_validity_proof(
            args.party0_addr(),
            obligation0,
            args,
        )?;

    // Party 1 validity proofs
    let (mut state_intent1, validity_statement1, validity_proof1, validity_hint1) =
        private_intent_private_balance::generate_validity_proof_first_fill(
            intent1,
            input_bal1,
            input_bal1_opening,
        )?;
    let (mut output_balance1, new_output_statement1, new_output_proof1, new_output_hint1) =
        private_intent_private_balance::generate_new_output_balance_validity_proof(
            args.party1_addr(),
            obligation1,
            args,
        )?;

    // Create settlement proofs
    let (settlement_statement, settlement_proof, settlement_hint) = generate_settlement_proof(
        obligation0,
        obligation1,
        &mut state_intent0,
        &mut state_intent1,
        input_bal0,
        input_bal1,
        &mut output_balance0,
        &mut output_balance1,
        args,
    )
    .await?;

    // Generate the settlement bundles
    let obligation_bundle = ObligationBundle::new_private(
        settlement_statement.clone().into(),
        settlement_proof.clone().into(),
    );

    let bundle0 = build_private_settlement_bundle_first_fill(
        0, /* party_id */
        validity_statement0,
        validity_proof0,
        &validity_hint0,
        new_output_statement0,
        new_output_proof0,
        &new_output_hint0,
        &settlement_hint,
        args,
    )?;
    let bundle1 = build_private_settlement_bundle_first_fill(
        1, /* party_id */
        validity_statement1,
        validity_proof1.clone(),
        &validity_hint1,
        new_output_statement1,
        new_output_proof1.clone(),
        &new_output_hint1,
        &settlement_hint,
        args,
    )?;

    Ok((bundle0, bundle1, obligation_bundle))
}

/// Build a private settlement bundle for a party
#[allow(clippy::too_many_arguments)]
fn build_private_settlement_bundle_first_fill(
    party_id: u8,
    validity_statement: IntentAndBalanceFirstFillValidityStatement,
    validity_proof: PlonkProof,
    validity_hint: &ProofLinkingHint,
    output_validity_statement: NewOutputBalanceValidityStatement,
    output_validity_proof: PlonkProof,
    output_validity_hint: &ProofLinkingHint,
    settlement_hint: &ProofLinkingHint,
    args: &TestArgs,
) -> Result<SettlementBundle> {
    // Link the validity and settlement proofs
    let validity_link_proof = link_sized_intent_and_balance_settlement_with_party(
        party_id,
        validity_hint,
        settlement_hint,
    )?;
    let output_validity_link_proof = link_sized_output_balance_settlement_with_party(
        party_id,
        output_validity_hint,
        settlement_hint,
    )?;

    // Build the output balance bundle
    let output_balance_bundle = OutputBalanceBundle::new_output_balance(
        U256::from(MERKLE_HEIGHT),
        output_validity_statement.into(),
        output_validity_proof.into(),
        output_validity_link_proof.into(),
    );

    // Build a validity auth bundle
    let signer = if party_id == 0 {
        args.party0_signer()
    } else {
        args.party1_signer()
    };

    let auth_bundle = private_intent_private_balance::build_auth_bundle_first_fill(
        &signer,
        validity_statement.intent_and_authorizing_address_commitment,
        &validity_statement,
        &validity_proof,
    )?;

    // Build the settlement bundle
    Ok(SettlementBundle::renegade_settled_private_first_fill(
        auth_bundle,
        output_balance_bundle,
        validity_link_proof.into(),
    ))
}

// ----------
// | Proofs |
// ----------

/// Generate a private settlement proof
///
/// Mutates all state elements to reflect their post-settlement states
#[allow(clippy::too_many_arguments)]
async fn generate_settlement_proof(
    obligation0: &SettlementObligation,
    obligation1: &SettlementObligation,
    intent0: &mut DarkpoolStateIntent,
    intent1: &mut DarkpoolStateIntent,
    input_balance0: &mut DarkpoolStateBalance,
    input_balance1: &mut DarkpoolStateBalance,
    output_balance0: &mut DarkpoolStateBalance,
    output_balance1: &mut DarkpoolStateBalance,
    args: &TestArgs,
) -> Result<(
    IntentAndBalancePrivateSettlementStatement,
    PlonkProof,
    ProofLinkingHint,
)> {
    let pre_settlement_amount_public_share0 = intent0.public_share.amount_in;
    let pre_settlement_amount_public_share1 = intent1.public_share.amount_in;
    let pre_settlement_in_balance_shares0 =
        PostMatchBalanceShare::from(input_balance0.public_share.clone());
    let pre_settlement_in_balance_shares1 =
        PostMatchBalanceShare::from(input_balance1.public_share.clone());
    let pre_settlement_out_balance_shares0 =
        PostMatchBalanceShare::from(output_balance0.public_share.clone());
    let pre_settlement_out_balance_shares1 =
        PostMatchBalanceShare::from(output_balance1.public_share.clone());

    let witness = IntentAndBalancePrivateSettlementWitness {
        settlement_obligation0: obligation0.clone(),
        intent0: intent0.inner.clone(),
        pre_settlement_amount_public_share0,
        input_balance0: input_balance0.inner.clone(),
        pre_settlement_in_balance_shares0,
        output_balance0: output_balance0.inner.clone(),
        pre_settlement_out_balance_shares0,
        settlement_obligation1: obligation1.clone(),
        intent1: intent1.inner.clone(),
        pre_settlement_amount_public_share1,
        input_balance1: input_balance1.inner.clone(),
        pre_settlement_in_balance_shares1,
        output_balance1: output_balance1.inner.clone(),
        pre_settlement_out_balance_shares1,
    };

    // Update the state elements to reflect the settlement
    intent0.apply_settlement_obligation(obligation0);
    intent1.apply_settlement_obligation(obligation1);
    input_balance0.apply_obligation_in_balance(obligation0);
    input_balance1.apply_obligation_in_balance(obligation1);
    let fee_take0 = compute_fee_take(obligation0, args).await?;
    let fee_take1 = compute_fee_take(obligation1, args).await?;
    output_balance0.apply_obligation_out_balance(obligation0, &fee_take0);
    output_balance1.apply_obligation_out_balance(obligation1, &fee_take1);

    let relayer_fee = settlement_relayer_fee();
    let protocol_fee = args.protocol_fee().await?;
    let statement = IntentAndBalancePrivateSettlementStatement {
        new_amount_public_share0: intent0.public_share.amount_in,
        new_in_balance_public_shares0: PostMatchBalanceShare::from(
            input_balance0.public_share.clone(),
        ),
        new_out_balance_public_shares0: PostMatchBalanceShare::from(
            output_balance0.public_share.clone(),
        ),
        new_amount_public_share1: intent1.public_share.amount_in,
        new_in_balance_public_shares1: PostMatchBalanceShare::from(
            input_balance1.public_share.clone(),
        ),
        new_out_balance_public_shares1: PostMatchBalanceShare::from(
            output_balance1.public_share.clone(),
        ),
        relayer_fee0: relayer_fee,
        relayer_fee1: relayer_fee,
        protocol_fee,
    };

    // Prove the relation
    let (proof, hint) = singleprover_prove_with_hint::<IntentAndBalancePrivateSettlementCircuit>(
        &witness, &statement,
    )?;

    Ok((statement, proof, hint))
}
