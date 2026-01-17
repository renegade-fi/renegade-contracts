//! Tests for settling a ring 2 (private intent, private balance) user's match against an external party's intent

use crate::{
    test_args::TestArgs,
    tests::settlement::{
        compute_fee_take as compute_fee_take_single,
        external_match::{compute_fee_take, setup_external_match},
        private_intent_private_balance::{
            build_auth_bundle_first_fill, fund_ring2_party,
            generate_existing_output_balance_validity_proof,
            generate_new_output_balance_validity_proof,
            generate_output_balance_settlement_linking_proof, generate_validity_proof_first_fill,
            generate_validity_proof_subsequent_fill, generate_validity_settlement_linking_proof,
        },
        settlement_relayer_fee,
    },
    util::{merkle::find_state_element_opening, transactions::wait_for_tx_success},
};
use alloy::{primitives::U256, rpc::types::TransactionReceipt, signers::local::PrivateKeySigner};
use eyre::Result;
use renegade_abi::v2::IDarkpoolV2::{
    OutputBalanceBundle, RenegadeSettledIntentAuthBundle, SettlementBundle,
};
use renegade_account_types::MerkleAuthenticationPath;
use renegade_circuit_types::{PlonkProof, ProofLinkingHint};
use renegade_circuits::{
    singleprover_prove_with_hint,
    test_helpers::create_bounded_match_result_with_balance,
    zk_circuits::settlement::intent_and_balance_bounded_settlement::{
        IntentAndBalanceBoundedSettlementCircuit, IntentAndBalanceBoundedSettlementStatement,
        IntentAndBalanceBoundedSettlementWitness,
    },
};
use renegade_constants::MERKLE_HEIGHT;
use renegade_darkpool_types::{
    balance::{DarkpoolStateBalance, PostMatchBalanceShare},
    bounded_match_result::BoundedMatchResult,
    intent::{DarkpoolStateIntent, Intent},
    settlement_obligation::SettlementObligation,
};
use test_helpers::{assert_eq_result, integration_test_async};

use super::private_intent_public_balance::{
    build_match_result_bundle, create_intent_and_bounded_match_result, create_obligations,
    pick_external_party_amt_in,
};

/// Test settling a Ring 2 match against an external party's intent
///
/// Party0 owns the ring-2 order and sells the base token
/// External party (tx_submitter) sells the quote token
#[allow(non_snake_case)]
async fn test_bounded_settlement__private_intent_private_balance(args: TestArgs) -> Result<()> {
    // Setup the external party (tx_submitter) with funding and darkpool approval
    setup_external_match(&args).await?;

    let (intent, bounded_match_result, first_fill_balance) =
        create_intent_and_bounded_match_result(&args)?;

    // --- First Fill --- //

    // Build match result bundle
    let bounded_match_result_bundle =
        build_match_result_bundle(&bounded_match_result, &args).await?;
    let external_party_amt_in = pick_external_party_amt_in(&bounded_match_result_bundle);
    let (internal_obligation, external_obligation) =
        create_obligations(&bounded_match_result_bundle, external_party_amt_in);

    // Fund the ring-2 party with the balance amount (guaranteed >= max by construction)
    let funding_obligation = SettlementObligation {
        input_token: internal_obligation.input_token,
        output_token: internal_obligation.output_token,
        amount_in: first_fill_balance,
        amount_out: internal_obligation.amount_out,
    };
    let (mut party0_bal, party0_bal_opening) =
        fund_ring2_party(&args.party0_signer(), &funding_obligation, &args).await?;

    // Build settlement bundle
    let (mut state_intent, mut out_balance, settlement_bundle) =
        build_settlement_bundle_first_fill(
            &args.party0_signer(),
            &intent,
            &bounded_match_result,
            &internal_obligation,
            &mut party0_bal,
            &party0_bal_opening,
            &args,
        )?;

    // Settle the first fill
    let external_party = args.tx_submitter.address();

    let internal_party_base_before = args.base_balance(args.party0_addr()).await?;
    let external_party_base_before = args.base_balance(external_party).await?;
    let internal_party_quote_before = args.quote_balance(args.party0_addr()).await?;
    let external_party_quote_before = args.quote_balance(external_party).await?;

    let tx = args.darkpool.settleExternalMatch(
        external_party_amt_in,
        external_party,
        bounded_match_result_bundle,
        settlement_bundle,
    );
    let tx_receipt = wait_for_tx_success(tx).await?;

    let internal_party_base_after = args.base_balance(args.party0_addr()).await?;
    let external_party_base_after = args.base_balance(external_party).await?;
    let internal_party_quote_after = args.quote_balance(args.party0_addr()).await?;
    let external_party_quote_after = args.quote_balance(external_party).await?;

    // Verify balance updates
    let (_internal_party_fee_take, external_party_fee_take) =
        compute_fee_take(&internal_obligation, &external_obligation, &args).await?;
    let external_party_total_fee = U256::from(external_party_fee_take.total());

    // Internal party balances should not change; they're settled into the darkpool state
    assert_eq_result!(internal_party_base_after, internal_party_base_before)?;
    assert_eq_result!(internal_party_quote_after, internal_party_quote_before)?;

    // External party receives base (amount_out) net of fees
    assert_eq_result!(
        external_party_base_after,
        external_party_base_before + U256::from(external_obligation.amount_out)
            - external_party_total_fee
    )?;
    // External party pays quote (amount_in)
    assert_eq_result!(
        external_party_quote_after,
        external_party_quote_before - U256::from(external_obligation.amount_in)
    )?;

    // --- Subsequent Fill --- //

    // Update the state values to match their post-settlement state committed on-chain
    let fee_take = compute_fee_take_single(&internal_obligation, &args).await?;
    state_intent.apply_settlement_obligation(&internal_obligation);
    party0_bal.apply_obligation_in_balance(&internal_obligation);
    out_balance.apply_obligation_out_balance_no_fees(&internal_obligation, &fee_take);

    // Create bounded match result for remaining amount (use updated state values)
    let remaining_balance = party0_bal.inner.amount;
    let bounded_match_result2 =
        create_bounded_match_result_with_balance(&state_intent.inner, remaining_balance);

    // Build match result bundle for second fill and pick external amount upfront
    let bounded_match_result_bundle2 =
        build_match_result_bundle(&bounded_match_result2, &args).await?;
    let external_party_amt_in2 = pick_external_party_amt_in(&bounded_match_result_bundle2);
    let (internal_obligation2, external_obligation2) =
        create_obligations(&bounded_match_result_bundle2, external_party_amt_in2);

    // Build settlement bundle for subsequent fill
    let settlement_bundle2 = build_settlement_bundle_subsequent_fill(
        &mut state_intent,
        &mut party0_bal,
        &mut out_balance,
        &bounded_match_result2,
        &tx_receipt,
    )
    .await?;

    // Record balances before second fill
    let internal_party_base_before2 = args.base_balance(args.party0_addr()).await?;
    let external_party_base_before2 = args.base_balance(external_party).await?;
    let internal_party_quote_before2 = args.quote_balance(args.party0_addr()).await?;
    let external_party_quote_before2 = args.quote_balance(external_party).await?;

    // Execute second fill
    let tx2 = args.darkpool.settleExternalMatch(
        external_party_amt_in2,
        external_party,
        bounded_match_result_bundle2,
        settlement_bundle2,
    );
    wait_for_tx_success(tx2).await?;

    // Verify balance updates for second fill
    let internal_party_base_after2 = args.base_balance(args.party0_addr()).await?;
    let external_party_base_after2 = args.base_balance(external_party).await?;
    let internal_party_quote_after2 = args.quote_balance(args.party0_addr()).await?;
    let external_party_quote_after2 = args.quote_balance(external_party).await?;

    let (_, external_party_fee_take2) =
        compute_fee_take(&internal_obligation2, &external_obligation2, &args).await?;
    let external_party_total_fee2 = U256::from(external_party_fee_take2.total());

    // Internal party balances should not change; they're settled into the darkpool state
    assert_eq_result!(internal_party_base_after2, internal_party_base_before2)?;
    assert_eq_result!(internal_party_quote_after2, internal_party_quote_before2)?;

    // External party receives base (amount_out) net of fees
    assert_eq_result!(
        external_party_base_after2,
        external_party_base_before2 + U256::from(external_obligation2.amount_out)
            - external_party_total_fee2
    )?;
    // External party pays quote (amount_in)
    assert_eq_result!(
        external_party_quote_after2,
        external_party_quote_before2 - U256::from(external_obligation2.amount_in)
    )?;

    Ok(())
}
integration_test_async!(test_bounded_settlement__private_intent_private_balance);

// -----------
// | Helpers |
// -----------

// --- Settlement Proof --- //

/// Generate a bounded settlement proof for intent and balance
fn generate_settlement_proof(
    intent: &DarkpoolStateIntent,
    input_balance: &DarkpoolStateBalance,
    output_balance: &DarkpoolStateBalance,
    bounded_match_result: &BoundedMatchResult,
) -> Result<(
    IntentAndBalanceBoundedSettlementStatement,
    PlonkProof,
    ProofLinkingHint,
)> {
    let pre_settlement_amount_public_share = intent.public_share.amount_in;
    let pre_settlement_in_balance_shares =
        PostMatchBalanceShare::from(input_balance.public_share.clone());
    let pre_settlement_out_balance_shares =
        PostMatchBalanceShare::from(output_balance.public_share.clone());

    let witness = IntentAndBalanceBoundedSettlementWitness {
        intent: intent.inner.clone(),
        pre_settlement_amount_public_share,
        in_balance: input_balance.inner.clone(),
        pre_settlement_in_balance_shares: pre_settlement_in_balance_shares.clone(),
        out_balance: output_balance.inner.clone(),
        pre_settlement_out_balance_shares: pre_settlement_out_balance_shares.clone(),
    };

    let statement = IntentAndBalanceBoundedSettlementStatement {
        bounded_match_result: bounded_match_result.clone(),
        amount_public_share: pre_settlement_amount_public_share,
        in_balance_public_shares: pre_settlement_in_balance_shares,
        out_balance_public_shares: pre_settlement_out_balance_shares,
        internal_relayer_fee: settlement_relayer_fee(),
        external_relayer_fee: settlement_relayer_fee(),
        relayer_fee_recipient: output_balance.inner.relayer_fee_recipient,
    };

    // Prove the relation
    let (proof, hint) = singleprover_prove_with_hint::<IntentAndBalanceBoundedSettlementCircuit>(
        &witness, &statement,
    )?;
    Ok((statement, proof, hint))
}

// --- Calldata Bundles --- //

/// Build a settlement bundle for the first fill
fn build_settlement_bundle_first_fill(
    signer: &PrivateKeySigner,
    intent: &Intent,
    bounded_match_result: &BoundedMatchResult,
    obligation: &SettlementObligation,
    in_balance: &mut DarkpoolStateBalance,
    balance_opening: &MerkleAuthenticationPath,
    args: &TestArgs,
) -> Result<(DarkpoolStateIntent, DarkpoolStateBalance, SettlementBundle)> {
    // Generate the validity proofs
    let in_bal_clone = in_balance.clone();
    let (state_intent, validity_statement, validity_proof, validity_hint) =
        generate_validity_proof_first_fill(intent, in_balance, balance_opening, args)?;
    let (out_balance, new_output_statement, new_output_proof, new_output_hint) =
        generate_new_output_balance_validity_proof(
            signer.address(),
            &in_bal_clone,
            balance_opening,
            obligation,
            args,
        )?;

    // Generate the bounded settlement proof
    let (settlement_statement, settlement_proof, settlement_hint) = generate_settlement_proof(
        &state_intent,
        in_balance,
        &out_balance,
        bounded_match_result,
    )?;

    // Build the auth bundles
    let auth_bundle = build_auth_bundle_first_fill(&validity_statement, &validity_proof)?;
    let validity_link_proof =
        generate_validity_settlement_linking_proof(&validity_hint, &settlement_hint)?;

    let output_balance_link_proof =
        generate_output_balance_settlement_linking_proof(&new_output_hint, &settlement_hint)?;
    let new_output_auth_bundle = OutputBalanceBundle::new_output_balance(
        U256::from(MERKLE_HEIGHT),
        new_output_statement.into(),
        new_output_proof.into(),
        output_balance_link_proof.into(),
    );

    let bundle = SettlementBundle::renegade_settled_private_intent_bounded_first_fill(
        auth_bundle,
        new_output_auth_bundle,
        settlement_statement.into(),
        settlement_proof.into(),
        validity_link_proof.into(),
    );

    Ok((state_intent, out_balance, bundle))
}

/// Build a settlement bundle for the subsequent fill
async fn build_settlement_bundle_subsequent_fill(
    state_intent: &mut DarkpoolStateIntent,
    in_balance: &mut DarkpoolStateBalance,
    out_balance: &mut DarkpoolStateBalance,
    bounded_match_result: &BoundedMatchResult,
    first_fill_receipt: &TransactionReceipt,
) -> Result<SettlementBundle> {
    let intent_opening = find_state_element_opening(state_intent, first_fill_receipt).await?;
    let in_balance_opening = find_state_element_opening(in_balance, first_fill_receipt).await?;
    let out_balance_opening = find_state_element_opening(out_balance, first_fill_receipt).await?;

    let (validity_statement, validity_proof, validity_hint) =
        generate_validity_proof_subsequent_fill(
            state_intent,
            in_balance,
            &intent_opening,
            &in_balance_opening,
        )?;
    let (output_balance_statement, output_balance_proof, output_balance_hint) =
        generate_existing_output_balance_validity_proof(out_balance, &out_balance_opening)?;

    let (settlement_statement, settlement_proof, settlement_hint) =
        generate_settlement_proof(state_intent, in_balance, out_balance, bounded_match_result)?;

    let auth_bundle = RenegadeSettledIntentAuthBundle {
        merkleDepth: U256::from(MERKLE_HEIGHT),
        statement: validity_statement.into(),
        validityProof: validity_proof.into(),
    };

    let validity_link_proof =
        generate_validity_settlement_linking_proof(&validity_hint, &settlement_hint)?;
    let output_balance_link_proof =
        generate_output_balance_settlement_linking_proof(&output_balance_hint, &settlement_hint)?;

    let existing_output_auth_bundle = OutputBalanceBundle::existing_output_balance(
        U256::from(MERKLE_HEIGHT),
        output_balance_statement.into(),
        output_balance_proof.into(),
        output_balance_link_proof.into(),
    );

    Ok(SettlementBundle::renegade_settled_private_intent_bounded(
        auth_bundle,
        existing_output_auth_bundle,
        settlement_statement.into(),
        settlement_proof.into(),
        validity_link_proof.into(),
    ))
}
