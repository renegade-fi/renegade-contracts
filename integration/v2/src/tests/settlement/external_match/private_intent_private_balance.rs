//! Tests for settling a ring 2 (private intent, private balance) user's match against an external party's intent

use crate::{
    test_args::TestArgs,
    tests::settlement::{
        external_match::{compute_fee_take, setup_external_match},
        private_intent_private_balance::{
            build_auth_bundle_first_fill, fund_ring2_party,
            generate_new_output_balance_validity_proof,
            generate_output_balance_settlement_linking_proof, generate_validity_proof_first_fill,
            generate_validity_settlement_linking_proof,
        },
        settlement_relayer_fee,
    },
    util::transactions::wait_for_tx_success,
};
use alloy::{primitives::U256, signers::local::PrivateKeySigner};
use eyre::Result;
use renegade_abi::v2::IDarkpoolV2::{OutputBalanceBundle, SettlementBundle};
use renegade_circuit_types::{PlonkProof, ProofLinkingHint};
use renegade_circuits::{
    singleprover_prove_with_hint,
    zk_circuits::settlement::intent_and_balance_bounded_settlement::{
        IntentAndBalanceBoundedSettlementCircuit, IntentAndBalanceBoundedSettlementStatement,
        IntentAndBalanceBoundedSettlementWitness,
    },
};
use renegade_common::types::merkle::MerkleAuthenticationPath;
use renegade_constants::MERKLE_HEIGHT;
use renegade_darkpool_types::{
    balance::{DarkpoolStateBalance, PostMatchBalanceShare},
    bounded_match_result::BoundedMatchResult,
    intent::{DarkpoolStateIntent, Intent},
    settlement_obligation::SettlementObligation,
};
use test_helpers::{assert_eq_result, integration_test_async};

use rand::{Rng, thread_rng};
use renegade_circuits::test_helpers::BOUNDED_MAX_AMT;

use super::private_intent_public_balance::{
    build_match_result_bundle, create_intent_and_bounded_match_result, create_obligations,
};

/// Test settling a Ring 2 match against an external party's intent
///
/// Party0 owns the ring-2 order and sells the base token
/// External party (tx_submitter) sells the quote token
#[allow(non_snake_case)]
async fn test_bounded_settlement__private_intent_private_balance(args: TestArgs) -> Result<()> {
    // Setup the external party (tx_submitter) with funding and darkpool approval
    setup_external_match(&args).await?;

    // Pick a random balance amount for the internal party
    let mut rng = thread_rng();
    let balance_amount = rng.gen_range(1..=BOUNDED_MAX_AMT);

    // Build the intent and bounded match result constrained by balance amount
    // This ensures max_internal_party_amount_in <= balance_amount
    let (intent, bounded_match_result) =
        create_intent_and_bounded_match_result(&args, balance_amount)?;

    // Build match result bundle
    let bounded_match_result_bundle = build_match_result_bundle(&bounded_match_result, &args)?;

    // Build obligations (pick a random external amount within bounds)
    let (external_party_amt_in, internal_obligation, external_obligation) =
        create_obligations(&bounded_match_result_bundle);

    // Fund the ring-2 party with the balance amount (guaranteed >= max by construction)
    let funding_obligation = SettlementObligation {
        input_token: internal_obligation.input_token,
        output_token: internal_obligation.output_token,
        amount_in: balance_amount,
        amount_out: internal_obligation.amount_out,
    };
    let (mut party0_bal, party0_bal_opening) =
        fund_ring2_party(&args.party0_signer(), &funding_obligation, &args).await?;

    // Build settlement bundle
    let settlement_bundle = build_settlement_bundle_first_fill(
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
        external_party, // recipient
        bounded_match_result_bundle,
        settlement_bundle,
    );
    let _tx_receipt = wait_for_tx_success(tx).await?;

    let internal_party_base_after = args.base_balance(args.party0_addr()).await?;
    let external_party_base_after = args.base_balance(external_party).await?;
    let internal_party_quote_after = args.quote_balance(args.party0_addr()).await?;
    let external_party_quote_after = args.quote_balance(external_party).await?;

    // Verify balance updates
    let (internal_party_fee_take, external_party_fee_take) =
        compute_fee_take(&internal_obligation, &external_obligation, &args).await?;
    let _internal_party_total_fee = U256::from(internal_party_fee_take.total());
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
) -> Result<SettlementBundle> {
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

    Ok(bundle)
}
