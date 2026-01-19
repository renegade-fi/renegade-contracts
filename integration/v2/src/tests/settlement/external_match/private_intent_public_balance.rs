//! Tests for bounded match results with a natively-settled private intent

use crate::{
    test_args::TestArgs,
    tests::settlement::{
        external_match::{compute_fee_take, setup_external_match},
        private_intent_public_balance::{
            build_auth_bundle_first_fill, build_auth_bundle_subsequent_fill, fund_parties,
            generate_first_fill_validity_proof, generate_linking_proof,
            generate_subsequent_fill_validity_proof,
        },
        settlement_relayer_fee,
    },
    util::transactions::wait_for_tx_success,
};
use alloy::{primitives::U256, signers::local::PrivateKeySigner};
use eyre::Result;
use rand::{Rng, thread_rng};
use renegade_abi::v2::{IDarkpoolV2::SettlementBundle, relayer_types::u256_to_u128};
use renegade_crypto::fields::scalar_to_u256;
use renegade_account_types::MerkleAuthenticationPath;
use renegade_circuit_types::{PlonkProof, ProofLinkingHint};
use renegade_circuits::{
    singleprover_prove_with_hint,
    test_helpers::{BOUNDED_MAX_AMT, create_bounded_match_result_with_balance, random_price},
    zk_circuits::settlement::intent_only_bounded_settlement::{
        self, IntentOnlyBoundedSettlementCircuit, IntentOnlyBoundedSettlementStatement,
    },
};
use renegade_darkpool_types::{
    bounded_match_result::BoundedMatchResult,
    intent::{DarkpoolStateIntent, Intent},
    settlement_obligation::SettlementObligation,
    state_wrapper::StateWrapper,
};
use test_helpers::{assert_eq_result, integration_test_async};

/// Tests settling a natively-settled private intent via external match
#[allow(non_snake_case)]
async fn test_bounded_settlement__native_settled_private_intent(args: TestArgs) -> Result<()> {
    // Setup the external party (tx_submitter) with funding and darkpool approval
    setup_external_match(&args).await?;

    // Fund the parties, party0 (internal party) sells the base; party1 (external party) sells the quote
    fund_parties(&args).await?;

    let (intent, bounded_match_result, _) = create_intent_and_bounded_match_result(&args)?;

    // --- First Fill --- //

    let external_party_amt_in = pick_external_party_amt_in(&bounded_match_result);
    let (internal_obligation, external_obligation) =
        create_obligations(&bounded_match_result, external_party_amt_in);

    // Build settlement bundle
    let chain_id = args.chain_id().await?;
    let (_, settlement_bundle0) = build_settlement_bundle_first_fill(
        chain_id,
        &args.party0_signer(),
        &intent,
        &bounded_match_result,
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
        bounded_match_result.clone().into(),
        settlement_bundle0,
    );
    wait_for_tx_success(tx).await?;

    let internal_party_base_after = args.base_balance(args.party0_addr()).await?;
    let external_party_base_after = args.base_balance(external_party).await?;
    let internal_party_quote_after = args.quote_balance(args.party0_addr()).await?;
    let external_party_quote_after = args.quote_balance(external_party).await?;

    // Verify balance updates
    let (internal_party_fee_take, external_party_fee_take) =
        compute_fee_take(&internal_obligation, &external_obligation, &args).await?;
    let internal_party_total_fee = U256::from(internal_party_fee_take.total());
    let external_party_total_fee = U256::from(external_party_fee_take.total());
    assert_eq_result!(
        internal_party_base_after,
        // Internal party sells base: balance decreases by amount_in
        internal_party_base_before - U256::from(internal_obligation.amount_in)
    )?;
    assert_eq_result!(
        internal_party_quote_after,
        // Internal party receives quote (amount_out) net of fees
        internal_party_quote_before + U256::from(internal_obligation.amount_out)
            - internal_party_total_fee
    )?;
    assert_eq_result!(
        external_party_base_after,
        // External party receives base (amount_out)
        external_party_base_before + U256::from(external_obligation.amount_out)
            - external_party_total_fee
    )?;
    assert_eq_result!(
        external_party_quote_after,
        // External party pays quote (amount_in)
        external_party_quote_before - U256::from(external_obligation.amount_in)
    )?;

    // TODO: Add subsequent fill tests

    Ok(())
}
integration_test_async!(test_bounded_settlement__native_settled_private_intent);

// -----------
// | Helpers |
// -----------

// --- Intents --- //

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

// --- Obligations --- //

/// Pick a random external party amount within the valid bounds
///
/// This is called once upfront to determine the trade size, then passed to
/// `create_obligations` to build the actual obligations.
pub(crate) fn pick_external_party_amt_in(match_result: &BoundedMatchResult) -> U256 {
    let mut rng = thread_rng();
    let price_repr = scalar_to_u256(&match_result.price.repr);
    let min_internal = match_result.min_internal_party_amount_in;
    let max_internal = match_result.max_internal_party_amount_in;

    // Pick internal amount in valid range, derive external via ceil division
    let picked_internal = U256::from(rng.gen_range(min_internal..=max_internal));
    let shift = U256::from(1u128) << 63u32;
    (picked_internal * price_repr + shift - U256::from(1u8)) / shift
}

/// Create obligations for an external match with a specified external amount
pub(crate) fn create_obligations(
    match_result: &BoundedMatchResult,
    external_party_amt_in: U256,
) -> (SettlementObligation, SettlementObligation) {
    let price_repr = scalar_to_u256(&match_result.price.repr);

    // Contract formula: internal_amt_in = (external_amt_in << 63) / price_repr
    let external_party_amt_out = (external_party_amt_in << 63u32) / price_repr;

    let external_obligation = SettlementObligation {
        input_token: match_result.internal_party_output_token,
        output_token: match_result.internal_party_input_token,
        amount_in: u256_to_u128(external_party_amt_in),
        amount_out: u256_to_u128(external_party_amt_out),
    };

    // Internal is mirror of external
    let internal_obligation = SettlementObligation {
        input_token: external_obligation.output_token,
        output_token: external_obligation.input_token,
        amount_in: external_obligation.amount_out,
        amount_out: external_obligation.amount_in,
    };

    (internal_obligation, external_obligation)
}

// --- Prover --- //

/// Generate a settlement proof for a private intent
fn generate_settlement_proof(
    intent: &Intent,
    bounded_match_result: &BoundedMatchResult,
) -> Result<(
    IntentOnlyBoundedSettlementStatement,
    PlonkProof,
    ProofLinkingHint,
)> {
    let (witness, mut statement) = intent_only_bounded_settlement::test_helpers::create_witness_statement_with_intent_and_bounded_match_result(intent, bounded_match_result);
    statement.internal_relayer_fee = settlement_relayer_fee();
    statement.external_relayer_fee = settlement_relayer_fee();
    let (proof, link_hint) =
        singleprover_prove_with_hint::<IntentOnlyBoundedSettlementCircuit>(&witness, &statement)?;

    Ok((statement, proof, link_hint))
}

// --- Calldata Bundles --- //

/// Build a settlement bundle for the first fill
fn build_settlement_bundle_first_fill(
    chain_id: u64,
    owner: &PrivateKeySigner,
    intent: &Intent,
    bounded_match_result: &BoundedMatchResult,
) -> Result<(DarkpoolStateIntent, SettlementBundle)> {
    let (commitment, state_intent, validity_statement, validity_proof, validity_link_hint) =
        generate_first_fill_validity_proof(intent)?;
    let (settlement_statement, settlement_proof, settlement_link_hint) =
        generate_settlement_proof(intent, bounded_match_result)?;
    let linking_proof = generate_linking_proof(&validity_link_hint, &settlement_link_hint)?;

    let auth_bundle = build_auth_bundle_first_fill(
        owner,
        commitment,
        chain_id,
        &validity_statement,
        &validity_proof,
    )?;
    let settlement_bundle = SettlementBundle::private_intent_public_balance_bounded_first_fill(
        auth_bundle,
        settlement_statement.into(),
        settlement_proof.into(),
        linking_proof.into(),
    );
    Ok((state_intent, settlement_bundle))
}

/// Build a settlement bundle for a subsequent fill
fn build_settlement_bundle_subsequent_fill(
    state_intent: &StateWrapper<Intent>,
    merkle_opening: &MerkleAuthenticationPath,
    bounded_match_result: &BoundedMatchResult,
) -> Result<SettlementBundle> {
    let (validity_statement, validity_proof, validity_link_hint) =
        generate_subsequent_fill_validity_proof(state_intent, merkle_opening)?;
    let (settlement_statement, settlement_proof, settlement_link_hint) =
        generate_settlement_proof(&state_intent.inner, bounded_match_result)?;
    let linking_proof = generate_linking_proof(&validity_link_hint, &settlement_link_hint)?;

    let auth_bundle = build_auth_bundle_subsequent_fill(&validity_statement, &validity_proof)?;
    Ok(SettlementBundle::private_intent_public_balance_bounded(
        auth_bundle,
        settlement_statement.into(),
        settlement_proof.into(),
        linking_proof.into(),
    ))
}
