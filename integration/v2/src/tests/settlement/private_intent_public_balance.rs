//! Tests for settling a natively-settled private intent

use alloy::{
    primitives::{aliases::U48, keccak256, Address, U160, U256},
    signers::local::PrivateKeySigner,
};
use eyre::Result;
use rand::{thread_rng, Rng};
use renegade_abi::v2::{
    auth_helpers::sign_with_nonce,
    IDarkpoolV2::{ObligationBundle, PrivateIntentAuthBundleFirstFill, SettlementBundle},
};
use renegade_circuit_types::{
    intent::{DarkpoolStateIntent, Intent},
    settlement_obligation::SettlementObligation,
    PlonkProof,
};
use renegade_circuits::{
    singleprover_prove_with_hint,
    test_helpers::{random_price, BOUNDED_MAX_AMT},
    zk_circuits::{
        settlement::intent_only_public_settlement::{
            self, IntentOnlyPublicSettlementStatement, SizedIntentOnlyPublicSettlementCircuit,
        },
        validity_proofs::intent_only_first_fill::{
            self, IntentOnlyFirstFillValidityCircuit, IntentOnlyFirstFillValidityStatement,
        },
    },
};
use renegade_constants::{Scalar, MERKLE_HEIGHT};
use renegade_crypto::fields::scalar_to_u256;
use test_helpers::{assert_eq_result, integration_test_async};

use crate::{
    test_args::TestArgs,
    util::{
        fuzzing::create_matching_intents_and_obligations,
        transactions::{send_tx, wait_for_tx_success},
    },
};

/// Tests settling a natively-settled private intent
#[allow(non_snake_case)]
async fn test_settlement__native_settled_private_intent(args: TestArgs) -> Result<()> {
    // Fund the parties, party0 sells the base; party1 sells the quote
    fund_parties(&args).await?;

    // Build the obligations and split them in two for two fills
    let (intent0, intent1, obligation0, obligation1) =
        create_intents_and_obligations(&args).await?;

    // TODO: Add a second fill
    let (first_obligation0, _second_obligation0) = split_obligation(&obligation0);
    let (first_obligation1, _second_obligation1) = split_obligation(&obligation1);

    // --- First Fill --- //
    // On the first fill, settle half of the obligations
    let (comm0, validity_statement0, validity_proof0) =
        generate_first_fill_validity_proof(&intent0)?;
    let (comm1, validity_statement1, validity_proof1) =
        generate_first_fill_validity_proof(&intent1)?;
    let (settlement_statement0, settlement_proof0) =
        generate_settlement_proof(&intent0, &first_obligation0)?;
    let (settlement_statement1, settlement_proof1) =
        generate_settlement_proof(&intent1, &first_obligation1)?;

    // Build the calldata
    let settlement_bundle0 = build_settlement_bundle_first_fill(
        &args.party0_signer(),
        comm0,
        &validity_statement0,
        &validity_proof0,
        &settlement_statement0,
        &settlement_proof0,
    )?;
    let settlement_bundle1 = build_settlement_bundle_first_fill(
        &args.party1_signer(),
        comm1,
        &validity_statement1,
        &validity_proof1,
        &settlement_statement1,
        &settlement_proof1,
    )?;
    let obligation_bundle = build_obligation_bundle(&first_obligation0, &first_obligation1);

    let party0_base_before = args.base_balance(args.party0_addr()).await?;
    let party1_base_before = args.base_balance(args.party1_addr()).await?;
    let tx = args
        .darkpool
        .settleMatch(obligation_bundle, settlement_bundle0, settlement_bundle1);
    wait_for_tx_success(tx).await?;

    let party0_base_after = args.base_balance(args.party0_addr()).await?;
    let party1_base_after = args.base_balance(args.party1_addr()).await?;

    // TODO: Verify balance updates
    println!("\n\n");
    println!("party0 base balance before: {party0_base_before}");
    println!("party0 base balance after: {party0_base_after}");
    println!("party1 balance before: {party1_base_before}");
    println!("party1 balance after: {party1_base_after}");

    Ok(())
}
integration_test_async!(test_settlement__native_settled_private_intent);

// -----------
// | Helpers |
// -----------

/// Split an obligation in two
///
/// Returns the two splits of the obligation
fn split_obligation(
    obligation: &SettlementObligation,
) -> (SettlementObligation, SettlementObligation) {
    let mut obligation0 = obligation.clone();
    let mut obligation1 = obligation.clone();
    obligation0.amount_in /= 2;
    obligation0.amount_out /= 2;
    obligation1.amount_in /= 2;
    obligation1.amount_out /= 2;

    (obligation0, obligation1)
}

// --- Funding --- //

/// Fund the two parties with the base and quote tokens
///
/// Test setup will fund the parties with the tokens and approve the permit2 contract to spend the tokens.
async fn fund_parties(args: &TestArgs) -> Result<()> {
    let base = args.base_addr()?;
    let quote = args.quote_addr()?;
    approve_balance(base, &args.party0_signer(), args).await?;
    approve_balance(quote, &args.party1_signer(), args).await?;
    Ok(())
}

/// Approve a balance to be spent by the darkpool via the permit2 contract
async fn approve_balance(token: Address, signer: &PrivateKeySigner, args: &TestArgs) -> Result<()> {
    let amt = U160::MAX;
    let permit2 = args.permit2_with_signer(signer)?;
    let darkpool = args.darkpool_addr();
    let expiration = U48::MAX;
    send_tx(permit2.approve(token, darkpool, amt, expiration)).await?;

    Ok(())
}

// --- Intents --- //

/// Create two matching intents and obligations
///
/// Party 0 sells the base; party1 sells the quote
async fn create_intents_and_obligations(
    args: &TestArgs,
) -> Result<(Intent, Intent, SettlementObligation, SettlementObligation)> {
    let mut rng = thread_rng();
    let amount_in = rng.gen_range(0..=BOUNDED_MAX_AMT);
    let min_price = random_price();
    let intent0 = Intent {
        in_token: args.base_addr()?,
        out_token: args.quote_addr()?,
        owner: args.party0_addr(),
        min_price,
        amount_in,
    };

    let counterparty = args.party1_addr();
    let (intent1, obligation0, obligation1) =
        create_matching_intents_and_obligations(&intent0, counterparty)?;
    Ok((intent0, intent1, obligation0, obligation1))
}

// --- Prover --- //

/// Generate first fill validity proofs for an intent
///
/// Also return a commitment to the intent
fn generate_first_fill_validity_proof(
    intent: &Intent,
) -> Result<(Scalar, IntentOnlyFirstFillValidityStatement, PlonkProof)> {
    // Build the witness and statement
    let (witness, statement) =
        intent_only_first_fill::test_helpers::create_witness_statement_with_intent(intent);

    // Compute a commitment to the initial intent
    let intent = witness.intent.clone();
    let share_stream_seed = witness.initial_intent_share_stream.seed;
    let recovery_stream_seed = witness.initial_intent_recovery_stream.seed;
    let mut state_intent =
        DarkpoolStateIntent::new(intent, share_stream_seed, recovery_stream_seed);
    state_intent.compute_recovery_id();
    let comm = state_intent.compute_commitment();
    let private_comm = state_intent.compute_private_commitment();
    assert_eq_result!(private_comm, statement.intent_private_commitment)?;

    // Generate the validity proof
    let (proof, _link_hint) = singleprover_prove_with_hint::<IntentOnlyFirstFillValidityCircuit>(
        witness,
        statement.clone(),
    )?;
    Ok((comm, statement, proof))
}

/// Generate a settlement proof for a private intent
fn generate_settlement_proof(
    intent: &Intent,
    obligation: &SettlementObligation,
) -> Result<(IntentOnlyPublicSettlementStatement, PlonkProof)> {
    let (witness, statement) = intent_only_public_settlement::test_helpers::create_witness_statement_with_intent_and_obligation(intent, obligation);
    let (proof, _link_hint) = singleprover_prove_with_hint::<SizedIntentOnlyPublicSettlementCircuit>(
        witness,
        statement.clone(),
    )?;

    Ok((statement, proof))
}

// --- Calldata Bundles --- //

/// Build an obligation bundle for two public obligations
fn build_obligation_bundle(
    obligation0: &SettlementObligation,
    obligation1: &SettlementObligation,
) -> ObligationBundle {
    ObligationBundle::new_public(obligation0.clone().into(), obligation1.clone().into())
}

/// Build a settlement bundle for the first fill
fn build_settlement_bundle_first_fill(
    owner: &PrivateKeySigner,
    commitment: Scalar,
    validity_statement: &IntentOnlyFirstFillValidityStatement,
    validity_proof: &PlonkProof,
    settlement_statement: &IntentOnlyPublicSettlementStatement,
    settlement_proof: &PlonkProof,
) -> Result<SettlementBundle> {
    let auth_bundle =
        build_auth_bundle_first_fill(owner, commitment, validity_statement, validity_proof)?;
    Ok(SettlementBundle::private_intent_public_balance_first_fill(
        auth_bundle.clone(),
        settlement_statement.clone().into(),
        settlement_proof.clone().into(),
    ))
}

/// Build an auth bundle for an intent
fn build_auth_bundle_first_fill(
    owner: &PrivateKeySigner,
    commitment: Scalar,
    validity_statement: &IntentOnlyFirstFillValidityStatement,
    validity_proof: &PlonkProof,
) -> Result<PrivateIntentAuthBundleFirstFill> {
    let comm_u256 = scalar_to_u256(&commitment);
    let comm_hash = keccak256(comm_u256.to_be_bytes_vec());
    let signature = sign_with_nonce(comm_hash.as_slice(), owner)?;

    Ok(PrivateIntentAuthBundleFirstFill {
        intentSignature: signature,
        merkleDepth: U256::from(MERKLE_HEIGHT),
        statement: validity_statement.clone().into(),
        validityProof: validity_proof.clone().into(),
    })
}
