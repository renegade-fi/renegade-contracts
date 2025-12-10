//! Settle a ring 2 (private intent, private balance) user's match against another use
//!
//! For simplicity, we use a ring-0 order for the counterparty.

use alloy::{
    primitives::{Address, U256},
    signers::local::PrivateKeySigner,
};
use eyre::Result;
use rand::{Rng, thread_rng};
use renegade_abi::v2::{
    IDarkpoolV2::{
        self, Deposit, ObligationBundle, OutputBalanceBundle, PublicIntentAuthBundle,
        PublicIntentPermit, RenegadeSettledIntentAuthBundleFirstFill, SettlementBundle,
    },
    auth_helpers::sign_with_nonce,
    relayer_types::scalar_to_contract_scalar,
};
use renegade_circuit_types::{
    PlonkLinkProof, PlonkProof, ProofLinkingHint,
    balance::{Balance, DarkpoolStateBalance, PostMatchBalance, PostMatchBalanceShare},
    intent::{DarkpoolStateIntent, Intent, PreMatchIntentShare},
    settlement_obligation::SettlementObligation,
    state_wrapper::StateWrapper,
    traits::BaseType,
};
use renegade_circuits::{
    singleprover_prove_with_hint,
    test_helpers::{BOUNDED_MAX_AMT, random_price},
    zk_circuits::{
        proof_linking::{
            intent_and_balance::link_sized_intent_and_balance_settlement,
            output_balance::link_sized_output_balance_settlement,
        },
        settlement::intent_and_balance_public_settlement::{
            IntentAndBalancePublicSettlementCircuit, IntentAndBalancePublicSettlementStatement,
            IntentAndBalancePublicSettlementWitness,
        },
        validity_proofs::{
            intent_and_balance_first_fill::{
                BALANCE_PARTIAL_COMMITMENT_SIZE, IntentAndBalanceFirstFillValidityStatement,
                IntentAndBalanceFirstFillValidityWitness,
                SizedIntentAndBalanceFirstFillValidityCircuit,
            },
            new_output_balance::{
                NewOutputBalanceValidityCircuit, NewOutputBalanceValidityStatement,
                test_helpers::create_witness_statement_with_balance as create_new_output_balance_witness_statement,
            },
        },
    },
};
use renegade_common::types::merkle::MerkleAuthenticationPath;
use renegade_constants::{MERKLE_HEIGHT, Scalar};
use renegade_crypto::{
    fields::{address_to_scalar, scalar_to_u256},
    hash::compute_poseidon_hash,
};
use test_helpers::integration_test_async;

use crate::{
    test_args::TestArgs,
    tests::{
        create_balance::create_balance,
        settlement::{settlement_relayer_fee, settlement_relayer_fee_rate, split_obligation},
    },
    util::{
        deposit::fund_for_deposit, fuzzing::create_matching_intents_and_obligations,
        merkle::find_state_element_opening, transactions::wait_for_tx_success,
    },
};

/// Test settling a Ring 2 match
///
/// Party0 owns the ring-2 order and sells the base token
#[allow(non_snake_case)]
async fn test_settlement__private_intent_private_balance(args: TestArgs) -> Result<()> {
    // Build the intents and obligations
    let (intent0, intent1, obligation0, obligation1) = create_intents_and_obligations(&args)?;

    // Fund both parties
    let (mut party0_bal, party0_bal_opening) =
        fund_party0(&args.party0_signer(), &obligation0, &args).await?;
    fund_party1(&args.party1_signer(), &obligation1, &args).await?;

    // Split the obligations in two for two fills
    let (first_obligation0, second_obligation0) = split_obligation(&obligation0);
    let (first_obligation1, second_obligation1) = split_obligation(&obligation1);

    // --- First Fill --- //

    // On the first fill, settle half of the obligations
    let obligation_bundle = ObligationBundle::new_public(
        first_obligation0.clone().into(),
        first_obligation1.clone().into(),
    );
    let (mut state_intent0, mut state_balance0, settlement_bundle0) =
        build_settlement_bundle_first_fill(
            &args.party0_signer(),
            &intent0,
            &first_obligation0,
            &mut party0_bal,
            &party0_bal_opening,
            &args,
        )?;
    let settlement_bundle1 =
        build_settlement_bundle_ring0(&args.party1_signer(), &intent1, &first_obligation1, &args)?;

    // TODO: Check balance updates
    let tx = args
        .darkpool
        .settleMatch(obligation_bundle, settlement_bundle0, settlement_bundle1);
    let tx_receipt = wait_for_tx_success(tx).await?;
    println!("tx success: {:#x}", tx_receipt.transaction_hash);

    Ok(())
}
integration_test_async!(test_settlement__private_intent_private_balance);

// -----------
// | Helpers |
// -----------

// --- Match Setup --- //

/// Create intents and obligations for the match
pub fn create_intents_and_obligations(
    args: &TestArgs,
) -> Result<(Intent, Intent, SettlementObligation, SettlementObligation)> {
    let mut rng = thread_rng();
    let amount_in = rng.gen_range(0..=BOUNDED_MAX_AMT);
    let party0_intent = Intent {
        in_token: args.base_addr()?,
        out_token: args.quote_addr()?,
        owner: args.party0_addr(),
        min_price: random_price(),
        amount_in,
    };

    let (counterparty_intent, obligation0, obligation1) =
        create_matching_intents_and_obligations(&party0_intent, args.party1_addr())?;
    Ok((party0_intent, counterparty_intent, obligation0, obligation1))
}

// --- Funding --- //

/// Fund the ring-2 party with a deposit
pub async fn fund_party0(
    signer: &PrivateKeySigner,
    obligation: &SettlementObligation,
    args: &TestArgs,
) -> Result<(DarkpoolStateBalance, MerkleAuthenticationPath)> {
    let deposit = Deposit {
        from: signer.address(),
        token: obligation.input_token,
        amount: U256::from(obligation.amount_in),
    };

    fund_for_deposit(obligation.input_token, signer, &deposit, args).await?;
    let (receipt, bal) = create_balance(args, &deposit).await?;
    let opening = find_state_element_opening(&bal, &receipt).await?;
    Ok((bal, opening))
}

/// Fund the ring-0 party
pub async fn fund_party1(
    signer: &PrivateKeySigner,
    obligation: &SettlementObligation,
    args: &TestArgs,
) -> Result<()> {
    // Mint the obligation amount to the given party
    let token = obligation.input_token;
    let amount = U256::from(obligation.amount_in);
    let erc20 = args.erc20_from_addr_with_signer(token, signer.clone())?;
    let mint_tx = erc20.mint(signer.address(), amount);
    wait_for_tx_success(mint_tx).await?;

    // Approve the darkpool to spend the tokens
    args.permit2_approve_darkpool(token, signer).await
}

// --- Settlement Bundles --- //

/// Build a ring 0 settlement bundle
pub fn build_settlement_bundle_ring0(
    signer: &PrivateKeySigner,
    intent: &Intent,
    obligation: &SettlementObligation,
    args: &TestArgs,
) -> Result<SettlementBundle> {
    let permit = PublicIntentPermit {
        intent: intent.clone().into(),
        executor: args.relayer_signer_addr(),
    };

    // Sign the intent with the owner's key
    let intent_signature = permit.sign(signer)?;
    let contracts_obligation = IDarkpoolV2::SettlementObligation::from(obligation.clone());
    let relayer_fee = settlement_relayer_fee_rate(args);
    let executor_signer = &args.relayer_signer;
    let executor_signature =
        contracts_obligation.create_executor_signature(&relayer_fee, executor_signer)?;
    let auth_bundle = PublicIntentAuthBundle {
        permit,
        intentSignature: intent_signature,
        executorSignature: executor_signature,
    };

    Ok(SettlementBundle::public_intent_settlement(
        auth_bundle,
        relayer_fee,
    ))
}

/// Build a settlement bundle for the first fill
///
/// Returns the new intent, new output balance, and settlement bundle
pub fn build_settlement_bundle_first_fill(
    signer: &PrivateKeySigner,
    intent: &Intent,
    obligation: &SettlementObligation,
    in_balance: &mut DarkpoolStateBalance,
    balance_opening: &MerkleAuthenticationPath,
    args: &TestArgs,
) -> Result<(DarkpoolStateIntent, DarkpoolStateBalance, SettlementBundle)> {
    // Generate the validity proofs
    let (state_intent, validity_statement, validity_proof, validity_hint) =
        generate_validity_proof_first_fill(intent, in_balance, balance_opening)?;
    let (out_balance, new_output_statement, new_output_proof, new_output_hint) =
        generate_new_output_balance_validity_proof(signer.address(), obligation, args)?;

    // Generate the settlement proof
    let (settlement_statement, settlement_proof, settlement_hint) =
        generate_settlement_proof(&state_intent, in_balance, &out_balance, obligation)?;

    // Build the auth bundles
    let commitment = validity_statement.intent_and_authorizing_address_commitment;
    let auth_bundle =
        build_auth_bundle_first_fill(signer, commitment, &validity_statement, &validity_proof)?;
    let validity_link_proof =
        generate_validity_settlement_linking_proof(&validity_hint, &settlement_hint)?;

    let output_balance_link_proof =
        generate_output_balance_settlement_linking_proof(&new_output_hint, &settlement_hint)?;
    let new_output_auth_bundle = build_new_output_balance_auth_bundle(
        new_output_statement,
        new_output_proof,
        output_balance_link_proof,
    )?;

    let bundle = SettlementBundle::renegade_settled_private_intent_first_fill(
        auth_bundle,
        new_output_auth_bundle,
        settlement_statement.into(),
        settlement_proof.into(),
        validity_link_proof.into(),
    );

    Ok((state_intent, out_balance, bundle))
}

/// Build an auth bundle for the first fill
fn build_auth_bundle_first_fill(
    owner: &PrivateKeySigner,
    commitment: Scalar,
    validity_statement: &IntentAndBalanceFirstFillValidityStatement,
    validity_proof: &PlonkProof,
) -> Result<RenegadeSettledIntentAuthBundleFirstFill> {
    let comm_bytes = scalar_to_u256(&commitment).to_be_bytes_vec();
    let signature = sign_with_nonce(comm_bytes.as_slice(), owner)?;

    Ok(RenegadeSettledIntentAuthBundleFirstFill {
        merkleDepth: U256::from(MERKLE_HEIGHT),
        ownerSignature: signature,
        statement: validity_statement.clone().into(),
        validityProof: validity_proof.clone().into(),
    })
}

/// Build a new output balance auth bundle
fn build_new_output_balance_auth_bundle(
    output_balance_statement: NewOutputBalanceValidityStatement,
    output_balance_proof: PlonkProof,
    linking_proof: PlonkLinkProof,
) -> Result<OutputBalanceBundle> {
    let bundle = OutputBalanceBundle::new_output_balance(
        U256::from(MERKLE_HEIGHT),
        output_balance_statement.into(),
        output_balance_proof.into(),
        linking_proof.into(),
    );

    Ok(bundle)
}

// --- Proofs --- //

/// Generate a validity proof for the ring 2 party on the first fill
fn generate_validity_proof_first_fill(
    intent: &Intent,
    bal: &mut DarkpoolStateBalance,
    balance_opening: &MerkleAuthenticationPath,
) -> Result<(
    DarkpoolStateIntent,
    IntentAndBalanceFirstFillValidityStatement,
    PlonkProof,
    ProofLinkingHint,
)> {
    let mut rng = thread_rng();

    // Generate the witness and statement
    let old_balance = bal.clone();
    let share_stream_seed = Scalar::random(&mut rng);
    let recovery_stream_seed = Scalar::random(&mut rng);
    let initial_intent = StateWrapper::new(intent.clone(), share_stream_seed, recovery_stream_seed);
    let mut state_intent = initial_intent.clone();

    let initial_intent_commitment = state_intent.compute_commitment();
    let old_balance_nullifier = bal.compute_nullifier();

    // Re-encrypt the new amount public share
    let new_amount_public_share = state_intent.public_share.amount_in;

    // Re-encrypt the post-match balance shares
    let new_one_time_address = bal.inner.one_time_authority;
    let new_one_time_share = bal.stream_cipher_encrypt(&new_one_time_address);
    let post_match_balance = PostMatchBalance::from(bal.inner.clone());
    let post_match_balance_shares = bal.stream_cipher_encrypt(&post_match_balance);
    bal.public_share.one_time_authority = new_one_time_share;
    bal.update_from_post_match(&post_match_balance_shares);

    let witness = IntentAndBalanceFirstFillValidityWitness {
        intent: intent.clone(),
        initial_intent_share_stream: initial_intent.share_stream.clone(),
        initial_intent_recovery_stream: initial_intent.recovery_stream.clone(),
        private_intent_shares: state_intent.private_shares(),
        new_amount_public_share,
        balance: old_balance.inner.clone(),
        old_balance,
        post_match_balance_shares,
        // TODO: Remove this when we remove one time addresses
        new_one_time_address,
        balance_opening: balance_opening.clone().into(),
    };

    // TODO: Remove this value
    let intent_and_authorizing_address_commitment = compute_poseidon_hash(&[
        initial_intent_commitment,
        address_to_scalar(&new_one_time_address),
    ]);

    let intent_public_share = PreMatchIntentShare::from(state_intent.public_share());
    let intent_recovery_id = state_intent.compute_recovery_id();
    let intent_private_share_commitment = state_intent.compute_private_commitment();
    let balance_recovery_id = bal.compute_recovery_id();
    let balance_partial_commitment =
        bal.compute_partial_commitment(BALANCE_PARTIAL_COMMITMENT_SIZE);

    let statement = IntentAndBalanceFirstFillValidityStatement {
        merkle_root: balance_opening.compute_root(),
        // TODO: Remove this when we implement in-circuit verification
        intent_and_authorizing_address_commitment,
        intent_public_share,
        intent_private_share_commitment,
        intent_recovery_id,
        balance_partial_commitment,
        new_one_time_address_public_share: new_one_time_share,
        old_balance_nullifier,
        balance_recovery_id,
        one_time_authorizing_address: bal.inner.one_time_authority,
    };

    // Prove the relation
    let (proof, hint) = singleprover_prove_with_hint::<
        SizedIntentAndBalanceFirstFillValidityCircuit,
    >(&witness, &statement)?;

    // Extract the state intent that was generated by the witness helper
    let stream_seed = witness.initial_intent_share_stream.seed;
    let recovery_seed = witness.initial_intent_recovery_stream.seed;
    let state_intent = StateWrapper::new(intent.clone(), stream_seed, recovery_seed);

    Ok((state_intent, statement, proof, hint))
}

/// Generate a new output balance validity proof
fn generate_new_output_balance_validity_proof(
    owner: Address,
    obligation: &SettlementObligation,
    test_args: &TestArgs,
) -> Result<(
    DarkpoolStateBalance,
    NewOutputBalanceValidityStatement,
    PlonkProof,
    ProofLinkingHint,
)> {
    let relayer_fee_recipient = test_args.relayer_signer_addr();
    let one_time_authority = owner;
    let bal = Balance::new(
        obligation.output_token,
        owner,
        relayer_fee_recipient,
        one_time_authority,
    );

    // Build the witness and statement
    let (witness, statement) = create_new_output_balance_witness_statement(bal.clone());

    let (proof, hint) =
        singleprover_prove_with_hint::<NewOutputBalanceValidityCircuit>(&witness, &statement)?;

    let share_seed = witness.initial_share_stream.seed;
    let recovery_seed = witness.initial_recovery_stream.seed;
    let state_balance = StateWrapper::new(bal, share_seed, recovery_seed);
    Ok((state_balance, statement, proof, hint))
}

/// Generate a settlement proof for the fill
fn generate_settlement_proof(
    intent: &DarkpoolStateIntent,
    input_balance: &DarkpoolStateBalance,
    output_balance: &DarkpoolStateBalance,
    obligation: &SettlementObligation,
) -> Result<(
    IntentAndBalancePublicSettlementStatement,
    PlonkProof,
    ProofLinkingHint,
)> {
    let pre_settlement_amount_public_share = intent.public_share.amount_in;
    let pre_settlement_in_balance_shares =
        PostMatchBalanceShare::from(input_balance.public_share.clone());
    let pre_settlement_out_balance_shares =
        PostMatchBalanceShare::from(output_balance.public_share.clone());

    let witness = IntentAndBalancePublicSettlementWitness {
        intent: intent.inner.clone(),
        pre_settlement_amount_public_share,
        in_balance: input_balance.inner.clone(),
        pre_settlement_in_balance_shares: pre_settlement_in_balance_shares.clone(),
        out_balance: output_balance.inner.clone(),
        pre_settlement_out_balance_shares: pre_settlement_out_balance_shares.clone(),
    };

    let statement = IntentAndBalancePublicSettlementStatement {
        settlement_obligation: obligation.clone(),
        amount_public_share: pre_settlement_amount_public_share,
        in_balance_public_shares: pre_settlement_in_balance_shares,
        out_balance_public_shares: pre_settlement_out_balance_shares,
        relayer_fee: settlement_relayer_fee(),
        relayer_fee_recipient: output_balance.inner.relayer_fee_recipient,
    };

    // Prove the relation
    let (proof, hint) = singleprover_prove_with_hint::<IntentAndBalancePublicSettlementCircuit>(
        &witness, &statement,
    )?;
    Ok((statement, proof, hint))
}

// --- Proof Linking --- //

/// Generate a linking proof between a validity proof and a settlement proof
fn generate_validity_settlement_linking_proof(
    validity_hint: &ProofLinkingHint,
    settlement_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof> {
    let proof = link_sized_intent_and_balance_settlement(validity_hint, settlement_hint)?;

    Ok(proof)
}

/// Generate a linking proof between an output balance validity proof and a settlement proof
fn generate_output_balance_settlement_linking_proof(
    output_balance_hint: &ProofLinkingHint,
    settlement_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof> {
    let proof = link_sized_output_balance_settlement(output_balance_hint, settlement_hint)?;
    Ok(proof)
}
