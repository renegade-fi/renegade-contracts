use crate::{
    TestArgs, U256,
    tests::settlement::{
        external_match::{
            compute_fee_take, create_intent_and_bounded_match_result,
            private_intent_public_balance::{create_obligations, pick_external_party_amt_in},
            setup_external_match,
        },
        fund_parties, settlement_relayer_fee_rate,
    },
    wait_for_tx_success,
};
use alloy::sol_types::SolValue;
use eyre::Result;
use renegade_abi::v2::IDarkpoolV2::{
    BoundedMatchResult, PublicIntentAuthBundle, PublicIntentPermit, SettlementBundle,
    SignatureWithNonce, SignedPermitSingle,
};
use test_helpers::{assert_eq_result, integration_test_async};

/// Tests settling a natively-settled public intent via external match (ring 0)
#[allow(non_snake_case)]
async fn test_bounded_settlement__native_settled_public_intent(args: TestArgs) -> Result<()> {
    // Setup the external party (tx_submitter) with funding and darkpool approval
    setup_external_match(&args).await?;

    // Fund the parties, party0 (internal party) sells the base; party1 (external party) sells the quote
    fund_parties(&args).await?;

    let (intent, bounded_match_result, _balance_amt) =
        create_intent_and_bounded_match_result(&args)?;

    let relayer_fee_rate = settlement_relayer_fee_rate(&args);

    let external_party_amt_in = pick_external_party_amt_in(&bounded_match_result);
    let (internal_obligation, external_obligation) =
        create_obligations(&bounded_match_result, external_party_amt_in);

    let chain_id = args.chain_id().await?;
    let executor_signer = &args.relayer_signer;

    // ABI-encode the payload to sign
    let payload = (
        relayer_fee_rate.clone(),
        BoundedMatchResult::from(bounded_match_result.clone()),
    )
        .abi_encode();

    // Sign the payload and chain ID
    let executor_signature =
        SignatureWithNonce::sign(payload.as_slice(), chain_id, executor_signer)?;

    // Generate the auth bundle
    let permit = PublicIntentPermit {
        intent: intent.clone().into(),
        executor: args.relayer_signer_addr(),
    };
    let intent_signature = permit.sign(chain_id, &args.party0_signer())?;

    let auth_bundle = PublicIntentAuthBundle {
        intentPermit: permit,
        intentSignature: intent_signature,
        executorSignature: executor_signature,
        allowancePermit: SignedPermitSingle::default(),
    };

    let settlement_bundle =
        SettlementBundle::public_intent_settlement(auth_bundle, relayer_fee_rate);

    // Get balances before fill
    let external_party = args.tx_submitter.address();

    let internal_party_base_before = args.base_balance(args.party0_addr()).await?;
    let external_party_base_before = args.base_balance(external_party).await?;
    let internal_party_quote_before = args.quote_balance(args.party0_addr()).await?;
    let external_party_quote_before = args.quote_balance(external_party).await?;

    let tx = args.darkpool.settleExternalMatch(
        external_party_amt_in,
        external_party, // recipient
        bounded_match_result.clone().into(),
        settlement_bundle,
    );
    wait_for_tx_success(tx).await?;

    // Get balances after fill
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

    Ok(())
}
integration_test_async!(test_bounded_settlement__native_settled_public_intent);
