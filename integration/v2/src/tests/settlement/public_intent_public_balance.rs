//! Tests for settling a public-public (ring0) fill
use crate::{
    U256,
    test_args::TestArgs,
    tests::settlement::private_intent_private_balance::{
        build_settlement_bundle_ring0, fund_ring0_party,
    },
    tests::settlement::{compute_fee_take, create_random_intents_and_obligations},
    wait_for_tx_success,
};
use eyre::Result;
use renegade_abi::v2::IDarkpoolV2::ObligationBundle;
use test_helpers::{assert_eq_result, integration_test_async};

#[allow(non_snake_case)]
pub async fn test_settlement__public_public_fill(args: TestArgs) -> Result<()> {
    // Build the intents and obligations
    let (intent0, intent1, obligation0, obligation1) =
        create_random_intents_and_obligations(&args).await?;

    let signer0 = args.party0_signer();
    let signer1 = args.party1_signer();

    // Fund both parties
    fund_ring0_party(&signer0, &obligation0, &args).await?;
    fund_ring0_party(&args.party1_signer(), &obligation1, &args).await?;

    // Build obligation bundle
    let obligation_bundle =
        ObligationBundle::new_public(obligation0.clone().into(), obligation1.clone().into());

    // Build settlement bundles
    let settlement_bundle0 =
        build_settlement_bundle_ring0(&signer0, &intent0, &obligation0, &args).await?;
    let settlement_bundle1 =
        build_settlement_bundle_ring0(&signer1, &intent1, &obligation1, &args).await?;

    // Get balances before the trade
    let party0_base_before = args.base_balance(args.party0_addr()).await?;
    let party1_base_before = args.base_balance(args.party1_addr()).await?;
    let party0_quote_before = args.quote_balance(args.party0_addr()).await?;
    let party1_quote_before = args.quote_balance(args.party1_addr()).await?;

    // Execute the transaction
    let tx = args
        .darkpool
        .settleMatch(obligation_bundle, settlement_bundle0, settlement_bundle1);
    let tx_receipt = wait_for_tx_success(tx).await.unwrap();

    // Print the gas used
    println!("\nGas used for a ring0 trade: {}", tx_receipt.gas_used);

    // Get balances after the trade
    let party0_base_after = args.base_balance(args.party0_addr()).await?;
    let party1_base_after = args.base_balance(args.party1_addr()).await?;
    let party0_quote_after = args.quote_balance(args.party0_addr()).await?;
    let party1_quote_after = args.quote_balance(args.party1_addr()).await?;

    // Verify balance updates
    let fee_take0 = compute_fee_take(&obligation0, &args).await?;
    let fee_take1 = compute_fee_take(&obligation1, &args).await?;
    let total_fee0 = U256::from(fee_take0.total());
    let total_fee1 = U256::from(fee_take1.total());
    assert_eq_result!(
        party0_base_after,
        party0_base_before - U256::from(obligation0.amount_in)
    )?;
    assert_eq_result!(
        party0_quote_after,
        party0_quote_before + U256::from(obligation0.amount_out) - total_fee0
    )?;
    assert_eq_result!(
        party1_base_after,
        party1_base_before + U256::from(obligation1.amount_out) - total_fee1
    )?;
    assert_eq_result!(
        party1_quote_after,
        party1_quote_before - U256::from(obligation1.amount_in)
    )?;

    Ok(())
}
integration_test_async!(test_settlement__public_public_fill);
