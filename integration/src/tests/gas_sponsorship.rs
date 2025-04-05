//! Integration tests for gas sponsorship

use alloy_primitives::{Address, U256};
use eyre::Result;
use scripts::utils::send_tx;
use test_helpers::{assert_eq_result, assert_true_result, integration_test_async};

use crate::{
    constants::REFUND_AMOUNT,
    utils::{
        assert_native_eth_gas_refund, serialize_to_calldata, setup_sponsored_match_test,
        SponsoredMatchTestOptions,
    },
    TestContext,
};

/// Test a sponsored match through the gas sponsor.
///
/// Asserts that the refunded amount is ~equal to the gas paid.
#[allow(non_snake_case)]
pub async fn test_sponsored_match_refund__simple(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let data = setup_sponsored_match_test(Default::default() /* options */, &ctx).await?;
    let initial_eth_balance = ctx.get_eth_balance().await?;

    let settle_tx = gas_sponsor_contract.sponsorAtomicMatchSettle(
        serialize_to_calldata(&data.process_atomic_match_settle_data.internal_party_match_payload)?,
        serialize_to_calldata(
            &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
        )?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_linking_proofs)?,
        data.refund_address,
        data.nonce,
        data.signature,
    );
    let receipt = send_tx(settle_tx).await?.expect("no tx receipt");
    let final_eth_balance = ctx.get_eth_balance().await?;

    assert_native_eth_gas_refund(initial_eth_balance, final_eth_balance, receipt)
}
integration_test_async!(test_sponsored_match_refund__simple);

/// Test a sponsored match through the gas sponsor, buying the native asset.
///
/// Asserts that the refunded amount is ~equal to the gas paid.
#[allow(non_snake_case)]
pub async fn test_sponsored_match_refund__native_asset_buy(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let data = setup_sponsored_match_test(
        SponsoredMatchTestOptions { trade_native_eth: true, ..Default::default() },
        &ctx,
    )
    .await?;
    let initial_eth_balance = ctx.get_eth_balance().await?;

    let settle_tx = gas_sponsor_contract.sponsorAtomicMatchSettle(
        serialize_to_calldata(&data.process_atomic_match_settle_data.internal_party_match_payload)?,
        serialize_to_calldata(
            &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
        )?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_linking_proofs)?,
        data.refund_address,
        data.nonce,
        data.signature,
    );
    let receipt = send_tx(settle_tx).await?.expect("no tx receipt");

    let match_result =
        &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement.match_result;

    let fees = &data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .external_party_fees;

    let eth_received_in_match = match_result.base_amount - fees.total();

    let final_eth_balance = ctx.get_eth_balance().await?;
    let post_refund_eth_balance = final_eth_balance - eth_received_in_match;

    assert_native_eth_gas_refund(initial_eth_balance, post_refund_eth_balance, receipt)
}
integration_test_async!(test_sponsored_match_refund__native_asset_buy);

/// Test a sponsored match through the gas sponsor, selling the native asset.
///
/// Asserts that the refunded amount is ~equal to the gas paid.
#[allow(non_snake_case)]
pub async fn test_sponsored_match_refund__native_asset_sell(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let data = setup_sponsored_match_test(
        SponsoredMatchTestOptions { sell_side: true, trade_native_eth: true, ..Default::default() },
        &ctx,
    )
    .await?;

    let base_amount = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .base_amount;
    let initial_eth_balance = ctx.get_eth_balance().await?;

    let settle_tx = gas_sponsor_contract
        .sponsorAtomicMatchSettle(
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.internal_party_match_payload,
            )?,
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
            )?,
            serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
            serialize_to_calldata(
                &data.process_atomic_match_settle_data.match_atomic_linking_proofs,
            )?,
            data.refund_address,
            data.nonce,
            data.signature,
        )
        .value(base_amount);
    let receipt = send_tx(settle_tx).await?.expect("no tx receipt");

    let final_eth_balance = ctx.get_eth_balance().await?;
    let post_refund_eth_balance = final_eth_balance + base_amount;
    assert_native_eth_gas_refund(initial_eth_balance, post_refund_eth_balance, receipt)
}
integration_test_async!(test_sponsored_match_refund__native_asset_sell);

/// Test a sponsored match which reuses an existing nonce.
///
/// Asserts that the match w/ the duplicate nonce fails.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__duplicate_nonce(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let data1 = setup_sponsored_match_test(Default::default() /* options */, &ctx).await?;
    let data2 = setup_sponsored_match_test(Default::default() /* options */, &ctx).await?;

    let settle_tx = gas_sponsor_contract.sponsorAtomicMatchSettle(
        serialize_to_calldata(
            &data1.process_atomic_match_settle_data.internal_party_match_payload,
        )?,
        serialize_to_calldata(
            &data1.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
        )?,
        serialize_to_calldata(&data1.process_atomic_match_settle_data.match_atomic_proofs)?,
        serialize_to_calldata(&data1.process_atomic_match_settle_data.match_atomic_linking_proofs)?,
        data1.refund_address,
        data1.nonce,
        data1.signature.clone(),
    );
    send_tx(settle_tx).await?.expect("no tx receipt");

    let settle_tx = gas_sponsor_contract.sponsorAtomicMatchSettle(
        serialize_to_calldata(
            &data2.process_atomic_match_settle_data.internal_party_match_payload,
        )?,
        serialize_to_calldata(
            &data2.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
        )?,
        serialize_to_calldata(&data2.process_atomic_match_settle_data.match_atomic_proofs)?,
        serialize_to_calldata(&data2.process_atomic_match_settle_data.match_atomic_linking_proofs)?,
        // Here, we reuse the refund address + nonce + signature from the first match
        data1.refund_address,
        data1.nonce,
        data1.signature,
    );
    let result = send_tx(settle_tx).await;
    assert_true_result!(result.is_err())
}
integration_test_async!(test_sponsored_match__duplicate_nonce);

/// Test a sponsored match which provides a refund address other than the
/// one that was signed.
///
/// Asserts that the match fails on account of an invalid signature.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__invalid_signature(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let data = setup_sponsored_match_test(Default::default() /* options */, &ctx).await?;

    let settle_tx = gas_sponsor_contract.sponsorAtomicMatchSettle(
        serialize_to_calldata(&data.process_atomic_match_settle_data.internal_party_match_payload)?,
        serialize_to_calldata(
            &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
        )?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_linking_proofs)?,
        Address::random(), // Incorrect refund address
        data.nonce,
        data.signature,
    );
    let result = send_tx(settle_tx).await;
    assert_true_result!(result.is_err())
}
integration_test_async!(test_sponsored_match__invalid_signature);

/// Test a sponsored match when the gas sponsor is paused.
///
/// Asserts that the match succeeds but is not sponsored.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__paused(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let data = setup_sponsored_match_test(Default::default() /* options */, &ctx).await?;

    // Pause the gas sponsor
    send_tx(gas_sponsor_contract.pause()).await?;
    let initial_eth_balance = ctx.get_eth_balance().await?;

    let settle_tx = gas_sponsor_contract.sponsorAtomicMatchSettle(
        serialize_to_calldata(&data.process_atomic_match_settle_data.internal_party_match_payload)?,
        serialize_to_calldata(
            &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
        )?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_linking_proofs)?,
        data.refund_address,
        data.nonce,
        data.signature,
    );
    let receipt = send_tx(settle_tx).await?.expect("no tx receipt");
    let gas_cost = receipt.gas_used as u128 * receipt.effective_gas_price;
    let final_eth_balance = ctx.get_eth_balance().await?;

    assert_eq_result!(initial_eth_balance - final_eth_balance, U256::from(gas_cost))
}
integration_test_async!(test_sponsored_match__paused);

/// Test a sponsored match when the gas sponsor is underfunded.
///
/// Asserts that the match succeeds but is not sponsored.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__underfunded(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let data = setup_sponsored_match_test(Default::default() /* options */, &ctx).await?;

    // Withdraw all ETH from the gas sponsor
    let balance = ctx.get_eth_balance_of(*gas_sponsor_contract.address()).await?;
    let withdraw_tx = gas_sponsor_contract.withdrawEth(ctx.client.address(), balance);
    send_tx(withdraw_tx).await?.expect("no tx receipt");

    let initial_eth_balance = ctx.get_eth_balance().await?;
    let settle_tx = gas_sponsor_contract.sponsorAtomicMatchSettle(
        serialize_to_calldata(&data.process_atomic_match_settle_data.internal_party_match_payload)?,
        serialize_to_calldata(
            &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
        )?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_linking_proofs)?,
        data.refund_address,
        data.nonce,
        data.signature,
    );
    let receipt = send_tx(settle_tx).await?.expect("no tx receipt");

    let gas_cost = receipt.gas_used as u128 * receipt.effective_gas_price;
    let final_eth_balance = ctx.get_eth_balance().await?;

    assert_eq_result!(initial_eth_balance - final_eth_balance, U256::from(gas_cost))
}
integration_test_async!(test_sponsored_match__underfunded);

/// Test a sponsored match through the gas sponsor with in-kind refunds.
///
/// Asserts that the refunded amount in the buy-side token is ~equal to the gas
/// paid.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__in_kind__simple(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let data = setup_sponsored_match_test(
        SponsoredMatchTestOptions {
            in_kind_refund: true,
            sign_refund_amount: true,
            ..Default::default()
        },
        &ctx,
    )
    .await?;

    let (buy_token_addr, _) = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .external_party_buy_mint_amount();
    let initial_balance =
        ctx.get_erc20_balance_of(buy_token_addr, *gas_sponsor_contract.address()).await?;

    let settle_tx = gas_sponsor_contract.sponsorAtomicMatchSettleWithRefundOptions(
        Address::ZERO, // receiver
        serialize_to_calldata(&data.process_atomic_match_settle_data.internal_party_match_payload)?,
        serialize_to_calldata(
            &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
        )?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_linking_proofs)?,
        data.refund_address,
        data.nonce,
        data.refund_native_eth,
        data.refund_amount,
        data.signature,
    );
    send_tx(settle_tx).await?.expect("no tx receipt");
    let final_balance =
        ctx.get_erc20_balance_of(buy_token_addr, *gas_sponsor_contract.address()).await?;

    assert_eq_result!(initial_balance - final_balance, U256::from(REFUND_AMOUNT))
}
integration_test_async!(test_sponsored_match__in_kind__simple);

/// Test a sponsored match through the gas sponsor with in-kind refunds when
/// buying native ETH.
///
/// Asserts that the refunded amount is ~equal to the gas paid in native ETH.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__in_kind__native_buy(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let data = setup_sponsored_match_test(
        SponsoredMatchTestOptions {
            in_kind_refund: true,
            sign_refund_amount: true,
            trade_native_eth: true,
            ..Default::default()
        },
        &ctx,
    )
    .await?;
    let initial_eth_balance = ctx.get_eth_balance_of(*gas_sponsor_contract.address()).await?;

    let settle_tx = gas_sponsor_contract.sponsorAtomicMatchSettleWithRefundOptions(
        Address::ZERO, // receiver
        serialize_to_calldata(&data.process_atomic_match_settle_data.internal_party_match_payload)?,
        serialize_to_calldata(
            &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
        )?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_linking_proofs)?,
        data.refund_address,
        data.nonce,
        data.refund_native_eth,
        data.refund_amount,
        data.signature,
    );
    send_tx(settle_tx).await?.expect("no tx receipt");
    let final_eth_balance = ctx.get_eth_balance_of(*gas_sponsor_contract.address()).await?;

    assert_eq_result!(initial_eth_balance - final_eth_balance, U256::from(REFUND_AMOUNT))
}
integration_test_async!(test_sponsored_match__in_kind__native_buy);

/// Test a sponsored match through the gas sponsor with a custom refund address.
///
/// Asserts that the refunded amount is sent to the specified refund address.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__refund_address__explicit(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();
    let refund_address = Address::random();
    let data = setup_sponsored_match_test(
        SponsoredMatchTestOptions { refund_address, ..Default::default() },
        &ctx,
    )
    .await?;
    let initial_eth_balance = ctx.get_eth_balance_of(refund_address).await?;

    let settle_tx = gas_sponsor_contract.sponsorAtomicMatchSettle(
        serialize_to_calldata(&data.process_atomic_match_settle_data.internal_party_match_payload)?,
        serialize_to_calldata(
            &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
        )?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_linking_proofs)?,
        data.refund_address,
        data.nonce,
        data.signature,
    );
    let receipt = send_tx(settle_tx).await?.expect("no tx receipt");
    let final_eth_balance = ctx.get_eth_balance_of(refund_address).await?;

    assert_native_eth_gas_refund(initial_eth_balance, final_eth_balance, receipt)
}
integration_test_async!(test_sponsored_match__refund_address__explicit);

/// Test that the gas refund is sent to tx::origin() when refund_address is zero
/// and refund_native_eth is true
#[allow(non_snake_case)]
pub async fn test_sponsored_match__refund_address__tx_origin(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();

    // Generate a random receiver address different from tx::origin to ensure
    // we can properly test that the refund goes to tx::origin and not the receiver
    let receiver = Address::random();
    let data = setup_sponsored_match_test(
        SponsoredMatchTestOptions { receiver, sign_refund_amount: true, ..Default::default() },
        &ctx,
    )
    .await?;

    // tx::origin() will be ctx.client.address() in this case
    let initial_eth_balance = ctx.get_eth_balance().await?;

    let settle_tx = gas_sponsor_contract.sponsorAtomicMatchSettleWithRefundOptions(
        receiver,
        serialize_to_calldata(&data.process_atomic_match_settle_data.internal_party_match_payload)?,
        serialize_to_calldata(
            &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
        )?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_linking_proofs)?,
        data.refund_address,
        data.nonce,
        data.refund_native_eth,
        data.refund_amount,
        data.signature,
    );
    let receipt = send_tx(settle_tx).await?.expect("no tx receipt");
    let final_eth_balance = ctx.get_eth_balance().await?;

    let diff = initial_eth_balance - final_eth_balance;
    let gas_cost = receipt.gas_used as u128 * receipt.effective_gas_price;
    assert_eq_result!(U256::from(gas_cost) - diff, U256::from(REFUND_AMOUNT))?;

    // Verify that the refund went to tx::origin and not the receiver
    let receiver_eth_balance = ctx.get_eth_balance_of(receiver).await?;
    assert_eq_result!(receiver_eth_balance, U256::ZERO)
}
integration_test_async!(test_sponsored_match__refund_address__tx_origin);

/// Test that the gas refund is sent to the receiver when refund_address is zero
/// and refund_native_eth is false
#[allow(non_snake_case)]
pub async fn test_sponsored_match__refund_address__receiver(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();

    // Generate a random receiver address different from tx::origin to ensure
    // we can properly test that the refund goes to the receiver and not tx::origin
    let receiver = Address::random();
    let data = setup_sponsored_match_test(
        SponsoredMatchTestOptions {
            receiver,
            in_kind_refund: true,
            sign_refund_amount: true,
            ..Default::default()
        },
        &ctx,
    )
    .await?;

    let (buy_token_addr, _) = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .external_party_buy_mint_amount();
    let initial_balance =
        ctx.get_erc20_balance_of(buy_token_addr, *gas_sponsor_contract.address()).await?;

    // Record tx::origin's initial balance to verify it doesn't receive the refund
    let tx_origin_initial_balance =
        ctx.get_erc20_balance_of(buy_token_addr, ctx.client.address()).await?;

    let settle_tx = gas_sponsor_contract.sponsorAtomicMatchSettleWithRefundOptions(
        receiver,
        serialize_to_calldata(&data.process_atomic_match_settle_data.internal_party_match_payload)?,
        serialize_to_calldata(
            &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
        )?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_linking_proofs)?,
        Address::ZERO, // refund_address
        data.nonce,
        data.refund_native_eth,
        data.refund_amount,
        data.signature,
    );
    send_tx(settle_tx).await?.expect("no tx receipt");
    let final_balance =
        ctx.get_erc20_balance_of(buy_token_addr, *gas_sponsor_contract.address()).await?;

    assert_eq_result!(initial_balance - final_balance, U256::from(REFUND_AMOUNT))?;

    // Verify that the refund was sent to the receiver
    let receiver_balance = ctx.get_erc20_balance_of(buy_token_addr, receiver).await?;
    assert_true_result!(receiver_balance > U256::ZERO)?;

    // Verify that tx::origin did not receive the refund by checking its balance
    // didn't change
    let tx_origin_final_balance =
        ctx.get_erc20_balance_of(buy_token_addr, ctx.client.address()).await?;
    assert_eq!(
        tx_origin_final_balance, tx_origin_initial_balance,
        "tx::origin's balance changed when it should not have received the refund"
    );

    Ok(())
}
integration_test_async!(test_sponsored_match__refund_address__receiver);

/// Test that the gas refund is sent to msg::sender() when refund_address is
/// zero, refund_native_eth is false, and the receiver is zero.
#[allow(non_snake_case)]
pub async fn test_sponsored_match__refund_address__msg_sender(ctx: TestContext) -> Result<()> {
    let gas_sponsor_contract = ctx.gas_sponsor_contract();

    // Generate a random receiver address different from tx::origin to ensure
    // we can properly test that the refund goes to the receiver and not tx::origin
    let data = setup_sponsored_match_test(
        SponsoredMatchTestOptions {
            in_kind_refund: true,
            sign_refund_amount: true,
            ..Default::default()
        },
        &ctx,
    )
    .await?;

    let (buy_token_addr, _) = data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .external_party_buy_mint_amount();

    // msg::sender() will be ctx.client.address() in this case
    let initial_balance = ctx.get_erc20_balance(buy_token_addr).await?;

    let settle_tx = gas_sponsor_contract.sponsorAtomicMatchSettleWithRefundOptions(
        Address::ZERO, // receiver
        serialize_to_calldata(&data.process_atomic_match_settle_data.internal_party_match_payload)?,
        serialize_to_calldata(
            &data.process_atomic_match_settle_data.valid_match_settle_atomic_statement,
        )?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_proofs)?,
        serialize_to_calldata(&data.process_atomic_match_settle_data.match_atomic_linking_proofs)?,
        Address::ZERO, // refund_address
        data.nonce,
        data.refund_native_eth,
        data.refund_amount,
        data.signature,
    );
    send_tx(settle_tx).await?;

    let final_balance = ctx.get_erc20_balance(buy_token_addr).await?;
    let base_amount = &data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .match_result
        .base_amount;
    let fees = &data
        .process_atomic_match_settle_data
        .valid_match_settle_atomic_statement
        .external_party_fees;

    let received_in_match = base_amount - fees.total();
    let post_refund_balance = final_balance - received_in_match;

    assert_eq_result!(post_refund_balance - initial_balance, U256::from(REFUND_AMOUNT))
}
integration_test_async!(test_sponsored_match__refund_address__msg_sender);
