//! Settlement tests

use alloy::{
    primitives::{Address, U160, U256, aliases::U48},
    signers::local::PrivateKeySigner,
};
use eyre::Result;
use rand::{Rng, thread_rng};
use renegade_abi::v2::IDarkpoolV2::{Deposit, FeeRate};
use renegade_account_types::MerkleAuthenticationPath;
use renegade_circuit_types::fixed_point::FixedPoint;
use renegade_circuits::test_helpers::{BOUNDED_MAX_AMT, random_price};
use renegade_crypto::fields::scalar_to_u128;
use renegade_darkpool_types::{
    balance::DarkpoolStateBalance, fee::FeeTake, intent::Intent,
    settlement_obligation::SettlementObligation,
};

use crate::{
    test_args::TestArgs,
    tests::state_updates::create_balance::create_balance,
    util::{
        deposit::fund_for_deposit,
        fuzzing::create_matching_intents_and_obligations,
        merkle::find_state_element_opening,
        transactions::{send_tx, wait_for_tx_success},
    },
};

mod external_match;

pub(crate) mod private_fill;
pub(crate) mod private_intent_private_balance;
mod private_intent_public_balance;
mod public_intent_public_balance;

/// The settlement relayer fee to use for testing
pub fn settlement_relayer_fee() -> FixedPoint {
    FixedPoint::from_f64_round_down(0.0001) // 1bp
}

/// Get the relayer's fee rate for settlement
pub fn settlement_relayer_fee_rate(args: &TestArgs) -> FeeRate {
    FeeRate {
        rate: settlement_relayer_fee().into(),
        recipient: args.relayer_signer_addr(),
    }
}

/// Get the total fee applicable to a settlement
pub async fn get_total_fee(args: &TestArgs) -> Result<(FixedPoint, FixedPoint)> {
    let protocol_fee = args.protocol_fee().await?;
    let relayer_fee = settlement_relayer_fee();
    Ok((relayer_fee, protocol_fee))
}

/// Compute the fee take for an obligation
pub async fn compute_fee_take(
    obligation: &SettlementObligation,
    args: &TestArgs,
) -> Result<FeeTake> {
    let (relayer_fee_rate, protocol_fee_rate) = get_total_fee(args).await?;
    let relayer_fee = relayer_fee_rate.floor_mul_int(obligation.amount_out);
    let protocol_fee = protocol_fee_rate.floor_mul_int(obligation.amount_out);

    Ok(FeeTake {
        relayer_fee: scalar_to_u128(&relayer_fee),
        protocol_fee: scalar_to_u128(&protocol_fee),
    })
}

/// Split an obligation in two
///
/// Returns the two splits of the obligation
pub(crate) fn split_obligation(
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

pub async fn create_random_intents_and_obligations(
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

/// Fund the two parties with the base and quote tokens
///
/// Test setup will fund the parties with the tokens and approve the permit2 contract to spend the tokens.
pub(crate) async fn fund_parties(args: &TestArgs) -> Result<()> {
    let base = args.base_addr()?;
    let quote = args.quote_addr()?;
    approve_balance(base, &args.party0_signer(), args).await?;
    approve_balance(quote, &args.party1_signer(), args).await?;
    Ok(())
}

/// Approve a balance to be spent by the darkpool via the permit2 contract
pub(crate) async fn approve_balance(
    token: Address,
    signer: &PrivateKeySigner,
    args: &TestArgs,
) -> Result<()> {
    // Approve Permit2 to spend the ERC20 tokens
    let erc20 = args.erc20_from_addr_with_signer(token, signer.clone())?;
    let permit2_addr = args.permit2_addr()?;
    send_tx(erc20.approve(permit2_addr, U256::MAX)).await?;

    // Approve the darkpool to spend the tokens via Permit2
    let amt = U160::MAX;
    let permit2 = args.permit2_with_signer(signer)?;
    let darkpool = args.darkpool_addr();
    let expiration = U48::MAX;
    send_tx(permit2.approve(token, darkpool, amt, expiration)).await?;

    Ok(())
}

/// Fund the ring-2 party
pub async fn fund_ring2_party(
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
    let (receipt, bal) = create_balance(signer, &deposit, args).await?;
    let opening = find_state_element_opening(&bal, &receipt).await?;
    Ok((bal, opening))
}

/// Fund the ring-0 party
pub async fn fund_ring0_party(
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

    // Approve Permit2 to spend the ERC20 tokens (required for transferFrom)
    let permit2_addr = args.permit2_addr()?;
    let approve_tx = erc20.approve(permit2_addr, U256::MAX);
    wait_for_tx_success(approve_tx).await?;

    // Approve the darkpool to spend the tokens via Permit2
    args.permit2_approve_darkpool(token, signer).await
}
