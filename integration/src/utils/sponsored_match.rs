//! Integration testing utilities for sponsored matches

use alloy::rpc::types::TransactionReceipt;
use alloy_primitives::{utils::parse_ether, Address, Bytes, U256};
use ark_std::UniformRand;
use contracts_common::types::ScalarField;
use contracts_utils::{
    crypto::hash_and_sign_message, proof_system::test_data::SponsoredAtomicMatchSettleData,
};
use eyre::Result;
use rand::thread_rng;
use scripts::utils::send_tx;
use test_helpers::assert_true_result;

use crate::{
    abis::DummyErc20Contract,
    constants::{GAS_COST_TOLERANCE, REFUND_AMOUNT},
    TestContext,
};

use super::{native_eth_address, scalar_to_u256, setup_atomic_match_settle_test};

// ---------
// | Types |
// ---------

/// The options for setting up a sponsored match test
#[derive(Default)]
pub struct SponsoredMatchTestOptions {
    /// Whether or not the external party sells the base
    pub sell_side: bool,
    /// Whether to use native ETH as the base
    pub trade_native_eth: bool,
    /// The address to refund to
    pub refund_address: Address,
    /// The address to receive the tokens
    pub receiver: Address,
    /// Whether to refund through the buy-side token
    pub in_kind_refund: bool,
    /// Whether to sign the refund amount. This should be `true`
    /// if we are invoking the `sponsorAtomicMatchSettleWithRefundOptions`
    /// method directly.
    pub sign_refund_amount: bool,
}

// -----------
// | Helpers |
// -----------

/// Setup a sponsored atomic match settle test
pub async fn setup_sponsored_match_test(
    options: SponsoredMatchTestOptions,
    ctx: &TestContext,
) -> Result<SponsoredAtomicMatchSettleData> {
    // Ensure that the gas sponsor is unpaused
    send_tx(ctx.gas_sponsor_contract().unpause()).await?;

    let mut process_atomic_match_settle_data =
        setup_atomic_match_settle_test(!options.sell_side, true /* use_gas_sponsor */, ctx).await?;

    if options.trade_native_eth {
        // Replace the base mint with the native ETH address
        process_atomic_match_settle_data
            .valid_match_settle_atomic_statement
            .match_result
            .base_mint = native_eth_address();
    }

    let mut rng = thread_rng();
    let nonce = scalar_to_u256(ScalarField::rand(&mut rng));
    let nonce_bytes = nonce.to_be_bytes_vec();

    let mut message = Vec::new();
    message.extend_from_slice(&nonce_bytes);
    message.extend_from_slice(options.refund_address.as_ref());

    if options.sign_refund_amount {
        // Add the refund amount to the message
        let refund_amount_bytes = REFUND_AMOUNT.to_be_bytes_vec();
        message.extend_from_slice(&refund_amount_bytes);
    }

    if options.in_kind_refund {
        // Fund the gas sponsor with some ERC20s
        let erc20_addr1 = DummyErc20Contract::new(ctx.test_erc20_address1, ctx.client.provider());
        let mint_tx1 = erc20_addr1.mint(ctx.gas_sponsor_proxy_address, REFUND_AMOUNT);
        send_tx(mint_tx1).await?;

        let erc20_addr2 = DummyErc20Contract::new(ctx.test_erc20_address2, ctx.client.provider());
        let mint_tx2 = erc20_addr2.mint(ctx.gas_sponsor_proxy_address, REFUND_AMOUNT);
        send_tx(mint_tx2).await?;
    }

    let signature = Bytes::from(hash_and_sign_message(ctx.signing_key(), &message).as_bytes());

    // Fund the gas sponsor with some ETH
    let sponsor_contract = ctx.gas_sponsor_contract();
    let receive_eth_tx = sponsor_contract.receiveEth().value(parse_ether("0.1")?);
    send_tx(receive_eth_tx).await?;

    Ok(SponsoredAtomicMatchSettleData {
        process_atomic_match_settle_data,
        nonce,
        signature,
        refund_address: options.refund_address,
        receiver: options.receiver,
        refund_native_eth: !options.in_kind_refund,
        refund_amount: REFUND_AMOUNT,
    })
}

/// Asserts that the gas refund through native ETH is within the acceptable
/// tolerance
pub fn assert_native_eth_gas_refund(
    initial_eth_balance: U256,
    post_refund_eth_balance: U256,
    receipt: TransactionReceipt,
) -> Result<()> {
    let gas_price = receipt.effective_gas_price;
    let eth_diff = initial_eth_balance.checked_sub(post_refund_eth_balance).unwrap_or_default();
    let gas_diff = eth_diff / U256::from(gas_price);
    assert_true_result!(gas_diff < GAS_COST_TOLERANCE)
}
