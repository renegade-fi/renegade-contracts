//! Integration testing utilities for sponsored matches

use alloy_primitives::U256 as AlloyU256;
use ark_std::UniformRand;
use contracts_common::{constants::NUM_BYTES_U256, types::ScalarField};
use contracts_utils::{
    crypto::hash_and_sign_message, proof_system::test_data::SponsoredAtomicMatchSettleData,
};
use ethers::{
    types::{Address, Bytes, TransactionReceipt, U256},
    utils::{parse_ether, WEI_IN_ETHER},
};
use eyre::Result;
use rand::thread_rng;
use tracing::info;

use crate::{
    abis::DummyErc20Contract,
    constants::{CONVERSION_RATE, GAS_COST_TOLERANCE},
    utils::u256_to_alloy_u256,
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
    ctx.gas_sponsor_contract().unpause().send().await?.await?;

    let mut process_atomic_match_settle_data =
        setup_atomic_match_settle_test(!options.sell_side, true /* use_gas_sponsor */, ctx).await?;

    if options.trade_native_eth {
        // Replace the base mint with the native ETH address
        process_atomic_match_settle_data
            .valid_match_settle_atomic_statement
            .match_result
            .base_mint = native_eth_address();
    }

    let is_native_eth_buy = options.trade_native_eth && !options.sell_side;

    let mut rng = thread_rng();
    let nonce = scalar_to_u256(ScalarField::rand(&mut rng));
    let mut nonce_bytes = [0_u8; NUM_BYTES_U256];
    nonce.to_big_endian(&mut nonce_bytes);

    let conversion_rate =
        if options.in_kind_refund && !is_native_eth_buy { CONVERSION_RATE } else { U256::zero() };
    let mut conversion_rate_bytes = [0_u8; NUM_BYTES_U256];
    conversion_rate.to_big_endian(&mut conversion_rate_bytes);

    let mut message = Vec::new();
    message.extend_from_slice(&nonce_bytes);
    message.extend_from_slice(options.refund_address.as_bytes());

    if options.in_kind_refund {
        // Add the conversion rate to the message if this is not a native ETH buy
        if !is_native_eth_buy {
            message.extend_from_slice(&conversion_rate_bytes);
        }

        // Fund the gas sponsor with some ERC20s
        let erc20_addr1 = DummyErc20Contract::new(ctx.test_erc20_address1, ctx.client.clone());
        erc20_addr1.mint(ctx.gas_sponsor_proxy_address, parse_ether("0.05")?).send().await?.await?;
        let erc20_addr2 = DummyErc20Contract::new(ctx.test_erc20_address2, ctx.client.clone());
        erc20_addr2.mint(ctx.gas_sponsor_proxy_address, parse_ether("0.05")?).send().await?.await?;
    }

    let signature = Bytes::from(hash_and_sign_message(ctx.signing_key(), &message).to_vec());

    // Fund the gas sponsor with some ETH
    ctx.gas_sponsor_contract().receive_eth().value(parse_ether("0.1")?).send().await?.await?;

    Ok(SponsoredAtomicMatchSettleData {
        process_atomic_match_settle_data,
        nonce,
        signature,
        refund_address: options.refund_address,
        receiver: options.receiver,
        refund_native_eth: !options.in_kind_refund,
        conversion_rate,
    })
}

/// Asserts that the gas refund through the buy-side token is within the
/// acceptable tolerance.
/// The conversion rate is expected to be in units of token/eth.
pub fn assert_token_gas_refund(
    gas_sponsor_initial_balance: AlloyU256,
    gas_sponsor_final_balance: AlloyU256,
    conversion_rate: U256,
    receipt: TransactionReceipt,
) {
    // Get the conversion rate in units of wei/token
    let alloy_inv_conversion_rate = u256_to_alloy_u256(WEI_IN_ETHER / conversion_rate);

    let gas_units_used = u256_to_alloy_u256(receipt.gas_used.unwrap());
    let gas_price = u256_to_alloy_u256(receipt.effective_gas_price.unwrap());

    let gas_units_refunded = ((gas_sponsor_initial_balance - gas_sponsor_final_balance)
        * alloy_inv_conversion_rate)
        / gas_price;

    info!("gas units used: {}", gas_units_used);
    info!("gas units refunded: {}", gas_units_refunded);

    let gas_diff = gas_units_used.checked_sub(gas_units_refunded).unwrap_or_default();
    assert!(gas_diff < GAS_COST_TOLERANCE, "Unrefunded gas amount of {gas_diff} is too high");
}

/// Asserts that the gas refund through native ETH is within the acceptable
/// tolerance
pub fn assert_native_eth_gas_refund(
    initial_eth_balance: AlloyU256,
    post_refund_eth_balance: AlloyU256,
    receipt: TransactionReceipt,
) {
    let gas_price = u256_to_alloy_u256(receipt.effective_gas_price.unwrap());
    let eth_diff = initial_eth_balance.checked_sub(post_refund_eth_balance).unwrap_or_default();
    let gas_diff = eth_diff / gas_price;
    assert!(gas_diff < GAS_COST_TOLERANCE, "Unrefunded gas amount of {gas_diff} is too high");
}
