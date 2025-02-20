//! Integration tests for atomic settlement

use ark_ff::One;
use contracts_common::{constants::TEST_MERKLE_HEIGHT, types::ScalarField};
use contracts_utils::merkle::new_ark_merkle_tree;
use ethers::{
    abi::Address,
    types::{TransactionReceipt, U256},
};
use eyre::Result;
use scripts::utils::LocalWalletHttpClient;
use test_helpers::{assert_eq_result, integration_test_async};

use crate::{
    abis::IAtomicMatchSettleContract,
    utils::{
        alloy_address_to_ethers_address, alloy_u256_to_ethers_u256, insert_shares_and_get_root,
        scalar_to_u256, serialize_to_calldata, setup_atomic_match_settle_test,
        setup_atomic_match_settle_test_native_eth, u256_to_alloy_u256, u256_to_scalar,
    },
    TestContext,
};

/// Test a successful call to `process_atomic_match_settle`
///
/// Validates only the state of the internal party after update
#[allow(non_snake_case)]
async fn test_process_atomic_match_settle__internal_party(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();
    let data = setup_atomic_match_settle_test(
        true,  // buy_side
        false, // use_gas_sponsor
        &ctx,
    )
    .await?;

    // Call process_atomic_match_settle
    contract
        .process_atomic_match_settle(
            serialize_to_calldata(&data.internal_party_match_payload)?,
            serialize_to_calldata(&data.valid_match_settle_atomic_statement)?,
            serialize_to_calldata(&data.match_atomic_proofs)?,
            serialize_to_calldata(&data.match_atomic_linking_proofs)?,
        )
        .send()
        .await?
        .await?;

    // Assert nullifier is spent
    let nullifier = scalar_to_u256(
        data.internal_party_match_payload.valid_reblind_statement.original_shares_nullifier,
    );
    let nullifier_spent = contract.is_nullifier_spent(nullifier).call().await?;
    assert!(nullifier_spent, "Nullifier not spent");

    // Verify merkle root
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);
    let expected_root = insert_shares_and_get_root(
        &mut ark_merkle,
        data.internal_party_match_payload
            .valid_reblind_statement
            .reblinded_private_shares_commitment,
        &data.valid_match_settle_atomic_statement.internal_party_modified_shares,
        0,
    )?;
    let actual_root = u256_to_scalar(contract.get_root().call().await?)?;
    assert_eq!(expected_root, actual_root, "Merkle root mismatch");

    Ok(())
}
integration_test_async!(test_process_atomic_match_settle__internal_party);

/// Test `process_atomic_match_settle` and verify the external party's state
/// after update. That is, the erc20 transfers that result from the atomic match
#[allow(non_snake_case)]
pub async fn _test_process_atomic_match_settle__external_party_buy_side(
    ctx: TestContext,
    contract: IAtomicMatchSettleContract<LocalWalletHttpClient>,
) -> Result<()> {
    // Setup test data
    let use_gas_sponsor = contract.address() == ctx.gas_sponsor_contract().address();
    let base_addr = ctx.test_erc20_address1;
    let quote_addr = ctx.test_erc20_address2;
    let darkpool = ctx.darkpool_contract();
    let data = setup_atomic_match_settle_test(
        true, // buy_side
        use_gas_sponsor,
        &ctx,
    )
    .await?;

    let relayer_fee_addr = alloy_address_to_ethers_address(
        &data.valid_match_settle_atomic_statement.relayer_fee_address,
    );
    let protocol_fee_addr = darkpool.get_protocol_external_fee_collection_address().call().await?;

    // Record initial balances
    let initial_base_balance = ctx.get_erc20_balance(base_addr).await?;
    let initial_quote_balance = ctx.get_erc20_balance(quote_addr).await?;
    let initial_relayer_balance = ctx.get_erc20_balance_of(base_addr, relayer_fee_addr).await?;
    let initial_protocol_balance = ctx.get_erc20_balance_of(base_addr, protocol_fee_addr).await?;

    // Call process_atomic_match_settle
    contract
        .process_atomic_match_settle(
            serialize_to_calldata(&data.internal_party_match_payload)?,
            serialize_to_calldata(&data.valid_match_settle_atomic_statement)?,
            serialize_to_calldata(&data.match_atomic_proofs)?,
            serialize_to_calldata(&data.match_atomic_linking_proofs)?,
        )
        .send()
        .await?
        .await?;

    // Verify updated erc20 balances
    let match_result = &data.valid_match_settle_atomic_statement.match_result;
    let fees = &data.valid_match_settle_atomic_statement.external_party_fees;
    let final_balance_base = ctx.get_erc20_balance(base_addr).await?;
    let final_balance_quote = ctx.get_erc20_balance(quote_addr).await?;
    let relayer_balance = ctx.get_erc20_balance_of(base_addr, relayer_fee_addr).await?;
    let protocol_balance = ctx.get_erc20_balance_of(base_addr, protocol_fee_addr).await?;

    let expected_quote_balance = initial_quote_balance - match_result.quote_amount;
    let expected_base_balance = initial_base_balance + match_result.base_amount - fees.total();
    let expected_relayer_balance = initial_relayer_balance + fees.relayer_fee;
    let expected_protocol_balance = initial_protocol_balance + fees.protocol_fee;

    assert_eq!(
        final_balance_base, expected_base_balance,
        "Unexpected change in base token balance"
    );
    assert_eq!(
        final_balance_quote, expected_quote_balance,
        "Unexpected change in quote token balance"
    );
    assert_eq!(
        relayer_balance, expected_relayer_balance,
        "Unexpected change in relayer fee balance"
    );
    assert_eq!(
        protocol_balance, expected_protocol_balance,
        "Unexpected change in protocol fee balance"
    );

    Ok(())
}

/// Run the `test_process_atomic_match_settle__external_party_buy_side` test
/// through the darkpool contract
#[allow(non_snake_case)]
async fn test_process_atomic_match_settle__external_party_buy_side(ctx: TestContext) -> Result<()> {
    let contract = IAtomicMatchSettleContract::new(ctx.darkpool_proxy_address, ctx.client.clone());
    _test_process_atomic_match_settle__external_party_buy_side(ctx, contract).await
}
integration_test_async!(test_process_atomic_match_settle__external_party_buy_side);

/// Test `process_atomic_match_settle` and verify the external party's state
/// after update. That is, the erc20 transfers that result from the atomic match
#[allow(non_snake_case)]
pub async fn _test_process_atomic_match_settle__external_party_sell_side(
    ctx: TestContext,
    contract: IAtomicMatchSettleContract<LocalWalletHttpClient>,
) -> Result<()> {
    // Setup test data
    let use_gas_sponsor = contract.address() == ctx.gas_sponsor_contract().address();
    let base_addr = ctx.test_erc20_address1;
    let quote_addr = ctx.test_erc20_address2;
    let darkpool = ctx.darkpool_contract();
    let data = setup_atomic_match_settle_test(
        false, // buy_side
        use_gas_sponsor,
        &ctx,
    )
    .await?;

    let relayer_fee_addr = alloy_address_to_ethers_address(
        &data.valid_match_settle_atomic_statement.relayer_fee_address,
    );
    let protocol_fee_addr = darkpool.get_protocol_external_fee_collection_address().call().await?;

    // Record initial balances
    let initial_base_balance = ctx.get_erc20_balance(base_addr).await?;
    let initial_quote_balance = ctx.get_erc20_balance(quote_addr).await?;
    let initial_relayer_balance = ctx.get_erc20_balance_of(quote_addr, relayer_fee_addr).await?;
    let initial_protocol_balance = ctx.get_erc20_balance_of(quote_addr, protocol_fee_addr).await?;

    // Call process_atomic_match_settle
    contract
        .process_atomic_match_settle(
            serialize_to_calldata(&data.internal_party_match_payload)?,
            serialize_to_calldata(&data.valid_match_settle_atomic_statement)?,
            serialize_to_calldata(&data.match_atomic_proofs)?,
            serialize_to_calldata(&data.match_atomic_linking_proofs)?,
        )
        .send()
        .await?
        .await?;

    // Verify updated erc20 balances
    let match_result = &data.valid_match_settle_atomic_statement.match_result;
    let fees = &data.valid_match_settle_atomic_statement.external_party_fees;
    let final_balance_base = ctx.get_erc20_balance(base_addr).await?;
    let final_balance_quote = ctx.get_erc20_balance(quote_addr).await?;
    let relayer_balance = ctx.get_erc20_balance_of(quote_addr, relayer_fee_addr).await?;
    let protocol_balance = ctx.get_erc20_balance_of(quote_addr, protocol_fee_addr).await?;

    let expected_quote_balance = initial_quote_balance + match_result.quote_amount - fees.total();
    let expected_base_balance = initial_base_balance - match_result.base_amount;
    let expected_relayer_balance = initial_relayer_balance + fees.relayer_fee;
    let expected_protocol_balance = initial_protocol_balance + fees.protocol_fee;

    assert_eq!(
        final_balance_base, expected_base_balance,
        "Unexpected change in base token balance"
    );
    assert_eq!(
        final_balance_quote, expected_quote_balance,
        "Unexpected change in quote token balance"
    );
    assert_eq!(
        relayer_balance, expected_relayer_balance,
        "Unexpected change in relayer fee balance"
    );
    assert_eq!(
        protocol_balance, expected_protocol_balance,
        "Unexpected change in protocol fee balance"
    );

    Ok(())
}

/// Run the `test_process_atomic_match_settle__external_party_sell_side` test
/// through the darkpool contract
#[allow(non_snake_case)]
async fn test_process_atomic_match_settle__external_party_sell_side(
    ctx: TestContext,
) -> Result<()> {
    let contract = IAtomicMatchSettleContract::new(ctx.darkpool_proxy_address, ctx.client.clone());
    _test_process_atomic_match_settle__external_party_sell_side(ctx, contract).await
}
integration_test_async!(test_process_atomic_match_settle__external_party_sell_side);

/// Test `process_atomic_match_settle` with the native asset
#[allow(non_snake_case)]
pub async fn _test_process_atomic_match_settle__native_asset_sell_side(
    ctx: TestContext,
    contract: IAtomicMatchSettleContract<LocalWalletHttpClient>,
) -> Result<()> {
    // Setup test data
    let use_gas_sponsor = contract.address() == ctx.gas_sponsor_contract().address();
    let quote_addr = ctx.test_erc20_address2;
    let darkpool = ctx.darkpool_contract();
    let data = setup_atomic_match_settle_test_native_eth(
        false, // buy_side
        use_gas_sponsor,
        &ctx,
    )
    .await?;

    let relayer_fee_addr = alloy_address_to_ethers_address(
        &data.valid_match_settle_atomic_statement.relayer_fee_address,
    );
    let protocol_fee_addr = darkpool.get_protocol_external_fee_collection_address().call().await?;

    // Record initial balances
    let initial_eth_balance = ctx.get_eth_balance().await?;
    let initial_quote_balance = ctx.get_erc20_balance(quote_addr).await?;
    let initial_relayer_balance = ctx.get_erc20_balance_of(quote_addr, relayer_fee_addr).await?;
    let initial_protocol_balance = ctx.get_erc20_balance_of(quote_addr, protocol_fee_addr).await?;

    // Call process_atomic_match_settle
    let base_amount = data.valid_match_settle_atomic_statement.match_result.base_amount;
    let value = alloy_u256_to_ethers_u256(base_amount);
    let receipt: TransactionReceipt = darkpool
        .process_atomic_match_settle(
            serialize_to_calldata(&data.internal_party_match_payload)?,
            serialize_to_calldata(&data.valid_match_settle_atomic_statement)?,
            serialize_to_calldata(&data.match_atomic_proofs)?,
            serialize_to_calldata(&data.match_atomic_linking_proofs)?,
        )
        .value(value)
        .send()
        .await?
        .await?
        .expect("no tx receipt");

    let gas_used = receipt.gas_used.unwrap();
    let gas_price = receipt.effective_gas_price.unwrap();
    let eth_gas_cost = u256_to_alloy_u256(gas_used * gas_price);

    // Verify updated erc20 balances
    let match_result = &data.valid_match_settle_atomic_statement.match_result;
    let fees = &data.valid_match_settle_atomic_statement.external_party_fees;
    let final_balance_eth = ctx.get_eth_balance().await?;
    let final_balance_quote = ctx.get_erc20_balance(quote_addr).await?;
    let relayer_balance = ctx.get_erc20_balance_of(quote_addr, relayer_fee_addr).await?;
    let protocol_balance = ctx.get_erc20_balance_of(quote_addr, protocol_fee_addr).await?;

    let expected_quote_balance = initial_quote_balance + match_result.quote_amount - fees.total();
    let expected_eth_balance = initial_eth_balance - match_result.base_amount - eth_gas_cost;
    let expected_relayer_balance = initial_relayer_balance + fees.relayer_fee;
    let expected_protocol_balance = initial_protocol_balance + fees.protocol_fee;

    assert_eq!(final_balance_eth, expected_eth_balance, "Unexpected change in ETH balance");
    assert_eq!(
        final_balance_quote, expected_quote_balance,
        "Unexpected change in quote token balance"
    );
    assert_eq!(
        relayer_balance, expected_relayer_balance,
        "Unexpected change in relayer fee balance"
    );
    assert_eq!(
        protocol_balance, expected_protocol_balance,
        "Unexpected change in protocol fee balance"
    );

    Ok(())
}

/// Run the `test_process_atomic_match_settle__native_asset_sell_side` test
/// through the darkpool contract
#[allow(non_snake_case)]
async fn test_process_atomic_match_settle__native_asset_sell_side(ctx: TestContext) -> Result<()> {
    let contract = IAtomicMatchSettleContract::new(ctx.darkpool_proxy_address, ctx.client.clone());
    _test_process_atomic_match_settle__native_asset_sell_side(ctx, contract).await
}
integration_test_async!(test_process_atomic_match_settle__native_asset_sell_side);

/// Test `process_atomic_match_settle` with native asset on buy side
#[allow(non_snake_case)]
pub async fn _test_process_atomic_match_settle__native_asset_buy_side(
    ctx: TestContext,
    contract: IAtomicMatchSettleContract<LocalWalletHttpClient>,
) -> Result<()> {
    let use_gas_sponsor = contract.address() == ctx.gas_sponsor_contract().address();
    let quote_addr = ctx.test_erc20_address2;
    let darkpool = ctx.darkpool_contract();
    let data = setup_atomic_match_settle_test_native_eth(
        true, // buy_side
        use_gas_sponsor,
        &ctx,
    )
    .await?;

    let relayer_fee_addr = alloy_address_to_ethers_address(
        &data.valid_match_settle_atomic_statement.relayer_fee_address,
    );
    let protocol_fee_addr = darkpool.get_protocol_external_fee_collection_address().call().await?;

    // Get initial balances
    let initial_eth_balance = ctx.get_eth_balance().await?;
    let initial_quote_balance = ctx.get_erc20_balance(quote_addr).await?;
    let initial_relayer_balance = ctx.get_eth_balance_of(relayer_fee_addr).await?;
    let initial_protocol_balance = ctx.get_eth_balance_of(protocol_fee_addr).await?;

    let receipt: TransactionReceipt = contract
        .process_atomic_match_settle(
            serialize_to_calldata(&data.internal_party_match_payload)?,
            serialize_to_calldata(&data.valid_match_settle_atomic_statement)?,
            serialize_to_calldata(&data.match_atomic_proofs)?,
            serialize_to_calldata(&data.match_atomic_linking_proofs)?,
        )
        .send()
        .await?
        .await?
        .expect("no tx receipt");

    let gas_used = receipt.gas_used.unwrap();
    let gas_price = receipt.effective_gas_price.unwrap();
    let eth_gas_cost = u256_to_alloy_u256(gas_used * gas_price);

    // Verify updated erc20 balances
    let match_result = &data.valid_match_settle_atomic_statement.match_result;
    let fees = &data.valid_match_settle_atomic_statement.external_party_fees;
    let final_balance_eth = ctx.get_eth_balance().await?;
    let final_balance_quote = ctx.get_erc20_balance(quote_addr).await?;
    let relayer_balance = ctx.get_eth_balance_of(relayer_fee_addr).await?;
    let protocol_balance = ctx.get_eth_balance_of(protocol_fee_addr).await?;

    let expected_quote_balance = initial_quote_balance - match_result.quote_amount;
    let expected_eth_balance =
        initial_eth_balance - eth_gas_cost + match_result.base_amount - fees.total();
    let expected_relayer_balance = initial_relayer_balance + fees.relayer_fee;
    let expected_protocol_balance = initial_protocol_balance + fees.protocol_fee;

    assert_eq!(final_balance_eth, expected_eth_balance, "Unexpected change in ETH balance");
    assert_eq!(
        final_balance_quote, expected_quote_balance,
        "Unexpected change in quote token balance"
    );
    assert_eq!(
        relayer_balance, expected_relayer_balance,
        "Unexpected change in relayer fee balance"
    );
    assert_eq!(
        protocol_balance, expected_protocol_balance,
        "Unexpected change in protocol fee balance"
    );

    Ok(())
}

/// Run the `test_process_atomic_match_settle__native_asset_buy_side` test
/// through the darkpool contract
#[allow(non_snake_case)]
async fn test_process_atomic_match_settle__native_asset_buy_side(ctx: TestContext) -> Result<()> {
    let contract = IAtomicMatchSettleContract::new(ctx.darkpool_proxy_address, ctx.client.clone());
    _test_process_atomic_match_settle__native_asset_buy_side(ctx, contract).await
}
integration_test_async!(test_process_atomic_match_settle__native_asset_buy_side);

/// Test `process_atomic_match_settle` with inconsistent indices
async fn test_process_atomic_match_settle_inconsistent_indices(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();
    let mut data = setup_atomic_match_settle_test(
        true,  // buy_side
        false, // use_gas_sponsor
        &ctx,
    )
    .await?;

    // Modify the index to make it inconsistent
    data.valid_match_settle_atomic_statement.internal_party_indices.balance_receive += 1;

    // Call process_atomic_match_settle
    let call = contract.process_atomic_match_settle(
        serialize_to_calldata(&data.internal_party_match_payload)?,
        serialize_to_calldata(&data.valid_match_settle_atomic_statement)?,
        serialize_to_calldata(&data.match_atomic_proofs)?,
        serialize_to_calldata(&data.match_atomic_linking_proofs)?,
    );
    let result = call.send().await;

    assert!(result.is_err(), "Expected error due to inconsistent indices");

    Ok(())
}
integration_test_async!(test_process_atomic_match_settle_inconsistent_indices);

/// Test `process_atomic_match_settle` with inconsistent protocol fee
async fn test_process_atomic_match_settle_inconsistent_protocol_fee(
    ctx: TestContext,
) -> Result<()> {
    let contract = ctx.darkpool_contract();
    let mut data = setup_atomic_match_settle_test(
        true,  // buy_side
        false, // use_gas_sponsor
        &ctx,
    )
    .await?;

    // Modify the protocol fee to make it inconsistent
    data.valid_match_settle_atomic_statement.protocol_fee += ScalarField::one();

    // Call process_atomic_match_settle
    let call = contract.process_atomic_match_settle(
        serialize_to_calldata(&data.internal_party_match_payload)?,
        serialize_to_calldata(&data.valid_match_settle_atomic_statement)?,
        serialize_to_calldata(&data.match_atomic_proofs)?,
        serialize_to_calldata(&data.match_atomic_linking_proofs)?,
    );
    let result = call.send().await;

    assert!(result.is_err(), "Expected error due to inconsistent protocol fee");

    Ok(())
}
integration_test_async!(test_process_atomic_match_settle_inconsistent_protocol_fee);

/// Test `process_atomic_match_settle` with invalid transaction value
async fn test_process_atomic_match_settle_invalid_transaction_value(
    ctx: TestContext,
) -> Result<()> {
    let contract = ctx.darkpool_contract();
    let data = setup_atomic_match_settle_test_native_eth(
        false, // buy_side
        false, // use_gas_sponsor
        &ctx,
    )
    .await?;

    // Try to execute with insufficient ETH value
    let required_eth_value = data.valid_match_settle_atomic_statement.match_result.base_amount;
    let insufficient_value = alloy_u256_to_ethers_u256(required_eth_value) - U256::from(1);
    let call = contract
        .process_atomic_match_settle(
            serialize_to_calldata(&data.internal_party_match_payload)?,
            serialize_to_calldata(&data.valid_match_settle_atomic_statement)?,
            serialize_to_calldata(&data.match_atomic_proofs)?,
            serialize_to_calldata(&data.match_atomic_linking_proofs)?,
        )
        .value(insufficient_value);
    let result = call.send().await;
    assert!(result.is_err(), "Transaction with insufficient ETH value should fail");

    Ok(())
}
integration_test_async!(test_process_atomic_match_settle_invalid_transaction_value);

/// Test `process_atomic_match_settle` with non-zero transaction value when it
/// should be zero
async fn test_process_atomic_match_settle_nonzero_transaction_value(
    ctx: TestContext,
) -> Result<()> {
    let contract = ctx.darkpool_contract();
    let data = setup_atomic_match_settle_test_native_eth(
        true,  // buy_side
        false, // use_gas_sponsor
        &ctx,
    )
    .await?;

    // Try to execute with non-zero ETH value when it should be zero for buy-side
    let call = contract
        .process_atomic_match_settle(
            serialize_to_calldata(&data.internal_party_match_payload)?,
            serialize_to_calldata(&data.valid_match_settle_atomic_statement)?,
            serialize_to_calldata(&data.match_atomic_proofs)?,
            serialize_to_calldata(&data.match_atomic_linking_proofs)?,
        )
        .value(U256::from(1)); // Set non-zero value when it should be zero

    let result = call.send().await;
    assert!(result.is_err(), "Transaction with non-zero ETH value should fail for buy-side match");
    Ok(())
}
integration_test_async!(test_process_atomic_match_settle_nonzero_transaction_value);

/// Test the `process_atomic_match_settle_with_receiver` method on the darkpool
///
/// I.e. test an atomic settlement with a non-sender receiver specified
pub async fn _test_process_atomic_match_settle_with_receiver(
    ctx: TestContext,
    contract: IAtomicMatchSettleContract<LocalWalletHttpClient>,
) -> Result<()> {
    // Setup test with a random receiver address
    let use_gas_sponsor = contract.address() == ctx.gas_sponsor_contract().address();
    let receiver = Address::random();
    let base_addr = ctx.test_erc20_address1;
    let quote_addr = ctx.test_erc20_address2;
    let data = setup_atomic_match_settle_test(
        true, // buy_side
        use_gas_sponsor,
        &ctx,
    )
    .await?;

    // Get pre-balances
    let darkpool_addr = ctx.darkpool_contract().address();
    let sender_pre_base_balance = ctx.get_erc20_balance(base_addr).await?;
    let sender_pre_quote_balance = ctx.get_erc20_balance(quote_addr).await?;
    let receiver_pre_base_balance = ctx.get_erc20_balance_of(base_addr, receiver).await?;
    let receiver_pre_quote_balance = ctx.get_erc20_balance_of(quote_addr, receiver).await?;
    let darkpool_pre_base_balance = ctx.get_erc20_balance_of(base_addr, darkpool_addr).await?;
    let darkpool_pre_quote_balance = ctx.get_erc20_balance_of(quote_addr, darkpool_addr).await?;

    // Execute match with specified receiver
    contract
        .process_atomic_match_settle_with_receiver(
            receiver,
            serialize_to_calldata(&data.internal_party_match_payload)?,
            serialize_to_calldata(&data.valid_match_settle_atomic_statement)?,
            serialize_to_calldata(&data.match_atomic_proofs)?,
            serialize_to_calldata(&data.match_atomic_linking_proofs)?,
        )
        .send()
        .await?;

    // Get post-balances for receiver
    let sender_post_base_balance = ctx.get_erc20_balance(base_addr).await?;
    let sender_post_quote_balance = ctx.get_erc20_balance(quote_addr).await?;
    let receiver_post_base_balance = ctx.get_erc20_balance_of(base_addr, receiver).await?;
    let receiver_post_quote_balance = ctx.get_erc20_balance_of(quote_addr, receiver).await?;
    let darkpool_post_base_balance = ctx.get_erc20_balance_of(base_addr, darkpool_addr).await?;
    let darkpool_post_quote_balance = ctx.get_erc20_balance_of(quote_addr, darkpool_addr).await?;

    // Verify receiver balances changed correctly
    let fees = &data.valid_match_settle_atomic_statement.external_party_fees;
    let base_amount = data.valid_match_settle_atomic_statement.match_result.base_amount;
    let quote_amount = data.valid_match_settle_atomic_statement.match_result.quote_amount;
    let expected_sender_base_balance = sender_pre_base_balance; // Unchanged
    let expected_sender_quote_balance = sender_pre_quote_balance - quote_amount;
    let expected_receiver_base_balance = receiver_pre_base_balance + base_amount - fees.total();
    let expected_receiver_quote_balance = receiver_pre_quote_balance; // Unchanged
    let expected_darkpool_base_balance = darkpool_pre_base_balance - base_amount;
    let expected_darkpool_quote_balance = darkpool_pre_quote_balance + quote_amount;

    assert_eq!(
        sender_post_base_balance, expected_sender_base_balance,
        "Sender's base balance change incorrect"
    );
    assert_eq!(
        sender_post_quote_balance, expected_sender_quote_balance,
        "Sender's quote balance change incorrect"
    );
    assert_eq!(
        receiver_post_base_balance, expected_receiver_base_balance,
        "Receiver's base balance change incorrect"
    );
    assert_eq!(
        receiver_post_quote_balance, expected_receiver_quote_balance,
        "Receiver's quote balance change incorrect"
    );
    assert_eq!(
        darkpool_post_base_balance, expected_darkpool_base_balance,
        "Darkpool's base balance change incorrect"
    );
    assert_eq!(
        darkpool_post_quote_balance, expected_darkpool_quote_balance,
        "Darkpool's quote balance change incorrect"
    );

    Ok(())
}

/// Run the `test_process_atomic_match_settle_with_receiver` test
/// through the darkpool contract
#[allow(non_snake_case)]
async fn test_process_atomic_match_settle_with_receiver(ctx: TestContext) -> Result<()> {
    let contract = IAtomicMatchSettleContract::new(ctx.darkpool_proxy_address, ctx.client.clone());
    _test_process_atomic_match_settle_with_receiver(ctx, contract).await
}
integration_test_async!(test_process_atomic_match_settle_with_receiver);

/// Test the `process_atomic_match_settle` method with a fee override
#[allow(non_snake_case)]
async fn test_atomic_match_settle__fee_override(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Override the fee to twice the original
    let base = ctx.test_erc20_address1;
    let fee: U256 = contract.get_external_match_fee_for_asset(base).call().await?;
    let new_fee = fee * U256::from(2);
    contract.set_external_match_fee_override(base, new_fee).send().await?;

    // Get the fee from the contract
    let fee: U256 = contract.get_external_match_fee_for_asset(base).call().await?;
    assert_eq_result!(fee, new_fee)?;

    // Call process_atomic_match_settle with the new fee
    let data = setup_atomic_match_settle_test(
        true,  // buy_side
        false, // use_gas_sponsor
        &ctx,
    )
    .await?;
    let expected_fee = u256_to_scalar(new_fee)?;
    assert_eq_result!(data.valid_match_settle_atomic_statement.protocol_fee, expected_fee)?;

    let call = contract.process_atomic_match_settle(
        serialize_to_calldata(&data.internal_party_match_payload)?,
        serialize_to_calldata(&data.valid_match_settle_atomic_statement)?,
        serialize_to_calldata(&data.match_atomic_proofs)?,
        serialize_to_calldata(&data.match_atomic_linking_proofs)?,
    );
    call.send().await?;

    // Remove the fee override
    contract.remove_external_match_fee_override(base).send().await?;

    // Check that the fee is back to the default
    let default_fee: U256 = contract.get_fee().call().await?;
    let base_fee: U256 = contract.get_external_match_fee_for_asset(base).call().await?;
    assert_eq_result!(base_fee, default_fee)?;

    // Call process_atomic_match_settle again with the default fee
    let data = setup_atomic_match_settle_test(
        true,  // buy_side
        false, // use_gas_sponsor
        &ctx,
    )
    .await?;
    let expected_fee = u256_to_scalar(default_fee)?;
    assert_eq_result!(data.valid_match_settle_atomic_statement.protocol_fee, expected_fee)?;

    let call = contract.process_atomic_match_settle(
        serialize_to_calldata(&data.internal_party_match_payload)?,
        serialize_to_calldata(&data.valid_match_settle_atomic_statement)?,
        serialize_to_calldata(&data.match_atomic_proofs)?,
        serialize_to_calldata(&data.match_atomic_linking_proofs)?,
    );
    call.send().await?;

    Ok(())
}
integration_test_async!(test_atomic_match_settle__fee_override);
