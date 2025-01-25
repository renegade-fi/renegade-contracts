//! Integration tests for external transfer functionality

use alloy_primitives::Address as AlloyAddress;
use contracts_utils::crypto::random_keypair;
use ethers::{abi::Address, providers::Middleware, types::U256};
use eyre::Result;
use rand::thread_rng;
use scripts::constants::TEST_FUNDING_AMOUNT;
use test_helpers::integration_test_async;

use crate::{
    abis::{DummyErc20Contract, TransferExecutorContract},
    utils::{
        dummy_erc20_deposit, dummy_erc20_withdrawal, execute_transfer_and_get_balances,
        gen_transfer_aux_data, serialize_to_calldata,
    },
    TestContext,
};

/// Test deposit / withdrawal functionality of the darkpool
async fn test_external_transfer(ctx: TestContext) -> Result<()> {
    let transfer_executor_contract =
        TransferExecutorContract::new(ctx.transfer_executor_address, ctx.client.clone());

    // Initialize the transfer executor with the address of the Permit2 contract
    // being used
    transfer_executor_contract.init(ctx.permit2_address).send().await?.await?;

    let test_erc20_contract = DummyErc20Contract::new(ctx.test_erc20_address1, ctx.client.clone());

    let account_address = ctx.client.default_sender().unwrap();
    let mint = ctx.test_erc20_address1;

    let contract_initial_balance =
        test_erc20_contract.balance_of(ctx.transfer_executor_address).call().await?;
    let user_initial_balance = test_erc20_contract.balance_of(account_address).call().await?;

    let (signing_key, pk_root) = random_keypair(&mut thread_rng());

    // Create & execute deposit external transfer, check balances
    let deposit = dummy_erc20_deposit(account_address, mint);
    let (contract_balance, user_balance) = execute_transfer_and_get_balances(
        &transfer_executor_contract,
        &test_erc20_contract,
        ctx.permit2_address,
        &signing_key,
        pk_root,
        &deposit,
        account_address,
    )
    .await?;
    assert_eq!(
        contract_balance,
        contract_initial_balance + TEST_FUNDING_AMOUNT,
        "Post-deposit contract balance incorrect"
    );
    assert_eq!(
        user_balance,
        user_initial_balance - TEST_FUNDING_AMOUNT,
        "Post-deposit user balance incorrect"
    );

    // Create & execute withdrawal external transfer, check balances
    let withdrawal = dummy_erc20_withdrawal(account_address, mint);
    let (contract_balance, user_balance) = execute_transfer_and_get_balances(
        &transfer_executor_contract,
        &test_erc20_contract,
        ctx.permit2_address,
        &signing_key,
        pk_root,
        &withdrawal,
        account_address,
    )
    .await?;
    assert_eq!(
        contract_balance, contract_initial_balance,
        "Post-withdrawal contract balance incorrect"
    );
    assert_eq!(user_balance, user_initial_balance, "Post-withdrawal user balance incorrect");

    Ok(())
}
integration_test_async!(test_external_transfer);

/// Test that a deposit specified from a different ETH address is rejected
#[allow(non_snake_case)]
async fn test_external_transfer__wrong_eth_addr(ctx: TestContext) -> Result<()> {
    let transfer_executor_contract =
        TransferExecutorContract::new(ctx.transfer_executor_address, ctx.client.clone());

    // Initialize the transfer executor with the address of the Permit2 contract
    // being used
    transfer_executor_contract.init(ctx.permit2_address).send().await?.await?;

    let test_erc20_contract = DummyErc20Contract::new(ctx.test_erc20_address1, ctx.client.clone());

    let account_address = ctx.client.default_sender().unwrap();
    let mint = ctx.test_erc20_address1;

    // Generate dummy address & fund with some ERC20 tokens
    // (lack of funding should not be the reason the test fails)
    let dummy_address = Address::random();
    test_erc20_contract.mint(dummy_address, U256::from(TEST_FUNDING_AMOUNT)).send().await?.await?;

    let (signing_key, pk_root) = random_keypair(&mut thread_rng());

    // Create & execute deposit external transfer, attempting to deposit from the
    // dummy address
    let deposit = dummy_erc20_deposit(dummy_address, mint);
    assert!(
        execute_transfer_and_get_balances(
            &transfer_executor_contract,
            &test_erc20_contract,
            ctx.permit2_address,
            &signing_key,
            pk_root,
            &deposit,
            account_address,
        )
        .await
        .is_err(),
        "Deposit from wrong ETH address succeeded"
    );

    Ok(())
}
integration_test_async!(test_external_transfer__wrong_eth_addr);

/// Test that a deposit directed to a different Renegade wallet is rejected
#[allow(non_snake_case)]
async fn test_external_transfer__wrong_rng_wallet(ctx: TestContext) -> Result<()> {
    let mut rng = thread_rng();

    let transfer_executor_contract =
        TransferExecutorContract::new(ctx.transfer_executor_address, ctx.client.clone());

    // Initialize the transfer executor with the address of the Permit2 contract
    // being used
    transfer_executor_contract.init(ctx.permit2_address).send().await?.await?;

    let account_address = ctx.client.default_sender().unwrap();
    let mint = ctx.test_erc20_address1;

    let (signing_key, pk_root) = random_keypair(&mut rng);

    // Create a valid deposit w/ accompanying aux data
    let deposit = dummy_erc20_deposit(account_address, mint);
    let transfer_aux_data = gen_transfer_aux_data(
        &signing_key,
        pk_root,
        &deposit,
        ctx.permit2_address,
        &transfer_executor_contract,
    )
    .await?;

    // Execute the deposit with a pk_root that does not match the one in the aux
    // data
    let (_, dummy_pk_root) = random_keypair(&mut rng);
    assert!(
        transfer_executor_contract
            .execute_external_transfer(
                serialize_to_calldata(&dummy_pk_root)?,
                serialize_to_calldata(&deposit)?,
                serialize_to_calldata(&transfer_aux_data)?,
            )
            .send()
            .await
            .is_err(),
        "Deposit to wrong Renegade wallet succeeded"
    );

    Ok(())
}
integration_test_async!(test_external_transfer__wrong_rng_wallet);

/// Test that a malformed withdrawal is rejected
#[allow(non_snake_case)]
async fn test_external_transfer__malicious_withdrawal(ctx: TestContext) -> Result<()> {
    let transfer_executor_contract =
        TransferExecutorContract::new(ctx.transfer_executor_address, ctx.client.clone());

    // Initialize the transfer executor with the address of the Permit2 contract
    // being used
    transfer_executor_contract.init(ctx.permit2_address).send().await?.await?;

    let test_erc20_contract = DummyErc20Contract::new(ctx.test_erc20_address1, ctx.client.clone());

    let account_address = ctx.client.default_sender().unwrap();
    let mint = ctx.test_erc20_address1;

    // Fund contract with some ERC20 tokens
    // (lack of funding should not be the reason the test fails)
    test_erc20_contract
        .mint(ctx.transfer_executor_address, U256::from(TEST_FUNDING_AMOUNT))
        .send()
        .await?
        .await?;

    let (signing_key, pk_root) = random_keypair(&mut thread_rng());

    // Create withdrawal external transfer & aux data
    let mut withdrawal = dummy_erc20_withdrawal(account_address, mint);
    let transfer_aux_data = gen_transfer_aux_data(
        &signing_key,
        pk_root,
        &withdrawal,
        ctx.permit2_address,
        &transfer_executor_contract,
    )
    .await?;

    // Tamper with withdrawal by attempting to specify a dummy recipient
    let dummy_address = Address::random();
    withdrawal.account_addr = AlloyAddress::from_slice(dummy_address.as_bytes());

    // Attempt to execute withdrawal
    assert!(
        transfer_executor_contract
            .execute_external_transfer(
                serialize_to_calldata(&pk_root)?,
                serialize_to_calldata(&withdrawal)?,
                serialize_to_calldata(&transfer_aux_data)?,
            )
            .send()
            .await
            .is_err(),
        "Malicious withdrawal succeeded"
    );

    // Burn contract tokens so future tests are unaffected
    test_erc20_contract
        .burn(ctx.transfer_executor_address, U256::from(TEST_FUNDING_AMOUNT))
        .send()
        .await?
        .await?;

    Ok(())
}
integration_test_async!(test_external_transfer__malicious_withdrawal);
