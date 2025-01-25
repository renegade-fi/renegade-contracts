//! Integration tests for darkpool contract admin controls

use ark_ff::UniformRand;
use circuit_types::fixed_point::FixedPoint;
use constants::Scalar;
use contracts_common::{
    constants::{
        CORE_SETTLEMENT_ADDRESS_SELECTOR, CORE_WALLET_OPS_ADDRESS_SELECTOR,
        MERKLE_ADDRESS_SELECTOR, TRANSFER_EXECUTOR_ADDRESS_SELECTOR,
        VERIFIER_CORE_ADDRESS_SELECTOR, VERIFIER_SETTLEMENT_ADDRESS_SELECTOR,
        VKEYS_ADDRESS_SELECTOR,
    },
    types::ScalarField,
};
use contracts_utils::proof_system::test_data::{
    gen_new_wallet_data, gen_process_match_settle_data, gen_settle_online_relayer_fee_data,
    gen_update_wallet_data,
};
use ethers::{
    abi::Address,
    providers::Middleware,
    types::{Bytes, TransactionRequest, U256},
    utils::parse_ether,
};
use eyre::Result;
use rand::thread_rng;
use test_helpers::integration_test_async;

use crate::{
    abis::{DarkpoolProxyAdminContract, DarkpoolTestContract, DummyUpgradeTargetContract},
    constants::{
        PAUSE_METHOD_NAME, SET_CORE_SETTLEMENT_ADDRESS_METHOD_NAME,
        SET_CORE_WALLET_OPS_ADDRESS_METHOD_NAME, SET_FEE_METHOD_NAME,
        SET_MERKLE_ADDRESS_METHOD_NAME, SET_TRANSFER_EXECUTOR_ADDRESS_METHOD_NAME,
        SET_VERIFIER_CORE_ADDRESS_METHOD_NAME, SET_VERIFIER_SETTLEMENT_ADDRESS_METHOD_NAME,
        SET_VKEYS_ADDRESS_METHOD_NAME, TRANSFER_OWNERSHIP_METHOD_NAME, UNPAUSE_METHOD_NAME,
    },
    utils::{
        assert_all_revert, assert_all_succeed, assert_only_owner, scalar_to_u256,
        serialize_to_calldata, setup_dummy_client, u256_to_scalar,
    },
    TestContext,
};

/// Test the upgradeability of the darkpool
async fn test_upgradeable(ctx: TestContext) -> Result<()> {
    let proxy_admin_contract =
        DarkpoolProxyAdminContract::new(ctx.proxy_admin_address, ctx.client.clone());
    let darkpool = DarkpoolTestContract::new(ctx.darkpool_proxy_address, ctx.client.clone());

    // Mark a random nullifier as spent to test that it is not cleared on upgrade
    let mut rng = thread_rng();
    let nullifier = scalar_to_u256(ScalarField::rand(&mut rng));

    darkpool.mark_nullifier_spent(nullifier).send().await?.await?;

    // Ensure that only the owner can upgrade the contract
    let dummy_signer = setup_dummy_client(ctx.client.clone()).await?;
    let proxy_admin_contract_with_dummy_signer =
        DarkpoolProxyAdminContract::new(proxy_admin_contract.address(), dummy_signer);

    assert!(
        proxy_admin_contract_with_dummy_signer
            .upgrade_and_call(
                ctx.darkpool_proxy_address,
                ctx.test_upgrade_target_address,
                Bytes::new(), // data
            )
            .send()
            .await
            .is_err(),
        "Upgraded contract with non-owner"
    );

    // Upgrade to dummy upgrade target contract
    proxy_admin_contract
        .upgrade_and_call(
            ctx.darkpool_proxy_address,
            ctx.test_upgrade_target_address,
            Bytes::new(), // data
        )
        .send()
        .await?
        .await?;

    let dummy_upgrade_target_contract =
        DummyUpgradeTargetContract::new(ctx.darkpool_proxy_address, ctx.client);

    // Assert that the proxy now points to the dummy upgrade target
    // by attempting to call the `is_dummy_upgrade_target` method through
    // the proxy, which only exists on the dummy upgrade target
    assert!(
        dummy_upgrade_target_contract.is_dummy_upgrade_target().call().await?,
        "Upgrade target contract not upgraded"
    );

    // Upgrade back to darkpool test contract
    proxy_admin_contract
        .upgrade_and_call(ctx.darkpool_proxy_address, ctx.darkpool_impl_address, Bytes::new())
        .send()
        .await?
        .await?;

    // Assert that the nullifier is still marked spent, and that
    // we can call the `is_nullifier_spent` method through the proxy,
    // indicating that the upgrade back to the darkpool test contract
    // was successful
    assert!(darkpool.is_nullifier_spent(nullifier).call().await?);

    Ok(())
}
integration_test_async!(test_upgradeable);

/// Test the upgradeability of the contracts the darkpool calls
/// (verifier, vkeys, & Merkle)
async fn test_implementation_address_setters(ctx: TestContext) -> Result<()> {
    let contract = DarkpoolTestContract::new(ctx.darkpool_proxy_address, ctx.client);

    for (method, address_selector, original_address) in [
        (
            SET_CORE_WALLET_OPS_ADDRESS_METHOD_NAME,
            CORE_WALLET_OPS_ADDRESS_SELECTOR,
            ctx.core_wallet_ops_address,
        ),
        (
            SET_CORE_SETTLEMENT_ADDRESS_METHOD_NAME,
            CORE_SETTLEMENT_ADDRESS_SELECTOR,
            ctx.core_settlement_address,
        ),
        (
            SET_VERIFIER_CORE_ADDRESS_METHOD_NAME,
            VERIFIER_CORE_ADDRESS_SELECTOR,
            ctx.verifier_core_address,
        ),
        (
            SET_VERIFIER_SETTLEMENT_ADDRESS_METHOD_NAME,
            VERIFIER_SETTLEMENT_ADDRESS_SELECTOR,
            ctx.verifier_settlement_address,
        ),
        (SET_VKEYS_ADDRESS_METHOD_NAME, VKEYS_ADDRESS_SELECTOR, ctx.vkeys_address),
        (SET_MERKLE_ADDRESS_METHOD_NAME, MERKLE_ADDRESS_SELECTOR, ctx.merkle_address),
        (
            SET_TRANSFER_EXECUTOR_ADDRESS_METHOD_NAME,
            TRANSFER_EXECUTOR_ADDRESS_SELECTOR,
            ctx.transfer_executor_address,
        ),
    ] {
        // Set the new implementation address as the dummy upgrade target address
        contract
            .method::<Address, ()>(method, ctx.test_upgrade_target_address)?
            .send()
            .await?
            .await?;

        // Check that the implementation address was set
        assert!(
            contract.is_implementation_upgraded(address_selector).call().await?,
            "Implementation address not set"
        );

        // Set the implementation address back to the original address
        contract.method::<Address, ()>(method, original_address)?.send().await?.await?;

        // Check that the implementation address was unset
        assert!(
            contract.is_implementation_upgraded(address_selector).call().await.is_err(),
            "Implementation address not unset"
        );
    }

    Ok(())
}
integration_test_async!(test_implementation_address_setters);

/// Test the initialization of the darkpool
async fn test_initializable(ctx: TestContext) -> Result<()> {
    let contract = DarkpoolTestContract::new(ctx.darkpool_proxy_address, ctx.client);

    let dummy_core_wallet_ops_address = Address::random();
    let dummy_core_settlement_address = Address::random();
    let dummy_verifier_core_address = Address::random();
    let dummy_verifier_settlement_address = Address::random();
    let dummy_vkeys_address = Address::random();
    let dummy_merkle_address = Address::random();
    let dummy_transfer_executor_address = Address::random();
    let dummy_permit2_address = Address::random();
    let dummy_protocol_fee = U256::from(1);
    let dummy_protocol_public_encryption_key = [U256::from(1), U256::from(2)];

    assert!(
        contract
            .initialize(
                dummy_core_wallet_ops_address,
                dummy_core_settlement_address,
                dummy_verifier_core_address,
                dummy_verifier_settlement_address,
                dummy_vkeys_address,
                dummy_merkle_address,
                dummy_transfer_executor_address,
                dummy_permit2_address,
                dummy_protocol_fee,
                dummy_protocol_public_encryption_key,
            )
            .send()
            .await
            .is_err(),
        "Initialized contract twice"
    );

    Ok(())
}
integration_test_async!(test_initializable);

/// Test the ownership of the darkpool
// TODO: Add darkpool core & transfer executor address setters to this test
async fn test_ownable(ctx: TestContext) -> Result<()> {
    let contract = DarkpoolTestContract::new(ctx.darkpool_proxy_address, ctx.client.clone());
    let initial_owner = ctx.client.default_sender().unwrap();

    // Assert that the owner is set correctly initially
    assert_eq!(contract.owner().call().await?, initial_owner, "Incorrect initial owner");

    // Set up a dummy owner account and a contract instance with that account
    // attached as the sender
    let dummy_owner = setup_dummy_client(ctx.client.clone()).await?;
    let dummy_owner_address = dummy_owner.default_sender().unwrap();
    let contract_with_dummy_owner = DarkpoolTestContract::new(contract.address(), dummy_owner);

    // Assert that only the owner can transfer ownership
    assert_only_owner::<_, Address>(
        &contract,
        &contract_with_dummy_owner,
        TRANSFER_OWNERSHIP_METHOD_NAME,
        dummy_owner_address,
    )
    .await?;

    // Assert that ownership was properly transferred
    assert_eq!(contract.owner().call().await?, dummy_owner_address, "Incorrect new owner");

    // Transfer ownership back so that future tests have the correct owner
    // To do so, we need to fund the dummy signer with some ETH for gas

    let transfer_tx = TransactionRequest::new()
        .from(initial_owner)
        .to(dummy_owner_address)
        .value(parse_ether(1_u64)?);

    ctx.client.send_transaction(transfer_tx, None).await?.await?;

    contract_with_dummy_owner.transfer_ownership(initial_owner).send().await?.await?;

    // Assert that only the owner can call the `pause`/`unpause` methods
    assert_only_owner::<_, ()>(&contract, &contract_with_dummy_owner, PAUSE_METHOD_NAME, ())
        .await?;
    assert_only_owner::<_, ()>(&contract, &contract_with_dummy_owner, UNPAUSE_METHOD_NAME, ())
        .await?;

    // Assert that only the owner can call the `set_fee` method
    assert_only_owner::<_, U256>(
        &contract,
        &contract_with_dummy_owner,
        SET_FEE_METHOD_NAME,
        U256::from(1),
    )
    .await?;

    // Assert that only the owner can call the implementation address setters
    // We set the implementation addresses to the original addresses to ensure
    // that future tests have the correct implementation addresses
    assert_only_owner::<_, Address>(
        &contract,
        &contract_with_dummy_owner,
        SET_VERIFIER_CORE_ADDRESS_METHOD_NAME,
        ctx.verifier_core_address,
    )
    .await?;
    assert_only_owner::<_, Address>(
        &contract,
        &contract_with_dummy_owner,
        SET_VKEYS_ADDRESS_METHOD_NAME,
        ctx.vkeys_address,
    )
    .await?;
    assert_only_owner::<_, Address>(
        &contract,
        &contract_with_dummy_owner,
        SET_MERKLE_ADDRESS_METHOD_NAME,
        ctx.merkle_address,
    )
    .await?;

    Ok(())
}
integration_test_async!(test_ownable);

/// Test the pausability of the darkpool
// TODO: Ensure that only the owner can pause the contract
async fn test_pausable(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    let mut rng = thread_rng();
    let contract_root = Scalar::new(u256_to_scalar(contract.get_root().call().await?)?);
    let protocol_fee =
        FixedPoint::from(Scalar::new(u256_to_scalar(contract.get_fee().call().await?)?));

    contract.pause().send().await?.await?;

    // Assert that the contract is paused
    assert!(contract.paused().call().await?, "Contract not paused");

    // Assert that all setters revert when the contract is paused
    // This requires passing in valid data

    let (new_wallet_proof, new_wallet_statement) = gen_new_wallet_data(&mut rng)?;

    let (update_wallet_proof, update_wallet_statement, update_wallet_commitment_signature) =
        gen_update_wallet_data(&mut rng, contract_root)?;

    let data = gen_process_match_settle_data(&mut rng, contract_root, protocol_fee)?;

    let (
        valid_relayer_fee_settlement_proof,
        valid_relayer_fee_settlement_statement,
        online_relayer_wallet_commitment_signature,
    ) = gen_settle_online_relayer_fee_data(&mut rng, contract_root)?;

    assert_all_revert(vec![
        contract
            .new_wallet(
                serialize_to_calldata(&new_wallet_proof)?,
                serialize_to_calldata(&new_wallet_statement)?,
            )
            .send(),
        contract
            .update_wallet(
                serialize_to_calldata(&update_wallet_proof)?,
                serialize_to_calldata(&update_wallet_statement)?,
                update_wallet_commitment_signature.clone(),
                Bytes::new(), // transfer_aux_data
            )
            .send(),
        contract
            .process_match_settle(
                serialize_to_calldata(&data.match_payload_0)?,
                serialize_to_calldata(&data.match_payload_1)?,
                serialize_to_calldata(&data.valid_match_settle_statement)?,
                serialize_to_calldata(&data.match_proofs)?,
                serialize_to_calldata(&data.match_linking_proofs)?,
            )
            .send(),
        contract
            .settle_online_relayer_fee(
                serialize_to_calldata(&valid_relayer_fee_settlement_proof)?,
                serialize_to_calldata(&valid_relayer_fee_settlement_statement)?,
                online_relayer_wallet_commitment_signature.clone(),
            )
            .send(),
        contract.pause().send(),
    ])
    .await?;

    // Assert that setters work when the contract is unpaused

    contract.unpause().send().await?.await?;

    assert_all_succeed(vec![
        contract
            .new_wallet(
                serialize_to_calldata(&new_wallet_proof)?,
                serialize_to_calldata(&new_wallet_statement)?,
            )
            .send(),
        contract
            .update_wallet(
                serialize_to_calldata(&update_wallet_proof)?,
                serialize_to_calldata(&update_wallet_statement)?,
                update_wallet_commitment_signature,
                Bytes::new(), // transfer_aux_data
            )
            .send(),
        contract
            .process_match_settle(
                serialize_to_calldata(&data.match_payload_0)?,
                serialize_to_calldata(&data.match_payload_1)?,
                serialize_to_calldata(&data.valid_match_settle_statement)?,
                serialize_to_calldata(&data.match_proofs)?,
                serialize_to_calldata(&data.match_linking_proofs)?,
            )
            .send(),
        contract
            .settle_online_relayer_fee(
                serialize_to_calldata(&valid_relayer_fee_settlement_proof)?,
                serialize_to_calldata(&valid_relayer_fee_settlement_statement)?,
                online_relayer_wallet_commitment_signature.clone(),
            )
            .send(),
    ])
    .await?;

    Ok(())
}
integration_test_async!(test_pausable);
