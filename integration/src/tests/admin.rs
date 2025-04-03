//! Integration tests for darkpool contract admin controls

use alloy::{providers::Provider, rpc::types::TransactionRequest};
use alloy_primitives::{utils::parse_ether, Address, Bytes, TxKind, U256};
use alloy_sol_types::{SolCall, SolType};
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
use eyre::Result;
use rand::thread_rng;
use scripts::utils::{call_helper, send_tx};
use test_helpers::integration_test_async;

use crate::{
    abis::{
        DarkpoolProxyAdminContract,
        DarkpoolTestContract::{
            self, pauseCall, setCoreSettlementAddressCall, setCoreWalletOpsAddressCall, setFeeCall,
            setMerkleAddressCall, setTransferExecutorAddressCall, setVerifierCoreAddressCall,
            setVerifierSettlementAddressCall, setVkeysAddressCall, transferOwnershipCall,
            unpauseCall,
        },
        DummyUpgradeTargetContract,
    },
    utils::{
        assert_only_owner, assert_revert, assert_success, scalar_to_u256, serialize_to_calldata,
        setup_dummy_client, u256_to_scalar,
    },
    DarkpoolTestInstance, TestContext,
};

/// Test the upgradeability of the darkpool
async fn test_upgradeable(ctx: TestContext) -> Result<()> {
    let proxy_admin_contract =
        DarkpoolProxyAdminContract::new(ctx.proxy_admin_address, ctx.provider());
    let darkpool = DarkpoolTestContract::new(ctx.darkpool_proxy_address, ctx.provider());

    // Mark a random nullifier as spent to test that it is not cleared on upgrade
    let mut rng = thread_rng();
    let nullifier = scalar_to_u256(ScalarField::rand(&mut rng));
    send_tx(darkpool.markNullifierSpent(nullifier)).await?;

    // Ensure that only the owner can upgrade the contract
    let dummy_signer = setup_dummy_client(ctx.client.clone());
    let proxy_admin_contract_with_dummy_signer =
        DarkpoolProxyAdminContract::new(*proxy_admin_contract.address(), dummy_signer.provider());

    let upgrade_tx = proxy_admin_contract_with_dummy_signer.upgradeAndCall(
        ctx.darkpool_proxy_address,
        ctx.test_upgrade_target_address,
        Bytes::new(),
    );
    let res = send_tx(upgrade_tx).await;
    assert!(res.is_err(), "Upgraded contract with non-owner");

    // Upgrade to dummy upgrade target contract
    let upgrade_tx = proxy_admin_contract.upgradeAndCall(
        ctx.darkpool_proxy_address,
        ctx.test_upgrade_target_address,
        Bytes::new(),
    );
    send_tx(upgrade_tx).await?;

    let dummy_upgrade_target_contract =
        DummyUpgradeTargetContract::new(ctx.darkpool_proxy_address, ctx.provider());

    // Assert that the proxy now points to the dummy upgrade target
    // by attempting to call the `is_dummy_upgrade_target` method through
    // the proxy, which only exists on the dummy upgrade target
    let res = call_helper(dummy_upgrade_target_contract.isDummyUpgradeTarget()).await?._0;
    assert!(res, "Upgrade target contract not upgraded");

    // Upgrade back to darkpool test contract
    let upgrade_tx = proxy_admin_contract.upgradeAndCall(
        ctx.darkpool_proxy_address,
        ctx.darkpool_impl_address,
        Bytes::new(),
    );
    send_tx(upgrade_tx).await?;

    // Assert that the nullifier is still marked spent, and that
    // we can call the `is_nullifier_spent` method through the proxy,
    // indicating that the upgrade back to the darkpool test contract
    // was successful
    let res = call_helper(darkpool.isNullifierSpent(nullifier)).await?._0;
    assert!(res, "Nullifier not marked spent");

    Ok(())
}
integration_test_async!(test_upgradeable);

/// Test the upgradeability of the contracts the darkpool
async fn test_implementation_address_setters(ctx: TestContext) -> Result<()> {
    let contract = DarkpoolTestContract::new(ctx.darkpool_proxy_address, ctx.provider());

    /// Helper to test an upgrade method
    async fn test_upgrade<'a, SetAddrCall, Param>(
        upgrade_addr: Address,
        downgrade_addr: Address,
        selector: u8,
        contract: &DarkpoolTestInstance,
    ) -> Result<()>
    where
        Param: SolType<RustType = Address>,
        SetAddrCall: SolCall<Parameters<'a> = (Param,)> + Unpin,
    {
        let upgrade_call = SetAddrCall::new((upgrade_addr,));
        let downgrade_call = SetAddrCall::new((downgrade_addr,));

        send_tx(contract.call_builder(&upgrade_call)).await?;
        let res = call_helper(contract.isImplementationUpgraded(selector)).await?._0;
        assert!(res, "Implementation not upgraded");

        send_tx(contract.call_builder(&downgrade_call)).await?;
        let res = call_helper(contract.isImplementationUpgraded(selector)).await?._0;
        assert!(!res, "Implementation not downgraded");

        Ok(())
    }

    let upgrade_addr = ctx.test_upgrade_target_address;

    // Core wallet ops
    test_upgrade::<setCoreWalletOpsAddressCall, _>(
        upgrade_addr,
        ctx.core_wallet_ops_address,
        CORE_WALLET_OPS_ADDRESS_SELECTOR,
        &contract,
    )
    .await?;

    // Core settlement
    test_upgrade::<setCoreSettlementAddressCall, _>(
        upgrade_addr,
        ctx.core_settlement_address,
        CORE_SETTLEMENT_ADDRESS_SELECTOR,
        &contract,
    )
    .await?;

    // Verifier core
    test_upgrade::<setVerifierCoreAddressCall, _>(
        upgrade_addr,
        ctx.verifier_core_address,
        VERIFIER_CORE_ADDRESS_SELECTOR,
        &contract,
    )
    .await?;

    // Verifier settlement
    test_upgrade::<setVerifierSettlementAddressCall, _>(
        upgrade_addr,
        ctx.verifier_settlement_address,
        VERIFIER_SETTLEMENT_ADDRESS_SELECTOR,
        &contract,
    )
    .await?;

    // Vkeys
    test_upgrade::<setVkeysAddressCall, _>(
        upgrade_addr,
        ctx.vkeys_address,
        VKEYS_ADDRESS_SELECTOR,
        &contract,
    )
    .await?;

    // Merkle
    test_upgrade::<setMerkleAddressCall, _>(
        upgrade_addr,
        ctx.merkle_address,
        MERKLE_ADDRESS_SELECTOR,
        &contract,
    )
    .await?;

    // Transfer executor
    test_upgrade::<setTransferExecutorAddressCall, _>(
        upgrade_addr,
        ctx.transfer_executor_address,
        TRANSFER_EXECUTOR_ADDRESS_SELECTOR,
        &contract,
    )
    .await?;

    Ok(())
}
integration_test_async!(test_implementation_address_setters);

/// Test the initialization of the darkpool
async fn test_initializable(ctx: TestContext) -> Result<()> {
    let contract = DarkpoolTestContract::new(ctx.darkpool_proxy_address, ctx.provider());

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
    let contract = DarkpoolTestContract::new(ctx.darkpool_proxy_address, ctx.provider());
    let initial_owner = ctx.client.address();

    // Assert that the owner is set correctly initially
    let owner = call_helper(contract.owner()).await?._0;
    assert_eq!(owner, initial_owner, "Incorrect initial owner");

    // Set up a dummy owner account and a contract instance with that account
    // attached as the sender
    let dummy_owner = setup_dummy_client(ctx.client.clone());
    let dummy_owner_address = dummy_owner.address();
    let contract_with_dummy_owner =
        DarkpoolTestContract::new(*contract.address(), dummy_owner.provider());

    // Assert that only the owner can transfer ownership
    let transfer_call = transferOwnershipCall::new((dummy_owner_address,));
    assert_only_owner::<transferOwnershipCall>(
        transfer_call,
        &contract,
        &contract_with_dummy_owner,
    )
    .await?;

    // Assert that ownership was properly transferred
    let owner = call_helper(contract.owner()).await?._0;
    assert_eq!(owner, dummy_owner_address, "Incorrect new owner");

    // Transfer ownership back so that future tests have the correct owner
    // To do so, we need to fund the dummy signer with some ETH for gas
    let transfer_tx = TransactionRequest {
        from: Some(initial_owner),
        to: Some(TxKind::Call(dummy_owner_address)),
        value: Some(parse_ether("0.01")?),
        ..Default::default()
    };
    ctx.provider().send_transaction(transfer_tx).await?.watch().await?;
    send_tx(contract_with_dummy_owner.transferOwnership(initial_owner)).await?;

    // Assert that only the owner can call the `pause`/`unpause` methods
    let pause_call = pauseCall::new(());
    let unpause_call = unpauseCall::new(());
    assert_only_owner(pause_call, &contract, &contract_with_dummy_owner).await?;
    assert_only_owner(unpause_call, &contract, &contract_with_dummy_owner).await?;

    // Assert that only the owner can call the `set_fee` method
    let set_fee_call = setFeeCall::new((U256::from(1),));
    assert_only_owner(set_fee_call, &contract, &contract_with_dummy_owner).await?;

    // Assert that only the owner can call the implementation address setters
    // We set the implementation addresses to the original addresses to ensure
    // that future tests have the correct implementation addresses
    let set_verifier_core_call = setVerifierCoreAddressCall::new((ctx.verifier_core_address,));
    assert_only_owner(set_verifier_core_call, &contract, &contract_with_dummy_owner).await?;

    let set_verifier_settlement_call =
        setVerifierSettlementAddressCall::new((ctx.verifier_settlement_address,));
    assert_only_owner(set_verifier_settlement_call, &contract, &contract_with_dummy_owner).await?;

    let set_vkeys_call = setVkeysAddressCall::new((ctx.vkeys_address,));
    assert_only_owner(set_vkeys_call, &contract, &contract_with_dummy_owner).await?;

    let set_merkle_call = setMerkleAddressCall::new((ctx.merkle_address,));
    assert_only_owner(set_merkle_call, &contract, &contract_with_dummy_owner).await?;

    let set_transfer_executor_call =
        setTransferExecutorAddressCall::new((ctx.transfer_executor_address,));
    assert_only_owner(set_transfer_executor_call, &contract, &contract_with_dummy_owner).await?;

    Ok(())
}
integration_test_async!(test_ownable);

/// Test the pausability of the darkpool
// TODO: Ensure that only the owner can pause the contract
async fn test_pausable(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Ensure the merkle state is cleared for the test
    send_tx(contract.clearMerkle()).await?;

    let mut rng = thread_rng();
    let root_u256 = call_helper(contract.getRoot()).await?._0;
    let fee_u256 = call_helper(contract.getFee()).await?._0;
    let contract_root = Scalar::new(u256_to_scalar(root_u256));
    let protocol_fee = FixedPoint::from(Scalar::new(u256_to_scalar(fee_u256)));

    send_tx(contract.pause()).await?;

    // Assert that the contract is paused
    let is_paused = call_helper(contract.paused()).await?._0;
    assert!(is_paused, "Contract not paused");

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

    // Check that all the mutating methods now revert

    let new_wallet = contract.newWallet(
        serialize_to_calldata(&new_wallet_proof)?,
        serialize_to_calldata(&new_wallet_statement)?,
    );
    assert_revert(new_wallet.clone()).await?;

    let update_wallet = contract.updateWallet(
        serialize_to_calldata(&update_wallet_proof)?,
        serialize_to_calldata(&update_wallet_statement)?,
        update_wallet_commitment_signature.clone(),
        Bytes::new(), // transfer_aux_data
    );
    assert_revert(update_wallet.clone()).await?;

    let process_match_settle = contract.processMatchSettle(
        serialize_to_calldata(&data.match_payload_0)?,
        serialize_to_calldata(&data.match_payload_1)?,
        serialize_to_calldata(&data.valid_match_settle_statement)?,
        serialize_to_calldata(&data.match_proofs)?,
        serialize_to_calldata(&data.match_linking_proofs)?,
    );
    assert_revert(process_match_settle.clone()).await?;

    let settle_online_relayer_fee = contract.settleOnlineRelayerFee(
        serialize_to_calldata(&valid_relayer_fee_settlement_proof)?,
        serialize_to_calldata(&valid_relayer_fee_settlement_statement)?,
        online_relayer_wallet_commitment_signature.clone(),
    );
    assert_revert(settle_online_relayer_fee.clone()).await?;
    assert_revert(contract.pause()).await?;

    // Assert that setters work when the contract is unpaused
    send_tx(contract.unpause()).await?;

    assert_success(new_wallet).await?;
    assert_success(update_wallet).await?;
    assert_success(process_match_settle).await?;
    assert_success(settle_online_relayer_fee).await?;

    Ok(())
}
integration_test_async!(test_pausable);
