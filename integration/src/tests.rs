//! Integration tests for the contracts

use alloy_primitives::Address as AlloyAddress;
use ark_ec::AffineRepr;
use ark_ff::One;
use ark_std::UniformRand;
use circuit_types::fixed_point::FixedPoint;
use constants::Scalar;
use contracts_common::{
    constants::{
        DARKPOOL_CORE_ADDRESS_SELECTOR, MERKLE_ADDRESS_SELECTOR, TEST_MERKLE_HEIGHT,
        TRANSFER_EXECUTOR_ADDRESS_SELECTOR, VERIFIER_ADDRESS_SELECTOR, VKEYS_ADDRESS_SELECTOR,
    },
    custom_serde::statement_to_public_inputs,
    serde_def_types::{SerdeG1Affine, SerdeG2Affine, SerdeScalarField},
    types::{G1Affine, G2Affine, ScalarField},
};
use contracts_core::crypto::{ecdsa::pubkey_to_address, poseidon::compute_poseidon_hash};
use contracts_utils::{
    crypto::{hash_and_sign_message, random_keypair, NativeHasher},
    merkle::new_ark_merkle_tree,
    proof_system::test_data::{
        dummy_circuit_type, gen_new_wallet_data, gen_process_match_settle_data,
        gen_redeem_fee_data, gen_settle_offline_fee_data, gen_settle_online_relayer_fee_data,
        gen_update_wallet_data, gen_verification_bundle, generate_match_bundle,
        mutate_random_linking_proof, mutate_random_plonk_proof, random_scalars,
    },
};
use ethers::{
    abi::Address,
    providers::Middleware,
    types::{Bytes, TransactionRequest, U256},
    utils::{keccak256, parse_ether},
};
use eyre::{eyre, Result};
use rand::{thread_rng, Rng, RngCore};
use scripts::constants::TEST_FUNDING_AMOUNT;
use test_helpers::integration_test_async;

use crate::{
    abis::{
        DarkpoolProxyAdminContract, DarkpoolTestContract, DummyErc20Contract,
        DummyUpgradeTargetContract, MerkleContract, PrecompileTestContract,
        TransferExecutorContract, VerifierContract,
    },
    constants::{
        PAUSE_METHOD_NAME, SET_DARKPOOL_CORE_ADDRESS_METHOD_NAME, SET_FEE_METHOD_NAME,
        SET_MERKLE_ADDRESS_METHOD_NAME, SET_TRANSFER_EXECUTOR_ADDRESS_METHOD_NAME,
        SET_VERIFIER_ADDRESS_METHOD_NAME, SET_VKEYS_ADDRESS_METHOD_NAME,
        TRANSFER_OWNERSHIP_METHOD_NAME, UNPAUSE_METHOD_NAME,
    },
    utils::{
        assert_all_revert, assert_all_suceed, assert_only_owner, dummy_erc20_deposit,
        dummy_erc20_withdrawal, execute_transfer_and_get_balances, gen_transfer_aux_data,
        get_protocol_pubkey, insert_shares_and_get_root, scalar_to_u256,
        serialize_match_verification_bundle, serialize_to_calldata, serialize_verification_bundle,
        setup_dummy_client, u256_to_scalar,
    },
    TestArgs,
};

/// Test how the contracts call the `ecAdd` precompile
async fn test_ec_add(test_args: TestArgs) -> Result<()> {
    let contract =
        PrecompileTestContract::new(test_args.precompiles_contract_address, test_args.client);
    let mut rng = thread_rng();

    let a = G1Affine::rand(&mut rng);
    let b = G1Affine::rand(&mut rng);

    let c_bytes = contract
        .test_ec_add(
            serialize_to_calldata(&SerdeG1Affine(a))?,
            serialize_to_calldata(&SerdeG1Affine(b))?,
        )
        .call()
        .await?;
    let c: SerdeG1Affine = postcard::from_bytes(&c_bytes)?;

    assert_eq!(c.0, a + b, "Incorrect EC addition result");

    Ok(())
}
integration_test_async!(test_ec_add);

/// Test how the contracts call the `ecMul` precompile
async fn test_ec_mul(test_args: TestArgs) -> Result<()> {
    let contract =
        PrecompileTestContract::new(test_args.precompiles_contract_address, test_args.client);
    let mut rng = thread_rng();

    let a = ScalarField::rand(&mut rng);
    let b = G1Affine::rand(&mut rng);

    let c_bytes = contract
        .test_ec_mul(
            serialize_to_calldata(&SerdeScalarField(a))?,
            serialize_to_calldata(&SerdeG1Affine(b))?,
        )
        .call()
        .await?;
    let c: SerdeG1Affine = postcard::from_bytes(&c_bytes)?;

    let mut expected = b.into_group();
    expected *= a;

    assert_eq!(c.0, expected, "Incorrect EC scalar multiplication result");

    Ok(())
}
integration_test_async!(test_ec_mul);

/// Test how the contracts call the `ecPairing` precompile
async fn test_ec_pairing(test_args: TestArgs) -> Result<()> {
    let contract =
        PrecompileTestContract::new(test_args.precompiles_contract_address, test_args.client);
    let mut rng = thread_rng();

    let a = G1Affine::rand(&mut rng);
    let b = G2Affine::rand(&mut rng);

    let res = contract
        .test_ec_pairing(
            serialize_to_calldata(&SerdeG1Affine(a))?,
            serialize_to_calldata(&SerdeG2Affine(b))?,
        )
        .call()
        .await?;

    assert!(res, "Incorrect EC pairing result");

    Ok(())
}
integration_test_async!(test_ec_pairing);

/// Test how the contracts call the `ecRecover` precompile
async fn test_ec_recover(test_args: TestArgs) -> Result<()> {
    let contract =
        PrecompileTestContract::new(test_args.precompiles_contract_address, test_args.client);
    let mut rng = thread_rng();

    let (signing_key, pubkey) = random_keypair(&mut rng);

    let mut msg = [0u8; 32];
    rng.fill_bytes(&mut msg);

    let sig = hash_and_sign_message(&signing_key, &msg);

    let msg_hash = keccak256(msg);
    let res = contract
        .test_ec_recover(msg_hash.to_vec().into(), sig.to_vec().into())
        .call()
        .await?;

    assert_eq!(
        res,
        pubkey_to_address::<NativeHasher>(&pubkey).to_vec(),
        "Incorrect recovered address"
    );

    Ok(())
}
integration_test_async!(test_ec_recover);

/// Test the Merkle tree functionality
async fn test_merkle(test_args: TestArgs) -> Result<()> {
    let contract = MerkleContract::new(test_args.merkle_address, test_args.client);
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);
    contract.init().send().await?.await?;

    let contract_root = u256_to_scalar(contract.root().call().await?)?;

    assert_eq!(
        ark_merkle.root(),
        contract_root,
        "Initial merkle root incorrect"
    );

    let num_leaves = 2_u128.pow((TEST_MERKLE_HEIGHT) as u32);
    let mut rng = thread_rng();
    let leaves = random_scalars(num_leaves as usize, &mut rng);

    for (i, leaf) in leaves.into_iter().enumerate() {
        ark_merkle
            .update(i, &compute_poseidon_hash(&[leaf]))
            .map_err(|e| eyre!("{}", e))?;
        contract
            .insert_shares_commitment(vec![scalar_to_u256(leaf)])
            .send()
            .await?
            .await?;

        let contract_root = u256_to_scalar(contract.root().call().await?)?;

        assert_eq!(ark_merkle.root(), contract_root, "Merkle root incorrect");
    }

    assert!(
        contract
            .insert_shares_commitment(vec![scalar_to_u256(ScalarField::rand(&mut rng))])
            .send()
            .await
            .is_err(),
        "Inserted more leaves than allowed"
    );

    Ok(())
}
integration_test_async!(test_merkle);

/// Test the verifier functionality
async fn test_verifier(test_args: TestArgs) -> Result<()> {
    let contract = VerifierContract::new(test_args.verifier_address, test_args.client);
    let mut rng = thread_rng();

    // Test valid single proof verification
    let (statement, mut proof, vkey) = gen_verification_bundle(&mut rng)?;
    let public_inputs = statement_to_public_inputs(&statement).map_err(|e| eyre!("{:?}", e))?;

    let verification_bundle_calldata =
        serialize_verification_bundle(&vkey, &proof, &public_inputs)?;

    let successful_res = contract.verify(verification_bundle_calldata).call().await?;
    assert!(successful_res, "Valid proof did not verify");

    // Test invalid single proof verification
    proof.z_bar += ScalarField::one();

    let verification_bundle_calldata =
        serialize_verification_bundle(&vkey, &proof, &public_inputs)?;

    let unsuccessful_res = contract.verify(verification_bundle_calldata).call().await?;
    assert!(!unsuccessful_res, "Invalid proof verified");

    // Test valid batch verification

    let (
        match_vkeys,
        mut match_proofs,
        match_public_inputs,
        match_linking_vkeys,
        mut match_linking_proofs,
        _,
    ) = generate_match_bundle(&mut rng)?;

    let match_verification_bundle_calldata = serialize_match_verification_bundle(
        &match_vkeys,
        &match_linking_vkeys,
        &match_proofs,
        &match_public_inputs,
        &match_linking_proofs,
    )?;

    let successful_res = contract
        .verify_match(match_verification_bundle_calldata)
        .call()
        .await?;
    assert!(successful_res, "Valid match bundle did not verify");

    // Test invalid batch verification

    let mutate_plonk_proof = rng.gen_bool(0.5);
    if mutate_plonk_proof {
        mutate_random_plonk_proof(&mut rng, &mut match_proofs);
    } else {
        mutate_random_linking_proof(&mut rng, &mut match_linking_proofs);
    }

    let match_verification_bundle_calldata = serialize_match_verification_bundle(
        &match_vkeys,
        &match_linking_vkeys,
        &match_proofs,
        &match_public_inputs,
        &match_linking_proofs,
    )?;

    let unsuccessful_res = contract
        .verify_match(match_verification_bundle_calldata)
        .call()
        .await?;
    assert!(!unsuccessful_res, "Invalid match bundle verified");

    Ok(())
}
integration_test_async!(test_verifier);

/// Test the upgradeability of the darkpool
async fn test_upgradeable(test_args: TestArgs) -> Result<()> {
    let proxy_admin_contract =
        DarkpoolProxyAdminContract::new(test_args.proxy_admin_address, test_args.client.clone());
    let darkpool =
        DarkpoolTestContract::new(test_args.darkpool_proxy_address, test_args.client.clone());

    // Mark a random nullifier as spent to test that it is not cleared on upgrade
    let mut rng = thread_rng();
    let nullifier = scalar_to_u256(ScalarField::rand(&mut rng));

    darkpool
        .mark_nullifier_spent(nullifier)
        .send()
        .await?
        .await?;

    // Ensure that only the owner can upgrade the contract
    let dummy_signer = setup_dummy_client(test_args.client.clone()).await?;
    let proxy_admin_contract_with_dummy_signer =
        DarkpoolProxyAdminContract::new(proxy_admin_contract.address(), dummy_signer);

    assert!(
        proxy_admin_contract_with_dummy_signer
            .upgrade_and_call(
                test_args.darkpool_proxy_address,
                test_args.test_upgrade_target_address,
                Bytes::new(), /* data */
            )
            .send()
            .await
            .is_err(),
        "Upgraded contract with non-owner"
    );

    // Upgrade to dummy upgrade target contract
    proxy_admin_contract
        .upgrade_and_call(
            test_args.darkpool_proxy_address,
            test_args.test_upgrade_target_address,
            Bytes::new(), /* data */
        )
        .send()
        .await?
        .await?;

    let dummy_upgrade_target_contract =
        DummyUpgradeTargetContract::new(test_args.darkpool_proxy_address, test_args.client);

    // Assert that the proxy now points to the dummy upgrade target
    // by attempting to call the `is_dummy_upgrade_target` method through
    // the proxy, which only exists on the dummy upgrade target
    assert!(
        dummy_upgrade_target_contract
            .is_dummy_upgrade_target()
            .call()
            .await?,
        "Upgrade target contract not upgraded"
    );

    // Upgrade back to darkpool test contract
    proxy_admin_contract
        .upgrade_and_call(
            test_args.darkpool_proxy_address,
            test_args.darkpool_impl_address,
            Bytes::new(),
        )
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
async fn test_implementation_address_setters(test_args: TestArgs) -> Result<()> {
    let contract = DarkpoolTestContract::new(test_args.darkpool_proxy_address, test_args.client);

    for (method, address_selector, original_address) in [
        (
            SET_DARKPOOL_CORE_ADDRESS_METHOD_NAME,
            DARKPOOL_CORE_ADDRESS_SELECTOR,
            test_args.darkpool_core_address,
        ),
        (
            SET_VERIFIER_ADDRESS_METHOD_NAME,
            VERIFIER_ADDRESS_SELECTOR,
            test_args.verifier_address,
        ),
        (
            SET_VKEYS_ADDRESS_METHOD_NAME,
            VKEYS_ADDRESS_SELECTOR,
            test_args.vkeys_address,
        ),
        (
            SET_MERKLE_ADDRESS_METHOD_NAME,
            MERKLE_ADDRESS_SELECTOR,
            test_args.merkle_address,
        ),
        (
            SET_TRANSFER_EXECUTOR_ADDRESS_METHOD_NAME,
            TRANSFER_EXECUTOR_ADDRESS_SELECTOR,
            test_args.transfer_executor_address,
        ),
    ] {
        // Set the new implementation address as the dummy upgrade target address
        contract
            .method::<Address, ()>(method, test_args.test_upgrade_target_address)?
            .send()
            .await?
            .await?;

        // Check that the implementation address was set
        assert!(
            contract
                .is_implementation_upgraded(address_selector)
                .call()
                .await?,
            "Implementation address not set"
        );

        // Set the implementation address back to the original address
        contract
            .method::<Address, ()>(method, original_address)?
            .send()
            .await?
            .await?;

        // Check that the implementation address was unset
        assert!(
            contract
                .is_implementation_upgraded(address_selector)
                .call()
                .await
                .is_err(),
            "Implementation address not unset"
        );
    }

    Ok(())
}
integration_test_async!(test_implementation_address_setters);

/// Test the initialization of the darkpool
async fn test_initializable(test_args: TestArgs) -> Result<()> {
    let contract = DarkpoolTestContract::new(test_args.darkpool_proxy_address, test_args.client);

    let dummy_darkpool_core_address = Address::random();
    let dummy_verifier_address = Address::random();
    let dummy_vkeys_address = Address::random();
    let dummy_merkle_address = Address::random();
    let dummy_transfer_executor_address = Address::random();
    let dummy_permit2_address = Address::random();
    let dummy_protocol_fee = U256::from(1);
    let dummy_protocol_public_encryption_key = [U256::from(1), U256::from(2)];

    assert!(
        contract
            .initialize(
                dummy_darkpool_core_address,
                dummy_verifier_address,
                dummy_vkeys_address,
                dummy_merkle_address,
                dummy_transfer_executor_address,
                dummy_permit2_address,
                dummy_protocol_fee,
                dummy_protocol_public_encryption_key
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
async fn test_ownable(test_args: TestArgs) -> Result<()> {
    let contract =
        DarkpoolTestContract::new(test_args.darkpool_proxy_address, test_args.client.clone());
    let initial_owner = test_args.client.default_sender().unwrap();

    // Assert that the owner is set correctly initially
    assert_eq!(
        contract.owner().call().await?,
        initial_owner,
        "Incorrect initial owner"
    );

    // Set up a dummy owner account and a contract instance with that account attached as the sender
    let dummy_owner = setup_dummy_client(test_args.client.clone()).await?;
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
    assert_eq!(
        contract.owner().call().await?,
        dummy_owner_address,
        "Incorrect new owner"
    );

    // Transfer ownership back so that future tests have the correct owner
    // To do so, we need to fund the dummy signer with some ETH for gas

    let transfer_tx = TransactionRequest::new()
        .from(initial_owner)
        .to(dummy_owner_address)
        .value(parse_ether(1_u64)?);

    test_args
        .client
        .send_transaction(transfer_tx, None)
        .await?
        .await?;

    contract_with_dummy_owner
        .transfer_ownership(initial_owner)
        .send()
        .await?
        .await?;

    // Assert that only the owner can call the `pause`/`unpause` methods
    assert_only_owner::<_, ()>(&contract, &contract_with_dummy_owner, PAUSE_METHOD_NAME, ())
        .await?;
    assert_only_owner::<_, ()>(
        &contract,
        &contract_with_dummy_owner,
        UNPAUSE_METHOD_NAME,
        (),
    )
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
        SET_VERIFIER_ADDRESS_METHOD_NAME,
        test_args.verifier_address,
    )
    .await?;
    assert_only_owner::<_, Address>(
        &contract,
        &contract_with_dummy_owner,
        SET_VKEYS_ADDRESS_METHOD_NAME,
        test_args.vkeys_address,
    )
    .await?;
    assert_only_owner::<_, Address>(
        &contract,
        &contract_with_dummy_owner,
        SET_MERKLE_ADDRESS_METHOD_NAME,
        test_args.merkle_address,
    )
    .await?;

    Ok(())
}
integration_test_async!(test_ownable);

/// Test the pausability of the darkpool
// TODO: Ensure that only the owner can pause the contract
async fn test_pausable(test_args: TestArgs) -> Result<()> {
    let contract = DarkpoolTestContract::new(test_args.darkpool_proxy_address, test_args.client);

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    let mut rng = thread_rng();
    let contract_root = Scalar::new(u256_to_scalar(contract.get_root().call().await?)?);
    let protocol_fee = FixedPoint::from(Scalar::new(u256_to_scalar(
        contract.get_fee().call().await?,
    )?));

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
                Bytes::new(), /* transfer_aux_data */
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

    assert_all_suceed(vec![
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
                Bytes::new(), /* transfer_aux_data */
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

/// Test the nullifier set functionality
async fn test_nullifier_set(test_args: TestArgs) -> Result<()> {
    let contract = DarkpoolTestContract::new(test_args.darkpool_proxy_address, test_args.client);
    let mut rng = thread_rng();
    let nullifier = scalar_to_u256(ScalarField::rand(&mut rng));

    let nullifier_spent = contract.is_nullifier_spent(nullifier).call().await?;

    assert!(!nullifier_spent, "Nullifier already spent");

    contract
        .mark_nullifier_spent(nullifier)
        .send()
        .await?
        .await?;

    let nullifier_spent = contract.is_nullifier_spent(nullifier).call().await?;

    assert!(nullifier_spent, "Nullifier not spent");

    Ok(())
}
integration_test_async!(test_nullifier_set);

/// Test deposit / withdrawal functionality of the darkpool
async fn test_external_transfer(test_args: TestArgs) -> Result<()> {
    let transfer_executor_contract = TransferExecutorContract::new(
        test_args.transfer_executor_address,
        test_args.client.clone(),
    );

    // Initialize the transfer executor with the address of the Permit2 contract being used
    transfer_executor_contract
        .init(test_args.permit2_address)
        .send()
        .await?
        .await?;

    let test_erc20_contract =
        DummyErc20Contract::new(test_args.test_erc20_address, test_args.client.clone());

    let account_address = test_args.client.default_sender().unwrap();
    let mint = test_args.test_erc20_address;

    let contract_initial_balance = test_erc20_contract
        .balance_of(test_args.transfer_executor_address)
        .call()
        .await?;
    let user_initial_balance = test_erc20_contract
        .balance_of(account_address)
        .call()
        .await?;

    let (signing_key, pk_root) = random_keypair(&mut thread_rng());

    // Create & execute deposit external transfer, check balances
    let deposit = dummy_erc20_deposit(account_address, mint);
    let (contract_balance, user_balance) = execute_transfer_and_get_balances(
        &transfer_executor_contract,
        &test_erc20_contract,
        test_args.permit2_address,
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
        test_args.permit2_address,
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
    assert_eq!(
        user_balance, user_initial_balance,
        "Post-withdrawal user balance incorrect"
    );

    Ok(())
}
integration_test_async!(test_external_transfer);

/// Test that a deposit specified from a different ETH address is rejected
#[allow(non_snake_case)]
async fn test_external_transfer__wrong_eth_addr(test_args: TestArgs) -> Result<()> {
    let transfer_executor_contract = TransferExecutorContract::new(
        test_args.transfer_executor_address,
        test_args.client.clone(),
    );

    // Initialize the transfer executor with the address of the Permit2 contract being used
    transfer_executor_contract
        .init(test_args.permit2_address)
        .send()
        .await?
        .await?;

    let test_erc20_contract =
        DummyErc20Contract::new(test_args.test_erc20_address, test_args.client.clone());

    let account_address = test_args.client.default_sender().unwrap();
    let mint = test_args.test_erc20_address;

    // Generate dummy address & fund with some ERC20 tokens
    // (lack of funding should not be the reason the test fails)
    let dummy_address = Address::random();
    test_erc20_contract
        .mint(dummy_address, U256::from(TEST_FUNDING_AMOUNT))
        .send()
        .await?
        .await?;

    let (signing_key, pk_root) = random_keypair(&mut thread_rng());

    // Create & execute deposit external transfer, attempting to deposit from the dummy address
    let deposit = dummy_erc20_deposit(dummy_address, mint);
    assert!(
        execute_transfer_and_get_balances(
            &transfer_executor_contract,
            &test_erc20_contract,
            test_args.permit2_address,
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
async fn test_external_transfer__wrong_rng_wallet(test_args: TestArgs) -> Result<()> {
    let mut rng = thread_rng();

    let transfer_executor_contract = TransferExecutorContract::new(
        test_args.transfer_executor_address,
        test_args.client.clone(),
    );

    // Initialize the transfer executor with the address of the Permit2 contract being used
    transfer_executor_contract
        .init(test_args.permit2_address)
        .send()
        .await?
        .await?;

    let account_address = test_args.client.default_sender().unwrap();
    let mint = test_args.test_erc20_address;

    let (signing_key, pk_root) = random_keypair(&mut rng);

    // Create a valid deposit w/ accompanying aux data
    let deposit = dummy_erc20_deposit(account_address, mint);
    let transfer_aux_data = gen_transfer_aux_data(
        &signing_key,
        pk_root,
        &deposit,
        test_args.permit2_address,
        &transfer_executor_contract,
    )
    .await?;

    // Execute the deposit with a pk_root that does not match the one in the aux data
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
async fn test_external_transfer__malicious_withdrawal(test_args: TestArgs) -> Result<()> {
    let transfer_executor_contract = TransferExecutorContract::new(
        test_args.transfer_executor_address,
        test_args.client.clone(),
    );

    // Initialize the transfer executor with the address of the Permit2 contract being used
    transfer_executor_contract
        .init(test_args.permit2_address)
        .send()
        .await?
        .await?;

    let test_erc20_contract =
        DummyErc20Contract::new(test_args.test_erc20_address, test_args.client.clone());

    let account_address = test_args.client.default_sender().unwrap();
    let mint = test_args.test_erc20_address;

    // Fund contract with some ERC20 tokens
    // (lack of funding should not be the reason the test fails)
    test_erc20_contract
        .mint(
            test_args.transfer_executor_address,
            U256::from(TEST_FUNDING_AMOUNT),
        )
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
        test_args.permit2_address,
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
        .burn(
            test_args.transfer_executor_address,
            U256::from(TEST_FUNDING_AMOUNT),
        )
        .send()
        .await?
        .await?;

    Ok(())
}
integration_test_async!(test_external_transfer__malicious_withdrawal);

/// Test the `new_wallet` method on the darkpool
async fn test_new_wallet(test_args: TestArgs) -> Result<()> {
    let contract = DarkpoolTestContract::new(test_args.darkpool_proxy_address, test_args.client);

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    let mut rng = thread_rng();
    let (proof, statement) = gen_new_wallet_data(&mut rng)?;

    // Call `new_wallet`
    contract
        .new_wallet(
            serialize_to_calldata(&proof)?,
            serialize_to_calldata(&statement)?,
        )
        .send()
        .await?
        .await?;

    // Assert that Merkle root is correct
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let ark_root = insert_shares_and_get_root(
        &mut ark_merkle,
        statement.private_shares_commitment,
        &statement.public_wallet_shares,
        0, /* index */
    )?;

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    Ok(())
}
integration_test_async!(test_new_wallet);

/// Test the `update_wallet` method on the darkpool
async fn test_update_wallet(test_args: TestArgs) -> Result<()> {
    let contract = DarkpoolTestContract::new(test_args.darkpool_proxy_address, test_args.client);

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let mut rng = thread_rng();

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;
    let (proof, statement, wallet_commitment_signature) =
        gen_update_wallet_data(&mut rng, Scalar::new(contract_root))?;

    // Call `update_wallet`
    contract
        .update_wallet(
            serialize_to_calldata(&proof)?,
            serialize_to_calldata(&statement)?,
            wallet_commitment_signature,
            Bytes::new(), /* transfer_aux_data */
        )
        .send()
        .await?
        .await?;

    // Assert that correct nullifier is spent
    let nullifier = scalar_to_u256(statement.old_shares_nullifier);

    let nullifier_spent = contract.is_nullifier_spent(nullifier).call().await?;
    assert!(nullifier_spent, "Nullifier not spent");

    // Assert that Merkle root is correct
    let ark_root = insert_shares_and_get_root(
        &mut ark_merkle,
        statement.new_private_shares_commitment,
        &statement.new_public_shares,
        0, /* index */
    )
    .map_err(|e| eyre!("{}", e))?;

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    Ok(())
}
integration_test_async!(test_update_wallet);

/// Test the `process_match_settle` method on the darkpool
async fn test_process_match_settle(test_args: TestArgs) -> Result<()> {
    let contract = DarkpoolTestContract::new(test_args.darkpool_proxy_address, test_args.client);

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let contract_root = Scalar::new(u256_to_scalar(contract.get_root().call().await?)?);
    let protocol_fee = FixedPoint::from(Scalar::new(u256_to_scalar(
        contract.get_fee().call().await?,
    )?));
    let mut rng = thread_rng();
    let data = gen_process_match_settle_data(&mut rng, contract_root, protocol_fee)?;

    // Call `process_match_settle` with valid data
    contract
        .process_match_settle(
            serialize_to_calldata(&data.match_payload_0)?,
            serialize_to_calldata(&data.match_payload_1)?,
            serialize_to_calldata(&data.valid_match_settle_statement)?,
            serialize_to_calldata(&data.match_proofs)?,
            serialize_to_calldata(&data.match_linking_proofs)?,
        )
        .send()
        .await?
        .await?;

    // Assert that correct nullifiers are spent
    let party_0_nullifier = scalar_to_u256(
        data.match_payload_0
            .valid_reblind_statement
            .original_shares_nullifier,
    );
    let party_1_nullifier = scalar_to_u256(
        data.match_payload_1
            .valid_reblind_statement
            .original_shares_nullifier,
    );

    let party_0_nullifier_spent = contract
        .is_nullifier_spent(party_0_nullifier)
        .call()
        .await?;
    assert!(party_0_nullifier_spent, "Party 0 nullifier not spent");

    let party_1_nullifier_spent = contract
        .is_nullifier_spent(party_1_nullifier)
        .call()
        .await?;
    assert!(party_1_nullifier_spent, "Party 1 nullifier not spent");

    // Assert that Merkle root is correct
    insert_shares_and_get_root(
        &mut ark_merkle,
        data.match_payload_0
            .valid_reblind_statement
            .reblinded_private_shares_commitment,
        &data.valid_match_settle_statement.party0_modified_shares,
        0, /* index */
    )
    .map_err(|e| eyre!("{}", e))?;
    let ark_root = insert_shares_and_get_root(
        &mut ark_merkle,
        data.match_payload_1
            .valid_reblind_statement
            .reblinded_private_shares_commitment,
        &data.valid_match_settle_statement.party1_modified_shares,
        1, /* index */
    )
    .map_err(|e| eyre!("{}", e))?;

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    Ok(())
}
integration_test_async!(test_process_match_settle);

/// Test that the `process_match_settle` method on the darkpool
/// fails when order settlement indices are inconsistent
#[allow(non_snake_case)]
async fn test_process_match_settle__inconsistent_indices(test_args: TestArgs) -> Result<()> {
    let contract = DarkpoolTestContract::new(test_args.darkpool_proxy_address, test_args.client);

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    let contract_root = Scalar::new(u256_to_scalar(contract.get_root().call().await?)?);
    let protocol_fee = FixedPoint::from(Scalar::new(u256_to_scalar(
        contract.get_fee().call().await?,
    )?));
    let mut rng = thread_rng();

    let mut data = gen_process_match_settle_data(&mut rng, contract_root, protocol_fee)?;
    // Mutate the order settlement indices to be inconsistent
    data.valid_match_settle_statement
        .party0_indices
        .balance_receive += 1;

    // Call `process_match_settle` with invalid data
    assert!(
        contract
            .process_match_settle(
                serialize_to_calldata(&data.match_payload_0)?,
                serialize_to_calldata(&data.match_payload_1)?,
                serialize_to_calldata(&data.valid_match_settle_statement)?,
                serialize_to_calldata(&data.match_proofs)?,
                serialize_to_calldata(&data.match_linking_proofs)?,
            )
            .send()
            .await
            .is_err(),
        "Inconsistent order settlement indices did not fail"
    );

    Ok(())
}
integration_test_async!(test_process_match_settle__inconsistent_indices);

/// Test that the `process_match_settle` method on the darkpool
/// fails when protocol fee is inconsistent
#[allow(non_snake_case)]
async fn test_process_match_settle__inconsistent_fee(test_args: TestArgs) -> Result<()> {
    let contract = DarkpoolTestContract::new(test_args.darkpool_proxy_address, test_args.client);

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    let contract_root = Scalar::new(u256_to_scalar(contract.get_root().call().await?)?);
    let protocol_fee = FixedPoint::from(Scalar::new(u256_to_scalar(
        contract.get_fee().call().await?,
    )?));
    let mut rng = thread_rng();

    let mut data = gen_process_match_settle_data(&mut rng, contract_root, protocol_fee)?;
    // Mutate the protocol fee to be inconsistent
    data.valid_match_settle_statement.protocol_fee += ScalarField::one();

    // Call `process_match_settle` with invalid data
    assert!(
        contract
            .process_match_settle(
                serialize_to_calldata(&data.match_payload_0)?,
                serialize_to_calldata(&data.match_payload_1)?,
                serialize_to_calldata(&data.valid_match_settle_statement)?,
                serialize_to_calldata(&data.match_proofs)?,
                serialize_to_calldata(&data.match_linking_proofs)?,
            )
            .send()
            .await
            .is_err(),
        "Inconsistent protocol fee did not fail"
    );

    Ok(())
}
integration_test_async!(test_process_match_settle__inconsistent_fee);

/// Test the `settle_online_relayer_fee` method on the darkpool
async fn test_settle_online_relayer_fee(test_args: TestArgs) -> Result<()> {
    let contract = DarkpoolTestContract::new(test_args.darkpool_proxy_address, test_args.client);

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let mut rng = thread_rng();

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;
    let (proof, statement, relayer_wallet_commitment_signature) =
        gen_settle_online_relayer_fee_data(&mut rng, Scalar::new(contract_root))?;

    // Call `settle_online_relayer_fee`
    contract
        .settle_online_relayer_fee(
            serialize_to_calldata(&proof)?,
            serialize_to_calldata(&statement)?,
            relayer_wallet_commitment_signature,
        )
        .send()
        .await?
        .await?;

    // Assert that both sender & recipient nullifiers are spent

    let sender_nullifier = scalar_to_u256(statement.sender_nullifier);
    let nullifier_spent = contract.is_nullifier_spent(sender_nullifier).call().await?;
    assert!(nullifier_spent, "Sender nullifier not spent");

    let recipient_nullifier = scalar_to_u256(statement.recipient_nullifier);
    let nullifier_spent = contract
        .is_nullifier_spent(recipient_nullifier)
        .call()
        .await?;
    assert!(nullifier_spent, "Recipient nullifier not spent");

    // Assert that Merkle root is correct

    insert_shares_and_get_root(
        &mut ark_merkle,
        statement.sender_wallet_commitment,
        &statement.sender_updated_public_shares,
        0, /* index */
    )
    .map_err(|e| eyre!("{}", e))?;

    let ark_root = insert_shares_and_get_root(
        &mut ark_merkle,
        statement.recipient_wallet_commitment,
        &statement.recipient_updated_public_shares,
        1, /* index */
    )
    .map_err(|e| eyre!("{}", e))?;

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    Ok(())
}
integration_test_async!(test_settle_online_relayer_fee);

/// Test the `settle_offline_fee` method on the darkpool
async fn test_settle_offline_fee(test_args: TestArgs) -> Result<()> {
    let contract = DarkpoolTestContract::new(test_args.darkpool_proxy_address, test_args.client);

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let mut rng = thread_rng();

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;
    let protocol_pubkey = get_protocol_pubkey(&contract).await?;
    let (proof, statement) = gen_settle_offline_fee_data(
        &mut rng,
        Scalar::new(contract_root),
        protocol_pubkey,
        true, /* is_protocol_fee */
    )?;

    // Call `settle_offline_fee`
    contract
        .settle_offline_fee(
            serialize_to_calldata(&proof)?,
            serialize_to_calldata(&statement)?,
        )
        .send()
        .await?
        .await?;

    // Assert that nullifier is spent

    let nullifier = scalar_to_u256(statement.nullifier);
    let nullifier_spent = contract.is_nullifier_spent(nullifier).call().await?;
    assert!(nullifier_spent, "Nullifier not spent");

    // Assert that Merkle root is correct

    insert_shares_and_get_root(
        &mut ark_merkle,
        statement.updated_wallet_commitment,
        &statement.updated_wallet_public_shares,
        0, /* index */
    )
    .map_err(|e| eyre!("{}", e))?;

    ark_merkle
        .update(1 /*index */, &statement.note_commitment)
        .map_err(|_| eyre!("Failed to update Arkworks Merkle tree"))?;

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    assert_eq!(ark_merkle.root(), contract_root, "Merkle root incorrect");

    Ok(())
}
integration_test_async!(test_settle_offline_fee);

/// Test that the `settle_offline_fee` method on the darkpool
/// fails when the protocol key is incorrect
#[allow(non_snake_case)]
async fn test_settle_offline_fee__incorrect_protocol_key(test_args: TestArgs) -> Result<()> {
    let contract = DarkpoolTestContract::new(test_args.darkpool_proxy_address, test_args.client);

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    // Generate test data
    let mut rng = thread_rng();

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    // Generate a dummy protocol pubkey
    let protocol_pubkey = dummy_circuit_type(&mut rng);

    let (proof, statement) = gen_settle_offline_fee_data(
        &mut rng,
        Scalar::new(contract_root),
        protocol_pubkey,
        true, /* is_protocol_fee */
    )?;

    // Call `settle_offline_fee` with invalid data
    assert!(
        contract
            .settle_offline_fee(
                serialize_to_calldata(&proof)?,
                serialize_to_calldata(&statement)?,
            )
            .send()
            .await
            .is_err(),
        "Incorrect protocol key did not fail"
    );

    Ok(())
}
integration_test_async!(test_settle_offline_fee__incorrect_protocol_key);

/// Test the `redeem_fee` method on the darkpool
async fn test_redeem_fee(test_args: TestArgs) -> Result<()> {
    let contract = DarkpoolTestContract::new(test_args.darkpool_proxy_address, test_args.client);

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let mut rng = thread_rng();

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;
    let (proof, statement, wallet_commitment_signature) =
        gen_redeem_fee_data(&mut rng, Scalar::new(contract_root))?;

    // Call `redeem_fee`
    contract
        .redeem_fee(
            serialize_to_calldata(&proof)?,
            serialize_to_calldata(&statement)?,
            wallet_commitment_signature,
        )
        .send()
        .await?
        .await?;

    // Assert that both recipient & note nullifiers are spent

    let recipient_nullifier = scalar_to_u256(statement.nullifier);
    let nullifier_spent = contract
        .is_nullifier_spent(recipient_nullifier)
        .call()
        .await?;
    assert!(nullifier_spent, "Recipient nullifier not spent");

    let note_nullifier = scalar_to_u256(statement.note_nullifier);
    let nullifier_spent = contract.is_nullifier_spent(note_nullifier).call().await?;
    assert!(nullifier_spent, "Note nullifier not spent");

    // Assert that Merkle root is correct

    let ark_root = insert_shares_and_get_root(
        &mut ark_merkle,
        statement.new_wallet_commitment,
        &statement.new_wallet_public_shares,
        0, /* index */
    )
    .map_err(|e| eyre!("{}", e))?;

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    Ok(())
}
integration_test_async!(test_redeem_fee);

// TODO: Add test cases covering invalid historical Merkle roots,
// invalid signatures over wallet commitments, and duplicate nullifiers
