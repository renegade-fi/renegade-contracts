//! Integration tests for the contracts

use ark_ec::AffineRepr;
use ark_ff::One;
use ark_std::UniformRand;
use circuit_types::test_helpers::TESTING_SRS;
use constants::{Scalar, SystemCurve};
use contracts_common::{
    constants::{
        MERKLE_ADDRESS_SELECTOR, TEST_MERKLE_HEIGHT, VERIFIER_ADDRESS_SELECTOR,
        VKEYS_ADDRESS_SELECTOR,
    },
    serde_def_types::{SerdeG1Affine, SerdeG2Affine, SerdeScalarField},
    types::{G1Affine, G2Affine, PublicInputs, ScalarField},
};
use contracts_core::crypto::{ecdsa::pubkey_to_address, poseidon::compute_poseidon_hash};
use contracts_utils::{
    crypto::{hash_and_sign_message, random_keypair, NativeHasher},
    merkle::new_ark_merkle_tree,
    proof_system::{
        test_circuit::gen_test_circuit_proofs_and_vkeys,
        test_data::{
            gen_new_wallet_data, gen_process_match_settle_data, gen_update_wallet_data,
            random_scalars,
        },
    },
};
use ethers::{
    abi::Address,
    middleware::SignerMiddleware,
    providers::Middleware,
    signers::LocalWallet,
    types::{Bytes, TransactionRequest, U256},
    utils::{keccak256, parse_ether},
};
use eyre::Result;
use itertools::multiunzip;
use jf_primitives::pcs::prelude::UnivariateUniversalParams;
use rand::{thread_rng, RngCore};
use std::sync::Arc;

use crate::{
    abis::{
        DarkpoolProxyAdminContract, DarkpoolTestContract, DummyErc20Contract,
        DummyUpgradeTargetContract, MerkleContract, PrecompileTestContract, VerifierContract,
    },
    constants::{
        L, PAUSE_METHOD_NAME, PROOF_BATCH_SIZE, SET_FEE_METHOD_NAME,
        SET_MERKLE_ADDRESS_METHOD_NAME, SET_VERIFIER_ADDRESS_METHOD_NAME,
        SET_VKEYS_ADDRESS_METHOD_NAME, TRANSFER_AMOUNT, TRANSFER_OWNERSHIP_METHOD_NAME,
        UNPAUSE_METHOD_NAME,
    },
    utils::{
        assert_all_revert, assert_all_suceed, assert_only_owner, dummy_erc20_deposit,
        dummy_erc20_withdrawal, execute_transfer_and_get_balances, insert_shares_and_get_root,
        mint_dummy_erc20, scalar_to_u256, serialize_to_calldata, serialize_verification_bundle,
        u256_to_scalar,
    },
};

/// Test how the contracts call the `ecAdd` precompile
pub(crate) async fn test_ec_add(
    contract: PrecompileTestContract<impl Middleware + 'static>,
) -> Result<()> {
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

/// Test how the contracts call the `ecMul` precompile
pub(crate) async fn test_ec_mul(
    contract: PrecompileTestContract<impl Middleware + 'static>,
) -> Result<()> {
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

/// Test how the contracts call the `ecPairing` precompile
pub(crate) async fn test_ec_pairing(
    contract: PrecompileTestContract<impl Middleware + 'static>,
) -> Result<()> {
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

/// Test how the contracts call the `ecRecover` precompile
pub(crate) async fn test_ec_recover(
    contract: PrecompileTestContract<impl Middleware + 'static>,
) -> Result<()> {
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

/// Test the Merkle tree functionality
pub(crate) async fn test_merkle(contract: MerkleContract<impl Middleware + 'static>) -> Result<()> {
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
            .unwrap();
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

/// Test the upgradeability of the darkpool
pub(crate) async fn test_verifier(
    contract: VerifierContract<impl Middleware + 'static>,
) -> Result<()> {
    let mut rng = thread_rng();
    let (vkey_batch, mut proof_batch, mut public_inputs_batch): (Vec<_>, Vec<_>, Vec<_>) =
        multiunzip((0..PROOF_BATCH_SIZE).map(|_| {
            let public_inputs = PublicInputs(random_scalars(L, &mut rng));
            let (proof, _, vkeys) =
                gen_test_circuit_proofs_and_vkeys(&TESTING_SRS, &public_inputs, &[]).unwrap();
            let vkey = vkeys.vkey;
            (vkey, proof, public_inputs)
        }));

    // Duplicate the first two proofs/public inputs, this is the structure expected by the
    // batch verification method (mirrors that of `process_match_settle`)
    let first_two_proofs = proof_batch[..2].to_vec();
    let first_two_public_inputs = public_inputs_batch[..2].to_vec();
    proof_batch.splice(0..0, first_two_proofs);
    public_inputs_batch.splice(0..0, first_two_public_inputs);

    // First, we test single verification success
    let single_verification_bundle = serialize_verification_bundle(
        &[vkey_batch[0]],
        &[proof_batch[0].clone()],
        &[public_inputs_batch[0].clone()],
    )
    .unwrap();

    let successful_res = contract.verify(single_verification_bundle).call().await?;

    assert!(successful_res, "Valid proof did not verify");

    // Next, we test batch verification success
    let batch_verification_bundle =
        serialize_verification_bundle(&vkey_batch, &proof_batch, &public_inputs_batch).unwrap();

    let successful_res = contract
        .verify_match(batch_verification_bundle)
        .call()
        .await?;

    assert!(successful_res, "Valid proof batch did not verify");

    // Now, we check that invalid proofs fail

    let proof = &mut proof_batch[0];
    proof.z_bar += ScalarField::one();

    // First, for single verification
    let single_verification_bundle = serialize_verification_bundle(
        &[vkey_batch[0]],
        &[proof_batch[0].clone()],
        &[public_inputs_batch[0].clone()],
    )
    .unwrap();

    let unsuccessful_res = contract.verify(single_verification_bundle).call().await?;

    assert!(!unsuccessful_res, "Invalid proof did not verified");

    // Next, for batch verification
    let bundle_bytes =
        serialize_verification_bundle(&vkey_batch, &proof_batch, &public_inputs_batch)?;
    let unsuccessful_res = contract.verify_match(bundle_bytes).call().await?;

    assert!(!unsuccessful_res, "Invalid proof batch verified");

    Ok(())
}

/// Test the upgradeability of the darkpool
pub(crate) async fn test_upgradeable(
    proxy_admin_contract: DarkpoolProxyAdminContract<impl Middleware + 'static>,
    proxy_address: Address,
    dummy_upgrade_target_address: Address,
    darkpool_address: Address,
) -> Result<()> {
    let client = proxy_admin_contract.client();

    let darkpool = DarkpoolTestContract::new(proxy_address, client.clone());

    // Mark a random nullifier as spent to test that it is not cleared on upgrade
    let mut rng = thread_rng();
    let nullifier = scalar_to_u256(ScalarField::rand(&mut rng));

    darkpool
        .mark_nullifier_spent(nullifier)
        .send()
        .await?
        .await?;

    // Ensure that only the owner can upgrade the contract
    let dummy_signer = Arc::new(
        SignerMiddleware::new_with_provider_chain(
            proxy_admin_contract.client(),
            LocalWallet::new(&mut rng),
        )
        .await?,
    );
    let proxy_admin_contract_with_dummy_signer =
        DarkpoolProxyAdminContract::new(proxy_admin_contract.address(), dummy_signer);

    assert!(
        proxy_admin_contract_with_dummy_signer
            .upgrade_and_call(
                proxy_address,
                dummy_upgrade_target_address,
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
            proxy_address,
            dummy_upgrade_target_address,
            Bytes::new(), /* data */
        )
        .send()
        .await?
        .await?;

    let dummy_upgrade_target_contract = DummyUpgradeTargetContract::new(proxy_address, client);

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
        .upgrade_and_call(proxy_address, darkpool_address, Bytes::new())
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

/// Test the upgradeability of the contracts the darkpool calls
/// (verifier, vkeys, & Merkle)
pub(crate) async fn test_implementation_address_setters(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
    verifier_address: Address,
    vkeys_address: Address,
    merkle_address: Address,
    dummy_upgrade_target_address: Address,
) -> Result<()> {
    for (method, address_selector, original_address) in [
        (
            SET_VERIFIER_ADDRESS_METHOD_NAME,
            VERIFIER_ADDRESS_SELECTOR,
            verifier_address,
        ),
        (
            SET_VKEYS_ADDRESS_METHOD_NAME,
            VKEYS_ADDRESS_SELECTOR,
            vkeys_address,
        ),
        (
            SET_MERKLE_ADDRESS_METHOD_NAME,
            MERKLE_ADDRESS_SELECTOR,
            merkle_address,
        ),
    ] {
        // Set the new implementation address as the dummy upgrade target address
        contract
            .method::<Address, ()>(method, dummy_upgrade_target_address)?
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

/// Test the initialization of the darkpool
pub(crate) async fn test_initializable(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
) -> Result<()> {
    let dummy_verifier_address = Address::random();
    let dummy_vkeys_address = Address::random();
    let dummy_merkle_address = Address::random();
    let dummy_protocol_fee = U256::from(1);

    assert!(
        contract
            .initialize(
                dummy_verifier_address,
                dummy_vkeys_address,
                dummy_merkle_address,
                dummy_protocol_fee,
            )
            .send()
            .await
            .is_err(),
        "Initialized contract twice"
    );

    Ok(())
}

/// Test the ownership of the darkpool
pub(crate) async fn test_ownable(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
    verifier_address: Address,
    vkeys_address: Address,
    merkle_address: Address,
) -> Result<()> {
    let initial_owner = contract.client().default_sender().unwrap();

    // Assert that the owner is set correctly initially
    assert_eq!(
        contract.owner().call().await?,
        initial_owner,
        "Incorrect initial owner"
    );

    // Set up a dummy owner account and a contract instance with that account attached as the sender
    let mut rng = thread_rng();
    let dummy_owner = Arc::new(
        SignerMiddleware::new_with_provider_chain(contract.client(), LocalWallet::new(&mut rng))
            .await?,
    );
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

    contract
        .client()
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
        verifier_address,
    )
    .await?;
    assert_only_owner::<_, Address>(
        &contract,
        &contract_with_dummy_owner,
        SET_VKEYS_ADDRESS_METHOD_NAME,
        vkeys_address,
    )
    .await?;
    assert_only_owner::<_, Address>(
        &contract,
        &contract_with_dummy_owner,
        SET_MERKLE_ADDRESS_METHOD_NAME,
        merkle_address,
    )
    .await?;

    Ok(())
}

/// Test the pausability of the darkpool
pub(crate) async fn test_pausable(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
    srs: &UnivariateUniversalParams<SystemCurve>,
) -> Result<()> {
    let mut rng = thread_rng();
    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    contract.pause().send().await?.await?;

    // Assert that the contract is paused
    assert!(contract.paused().call().await?, "Contract not paused");

    // Assert that all setters revert when the contract is paused
    // This requires passing in valid data

    let (new_wallet_proof, new_wallet_statement) = gen_new_wallet_data(&mut rng, srs)?;

    let (update_wallet_proof, update_wallet_statement, public_inputs_signature) =
        gen_update_wallet_data(&mut rng, srs, Scalar::new(contract_root))?;

    let data = gen_process_match_settle_data(&mut rng, srs, Scalar::new(contract_root))?;

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
                public_inputs_signature.clone(),
            )
            .send(),
        contract
            .process_match_settle(
                serialize_to_calldata(&data.party_0_match_payload)?,
                serialize_to_calldata(&data.party_0_valid_commitments_proof)?,
                serialize_to_calldata(&data.party_0_valid_reblind_proof)?,
                serialize_to_calldata(&data.party_1_match_payload)?,
                serialize_to_calldata(&data.party_1_valid_commitments_proof)?,
                serialize_to_calldata(&data.party_1_valid_reblind_proof)?,
                serialize_to_calldata(&data.valid_match_settle_proof)?,
                serialize_to_calldata(&data.valid_match_settle_statement)?,
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
                public_inputs_signature,
            )
            .send(),
        contract
            .process_match_settle(
                serialize_to_calldata(&data.party_0_match_payload)?,
                serialize_to_calldata(&data.party_0_valid_commitments_proof)?,
                serialize_to_calldata(&data.party_0_valid_reblind_proof)?,
                serialize_to_calldata(&data.party_1_match_payload)?,
                serialize_to_calldata(&data.party_1_valid_commitments_proof)?,
                serialize_to_calldata(&data.party_1_valid_reblind_proof)?,
                serialize_to_calldata(&data.valid_match_settle_proof)?,
                serialize_to_calldata(&data.valid_match_settle_statement)?,
            )
            .send(),
    ])
    .await?;

    Ok(())
}

/// Test the nullifier set functionality
pub(crate) async fn test_nullifier_set(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
) -> Result<()> {
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

/// Test deposit / withdrawal functionality of the darkpool
pub(crate) async fn test_external_transfer(
    darkpool_test_contract: DarkpoolTestContract<impl Middleware + 'static>,
    dummy_erc20_contract: DummyErc20Contract<impl Middleware + 'static>,
) -> Result<()> {
    let darkpool_address = darkpool_test_contract.address();
    let account_address = darkpool_test_contract.client().default_sender().unwrap();
    let mint = dummy_erc20_contract.address();

    // Deposit initial funds for darkpool & user in dummy erc20 address
    mint_dummy_erc20(&dummy_erc20_contract, &[darkpool_address, account_address]).await?;

    let darkpool_initial_balance = dummy_erc20_contract
        .balance_of(darkpool_address)
        .call()
        .await?;
    let user_initial_balance = dummy_erc20_contract
        .balance_of(account_address)
        .call()
        .await?;

    // Create & execute deposit external transfer, check balances
    let deposit = dummy_erc20_deposit(account_address, mint);
    let (darkpool_balance, user_balance) = execute_transfer_and_get_balances(
        &darkpool_test_contract,
        &dummy_erc20_contract,
        &deposit,
        account_address,
    )
    .await?;
    assert_eq!(
        darkpool_balance,
        darkpool_initial_balance + TRANSFER_AMOUNT,
        "Post-deposit darkpool balance incorrect"
    );
    assert_eq!(
        user_balance,
        user_initial_balance - TRANSFER_AMOUNT,
        "Post-deposit user balance incorrect"
    );

    // Create & execute withdrawal external transfer, check balances
    let withdrawal = dummy_erc20_withdrawal(account_address, mint);
    let (darkpool_balance, user_balance) = execute_transfer_and_get_balances(
        &darkpool_test_contract,
        &dummy_erc20_contract,
        &withdrawal,
        account_address,
    )
    .await?;
    assert_eq!(
        darkpool_balance, darkpool_initial_balance,
        "Post-withdrawal darkpool balance incorrect"
    );
    assert_eq!(
        user_balance, user_initial_balance,
        "Post-withdrawal user balance incorrect"
    );

    Ok(())
}

/// Test the `new_wallet` method on the darkpool
pub(crate) async fn test_new_wallet(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
    srs: &UnivariateUniversalParams<SystemCurve>,
) -> Result<()> {
    let mut rng = thread_rng();

    let (proof, statement) = gen_new_wallet_data(&mut rng, srs)?;

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
    )
    .unwrap();

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    // Clear merkle state for future tests
    contract.clear_merkle().send().await?.await?;

    Ok(())
}

/// Test the `update_wallet` method on the darkpool
pub(crate) async fn test_update_wallet(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
    srs: &UnivariateUniversalParams<SystemCurve>,
) -> Result<()> {
    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let mut rng = thread_rng();

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;
    let (proof, statement, public_inputs_signature) =
        gen_update_wallet_data(&mut rng, srs, Scalar::new(contract_root))?;

    // Call `update_wallet`
    contract
        .update_wallet(
            serialize_to_calldata(&proof)?,
            serialize_to_calldata(&statement)?,
            public_inputs_signature,
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
    .unwrap();

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    // Clear merkle state for future tests
    contract.clear_merkle().send().await?.await?;

    Ok(())
}

/// Test the `process_match_settle` method on the darkpool
pub(crate) async fn test_process_match_settle(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
    srs: &UnivariateUniversalParams<SystemCurve>,
) -> Result<()> {
    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;
    let mut rng = thread_rng();
    let data = gen_process_match_settle_data(&mut rng, srs, Scalar::new(contract_root))?;

    // Call `process_match_settle` with valid data
    contract
        .process_match_settle(
            serialize_to_calldata(&data.party_0_match_payload)?,
            serialize_to_calldata(&data.party_0_valid_commitments_proof)?,
            serialize_to_calldata(&data.party_0_valid_reblind_proof)?,
            serialize_to_calldata(&data.party_1_match_payload)?,
            serialize_to_calldata(&data.party_1_valid_commitments_proof)?,
            serialize_to_calldata(&data.party_1_valid_reblind_proof)?,
            serialize_to_calldata(&data.valid_match_settle_proof)?,
            serialize_to_calldata(&data.valid_match_settle_statement)?,
        )
        .send()
        .await?
        .await?;

    // Assert that correct nullifiers are spent
    let party_0_nullifier = scalar_to_u256(
        data.party_0_match_payload
            .valid_reblind_statement
            .original_shares_nullifier,
    );
    let party_1_nullifier = scalar_to_u256(
        data.party_1_match_payload
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
        data.party_0_match_payload
            .valid_reblind_statement
            .reblinded_private_shares_commitment,
        &data.valid_match_settle_statement.party0_modified_shares,
        0, /* index */
    )
    .unwrap();
    let ark_root = insert_shares_and_get_root(
        &mut ark_merkle,
        data.party_1_match_payload
            .valid_reblind_statement
            .reblinded_private_shares_commitment,
        &data.valid_match_settle_statement.party1_modified_shares,
        1, /* index */
    )
    .unwrap();

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    // Clear merkle state for future tests
    contract.clear_merkle().send().await?.await?;

    Ok(())
}
