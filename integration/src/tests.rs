//! Integration tests for the contracts

use std::sync::Arc;

use ark_ec::AffineRepr;
use ark_ff::One;
use ark_std::UniformRand;
use circuit_types::test_helpers::TESTING_SRS;
use common::{
    constants::TEST_MERKLE_HEIGHT,
    serde_def_types::{SerdeG1Affine, SerdeG2Affine, SerdeScalarField},
    types::{G1Affine, G2Affine, PublicInputs, ScalarField, ValidWalletCreateStatement},
};
use constants::SystemCurve;
use contracts_core::crypto::{ecdsa::pubkey_to_address, poseidon::compute_poseidon_hash};
use ethers::{
    abi::Address, middleware::SignerMiddleware, providers::Middleware, signers::LocalWallet,
    types::Bytes, utils::keccak256,
};
use eyre::Result;
use itertools::multiunzip;
use jf_primitives::pcs::prelude::UnivariateUniversalParams;
use rand::{seq::SliceRandom, thread_rng, RngCore};
use test_helpers::{
    crypto::{hash_and_sign_message, random_keypair, NativeHasher},
    merkle::new_ark_merkle_tree,
    misc::random_scalars,
    proof_system::{convert_jf_proof, convert_jf_vkey, gen_jf_proof_and_vkey},
    renegade_circuits::{
        dummy_circuit_bundle, gen_valid_wallet_update_statement, proof_from_statement,
    },
};

use crate::{
    abis::{
        DarkpoolProxyAdminContract, DarkpoolTestContract, DummyErc20Contract,
        DummyUpgradeTargetContract, MerkleContract, PrecompileTestContract, VerifierTestContract,
    },
    constants::{L, N, PROOF_BATCH_SIZE, TRANSFER_AMOUNT},
    utils::{
        dummy_erc20_deposit, dummy_erc20_withdrawal, execute_transfer_and_get_balances,
        get_process_match_settle_data, insert_shares_and_get_root, mint_dummy_erc20,
        scalar_to_u256, serialize_to_calldata, serialize_verification_bundle, u256_to_scalar,
    },
};

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

pub(crate) async fn test_merkle(contract: MerkleContract<impl Middleware + 'static>) -> Result<()> {
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);
    contract.init().send().await?.await?;

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
    }

    let contract_root = u256_to_scalar(contract.root().call().await?)?;

    assert_eq!(ark_merkle.root(), contract_root, "Merkle root incorrect");

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

pub(crate) async fn test_verifier(
    contract: VerifierTestContract<impl Middleware + 'static>,
    verifier_address: Address,
) -> Result<()> {
    let mut rng = thread_rng();
    let (vkey_batch, mut proof_batch, public_inputs_batch): (Vec<_>, Vec<_>, Vec<_>) =
        multiunzip((0..PROOF_BATCH_SIZE).map(|_| {
            let public_inputs = PublicInputs(random_scalars(L, &mut rng));
            let (jf_proof, jf_vkey) =
                gen_jf_proof_and_vkey(&TESTING_SRS, N, &public_inputs).unwrap();
            let proof = convert_jf_proof(jf_proof).unwrap();
            let vkey = convert_jf_vkey(jf_vkey).unwrap();
            (vkey, proof, public_inputs)
        }));

    let bundle_bytes =
        serialize_verification_bundle(&vkey_batch, &proof_batch, &public_inputs_batch)?;

    let successful_res = contract
        .verify(verifier_address, bundle_bytes)
        .call()
        .await?;

    assert!(successful_res, "Valid proof did not verify");

    let proof = proof_batch.choose_mut(&mut rng).unwrap();
    proof.z_bar += ScalarField::one();
    let bundle_bytes =
        serialize_verification_bundle(&vkey_batch, &proof_batch, &public_inputs_batch)?;
    let unsuccessful_res = contract
        .verify(verifier_address, bundle_bytes)
        .call()
        .await?;

    assert!(!unsuccessful_res, "Invalid proof verified");

    Ok(())
}

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

pub(crate) async fn test_initializable(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
) -> Result<()> {
    let dummy_verifier_address = Address::random();
    let dummy_vkeys_address = Address::random();
    let dummy_merkle_address = Address::random();

    assert!(
        contract
            .initialize(
                dummy_verifier_address,
                dummy_vkeys_address,
                dummy_merkle_address
            )
            .send()
            .await
            .is_err(),
        "Initialized contract twice"
    );

    Ok(())
}

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

pub(crate) async fn test_new_wallet(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
    srs: &UnivariateUniversalParams<SystemCurve>,
) -> Result<()> {
    // Generate test data
    let mut rng = thread_rng();
    let (valid_wallet_create_statement, proof) =
        dummy_circuit_bundle::<ValidWalletCreateStatement>(srs, N, &mut rng)?;

    // Call `new_wallet` with valid data
    contract
        .new_wallet(
            serialize_to_calldata(&vec![proof])?,
            serialize_to_calldata(&valid_wallet_create_statement)?,
        )
        .send()
        .await?
        .await?;

    // Assert that Merkle root is correct
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let ark_root = insert_shares_and_get_root(
        &mut ark_merkle,
        valid_wallet_create_statement.private_shares_commitment,
        &valid_wallet_create_statement.public_wallet_shares,
        0, /* index */
    )
    .unwrap();

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    // Clear merkle state for future tests
    contract.clear_merkle().send().await?.await?;

    Ok(())
}

pub(crate) async fn test_update_wallet(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
    srs: &UnivariateUniversalParams<SystemCurve>,
) -> Result<()> {
    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let mut rng = thread_rng();

    let (signing_key, pubkey) = random_keypair(&mut rng);

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    let valid_wallet_update_statement = gen_valid_wallet_update_statement(
        &mut rng,
        None, /* external_transfer */
        contract_root,
        pubkey,
    );

    let proof = proof_from_statement(srs, &valid_wallet_update_statement, N)?;

    let valid_wallet_update_statement_bytes =
        serialize_to_calldata(&valid_wallet_update_statement)?;
    let public_inputs_signature = Bytes::from(
        hash_and_sign_message(&signing_key, &valid_wallet_update_statement_bytes).to_vec(),
    );

    // Call `update_wallet` with valid data
    contract
        .update_wallet(
            serialize_to_calldata(&vec![proof])?,
            valid_wallet_update_statement_bytes,
            public_inputs_signature,
        )
        .send()
        .await?
        .await?;

    // Assert that correct nullifier is spent
    let nullifier = scalar_to_u256(valid_wallet_update_statement.old_shares_nullifier);

    let nullifier_spent = contract.is_nullifier_spent(nullifier).call().await?;
    assert!(nullifier_spent, "Nullifier not spent");

    // Assert that Merkle root is correct
    let ark_root = insert_shares_and_get_root(
        &mut ark_merkle,
        valid_wallet_update_statement.new_private_shares_commitment,
        &valid_wallet_update_statement.new_public_shares,
        0, /* index */
    )
    .unwrap();

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    // Clear merkle state for future tests
    contract.clear_merkle().send().await?.await?;

    Ok(())
}

pub(crate) async fn test_process_match_settle(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
    srs: &UnivariateUniversalParams<SystemCurve>,
) -> Result<()> {
    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;
    let mut rng = thread_rng();
    let data = get_process_match_settle_data(&mut rng, srs, contract_root)?;

    let proofs = vec![
        data.party_0_valid_commitments_proof,
        data.party_0_valid_reblind_proof,
        data.party_1_valid_commitments_proof,
        data.party_1_valid_reblind_proof,
        data.valid_match_settle_proof,
    ];

    // Call `process_match_settle` with valid data
    contract
        .process_match_settle(
            serialize_to_calldata(&data.party_0_match_payload)?,
            serialize_to_calldata(&data.party_1_match_payload)?,
            serialize_to_calldata(&data.valid_match_settle_statement)?,
            serialize_to_calldata(&proofs)?,
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
