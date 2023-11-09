//! Integration tests for the contracts

use std::sync::Arc;

use ark_crypto_primitives::merkle_tree::MerkleTree as ArkMerkleTree;
use ark_ec::AffineRepr;
use ark_ff::One;
use ark_std::UniformRand;
use common::{
    constants::TEST_MERKLE_HEIGHT,
    serde_def_types::{SerdeG1Affine, SerdeG2Affine, SerdeScalarField},
    types::{G1Affine, G2Affine, ScalarField, VerificationBundle},
};
use contracts_core::crypto::{ecdsa::pubkey_to_address, poseidon::compute_poseidon_hash};
use ethers::{
    abi::Address, middleware::SignerMiddleware, providers::Middleware, signers::LocalWallet,
    types::Bytes, utils::keccak256,
};
use eyre::Result;
use rand::{thread_rng, RngCore};
use test_helpers::{
    crypto::{hash_and_sign_message, random_keypair, NativeHasher},
    merkle::MerkleConfig,
    misc::random_scalars,
    proof_system::{convert_jf_proof_and_vkey, dummy_vkeys, gen_jf_proof_and_vkey},
    renegade_circuits::{
        circuit_bundle_from_statement, gen_valid_wallet_update_statement, Circuit,
    },
};

use crate::{
    abis::{
        DarkpoolTestContract, DummyErc20Contract, MerkleContract, PrecompileTestContract,
        VerifierTestContract,
    },
    constants::{L, N, TRANSFER_AMOUNT},
    utils::{
        assert_only_owner, dummy_erc20_deposit, dummy_erc20_withdrawal,
        execute_transfer_and_get_balances, get_process_match_settle_data, mint_dummy_erc20,
        serialize_to_calldata, setup_darkpool_test_contract,
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
    let mut ark_merkle =
        ArkMerkleTree::<MerkleConfig>::blank(&(), &(), TEST_MERKLE_HEIGHT).unwrap();
    contract.init().send().await?.await?;

    let num_leaves = 2_u128.pow((TEST_MERKLE_HEIGHT - 1) as u32);
    let mut rng = thread_rng();
    let leaves = random_scalars(num_leaves as usize, &mut rng);

    for (i, leaf) in leaves.into_iter().enumerate() {
        ark_merkle
            .update(i, &compute_poseidon_hash(&[leaf]))
            .unwrap();
        contract
            .insert_shares_commitment(serialize_to_calldata(&vec![SerdeScalarField(leaf)])?)
            .send()
            .await?
            .await?;
    }

    let contract_root: SerdeScalarField = postcard::from_bytes(&contract.root().call().await?)?;

    assert_eq!(ark_merkle.root(), contract_root.0, "Merkle root incorrect");

    assert!(
        contract
            .insert_shares_commitment(serialize_to_calldata(&vec![SerdeScalarField(
                ScalarField::rand(&mut rng)
            )])?)
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
    let public_inputs = random_scalars(L, &mut rng);
    let (jf_proof, jf_vkey) = gen_jf_proof_and_vkey(N, &public_inputs)?;
    let (proof, vkey) = convert_jf_proof_and_vkey(jf_proof, jf_vkey);

    let mut verification_bundle = VerificationBundle {
        vkey,
        proof,
        public_inputs,
    };
    let bundle_bytes = serialize_to_calldata(&verification_bundle)?;

    let successful_res = contract
        .verify(verifier_address, bundle_bytes)
        .call()
        .await?;

    assert!(successful_res, "Valid proof did not verify");

    verification_bundle.proof.z_bar += ScalarField::one();
    let bundle_bytes = serialize_to_calldata(&verification_bundle)?;
    let unsuccessful_res = contract
        .verify(verifier_address, bundle_bytes)
        .call()
        .await?;

    assert!(!unsuccessful_res, "Invalid proof verified");

    Ok(())
}

pub(crate) async fn test_ownership(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
    darkpool_test_contract_address: Address,
) -> Result<()> {
    // Set up contract instance w/ dummy signer
    let mut rng = thread_rng();
    let dummy_signer = Arc::new(
        SignerMiddleware::new_with_provider_chain(contract.client(), LocalWallet::new(&mut rng))
            .await?,
    );
    let contract_with_dummy_signer =
        DarkpoolTestContract::new(darkpool_test_contract_address, dummy_signer);

    // Set up test data
    let dummy_verifier_address = Address::random();
    let dummy_vkey_bytes = Bytes::from(postcard::to_allocvec(&dummy_vkeys(N as u64, L as u64).0)?);

    // Assert that transferring to 0 address fails
    assert!(
        contract
            .transfer_ownership(Address::zero())
            .send()
            .await
            .is_err(),
        "Transferred ownership to 0 address"
    );

    // Set the owner to the default sender
    contract
        .transfer_ownership(contract.client().default_sender().unwrap())
        .send()
        .await?
        .await?;

    // Assert that `setVerifierAddress` only succeeds for the owner
    assert_only_owner::<_, Address>(
        &contract,
        &contract_with_dummy_signer,
        "setVerifierAddress",
        dummy_verifier_address,
    )
    .await?;

    // Assert that `setValidWalletCreateVkey` only succeeds for the owner
    assert_only_owner::<_, Bytes>(
        &contract,
        &contract_with_dummy_signer,
        "setValidWalletCreateVkey",
        dummy_vkey_bytes.clone(),
    )
    .await?;

    // Assert that `setValidWalletUpdateVkey` only succeeds for the owner
    assert_only_owner::<_, Bytes>(
        &contract,
        &contract_with_dummy_signer,
        "setValidWalletUpdateVkey",
        dummy_vkey_bytes.clone(),
    )
    .await?;

    // Assert that `setValidCommitmentsVkey` only succeeds for the owner
    assert_only_owner::<_, Bytes>(
        &contract,
        &contract_with_dummy_signer,
        "setValidCommitmentsVkey",
        dummy_vkey_bytes.clone(),
    )
    .await?;

    // Assert that `setValidReblindVkey` only succeeds for the owner
    assert_only_owner::<_, Bytes>(
        &contract,
        &contract_with_dummy_signer,
        "setValidReblindVkey",
        dummy_vkey_bytes.clone(),
    )
    .await?;

    // Assert that `setValidMatchSettleVkey` only succeeds for the owner
    assert_only_owner::<_, Bytes>(
        &contract,
        &contract_with_dummy_signer,
        "setValidMatchSettleVkey",
        dummy_vkey_bytes.clone(),
    )
    .await?;

    Ok(())
}

pub(crate) async fn test_nullifier_set(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
) -> Result<()> {
    let mut rng = thread_rng();
    let nullifier_bytes = serialize_to_calldata(&SerdeScalarField(ScalarField::rand(&mut rng)))?;

    let nullifier_spent = contract
        .is_nullifier_spent(nullifier_bytes.clone())
        .call()
        .await?;

    assert!(!nullifier_spent, "Nullifier already spent");

    contract
        .mark_nullifier_spent(nullifier_bytes.clone())
        .send()
        .await?
        .await?;

    let nullifier_spent = contract.is_nullifier_spent(nullifier_bytes).call().await?;

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

pub(crate) async fn test_update_wallet(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
    merkle_address: Address,
    verifier_address: Address,
) -> Result<()> {
    // Generate test data
    let mut ark_merkle =
        ArkMerkleTree::<MerkleConfig>::blank(&(), &(), TEST_MERKLE_HEIGHT).unwrap();

    let mut rng = thread_rng();

    let (signing_key, pubkey) = random_keypair(&mut rng);
    let merkle_root = ark_merkle.root();

    let valid_wallet_update_statement = gen_valid_wallet_update_statement(
        &mut rng,
        None, /* external_transfer */
        merkle_root,
        pubkey,
    );

    let (vkey, proof) = circuit_bundle_from_statement(&valid_wallet_update_statement, N)?;

    let valid_wallet_update_statement_bytes =
        serialize_to_calldata(&valid_wallet_update_statement)?;
    let public_inputs_signature = Bytes::from(
        hash_and_sign_message(&signing_key, &valid_wallet_update_statement_bytes).to_vec(),
    );

    let wallet_blinder_share = SerdeScalarField(ScalarField::rand(&mut rng));

    // Set up contract
    setup_darkpool_test_contract(
        &contract,
        merkle_address,
        verifier_address,
        vec![(Circuit::ValidWalletUpdate, serialize_to_calldata(&vkey)?)],
    )
    .await?;

    // Call `update_wallet` with valid data
    contract
        .update_wallet(
            serialize_to_calldata(&wallet_blinder_share)?,
            serialize_to_calldata(&proof)?,
            valid_wallet_update_statement_bytes,
            public_inputs_signature,
        )
        .send()
        .await?
        .await?;

    // Assert that correct nullifier is spent
    let nullifier_bytes = serialize_to_calldata(&SerdeScalarField(
        valid_wallet_update_statement.old_shares_nullifier,
    ))?;

    let nullifier_spent = contract.is_nullifier_spent(nullifier_bytes).call().await?;
    assert!(nullifier_spent, "Nullifier not spent");

    // Assert that Merkle root is correct

    let mut shares = vec![valid_wallet_update_statement.new_private_shares_commitment];
    shares.extend(valid_wallet_update_statement.new_public_shares);
    let commitment = compute_poseidon_hash(&shares);
    ark_merkle.update(0, &commitment).unwrap();

    let ark_root = ark_merkle.root();
    let contract_root: ScalarField =
        postcard::from_bytes::<SerdeScalarField>(&contract.get_root().call().await?)
            .unwrap()
            .0;

    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    Ok(())
}

pub(crate) async fn test_process_match_settle(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
    merkle_address: Address,
    verifier_address: Address,
) -> Result<()> {
    // Generate test data
    let mut rng = thread_rng();
    let data = get_process_match_settle_data(&mut rng)?;

    // Set up contract
    setup_darkpool_test_contract(
        &contract,
        merkle_address,
        verifier_address,
        vec![
            (
                Circuit::ValidCommitments,
                serialize_to_calldata(&data.valid_commitments_vkey)?,
            ),
            (
                Circuit::ValidReblind,
                serialize_to_calldata(&data.valid_reblind_vkey)?,
            ),
            (
                Circuit::ValidMatchSettle,
                serialize_to_calldata(&data.valid_match_settle_vkey)?,
            ),
        ],
    )
    .await?;

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
    let party_0_nullifier_bytes = serialize_to_calldata(&SerdeScalarField(
        data.party_0_match_payload
            .valid_reblind_statement
            .original_shares_nullifier,
    ))?;
    let party_1_nullifier_bytes = serialize_to_calldata(&SerdeScalarField(
        data.party_1_match_payload
            .valid_reblind_statement
            .original_shares_nullifier,
    ))?;

    let party_0_nullifier_spent = contract
        .is_nullifier_spent(party_0_nullifier_bytes)
        .call()
        .await?;
    assert!(party_0_nullifier_spent, "Party 0 nullifier not spent");

    let party_1_nullifier_spent = contract
        .is_nullifier_spent(party_1_nullifier_bytes)
        .call()
        .await?;
    assert!(party_1_nullifier_spent, "Party 1 nullifier not spent");

    Ok(())
}
