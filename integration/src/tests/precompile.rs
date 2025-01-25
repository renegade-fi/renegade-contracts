//! Integration tests for precompile functionality

use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use contracts_common::{
    serde_def_types::{SerdeG1Affine, SerdeG2Affine, SerdeScalarField},
    types::{G1Affine, G2Affine, ScalarField},
};
use contracts_core::crypto::ecdsa::pubkey_to_address;
use contracts_utils::crypto::{hash_and_sign_message, random_keypair, NativeHasher};
use ethers::utils::keccak256;
use eyre::Result;
use rand::{thread_rng, RngCore};
use test_helpers::integration_test_async;

use crate::{abis::PrecompileTestContract, utils::serialize_to_calldata, TestContext};

/// Test how the contracts call the `ecAdd` precompile
async fn test_ec_add(ctx: TestContext) -> Result<()> {
    let contract = PrecompileTestContract::new(ctx.precompiles_contract_address, ctx.client);
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
async fn test_ec_mul(ctx: TestContext) -> Result<()> {
    let contract = PrecompileTestContract::new(ctx.precompiles_contract_address, ctx.client);
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
async fn test_ec_pairing(ctx: TestContext) -> Result<()> {
    let contract = PrecompileTestContract::new(ctx.precompiles_contract_address, ctx.client);
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
async fn test_ec_recover(ctx: TestContext) -> Result<()> {
    let contract = PrecompileTestContract::new(ctx.precompiles_contract_address, ctx.client);
    let mut rng = thread_rng();

    let (signing_key, pubkey) = random_keypair(&mut rng);

    let mut msg = [0u8; 32];
    rng.fill_bytes(&mut msg);

    let sig = hash_and_sign_message(&signing_key, &msg);

    let msg_hash = keccak256(msg);
    let res =
        contract.test_ec_recover(msg_hash.to_vec().into(), sig.to_vec().into()).call().await?;

    assert_eq!(
        res,
        pubkey_to_address::<NativeHasher>(&pubkey).to_vec(),
        "Incorrect recovered address"
    );

    Ok(())
}
integration_test_async!(test_ec_recover);
