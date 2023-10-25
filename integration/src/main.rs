//! Basic tests for Stylus programs. These assume that a devnet is already running locally.

use ark_ff::One;
use common::types::ScalarField;
use contracts_core::serde::Serializable;
use ethers::{
    middleware::SignerMiddleware,
    prelude::abigen,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{Address, Bytes},
};
use eyre::{eyre, Result};
use std::{str::FromStr, sync::Arc};
use test_helpers::{convert_jf_proof_and_vkey, gen_jf_proof_and_vkey};

/// Your private key.
const ENV_PRIV_KEY: &str = "PRIV_KEY";

/// Stylus RPC endpoint url.
const ENV_RPC_URL: &str = "RPC_URL";

/// Deployed pragram address.
const ENV_PROGRAM_ADDRESS: &str = "STYLUS_PROGRAM_ADDRESS";

abigen!(
    PrecompileTestContract,
    r#"[
        function testAdd() external view
        function testMul() external view
        function testPairing() external view
    ]"#
);

abigen!(
    VerifierContract,
    r#"[
        function verify(bytes memory vkey, bytes memory proof, bytes memory public_inputs) external view returns (bool)
    ]"#
);

/// Sets up the address and client with which to instantiate a contract for testing,
/// reading in the private key, RPC url, and contract address from the environment.
async fn setup_client() -> Result<(Address, Arc<impl Middleware>)> {
    let priv_key =
        std::env::var(ENV_PRIV_KEY).map_err(|_| eyre!("No {} env var set", ENV_PRIV_KEY))?;
    let rpc_url =
        std::env::var(ENV_RPC_URL).map_err(|_| eyre!("No {} env var set", ENV_RPC_URL))?;
    let program_address = std::env::var(ENV_PROGRAM_ADDRESS)
        .map_err(|_| eyre!("No {} env var set", ENV_PROGRAM_ADDRESS))?;

    let provider = Provider::<Http>::try_from(rpc_url)?;
    let address: Address = program_address.parse()?;

    let wallet = LocalWallet::from_str(&priv_key)?;
    let chain_id = provider.get_chainid().await?.as_u64();
    let client = Arc::new(SignerMiddleware::new(
        provider,
        wallet.clone().with_chain_id(chain_id),
    ));

    Ok((address, client))
}

/// Sets up the test contract using the ABI above
async fn setup_precompile_test_contract() -> Result<PrecompileTestContract<impl Middleware>> {
    let (address, client) = setup_client().await?;

    Ok(PrecompileTestContract::new(address, client))
}

/// Sets up the test contract using the ABI above
async fn setup_verifier_contract() -> Result<VerifierContract<impl Middleware>> {
    let (address, client) = setup_client().await?;

    Ok(VerifierContract::new(address, client))
}

#[tokio::main]
async fn main() -> Result<()> {
    // TODO: Read in which tests to run from the command line

    // let contract = setup_precompile_test_contract().await?;

    // contract.test_add().send().await?.await?;
    // contract.test_mul().send().await?.await?;
    // contract.test_pairing().send().await?.await?;

    let contract = setup_verifier_contract().await?;
    let (jf_proof, jf_vkey) = gen_jf_proof_and_vkey(8192)?;
    let (mut proof, vkey) = convert_jf_proof_and_vkey(jf_proof, jf_vkey);
    let vkey_bytes: Bytes = vkey.serialize().into();
    let proof_bytes: Bytes = proof.serialize().into();
    let public_input_bytes = Bytes::new();

    let successful_res = contract
        .verify(vkey_bytes.clone(), proof_bytes, public_input_bytes.clone())
        .call()
        .await?;

    assert!(successful_res, "Valid proof did not verify");

    proof.z_bar += ScalarField::one();
    let proof_bytes: Bytes = proof.serialize().into();
    let unsuccessful_res = contract
        .verify(vkey_bytes, proof_bytes, public_input_bytes)
        .call()
        .await?;

    assert!(!unsuccessful_res, "Invalid proof verified");

    Ok(())
}
