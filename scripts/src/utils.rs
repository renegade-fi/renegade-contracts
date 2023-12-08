//! Utilities for the deploy scripts.

use std::{
    env,
    fs::{self, File},
    io::Read,
    iter,
    path::PathBuf,
    process::{Command, Stdio},
    str::FromStr,
    sync::Arc,
};

use alloy_primitives::Address as AlloyAddress;
use alloy_sol_types::SolCall;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use circuit_types::traits::SingleProverCircuit;
use circuits::zk_circuits::{
    valid_commitments::SizedValidCommitments, valid_match_settle::SizedValidMatchSettle,
    valid_reblind::SizedValidReblind, valid_wallet_create::SizedValidWalletCreate,
    valid_wallet_update::SizedValidWalletUpdate,
};
use common::types::{
    ValidCommitmentsStatement, ValidMatchSettleStatement, ValidReblindStatement,
    ValidWalletCreateStatement, ValidWalletUpdateStatement, VerificationKey,
};
use constants::SystemCurve;
use ethers::{
    abi::Address,
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    utils::get_contract_address,
};
use itertools::Itertools;
use jf_primitives::pcs::prelude::UnivariateUniversalParams;
use json::JsonValue;

use rand::thread_rng;
use test_helpers::{
    proof_system::{convert_jf_vkey, gen_circuit_keys, gen_test_circuit_and_keys},
    renegade_circuits::RenegadeStatement,
};
use tracing::log::warn;

use crate::{
    cli::StylusContract,
    constants::{
        BUILD_COMMAND, CARGO_COMMAND, DARKPOOL_CONTRACT_KEY, DEPLOYMENTS_KEY, DEPLOY_COMMAND,
        DUMMY_ERC20_CONTRACT_KEY, MANIFEST_DIR_ENV_VAR, MERKLE_CONTRACT_KEY,
        NIGHTLY_TOOLCHAIN_SELECTOR, NO_VERIFY_FEATURE, RELEASE_PATH_SEGMENT,
        SIZE_OPTIMIZATION_FLAG, STYLUS_COMMAND, STYLUS_CONTRACTS_CRATE_NAME, TARGET_PATH_SEGMENT,
        TEST_CIRCUIT_DOMAIN_SIZE, VERIFIER_CONTRACT_KEY, WASM_EXTENSION, WASM_OPT_COMMAND,
        WASM_TARGET_TRIPLE, Z_FLAGS,
    },
    errors::ScriptError,
    solidity::initializeCall,
};

/// Sets up the address and client with which to instantiate a contract for testing,
/// reading in the private key, RPC url, and contract address from the environment.
pub async fn setup_client(
    priv_key: &str,
    rpc_url: &str,
) -> Result<Arc<impl Middleware>, ScriptError> {
    let provider = Provider::<Http>::try_from(rpc_url)
        .map_err(|e| ScriptError::ClientInitialization(e.to_string()))?;

    let wallet = LocalWallet::from_str(priv_key)
        .map_err(|e| ScriptError::ClientInitialization(e.to_string()))?;
    let chain_id = provider
        .get_chainid()
        .await
        .map_err(|e| ScriptError::ClientInitialization(e.to_string()))?
        .as_u64();
    let client = Arc::new(SignerMiddleware::new(
        provider,
        wallet.clone().with_chain_id(chain_id),
    ));

    Ok(client)
}

pub fn get_json_from_file(file_path: &str) -> Result<JsonValue, ScriptError> {
    let mut file_contents = String::new();
    File::open(file_path)
        .map_err(|e| ScriptError::ReadFile(e.to_string()))?
        .read_to_string(&mut file_contents)
        .map_err(|e| ScriptError::ReadFile(e.to_string()))?;

    json::parse(&file_contents).map_err(|e| ScriptError::ReadFile(e.to_string()))
}

pub fn parse_addr_from_deployments_file(
    file_path: &str,
    contract_key: &str,
) -> Result<Address, ScriptError> {
    let parsed_json = get_json_from_file(file_path)?;

    Address::from_str(
        parsed_json[DEPLOYMENTS_KEY][contract_key]
            .as_str()
            .ok_or_else(|| {
                ScriptError::ReadFile(
                    "Could not parse contract address from deployments file".to_string(),
                )
            })?,
    )
    .map_err(|e| ScriptError::ReadFile(e.to_string()))
}

pub fn parse_srs_from_file(
    file_path: &str,
) -> Result<UnivariateUniversalParams<SystemCurve>, ScriptError> {
    let srs_file = File::open(file_path).map_err(|e| ScriptError::ReadFile(e.to_string()))?;

    let srs = UnivariateUniversalParams::<SystemCurve>::deserialize_uncompressed(&srs_file)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;

    Ok(srs)
}

pub fn write_deployed_address(
    file_path: &str,
    contract_key: &str,
    address: Address,
) -> Result<(), ScriptError> {
    // If the file doesn't exist, create it
    if !PathBuf::from(file_path).exists() {
        fs::write(file_path, "{}").map_err(|e| ScriptError::WriteFile(e.to_string()))?;
    }
    let mut parsed_json = get_json_from_file(file_path)?;

    parsed_json[DEPLOYMENTS_KEY][contract_key] = JsonValue::String(format!("{address:#x}"));

    fs::write(file_path, json::stringify_pretty(parsed_json, 4))
        .map_err(|e| ScriptError::WriteFile(e.to_string()))?;

    Ok(())
}

pub fn write_srs_to_file(
    file_path: &str,
    srs: &UnivariateUniversalParams<SystemCurve>,
) -> Result<(), ScriptError> {
    // Create / open SRS file
    let mut srs_file =
        File::create(file_path).map_err(|e| ScriptError::WriteFile(e.to_string()))?;

    // Serialize SRS into file
    srs.serialize_uncompressed(&mut srs_file)
        .map_err(|e| ScriptError::Serde(e.to_string()))
}

pub fn get_contract_key(contract: StylusContract) -> &'static str {
    match contract {
        StylusContract::Darkpool | StylusContract::DarkpoolTestContract => DARKPOOL_CONTRACT_KEY,
        StylusContract::Merkle | StylusContract::MerkleTestContract => MERKLE_CONTRACT_KEY,
        StylusContract::Verifier => VERIFIER_CONTRACT_KEY,
        StylusContract::DummyErc20 => DUMMY_ERC20_CONTRACT_KEY,
    }
}

/// Prepare calldata for the Darkpool contract's `initialize` method
pub fn darkpool_initialize_calldata(
    verifier_address: Address,
    merkle_address: Address,
    srs_path: Option<String>,
    test: bool,
) -> Result<Vec<u8>, ScriptError> {
    let verifier_address = AlloyAddress::from_slice(verifier_address.as_bytes());
    let merkle_address = AlloyAddress::from_slice(merkle_address.as_bytes());

    let (
        valid_wallet_create_vkey_bytes,
        valid_wallet_update_vkey_bytes,
        valid_commitments_vkey_bytes,
        valid_reblind_vkey_bytes,
        valid_match_settle_vkey_bytes,
    ) = if let Some(srs_path) = srs_path {
        let srs = parse_srs_from_file(&srs_path)?;

        let (
            valid_wallet_create_vkey,
            valid_wallet_update_vkey,
            valid_commitments_vkey,
            valid_reblind_vkey,
            valid_match_settle_vkey,
        ) = if test {
            (
                gen_test_vkey::<ValidWalletCreateStatement>(&srs)?,
                gen_test_vkey::<ValidWalletUpdateStatement>(&srs)?,
                gen_test_vkey::<ValidCommitmentsStatement>(&srs)?,
                gen_test_vkey::<ValidReblindStatement>(&srs)?,
                gen_test_vkey::<ValidMatchSettleStatement>(&srs)?,
            )
        } else {
            (
                gen_vkey::<SizedValidWalletCreate>(&srs)?,
                gen_vkey::<SizedValidWalletUpdate>(&srs)?,
                gen_vkey::<SizedValidCommitments>(&srs)?,
                gen_vkey::<SizedValidReblind>(&srs)?,
                gen_vkey::<SizedValidMatchSettle>(&srs)?,
            )
        };

        let valid_wallet_create_vkey_bytes = postcard::to_allocvec(&valid_wallet_create_vkey)
            .map_err(|e| ScriptError::Serde(e.to_string()))?;
        let valid_wallet_update_vkey_bytes = postcard::to_allocvec(&valid_wallet_update_vkey)
            .map_err(|e| ScriptError::Serde(e.to_string()))?;
        let valid_commitments_vkey_bytes = postcard::to_allocvec(&valid_commitments_vkey)
            .map_err(|e| ScriptError::Serde(e.to_string()))?;
        let valid_reblind_vkey_bytes = postcard::to_allocvec(&valid_reblind_vkey)
            .map_err(|e| ScriptError::Serde(e.to_string()))?;
        let valid_match_settle_vkey_bytes = postcard::to_allocvec(&valid_match_settle_vkey)
            .map_err(|e| ScriptError::Serde(e.to_string()))?;

        (
            valid_wallet_create_vkey_bytes,
            valid_wallet_update_vkey_bytes,
            valid_commitments_vkey_bytes,
            valid_reblind_vkey_bytes,
            valid_match_settle_vkey_bytes,
        )
    } else {
        (vec![], vec![], vec![], vec![], vec![])
    };

    Ok(initializeCall::new((
        verifier_address,
        merkle_address,
        valid_wallet_create_vkey_bytes,
        valid_wallet_update_vkey_bytes,
        valid_commitments_vkey_bytes,
        valid_reblind_vkey_bytes,
        valid_match_settle_vkey_bytes,
    ))
    .encode())
}

fn command_success_or(mut cmd: Command, err_msg: &str) -> Result<(), ScriptError> {
    if !cmd
        .output()
        .map_err(|e| ScriptError::ContractCompilation(e.to_string()))?
        .status
        .success()
    {
        Err(ScriptError::ContractCompilation(String::from(err_msg)))
    } else {
        Ok(())
    }
}

/// Compiles the given Stylus contract to WASM and optimizes the resulting binary,
/// returning the path to the optimized WASM file.
///
/// Assumes that `cargo`, the `nightly` toolchain, and `wasm-opt` are locally available.
pub fn build_stylus_contract(
    contract: StylusContract,
    no_verify: bool,
) -> Result<PathBuf, ScriptError> {
    let current_dir = PathBuf::from(env::var(MANIFEST_DIR_ENV_VAR).unwrap());
    let workspace_path = current_dir
        .parent()
        .ok_or(ScriptError::ContractCompilation(String::from(
            "Could not find contracts directory",
        )))?;

    let mut build_cmd = Command::new(CARGO_COMMAND);
    build_cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    // Use the nightly toolchain, this allows us to use the -Z flags below
    build_cmd.arg(NIGHTLY_TOOLCHAIN_SELECTOR);
    // Set the working directory to the workspace root
    build_cmd.arg("-C");
    build_cmd.arg(workspace_path);
    // Invoke the build command
    build_cmd.arg(BUILD_COMMAND);
    // Use the release profile
    build_cmd.arg("-r");
    // Build the contracts-stylus package
    build_cmd.arg("-p");
    build_cmd.arg(STYLUS_CONTRACTS_CRATE_NAME);
    // Set the feature for the given contract,
    // ensuring that the contract gets built
    build_cmd.arg("--features");
    let mut features = vec![contract.to_string()];
    // If the `--no-verify` flag is set, enable the
    // "no-verify" feature
    if no_verify {
        features.push(NO_VERIFY_FEATURE.to_string());
    }
    build_cmd.arg(features.join(","));
    // Set the build target to WASM
    build_cmd.arg("--target");
    build_cmd.arg(WASM_TARGET_TRIPLE);
    // Set the Z flags, used to optimize the resulting binary size.
    // See constants.rs for the list of flags.
    let z_flags = iter::repeat("-Z")
        .take(Z_FLAGS.len())
        .interleave_shortest(Z_FLAGS);
    build_cmd.args(z_flags);

    command_success_or(build_cmd, "Failed to build contract WASM")?;

    let target_dir = workspace_path
        .join(TARGET_PATH_SEGMENT)
        .join(WASM_TARGET_TRIPLE)
        .join(RELEASE_PATH_SEGMENT);

    let wasm_file_path = fs::read_dir(target_dir)
        .map_err(|e| ScriptError::ContractCompilation(e.to_string()))?
        .find_map(|entry| {
            let path = entry.ok()?.path();
            path.extension()
                .is_some_and(|ext| ext == WASM_EXTENSION)
                .then_some(path)
        })
        .ok_or(ScriptError::ContractCompilation(String::from(
            "Could not find contract WASM file",
        )))?;

    let opt_wasm_file_path = wasm_file_path.with_extension("opt.wasm");

    let mut opt_cmd = Command::new(WASM_OPT_COMMAND);
    opt_cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    opt_cmd.arg(wasm_file_path);
    opt_cmd.arg("-o");
    opt_cmd.arg(opt_wasm_file_path.clone());
    opt_cmd.arg(SIZE_OPTIMIZATION_FLAG);

    command_success_or(opt_cmd, "Failed to optimize contract WASM")?;

    Ok(opt_wasm_file_path)
}

pub async fn deploy_stylus_contract(
    wasm_file_path: PathBuf,
    rpc_url: &str,
    priv_key: &str,
    client: Arc<impl Middleware>,
    contract: StylusContract,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    match contract {
        StylusContract::DarkpoolTestContract
        | StylusContract::MerkleTestContract
        | StylusContract::DummyErc20 => {
            warn!(
                "Deploying `{}` - THIS SHOULD ONLY BE DONE FOR TESTING",
                contract
            );
        }
        _ => {}
    }

    // Get expected deployment address
    let deployer_address = client
        .default_sender()
        .ok_or(ScriptError::ClientInitialization(
            "client does not have sender attached".to_string(),
        ))?;
    let deployer_nonce = client
        .get_transaction_count(deployer_address, None /* block */)
        .await
        .map_err(|e| ScriptError::NonceFetching(e.to_string()))?;
    let deployed_address = get_contract_address(deployer_address, deployer_nonce);

    // Run deploy command
    let mut deploy_cmd = Command::new(CARGO_COMMAND);
    deploy_cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    deploy_cmd.arg(STYLUS_COMMAND);
    deploy_cmd.arg(DEPLOY_COMMAND);
    deploy_cmd.arg("--nightly");
    deploy_cmd.arg("--wasm-file-path");
    deploy_cmd.arg(wasm_file_path);
    deploy_cmd.arg("-e");
    deploy_cmd.arg(rpc_url);
    deploy_cmd.arg("--private-key");
    deploy_cmd.arg(priv_key);

    command_success_or(deploy_cmd, "Failed to deploy Stylus contract")?;

    // Write deployed address to deployments file
    write_deployed_address(
        deployments_path,
        get_contract_key(contract),
        deployed_address,
    )?;

    Ok(())
}

fn gen_test_vkey<S: RenegadeStatement>(
    srs: &UnivariateUniversalParams<SystemCurve>,
) -> Result<VerificationKey, ScriptError> {
    let public_inputs = S::dummy(&mut thread_rng())
        .serialize_to_scalars()
        .map_err(|_| ScriptError::Serde("error serializing statement to scalars".to_string()))?;

    let (_, _, jf_vkey) = gen_test_circuit_and_keys(srs, TEST_CIRCUIT_DOMAIN_SIZE, &public_inputs)
        .map_err(|_| ScriptError::CircuitCreation)?;

    let vkey = convert_jf_vkey(jf_vkey).map_err(|_| ScriptError::ConversionError)?;

    Ok(vkey)
}

fn gen_vkey<C: SingleProverCircuit>(
    srs: &UnivariateUniversalParams<SystemCurve>,
) -> Result<VerificationKey, ScriptError> {
    let (_, vkey) = gen_circuit_keys::<C>(srs).map_err(|_| ScriptError::CircuitCreation)?;

    let vkey = convert_jf_vkey(vkey).map_err(|_| ScriptError::ConversionError)?;

    Ok(vkey)
}
