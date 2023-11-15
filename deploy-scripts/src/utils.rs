//! Utilities for the deploy scripts.

use std::{
    env, fs, iter,
    path::PathBuf,
    process::{Command, Stdio},
    str::FromStr,
    sync::Arc,
};

use alloy_primitives::{hex::FromHex, Address as AlloyAddress};
use alloy_sol_types::SolCall;
use ethers::{
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
};
use itertools::Itertools;

use crate::{
    cli::StylusContract,
    constants::{
        BUILD_COMMAND, CARGO_COMMAND, DEPLOY_COMMAND, MANIFEST_DIR_ENV_VAR,
        NIGHTLY_TOOLCHAIN_SELECTOR, RELEASE_PATH_SEGMENT, SIZE_OPTIMIZATION_FLAG, STYLUS_COMMAND,
        STYLUS_CONTRACTS_CRATE_NAME, TARGET_PATH_SEGMENT, WASM_EXTENSION, WASM_OPT_COMMAND,
        WASM_TARGET_TRIPLE, Z_FLAGS,
    },
    errors::DeployError,
    solidity::initializeCall,
};

/// Sets up the address and client with which to instantiate a contract for testing,
/// reading in the private key, RPC url, and contract address from the environment.
pub async fn setup_client(
    priv_key: &str,
    rpc_url: &str,
) -> Result<Arc<impl Middleware>, DeployError> {
    let provider = Provider::<Http>::try_from(rpc_url)
        .map_err(|e| DeployError::ClientInitialization(e.to_string()))?;

    let wallet = LocalWallet::from_str(priv_key)
        .map_err(|e| DeployError::ClientInitialization(e.to_string()))?;
    let chain_id = provider
        .get_chainid()
        .await
        .map_err(|e| DeployError::ClientInitialization(e.to_string()))?
        .as_u64();
    let client = Arc::new(SignerMiddleware::new(
        provider,
        wallet.clone().with_chain_id(chain_id),
    ));

    Ok(client)
}

/// Prepare calldata for the Darkpool contract's `initialize` method
pub fn darkpool_initialize_calldata(
    owner_address: &str,
    verifier_address: &str,
    merkle_address: &str,
) -> Result<Vec<u8>, DeployError> {
    let owner_address = AlloyAddress::from_hex(owner_address)
        .map_err(|e| DeployError::CalldataConstruction(e.to_string()))?;
    let verifier_address = AlloyAddress::from_hex(verifier_address)
        .map_err(|e| DeployError::CalldataConstruction(e.to_string()))?;
    let merkle_address = AlloyAddress::from_hex(merkle_address)
        .map_err(|e| DeployError::CalldataConstruction(e.to_string()))?;
    Ok(initializeCall::new((owner_address, verifier_address, merkle_address)).encode())
}

fn command_success_or(mut cmd: Command, err_msg: &str) -> Result<(), DeployError> {
    if !cmd
        .output()
        .map_err(|e| DeployError::ContractCompilation(e.to_string()))?
        .status
        .success()
    {
        Err(DeployError::ContractCompilation(String::from(err_msg)))
    } else {
        Ok(())
    }
}

/// Compiles the given Stylus contract to WASM and optimizes the resulting binary,
/// returning the path to the optimized WASM file.
///
/// Assumes that `cargo`, the `nightly` toolchain, and `wasm-opt` are locally available.
pub fn build_stylus_contract(contract: StylusContract) -> Result<PathBuf, DeployError> {
    let current_dir = PathBuf::from(env::var(MANIFEST_DIR_ENV_VAR).unwrap());
    let workspace_path = current_dir
        .parent()
        .ok_or(DeployError::ContractCompilation(String::from(
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
    build_cmd.arg(contract.to_string());
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
        .map_err(|e| DeployError::ContractCompilation(e.to_string()))?
        .find_map(|entry| {
            let path = entry.ok()?.path();
            path.extension()
                .is_some_and(|ext| ext == WASM_EXTENSION)
                .then_some(path)
        })
        .ok_or(DeployError::ContractCompilation(String::from(
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

pub fn deploy_stylus_contract(
    wasm_file_path: PathBuf,
    rpc_url: &str,
    priv_key: &str,
) -> Result<(), DeployError> {
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

    Ok(())
}
