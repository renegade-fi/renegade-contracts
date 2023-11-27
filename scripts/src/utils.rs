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
use ark_bn254::Bn254;
use circuit_types::traits::SingleProverCircuit;
use circuits::zk_circuits::{
    test_helpers::{MAX_BALANCES, MAX_FEES, MAX_ORDERS},
    valid_commitments::{SizedValidCommitments, ValidCommitments},
    valid_match_settle::{SizedValidMatchSettle, ValidMatchSettle},
    valid_reblind::{SizedValidReblind, ValidReblind},
    valid_wallet_create::{SizedValidWalletCreate, ValidWalletCreate},
    valid_wallet_update::{SizedValidWalletUpdate, ValidWalletUpdate},
};
use common::{
    constants::TEST_MERKLE_HEIGHT,
    types::{G1Affine, VerificationKey},
};
use ethers::{
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
};
use itertools::Itertools;
use jf_primitives::pcs::prelude::Commitment;
use mpc_plonk::proof_system::structs::VerifyingKey;

use crate::{
    cli::{Circuit, StylusContract},
    constants::{
        BUILD_COMMAND, CARGO_COMMAND, DEPLOY_COMMAND, MANIFEST_DIR_ENV_VAR,
        NIGHTLY_TOOLCHAIN_SELECTOR, RELEASE_PATH_SEGMENT, SIZE_OPTIMIZATION_FLAG, STYLUS_COMMAND,
        STYLUS_CONTRACTS_CRATE_NAME, TARGET_PATH_SEGMENT, WASM_EXTENSION, WASM_OPT_COMMAND,
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

/// Prepare calldata for the Darkpool contract's `initialize` method
pub fn darkpool_initialize_calldata(
    owner_address: &str,
    verifier_address: &str,
    merkle_address: &str,
) -> Result<Vec<u8>, ScriptError> {
    let owner_address = AlloyAddress::from_hex(owner_address)
        .map_err(|e| ScriptError::CalldataConstruction(e.to_string()))?;
    let verifier_address = AlloyAddress::from_hex(verifier_address)
        .map_err(|e| ScriptError::CalldataConstruction(e.to_string()))?;
    let merkle_address = AlloyAddress::from_hex(merkle_address)
        .map_err(|e| ScriptError::CalldataConstruction(e.to_string()))?;
    Ok(initializeCall::new((owner_address, verifier_address, merkle_address)).encode())
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
pub fn build_stylus_contract(contract: StylusContract) -> Result<PathBuf, ScriptError> {
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

pub fn deploy_stylus_contract(
    wasm_file_path: PathBuf,
    rpc_url: &str,
    priv_key: &str,
) -> Result<(), ScriptError> {
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

fn try_unwrap_commitments<const N: usize>(
    comms: &[Commitment<Bn254>],
) -> Result<[G1Affine; N], ScriptError> {
    comms
        .iter()
        .map(|c| c.0)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| ScriptError::ConversionError)
}

/// Convert a [`mpc_plonk::proof_system::structs::VerifyingKey`] to a [`common::types::VerificationKey`].
/// This converts the verification key type produced by the relayer codebase to the type used by the contracts,
/// which can be serialized into calldata.
pub fn convert_jf_vkey(jf_vkey: VerifyingKey<Bn254>) -> Result<VerificationKey, ScriptError> {
    Ok(VerificationKey {
        n: jf_vkey.domain_size as u64,
        l: jf_vkey.num_inputs as u64,
        k: jf_vkey
            .k
            .try_into()
            .map_err(|_| ScriptError::ConversionError)?,
        q_comms: try_unwrap_commitments(&jf_vkey.selector_comms)?,
        sigma_comms: try_unwrap_commitments(&jf_vkey.sigma_comms)?,
        g: jf_vkey.open_key.g,
        h: jf_vkey.open_key.h,
        x_h: jf_vkey.open_key.beta_h,
    })
}

pub fn gen_vkey_bytes(circuit: Circuit, small: bool) -> Result<Vec<u8>, ScriptError> {
    let jf_vkey = match circuit {
        Circuit::ValidWalletCreate => {
            if small {
                ValidWalletCreate::<MAX_BALANCES, MAX_ORDERS, MAX_FEES>::verifying_key()
            } else {
                SizedValidWalletCreate::verifying_key()
            }
        }
        Circuit::ValidWalletUpdate => {
            if small {
                ValidWalletUpdate::<MAX_BALANCES, MAX_ORDERS, MAX_FEES, TEST_MERKLE_HEIGHT>::verifying_key()
            } else {
                SizedValidWalletUpdate::verifying_key()
            }
        }
        Circuit::ValidCommitments => {
            if small {
                ValidCommitments::<MAX_BALANCES, MAX_ORDERS, MAX_FEES>::verifying_key()
            } else {
                SizedValidCommitments::verifying_key()
            }
        }
        Circuit::ValidReblind => {
            if small {
                ValidReblind::<MAX_BALANCES, MAX_ORDERS, MAX_FEES, TEST_MERKLE_HEIGHT>::verifying_key()
            } else {
                SizedValidReblind::verifying_key()
            }
        }
        Circuit::ValidMatchSettle => {
            if small {
                ValidMatchSettle::<MAX_BALANCES, MAX_ORDERS, MAX_FEES>::verifying_key()
            } else {
                SizedValidMatchSettle::verifying_key()
            }
        }
    };

    let vkey = convert_jf_vkey((*jf_vkey).clone())?;
    postcard::to_allocvec(&vkey).map_err(|e| ScriptError::Serde(e.to_string()))
}
