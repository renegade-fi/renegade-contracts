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

use alloy_primitives::{Address as AlloyAddress, U256};
use alloy_sol_types::SolCall;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
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
use tracing::log::warn;

use crate::{
    cli::StylusContract,
    constants::{
        AGGRESSIVE_OPTIMIZATION_FLAG, AGGRESSIVE_SIZE_OPTIMIZATION_FLAG, BUILD_COMMAND,
        CARGO_COMMAND, DARKPOOL_CONTRACT_KEY, DEPLOYMENTS_KEY, DEPLOY_COMMAND,
        DUMMY_ERC20_CONTRACT_KEY, DUMMY_UPGRADE_TARGET_CONTRACT_KEY, MANIFEST_DIR_ENV_VAR,
        MERKLE_CONTRACT_KEY, NIGHTLY_TOOLCHAIN_SELECTOR, NO_VERIFY_FEATURE, OPT_LEVEL_3,
        OPT_LEVEL_FLAG, OPT_LEVEL_S, OPT_LEVEL_Z, PRECOMPILE_TEST_CONTRACT_KEY,
        RELEASE_PATH_SEGMENT, RUSTFLAGS_ENV_VAR, STYLUS_COMMAND, STYLUS_CONTRACTS_CRATE_NAME,
        TARGET_PATH_SEGMENT, VERIFIER_CONTRACT_KEY, VKEYS_CONTRACT_KEY, WASM_EXTENSION,
        WASM_OPT_COMMAND, WASM_TARGET_TRIPLE, Z_FLAGS,
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

/// Parses the JSON file at the given path
pub fn get_json_from_file(file_path: &str) -> Result<JsonValue, ScriptError> {
    let mut file_contents = String::new();
    File::open(file_path)
        .map_err(|e| ScriptError::ReadFile(e.to_string()))?
        .read_to_string(&mut file_contents)
        .map_err(|e| ScriptError::ReadFile(e.to_string()))?;

    json::parse(&file_contents).map_err(|e| ScriptError::ReadFile(e.to_string()))
}

/// Parses a the given contract's deployment address from the
/// deployments file at the given path
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

/// Parses a structured reference string from the file at the given path
pub fn parse_srs_from_file(
    file_path: &str,
) -> Result<UnivariateUniversalParams<SystemCurve>, ScriptError> {
    let srs_file = File::open(file_path).map_err(|e| ScriptError::ReadFile(e.to_string()))?;

    let srs = UnivariateUniversalParams::<SystemCurve>::deserialize_uncompressed(&srs_file)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;

    Ok(srs)
}

/// Writes the given address for the deployed contract
/// to the deployments file at the given path
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

/// Writes the structured reference string to the file at the given path
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

/// Writes the verification key to the file at the given directory & path
pub fn write_vkey_file(
    vkeys_dir: &str,
    vkey_file_name: &str,
    vkey_bytes: &[u8],
) -> Result<(), ScriptError> {
    let vkeys_dir = PathBuf::from(vkeys_dir);
    let vkey_file_path = vkeys_dir.join(vkey_file_name);

    fs::write(vkey_file_path, vkey_bytes).map_err(|e| ScriptError::WriteFile(e.to_string()))
}

/// Returns the JSON key used in the deployments file for the given contract
pub fn get_contract_key(contract: StylusContract) -> &'static str {
    match contract {
        StylusContract::Darkpool | StylusContract::DarkpoolTestContract => DARKPOOL_CONTRACT_KEY,
        StylusContract::Merkle | StylusContract::MerkleTestContract => MERKLE_CONTRACT_KEY,
        StylusContract::Verifier => VERIFIER_CONTRACT_KEY,
        StylusContract::Vkeys | StylusContract::TestVkeys => VKEYS_CONTRACT_KEY,
        StylusContract::DummyErc20 => DUMMY_ERC20_CONTRACT_KEY,
        StylusContract::DummyUpgradeTarget => DUMMY_UPGRADE_TARGET_CONTRACT_KEY,
        StylusContract::PrecompileTestContract => PRECOMPILE_TEST_CONTRACT_KEY,
    }
}

/// Prepare calldata for the Darkpool contract's `initialize` method
pub fn darkpool_initialize_calldata(
    verifier_address: Address,
    vkeys_address: Address,
    merkle_address: Address,
    protocol_fee: U256,
) -> Result<Vec<u8>, ScriptError> {
    let verifier_address = AlloyAddress::from_slice(verifier_address.as_bytes());
    let vkeys_address = AlloyAddress::from_slice(vkeys_address.as_bytes());
    let merkle_address = AlloyAddress::from_slice(merkle_address.as_bytes());

    Ok(initializeCall::new((
        verifier_address,
        vkeys_address,
        merkle_address,
        protocol_fee,
    ))
    .encode())
}

/// Executes a command, returning an error if the command fails
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

/// Returns the RUSTFLAGS environment variable to use in the
/// compilation of the given contract
pub fn get_rustflags_for_contract(contract: StylusContract) -> String {
    let opt_level = match contract {
        StylusContract::Verifier => OPT_LEVEL_S,
        StylusContract::DarkpoolTestContract => OPT_LEVEL_Z,
        _ => OPT_LEVEL_3,
    };

    format!("{}{}", OPT_LEVEL_FLAG, opt_level)
}

/// Returns the wasm-opt flags to use in the optimization of the
/// given contract
pub fn get_wasm_opt_flags_for_contract(contract: StylusContract) -> &'static str {
    match contract {
        StylusContract::Verifier | StylusContract::DarkpoolTestContract => {
            AGGRESSIVE_SIZE_OPTIMIZATION_FLAG
        }
        _ => AGGRESSIVE_OPTIMIZATION_FLAG,
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

    env::set_var(RUSTFLAGS_ENV_VAR, get_rustflags_for_contract(contract));

    command_success_or(build_cmd, "Failed to build contract WASM")?;

    env::remove_var(RUSTFLAGS_ENV_VAR);

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
    opt_cmd.arg(get_wasm_opt_flags_for_contract(contract));

    command_success_or(opt_cmd, "Failed to optimize contract WASM")?;

    Ok(opt_wasm_file_path)
}

/// Deploys the given compiled Stylus contract, saving its deployment address
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
