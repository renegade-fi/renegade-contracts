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
use ark_ed_on_bn254::EdwardsProjective as BabyJubJubProjective;
use contracts_common::{custom_serde::scalar_to_u256, types::PublicEncryptionKey};
use ethers::{
    abi::Address,
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    utils::get_contract_address,
};
use itertools::Itertools;
use json::JsonValue;
use rand::{distributions::Standard, thread_rng, Rng};
use tracing::log::warn;
use util::hex::jubjub_from_hex_string;

use crate::{
    constants::{
        AGGRESSIVE_OPTIMIZATION_FLAG, AGGRESSIVE_SIZE_OPTIMIZATION_FLAG, BUILD_COMMAND,
        CARGO_COMMAND, DARKPOOL_CONTRACT_KEY, DARKPOOL_CORE_CONTRACT_KEY, DEFAULT_RUSTFLAGS,
        DEPLOYMENTS_KEY, DEPLOY_COMMAND, INLINE_THRESHOLD_FLAG, MANIFEST_DIR_ENV_VAR,
        MERKLE_CONTRACT_KEY, NO_VERIFY_FEATURE, OPT_LEVEL_3, OPT_LEVEL_FLAG, OPT_LEVEL_Z,
        PRECOMPILE_TEST_CONTRACT_KEY, RELEASE_PATH_SEGMENT, RUSTFLAGS_ENV_VAR, STYLUS_COMMAND,
        STYLUS_CONTRACTS_CRATE_NAME, TARGET_PATH_SEGMENT, TEST_UPGRADE_TARGET_CONTRACT_KEY,
        TRANSFER_EXECUTOR_CONTRACT_KEY, VERIFIER_CONTRACT_KEY, VKEYS_CONTRACT_KEY, WASM_EXTENSION,
        WASM_OPT_COMMAND, WASM_OPT_EXTENSION, WASM_TARGET_TRIPLE, Z_FLAGS,
    },
    errors::ScriptError,
    solidity::initializeCall,
    types::StylusContract,
};

/// An Ethers provider that uses a `LocalWallet` to generate signatures
/// & interfaces with the RPC endpoint over HTTP
pub type LocalWalletHttpClient = SignerMiddleware<Provider<Http>, LocalWallet>;

/// Sets up the address and client with which to instantiate a contract for testing,
/// reading in the private key, RPC url, and contract address from the environment.
pub async fn setup_client(
    priv_key: &str,
    rpc_url: &str,
) -> Result<Arc<LocalWalletHttpClient>, ScriptError> {
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
        StylusContract::DarkpoolCore => DARKPOOL_CORE_CONTRACT_KEY,
        StylusContract::Merkle | StylusContract::MerkleTestContract => MERKLE_CONTRACT_KEY,
        StylusContract::Verifier => VERIFIER_CONTRACT_KEY,
        StylusContract::Vkeys | StylusContract::TestVkeys => VKEYS_CONTRACT_KEY,
        StylusContract::TransferExecutor => TRANSFER_EXECUTOR_CONTRACT_KEY,
        StylusContract::DummyUpgradeTarget => TEST_UPGRADE_TARGET_CONTRACT_KEY,
        StylusContract::PrecompileTestContract => PRECOMPILE_TEST_CONTRACT_KEY,
        StylusContract::DummyErc20 => unreachable!("Must supply a ticker at which to find the deployment address of a dummy ERC20 contract"),
    }
}

/// Parses an EC-ElGamal public encryption key from a hex string,
/// or generate a random one if None is supplied
pub fn get_public_encryption_key(
    pubkey_hex: Option<String>,
) -> Result<PublicEncryptionKey, ScriptError> {
    let point = if let Some(pubkey_hex) = pubkey_hex {
        jubjub_from_hex_string(&pubkey_hex)
            .map_err(|e| ScriptError::PubkeyParsing(e.to_string()))?
    } else {
        warn!("Generating random public encryption key, decryption key will be lost");
        let mut rng = thread_rng();
        rng.sample::<BabyJubJubProjective, _>(Standard).into()
    };

    Ok(PublicEncryptionKey {
        x: point.x.inner(),
        y: point.y.inner(),
    })
}

/// Prepare calldata for the Darkpool contract's `initialize` method
#[allow(clippy::too_many_arguments)]
pub fn darkpool_initialize_calldata(
    darkpool_core_address: Address,
    verifier_address: Address,
    vkeys_address: Address,
    merkle_address: Address,
    transfer_executor_address: Address,
    permit2_address: Address,
    protocol_fee: U256,
    protocol_public_encryption_key: PublicEncryptionKey,
) -> Result<Vec<u8>, ScriptError> {
    let darkpool_core_address = AlloyAddress::from_slice(darkpool_core_address.as_bytes());
    let verifier_address = AlloyAddress::from_slice(verifier_address.as_bytes());
    let vkeys_address = AlloyAddress::from_slice(vkeys_address.as_bytes());
    let merkle_address = AlloyAddress::from_slice(merkle_address.as_bytes());
    let transfer_executor_address = AlloyAddress::from_slice(transfer_executor_address.as_bytes());
    let permit2_address = AlloyAddress::from_slice(permit2_address.as_bytes());
    let protocol_public_encryption_key = [
        scalar_to_u256(protocol_public_encryption_key.x),
        scalar_to_u256(protocol_public_encryption_key.y),
    ];

    Ok(initializeCall::new((
        darkpool_core_address,
        verifier_address,
        vkeys_address,
        merkle_address,
        transfer_executor_address,
        permit2_address,
        protocol_fee,
        protocol_public_encryption_key,
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
    let rustflags = match contract {
        StylusContract::Verifier
        | StylusContract::Darkpool
        | StylusContract::DarkpoolCore
        | StylusContract::DarkpoolTestContract => {
            format!(
                "{}{} {}",
                OPT_LEVEL_FLAG, OPT_LEVEL_Z, INLINE_THRESHOLD_FLAG
            )
        }
        _ => format!("{}{}", OPT_LEVEL_FLAG, OPT_LEVEL_3),
    };

    format!("{} {}", rustflags, DEFAULT_RUSTFLAGS)
}

/// Returns the wasm-opt flags to use in the optimization of the
/// given contract
pub fn get_wasm_opt_flags_for_contract(contract: StylusContract) -> &'static str {
    match contract {
        StylusContract::Verifier
        | StylusContract::Darkpool
        | StylusContract::DarkpoolCore
        | StylusContract::DarkpoolTestContract => AGGRESSIVE_SIZE_OPTIMIZATION_FLAG,
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

    let opt_wasm_file_path = wasm_file_path.with_extension(WASM_OPT_EXTENSION);

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
    client: Arc<LocalWalletHttpClient>,
    contract: StylusContract,
    deployments_path: &str,
    contract_key_override: Option<&str>,
) -> Result<Address, ScriptError> {
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
    deploy_cmd.arg("--wasm-file");
    deploy_cmd.arg(&wasm_file_path);
    deploy_cmd.arg("-e");
    deploy_cmd.arg(rpc_url);
    deploy_cmd.arg("--private-key");
    deploy_cmd.arg(priv_key);
    deploy_cmd.arg("--no-verify");

    command_success_or(deploy_cmd, "Failed to deploy Stylus contract")?;

    // Write deployed address to deployments file
    let contract_key = if let Some(contract_key_override) = contract_key_override {
        contract_key_override
    } else {
        get_contract_key(contract)
    };

    write_deployed_address(deployments_path, contract_key, deployed_address)?;

    Ok(deployed_address)
}
