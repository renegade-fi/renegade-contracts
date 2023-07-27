use eyre::Result;
use starknet::{
    accounts::{Account, Call, SingleOwnerAccount},
    contract::ContractFactory,
    core::{
        chain_id,
        crypto::compute_hash_on_elements,
        types::{
            contract::{CompiledClass, SierraClass},
            DeclareTransactionResult, FieldElement, InvokeTransactionResult,
        },
        utils::{cairo_short_string_to_felt, get_selector_from_name},
    },
    providers::{jsonrpc::HttpTransport, JsonRpcClient},
    signers::{LocalWallet, SigningKey},
};
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing::{debug, trace};
use url::Url;

use crate::cli::Network;

/// URL at which devnet is running
pub const DEVNET_HOST: &str = "http://localhost:5050";

/// Cairo string for "STARKNET_CONTRACT_ADDRESS"
const PREFIX_CONTRACT_ADDRESS: FieldElement = FieldElement::from_mont([
    3829237882463328880,
    17289941567720117366,
    8635008616843941496,
    533439743893157637,
]);

// 2 ** 251 - 256
const ADDR_BOUND: FieldElement = FieldElement::from_mont([
    18446743986131443745,
    160989183,
    18446744073709255680,
    576459263475590224,
]);

pub const DARKPOOL_CONTRACT_NAME: &str = "renegade_contracts_Darkpool";
pub const MERKLE_CONTRACT_NAME: &str = "renegade_contracts_Merkle";
pub const NULLIFIER_SET_CONTRACT_NAME: &str = "renegade_contracts_NullifierSet";

pub const SIERRA_FILE_EXTENSION: &str = "sierra.json";
pub const CASM_FILE_EXTENSION: &str = "casm.json";

pub const INITIALIZER_FN_NAME: &str = "initializer";
pub const MERKLE_HEIGHT: usize = 32;

pub fn setup_account(
    address: FieldElement,
    private_key: String,
    network: Network,
) -> Result<SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>> {
    let provider = match &network {
        // TODO: Use appropriate RPC endpoints
        Network::AlphaMainnet => JsonRpcClient::new(HttpTransport::new(Url::parse(DEVNET_HOST)?)),
        Network::AlphaGoerli => JsonRpcClient::new(HttpTransport::new(Url::parse(DEVNET_HOST)?)),
        Network::AlphaGoerli2 => JsonRpcClient::new(HttpTransport::new(Url::parse(DEVNET_HOST)?)),
        Network::Localhost => JsonRpcClient::new(HttpTransport::new(Url::parse(DEVNET_HOST)?)),
    };

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(FieldElement::from_hex_be(
        &private_key,
    )?));

    let chain_id = match &network {
        Network::AlphaMainnet => chain_id::MAINNET,
        Network::AlphaGoerli => chain_id::TESTNET,
        Network::AlphaGoerli2 => chain_id::TESTNET2,
        Network::Localhost => cairo_short_string_to_felt("KATANA").unwrap(),
    };

    Ok(SingleOwnerAccount::new(provider, signer, address, chain_id))
}

pub async fn get_or_declare(
    class_hash_hex: Option<String>,
    sierra_path: PathBuf,
    casm_path: PathBuf,
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
) -> Result<FieldElement> {
    if let Some(class_hash_hex) = class_hash_hex {
        let class_hash = FieldElement::from_hex_be(&class_hash_hex)?;
        debug!("Using provided class hash: {:?}", class_hash);
        Ok(class_hash)
    } else {
        let DeclareTransactionResult { class_hash, .. } =
            declare(sierra_path, casm_path, account).await?;
        debug!("Declared contract with class hash: {:?}", class_hash);
        Ok(class_hash)
    }
}

pub async fn declare(
    sierra_path: PathBuf,
    casm_path: PathBuf,
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
) -> Result<DeclareTransactionResult> {
    let sierra_contract: SierraClass = serde_json::from_reader(File::open(sierra_path)?)?;
    let flattened_class = sierra_contract.flatten()?;

    let casm_contract: CompiledClass = serde_json::from_reader(File::open(casm_path)?)?;
    let casm_class_hash = casm_contract.class_hash()?;

    let result = account
        .declare(Arc::new(flattened_class), casm_class_hash)
        .send()
        .await?;

    trace!("Declaration result: {:?}", result);

    Ok(result)
}

pub async fn deploy(
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
    class_hash: FieldElement,
    calldata: &[FieldElement],
) -> Result<InvokeTransactionResult> {
    let contract_factory = ContractFactory::new(class_hash, account);
    let deploy_result = contract_factory
        .deploy(
            calldata,
            FieldElement::ZERO, /* salt */
            false,              /* unique */
        )
        .send()
        .await?;

    trace!("Deploy result: {:?}", deploy_result);

    Ok(deploy_result)
}

pub async fn initialize(
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
    to: FieldElement,
    calldata: Vec<FieldElement>,
) -> Result<InvokeTransactionResult> {
    let initialization_result = account
        .execute(vec![Call {
            to,
            selector: get_selector_from_name(INITIALIZER_FN_NAME)?,
            calldata,
        }])
        .send()
        .await?;

    trace!("Initialization result: {:?}", initialization_result);

    Ok(initialization_result)
}

// Taken from https://github.com/xJonathanLEI/starknet-rs/blob/master/starknet-accounts/src/factory/mod.rs
pub fn calculate_contract_address(
    class_hash: FieldElement,
    constructor_calldata: &[FieldElement],
) -> FieldElement {
    compute_hash_on_elements(&[
        PREFIX_CONTRACT_ADDRESS,
        FieldElement::ZERO, /* deployer address */
        FieldElement::ZERO, /* salt */
        class_hash,
        compute_hash_on_elements(constructor_calldata),
    ]) % ADDR_BOUND
}

pub async fn deploy_darkpool(
    darkpool_class_hash: Option<String>,
    merkle_class_hash: Option<String>,
    nullifier_set_class_hash: Option<String>,
    artifacts_path: String,
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
) -> Result<(
    FieldElement,
    FieldElement,
    FieldElement,
    FieldElement,
    FieldElement,
)> {
    let darkpool_class_hash_felt = get_or_declare(
        darkpool_class_hash,
        Path::new(&artifacts_path).join(format!(
            "{}.{}",
            DARKPOOL_CONTRACT_NAME, SIERRA_FILE_EXTENSION
        )),
        Path::new(&artifacts_path).join(format!(
            "{}.{}",
            DARKPOOL_CONTRACT_NAME, CASM_FILE_EXTENSION
        )),
        account,
    )
    .await?;

    let merkle_class_hash_felt = get_or_declare(
        merkle_class_hash,
        Path::new(&artifacts_path).join(format!(
            "{}.{}",
            MERKLE_CONTRACT_NAME, SIERRA_FILE_EXTENSION
        )),
        Path::new(&artifacts_path)
            .join(format!("{}.{}", MERKLE_CONTRACT_NAME, CASM_FILE_EXTENSION)),
        account,
    )
    .await?;

    let nullifier_set_class_hash_felt = get_or_declare(
        nullifier_set_class_hash,
        Path::new(&artifacts_path).join(format!(
            "{}.{}",
            NULLIFIER_SET_CONTRACT_NAME, SIERRA_FILE_EXTENSION
        )),
        Path::new(&artifacts_path).join(format!(
            "{}.{}",
            NULLIFIER_SET_CONTRACT_NAME, CASM_FILE_EXTENSION
        )),
        account,
    )
    .await?;

    // Deploy darkpool
    debug!("Deploying darkpool contract...");
    let calldata = vec![account.address()];
    let InvokeTransactionResult {
        transaction_hash, ..
    } = deploy(account, darkpool_class_hash_felt, &calldata).await?;

    let darkpool_address = calculate_contract_address(darkpool_class_hash_felt, &calldata);

    Ok((
        darkpool_address,
        darkpool_class_hash_felt,
        merkle_class_hash_felt,
        nullifier_set_class_hash_felt,
        transaction_hash,
    ))
}

pub async fn deploy_merkle(
    merkle_class_hash: Option<String>,
    artifacts_path: String,
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
) -> Result<(FieldElement, FieldElement, FieldElement)> {
    let merkle_class_hash_felt = get_or_declare(
        merkle_class_hash,
        Path::new(&artifacts_path).join(format!(
            "{}.{}",
            MERKLE_CONTRACT_NAME, SIERRA_FILE_EXTENSION
        )),
        Path::new(&artifacts_path)
            .join(format!("{}.{}", MERKLE_CONTRACT_NAME, CASM_FILE_EXTENSION)),
        account,
    )
    .await?;

    // Deploy merkle
    debug!("Deploying merkle contract...");
    let InvokeTransactionResult {
        transaction_hash, ..
    } = deploy(account, merkle_class_hash_felt, &[]).await?;

    let merkle_address = calculate_contract_address(merkle_class_hash_felt, &[]);

    Ok((merkle_address, merkle_class_hash_felt, transaction_hash))
}

pub async fn deploy_nullifier_set(
    nullifier_set_class_hash: Option<String>,
    artifacts_path: String,
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
) -> Result<(FieldElement, FieldElement, FieldElement)> {
    let nullifier_set_class_hash_felt = get_or_declare(
        nullifier_set_class_hash,
        Path::new(&artifacts_path).join(format!(
            "{}.{}",
            NULLIFIER_SET_CONTRACT_NAME, SIERRA_FILE_EXTENSION
        )),
        Path::new(&artifacts_path).join(format!(
            "{}.{}",
            NULLIFIER_SET_CONTRACT_NAME, CASM_FILE_EXTENSION
        )),
        account,
    )
    .await?;

    // Deploy nullifier set
    debug!("Deploying nullifier set contract...");
    let InvokeTransactionResult {
        transaction_hash, ..
    } = deploy(account, nullifier_set_class_hash_felt, &[]).await?;

    let nullifier_set_address = calculate_contract_address(nullifier_set_class_hash_felt, &[]);

    Ok((
        nullifier_set_address,
        nullifier_set_class_hash_felt,
        transaction_hash,
    ))
}
