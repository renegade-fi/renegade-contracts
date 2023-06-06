use eyre::Result;
use starknet::{
    accounts::{Account, SingleOwnerAccount},
    core::{
        chain_id,
        crypto::compute_hash_on_elements,
        types::{
            contract::{CompiledClass, SierraClass},
            DeclareTransactionResult, FieldElement,
        },
    },
    providers::SequencerGatewayProvider,
    signers::{LocalWallet, SigningKey},
};
use std::{fs::File, path::PathBuf, sync::Arc};
use tracing::trace;
use url::Url;

use crate::cli::Network;

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

pub fn setup_account(
    address: FieldElement,
    private_key: String,
    network: Network,
) -> Result<SingleOwnerAccount<SequencerGatewayProvider, LocalWallet>> {
    let provider = match &network {
        Network::AlphaMainnet => SequencerGatewayProvider::starknet_alpha_mainnet(),
        Network::AlphaGoerli => SequencerGatewayProvider::starknet_alpha_goerli(),
        Network::AlphaGoerli2 => SequencerGatewayProvider::starknet_alpha_goerli_2(),
        Network::Localhost => SequencerGatewayProvider::new(
            Url::parse("http://localhost:5050/gateway")?,
            Url::parse("http://localhost:5050/feeder_gateway")?,
            chain_id::TESTNET,
        ),
    };

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(FieldElement::from_hex_be(
        &private_key,
    )?));

    let chain_id = match &network {
        Network::AlphaMainnet => chain_id::MAINNET,
        Network::AlphaGoerli => chain_id::TESTNET,
        Network::AlphaGoerli2 => chain_id::TESTNET2,
        Network::Localhost => chain_id::TESTNET,
    };

    Ok(SingleOwnerAccount::new(provider, signer, address, chain_id))
}

pub async fn declare(
    sierra_path: PathBuf,
    casm_path: PathBuf,
    account: &SingleOwnerAccount<SequencerGatewayProvider, LocalWallet>,
    nonce: FieldElement,
) -> Result<DeclareTransactionResult> {
    let sierra_contract: SierraClass = serde_json::from_reader(File::open(sierra_path)?)?;
    let flattened_class = sierra_contract.flatten()?;

    let casm_contract: CompiledClass = serde_json::from_reader(File::open(casm_path)?)?;
    let casm_class_hash = casm_contract.class_hash()?;

    let result = account
        .declare(Arc::new(flattened_class), casm_class_hash)
        .nonce(nonce)
        .send()
        .await?;

    trace!("Declaration result: {:?}", result);

    Ok(result)
}

// Taken from https://github.com/xJonathanLEI/starknet-rs/blob/master/starknet-accounts/src/factory/mod.rs
pub fn calculate_contract_address(
    salt: FieldElement,
    class_hash: FieldElement,
    constructor_calldata: &[FieldElement],
) -> FieldElement {
    compute_hash_on_elements(&[
        PREFIX_CONTRACT_ADDRESS,
        FieldElement::ZERO,
        salt,
        class_hash,
        compute_hash_on_elements(constructor_calldata),
    ]) % ADDR_BOUND
}
