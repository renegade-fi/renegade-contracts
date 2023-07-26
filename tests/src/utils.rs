use dojo_test_utils::sequencer::{get_default_test_starknet_config, TestSequencer};
use katana_core::sequencer::SequencerConfig;
use starknet::{accounts::Account, core::types::DeclareTransactionResult};
use starknet_scripts::{
    cli::Contract,
    commands::utils::{
        calculate_contract_address, declare, deploy, CASM_FILE_EXTENSION, DARKPOOL_CONTRACT_NAME,
        MERKLE_CONTRACT_NAME, NULLIFIER_SET_CONTRACT_NAME, SIERRA_FILE_EXTENSION,
    },
};
use std::{env, path::Path};
use tracing::debug;

use crate::merkle::utils::MERKLE_ADDRESS;

/// Name of env var representing path at which compiled contract artifacts are kept
pub const ARTIFACTS_PATH_ENV_VAR: &str = "ARTIFACTS_PATH";

pub async fn global_setup() -> TestSequencer {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).expect("ARTIFACTS_PATH env var not set");

    // Set up logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let sequencer = TestSequencer::start(
        SequencerConfig::default(),
        get_default_test_starknet_config(),
    )
    .await;

    debug!("Setting up devnet account...");
    let account = sequencer.account();

    // Declare & deploy all contracts
    // TODO: Switch to using `Contract::iter()` when tests are written
    for contract in vec![Contract::Merkle] {
        let contract_name = match contract {
            Contract::Darkpool => DARKPOOL_CONTRACT_NAME,
            Contract::Merkle => MERKLE_CONTRACT_NAME,
            Contract::NullifierSet => NULLIFIER_SET_CONTRACT_NAME,
        };

        let sierra_path =
            Path::new(&artifacts_path).join(format!("{}.{}", contract_name, SIERRA_FILE_EXTENSION));
        let casm_path =
            Path::new(&artifacts_path).join(format!("{}.{}", contract_name, CASM_FILE_EXTENSION));

        debug!("Declaring {} contract...", contract);
        let DeclareTransactionResult { class_hash, .. } =
            declare(sierra_path, casm_path, &account).await.unwrap();

        let calldata = match contract {
            Contract::Darkpool => vec![account.address()],
            _ => vec![],
        };

        let contract_address = calculate_contract_address(class_hash, &calldata);

        debug!("Deploying {} contract...", contract);
        deploy(&account, class_hash, &calldata).await.unwrap();

        #[allow(clippy::match_single_binding)]
        // TODO: Add arms for other contracts when tests are written
        let contract_address_cell = match contract {
            _ => &MERKLE_ADDRESS,
        };

        contract_address_cell.set(contract_address).unwrap();
    }

    sequencer
}

pub fn global_teardown(sequencer: TestSequencer) {
    sequencer.stop().unwrap();
}
