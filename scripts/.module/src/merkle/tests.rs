use eyre::{eyre, Result};
use starknet_crypto::FieldElement;
use tracing::log::{debug, info};

use crate::merkle::ark_merkle;
use crate::utils::{common_utils, devnet_utils};

// -------------
// | CONSTANTS |
// -------------

const CONTRACT_NAME: &'static str = "Merkle";
const INITIALIZER_FN_NAME: &'static str = "initializer";
const GET_ROOT_FN_NAME: &'static str = "get_root";
const ROOT_IN_HISTORY_FN_NAME: &'static str = "root_in_history";
const INSERT_FN_NAME: &'static str = "insert";

pub async fn run() -> Result<()> {
    let contract_name = String::from(CONTRACT_NAME);
    let contract_address = devnet_utils::prep_contract(&contract_name).await?;
    let mut merkle_test = MerkleTest::new(contract_name, contract_address, 5)?;

    info!("Running test `test_initialization__correct_root`");
    merkle_test.test_initialization__correct_root()?;
    info!("Test succeeded!");
    merkle_test.reset().await?;

    info!("Running test `test_initialization__correct_history`");
    merkle_test.test_initialization__correct_history()?;
    info!("Test succeeded!");
    merkle_test.reset().await?;

    info!("Running test `test_single_insert__correct_root`");
    merkle_test.test_single_insert__correct_root()?;
    info!("Test succeeded!");
    merkle_test.reset().await?;

    info!("Running test `test_single_insert__correct_history`");
    merkle_test.test_single_insert__correct_history()?;
    info!("Test succeeded!");
    merkle_test.reset().await?;

    info!("Running test `test_multi_insert__correct_root`");
    merkle_test.test_multi_insert__correct_root()?;
    info!("Test succeeded!");
    merkle_test.reset().await?;

    info!("Running test `test_multi_insert__correct_history`");
    merkle_test.test_multi_insert__correct_history()?;
    info!("Test succeeded!");
    merkle_test.reset().await?;

    info!("Running test `test_full_insert__fails`");
    merkle_test.test_full_insert__fails()?;
    info!("Test succeeded!");

    Ok(())
}

// ----------------
// | TEST HELPERS |
// ----------------

// These helper functions make the following assumptions:
// - A devnet node is running
// - The Merkle contract is declared & deployed
// - The contract state is uninitialized

struct MerkleTest {
    contract_name: String,
    contract_address: String,
    height: usize,
    merkle_tree: ark_merkle::FeltMerkleTree,
    next_index: usize,
}

#[allow(non_snake_case)]
impl MerkleTest {
    // ---------------
    // | CONSTRUCTOR |
    // ---------------

    fn new(contract_name: String, contract_address: String, height: usize) -> Result<Self> {
        // arkworks implementation does height inclusive of root,
        // so "height" here is one more than what's passed to the contract
        debug!("Initializing empty arkworks Merkle tree...");
        let merkle_tree = ark_merkle::setup_empty_tree(height + 1);

        debug!("Initializing {} contract...", &contract_name);
        devnet_utils::send(
            contract_address.clone(),
            INITIALIZER_FN_NAME.to_string(),
            vec![height.to_string()],
        )?;

        Ok(MerkleTest {
            contract_name,
            contract_address,
            height,
            merkle_tree,
            next_index: 0,
        })
    }

    // ---------
    // | TESTS |
    // ---------

    fn test_initialization__correct_root(&self) -> Result<()> {
        let (arkworks_root, contract_root) = self.get_roots()?;

        assert!(arkworks_root == contract_root);

        Ok(())
    }

    fn test_initialization__correct_history(&self) -> Result<()> {
        let (_, contract_root) = self.get_roots()?;

        assert!(self.root_in_history(contract_root)?);

        Ok(())
    }

    // TODO: test_initialization__correct_events

    fn test_single_insert__correct_root(&mut self) -> Result<()> {
        self.insert_random_val_to_both()?;

        let (arkworks_root, contract_root) = self.get_roots()?;

        assert!(arkworks_root == contract_root);

        Ok(())
    }

    fn test_single_insert__correct_history(&mut self) -> Result<()> {
        self.insert_random_val_to_contract()?;

        let (_, contract_root) = self.get_roots()?;

        assert!(self.root_in_history(contract_root)?);

        Ok(())
    }

    // TODO: test_single_insert__correct_events

    fn test_multi_insert__correct_root(&mut self) -> Result<()> {
        for _ in 0..2_usize.pow(self.height.try_into()?) {
            self.insert_random_val_to_both()?;
        }

        let (arkworks_root, contract_root) = self.get_roots()?;
        assert!(arkworks_root == contract_root);

        Ok(())
    }

    fn test_multi_insert__correct_history(&mut self) -> Result<()> {
        for _ in 0..2_usize.pow(self.height.try_into()?) {
            self.insert_random_val_to_contract()?;
            let (_, contract_root) = self.get_roots()?;
            assert!(self.root_in_history(contract_root)?);
        }

        Ok(())
    }

    fn test_full_insert__fails(&mut self) -> Result<()> {
        for _ in 0..2_usize.pow(self.height.try_into()?) {
            self.insert_random_val_to_contract()?;
        }

        assert!(self.insert_random_val_to_contract().is_err());

        Ok(())
    }

    // -----------
    // | HELPERS |
    // -----------

    async fn reset(&mut self) -> Result<()> {
        debug!("Initializing empty arkworks Merkle tree...");
        self.merkle_tree = ark_merkle::setup_empty_tree(self.height + 1);

        debug!("Loading devnet state...");
        devnet_utils::load_devnet_state().await?;

        debug!("Initializing {} contract...", &self.contract_name);
        devnet_utils::send(
            self.contract_address.clone(),
            INITIALIZER_FN_NAME.to_string(),
            vec![self.height.to_string()],
        )?;

        self.next_index = 0;

        Ok(())
    }

    fn get_roots(&self) -> Result<(FieldElement, FieldElement)> {
        debug!("Getting root from arkworks Merkle tree...");
        let arkworks_root = FieldElement::from_bytes_be(&self.merkle_tree.root())?;
        debug!("Got root: {arkworks_root:#?}");

        debug!("Getting root from {} contract...", &self.contract_name);
        let contract_root = devnet_utils::call(
            self.contract_address.clone(),
            GET_ROOT_FN_NAME.to_string(),
            vec![],
        )?[0];
        debug!("Got root: {contract_root:#?}");

        Ok((arkworks_root, contract_root))
    }

    fn root_in_history(&self, root: FieldElement) -> Result<bool> {
        let root_str = root.to_big_decimal(0).to_string();
        let bool_felt = devnet_utils::call(
            self.contract_address.clone(),
            ROOT_IN_HISTORY_FN_NAME.to_string(),
            vec![root_str],
        )?[0];
        Ok(bool_felt == FieldElement::ONE)
    }

    fn insert_val_to_contract(&self, leaf_val: FieldElement) -> Result<()> {
        let leaf_val_str = common_utils::felt_to_dec_str(leaf_val);
        debug!(
            "Inserting {} into {} contract...",
            &leaf_val_str, &self.contract_name
        );
        devnet_utils::send(
            self.contract_address.clone(),
            INSERT_FN_NAME.to_string(),
            vec![leaf_val_str],
        )
    }

    fn insert_val_to_arkworks(&mut self, leaf_val: FieldElement) -> Result<()> {
        debug!(
            "Inserting {} into arkworks Merkle tree...",
            common_utils::felt_to_dec_str(leaf_val.clone())
        );

        self.merkle_tree
            .update(self.next_index, &leaf_val.to_bytes_be())
            .map_err(|_| eyre!("unable to update arkworks merkle tree"))?;

        self.next_index += 1;

        Ok(())
    }

    fn insert_random_val_to_both(&mut self) -> Result<()> {
        let leaf_val = common_utils::gen_random_felt(common_utils::MAX_FELT_BIT_SIZE)?;

        self.insert_val_to_arkworks(leaf_val.clone())?;
        self.insert_val_to_contract(leaf_val)
    }

    fn insert_random_val_to_contract(&self) -> Result<()> {
        let leaf_val = common_utils::gen_random_felt(common_utils::MAX_FELT_BIT_SIZE)?;

        self.insert_val_to_contract(leaf_val)
    }
}
