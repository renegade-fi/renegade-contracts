use eyre::Result;
use starknet_crypto::FieldElement;
use tracing::log::{debug, info};

use crate::merkle::ark_merkle;
use crate::utils::{common_utils::*, devnet_utils};

pub async fn run() -> Result<()> {
    let mut merkle_test = MerkleTest::new(
        MERKLE_CONTRACT_NAME.to_string(),
        get_once_cell_string(&MERKLE_CONTRACT_ADDRESS)?.clone(),
        MERKLE_HEIGHT,
    )?;

    info!("Running test `test_initialization__correct_root`");
    merkle_test.test_initialization__correct_root()?;
    info!("Test succeeded!");
    merkle_test.reset().await?;

    info!("Running test `test_initialization__correct_root_history`");
    merkle_test.test_initialization__correct_root_history()?;
    info!("Test succeeded!");
    merkle_test.reset().await?;

    info!("Running test `test_single_insert__correct_root`");
    merkle_test.test_single_insert__correct_root()?;
    info!("Test succeeded!");
    merkle_test.reset().await?;

    info!("Running test `test_single_insert__correct_root_history`");
    merkle_test.test_single_insert__correct_root_history()?;
    info!("Test succeeded!");
    merkle_test.reset().await?;

    info!("Running test `test_multi_insert__correct_root`");
    merkle_test.test_multi_insert__correct_root()?;
    info!("Test succeeded!");
    merkle_test.reset().await?;

    info!("Running test `test_multi_insert__correct_root_history`");
    merkle_test.test_multi_insert__correct_root_history()?;
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
    merkle_contract_name: String,
    merkle_contract_address: String,
    height: usize,
    merkle_tree: ark_merkle::FeltMerkleTree,
    next_index: usize,
}

#[allow(non_snake_case)]
impl MerkleTest {
    // ---------------
    // | CONSTRUCTOR |
    // ---------------

    fn new(
        merkle_contract_name: String,
        merkle_contract_address: String,
        height: usize,
    ) -> Result<Self> {
        let merkle_tree = init_arkworks_merkle_tree(height);

        debug!("Initializing {} contract...", &merkle_contract_name);
        devnet_utils::send(
            &merkle_contract_address,
            INITIALIZER_FN_NAME,
            vec![&height.to_string()],
            0,
        )?;

        Ok(MerkleTest {
            merkle_contract_name,
            merkle_contract_address,
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

    fn test_initialization__correct_root_history(&self) -> Result<()> {
        let (_, contract_root) = self.get_roots()?;

        assert!(root_in_history(
            &self.merkle_contract_name,
            &self.merkle_contract_address,
            contract_root
        )?);

        Ok(())
    }

    // TODO: test_initialization__correct_events

    fn test_single_insert__correct_root(&mut self) -> Result<()> {
        self.insert_random_val_to_both()?;

        let (arkworks_root, contract_root) = self.get_roots()?;

        assert!(arkworks_root == contract_root);

        Ok(())
    }

    fn test_single_insert__correct_root_history(&mut self) -> Result<()> {
        self.insert_random_val_to_contract()?;

        let (_, contract_root) = self.get_roots()?;

        assert!(root_in_history(
            &self.merkle_contract_name,
            &self.merkle_contract_address,
            contract_root
        )?);

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

    fn test_multi_insert__correct_root_history(&mut self) -> Result<()> {
        for _ in 0..2_usize.pow(self.height.try_into()?) {
            self.insert_random_val_to_contract()?;
            let (_, contract_root) = self.get_roots()?;
            assert!(root_in_history(
                &self.merkle_contract_name,
                &self.merkle_contract_address,
                contract_root
            )?);
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

        debug!("Initializing {} contract...", &self.merkle_contract_name);
        devnet_utils::send(
            &self.merkle_contract_address,
            INITIALIZER_FN_NAME,
            vec![&self.height.to_string()],
            0,
        )?;

        self.next_index = 0;

        Ok(())
    }

    fn get_roots(&self) -> Result<(FieldElement, FieldElement)> {
        let arkworks_root = get_ark_root(&self.merkle_tree)?;

        let contract_root =
            get_contract_root(&self.merkle_contract_name, &self.merkle_contract_address)?;

        Ok((arkworks_root, contract_root))
    }

    fn insert_val_to_contract(&self, leaf_val: FieldElement) -> Result<()> {
        let leaf_val_str = felt_to_dec_str(leaf_val);
        debug!(
            "Inserting {} into {} contract...",
            &leaf_val_str, &self.merkle_contract_name
        );
        devnet_utils::send(
            &self.merkle_contract_address,
            INSERT_FN_NAME,
            vec![&leaf_val_str],
            0,
        )
        .map(|_| ())
    }

    fn insert_val_to_arkworks(&mut self, leaf_val: FieldElement) -> Result<()> {
        insert_val_to_arkworks(&mut self.merkle_tree, self.next_index, leaf_val)?;

        self.next_index += 1;

        Ok(())
    }

    fn insert_random_val_to_both(&mut self) -> Result<()> {
        let leaf_val = gen_random_felt(MAX_FELT_BIT_SIZE)?;

        self.insert_val_to_arkworks(leaf_val.clone())?;
        self.insert_val_to_contract(leaf_val)
    }

    fn insert_random_val_to_contract(&self) -> Result<()> {
        let leaf_val = gen_random_felt(MAX_FELT_BIT_SIZE)?;

        self.insert_val_to_contract(leaf_val)
    }
}
