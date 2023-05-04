use eyre::{eyre, Result};
use starknet_crypto::FieldElement;
use num_bigint::{BigUint, RandBigInt};

// Requires a devnet node running
async fn run(_nre: NileRuntimeEnvironment) -> Result<()> {

    let contract_name = "Merkle";
    let merkle_test_builder = MerkleTestBuilder::default().with_contract_name(contract_name.to_string()).with_height(5);

    debug!("Compiling {} contract...", &contract_name);
    utils::compile()?;

    debug!("Declaring {} contract...", &contract_name);
    utils::declare(&contract_name)?;

    debug!("Deploying {} contract...", &contract_name);
    let contract_address = utils::deploy(&contract_name)?;

    debug!("Dumping devnet state...");
    utils::dump_devnet_state().await?;

    let mut merkle_test = merkle_test_builder.with_contract_address(contract_address).build()?;

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

    Ok(())
}


// ----------------
// | TEST HELPERS |
// ----------------

// These helper functions make the following assumptions:
// - A devnet node is running
// - The Merkle contract is declared & deployed
// - The contract state is uninitialized

#[derive(Default)]
struct MerkleTestBuilder {
    contract_name: Option<String>,
    contract_address: Option<String>,
    height: Option<usize>,
}

impl MerkleTestBuilder {
    fn with_contract_name(mut self, contract_name: String) -> Self {
        self.contract_name = Some(contract_name);
        self
    }

    fn with_contract_address(mut self, contract_address: String) -> Self {
        self.contract_address = Some(contract_address);
        self
    }

    fn with_height(mut self, height: usize) -> Self {
        self.height = Some(height);
        self
    }

    fn build(self) -> Result<MerkleTest> {
        let height = self.height.ok_or_else(|| eyre!("height not set"))?;
        // arkworks implementation does height inclusive of root,
        // so "height" here is one more than what's passed to the contract
        debug!("Initializing empty arkworks Merkle tree...");
        let merkle_tree = merkle::setup_empty_tree(height + 1);

        let contract_name = self.contract_name.ok_or_else(|| eyre!("contract name not set"))?;
        let contract_address = self.contract_address.ok_or_else(|| eyre!("contract address not set"))?;
        debug!("Initializing {} contract...", &contract_name);
        utils::send(&contract_address, "initializer", vec![&height.to_string()])?;

        Ok(MerkleTest {
            contract_name,
            contract_address,
            height,
            merkle_tree,
            next_index: 0,
        })
    }
}

struct MerkleTest {
    contract_name: String,
    contract_address: String,
    height: usize,
    merkle_tree: merkle::FeltMerkleTree,
    next_index: usize,
}

impl MerkleTest {

    // ---------
    // | TESTS |
    // ---------

    #[allow(non_snake_case)]
    fn test_initialization__correct_root(&self) -> Result<()> {
        let (arkworks_root, contract_root) = self.get_roots()?;

        assert!(arkworks_root == contract_root);

        Ok(())
    }

    #[allow(non_snake_case)]
    fn test_initialization__correct_history(&self) -> Result<()> {
        let (_, contract_root) = self.get_roots()?;

        assert!(self.root_in_history(contract_root)?);

        Ok(())
    }

    // TODO: test_initialization__correct_events

    #[allow(non_snake_case)]
    fn test_single_insert__correct_root(&mut self) -> Result<()> {
        self.insert_random_val()?;

        let (arkworks_root, contract_root) = self.get_roots()?;

        assert!(arkworks_root == contract_root);

        Ok(())
    }

    #[allow(non_snake_case)]
    fn test_single_insert__correct_history(&mut self) -> Result<()> {
        self.insert_random_val()?;

        let (_, contract_root) = self.get_roots()?;

        assert!(self.root_in_history(contract_root)?);

        Ok(())
    }

    // TODO: test_single_insert__correct_events

    #[allow(non_snake_case)]
    fn test_multi_insert__correct_root(&mut self) -> Result<()> {
        for _ in 0..2_usize.pow(self.height.try_into()?) {
            self.insert_random_val()?;
        }

        let (arkworks_root, contract_root) = self.get_roots()?;
        assert!(arkworks_root == contract_root);

        Ok(())
    }

    #[allow(non_snake_case)]
    fn test_multi_insert__correct_history(&mut self) -> Result<()> {
        for _ in 0..2_usize.pow(self.height.try_into()?) {
            self.insert_random_val()?;
            let (_, contract_root) = self.get_roots()?;
            assert!(self.root_in_history(contract_root)?);
        }

        Ok(())
    }

    #[allow(non_snake_case)]
    fn test_full_insert__fails(&mut self) -> Result<()> {
        for _ in 0..2_usize.pow(self.height.try_into()?) {
            self.insert_random_val()?;
        }

        self.insert_random_val()?;

        Ok(())
    }

    // -----------
    // | HELPERS |
    // -----------

    async fn reset(&mut self) -> Result<()> {
        debug!("Initializing empty arkworks Merkle tree...");
        self.merkle_tree = merkle::setup_empty_tree(self.height + 1);

        debug!("Loading devnet state...");
        utils::load_devnet_state().await?;

        debug!("Initializing {} contract...", &self.contract_name); 
        utils::send(&self.contract_address, "initializer", vec![&self.height.to_string()])?;

        self.next_index = 0;

        Ok(())
    }

    fn get_roots(&self) -> Result<(FieldElement, FieldElement)> {
        debug!("Getting root from arkworks Merkle tree...");
        let arkworks_root = FieldElement::from_bytes_be(&self.merkle_tree.root())?;
        debug!("Got root: {arkworks_root:#?}");

        debug!("Getting root from Merkle contract...");
        let contract_root = utils::call(&self.contract_address, "get_root", vec![])?[0];
        debug!("Got root: {contract_root:#?}");

        Ok((arkworks_root, contract_root))
    }

    fn root_in_history(&self, root: FieldElement) -> Result<bool> {
        let root_str = root.to_big_decimal(0).to_string();
        let bool_felt = utils::call(&self.contract_address, "root_in_history", vec![&root_str])?[0];
        Ok(bool_felt == FieldElement::ONE)
    }

    fn insert_val(&mut self, leaf_val: BigUint) -> Result<()> {
        debug!("Inserting {leaf_val} into arkworks Merkle tree...");
        let mut leaf_val_bytes: [u8; 32] = [0; 32];
        let leaf_val_bytes_vec = leaf_val.to_bytes_be();
        // Unset bits pushed to beginning of array b/c big-endian
        leaf_val_bytes[32 - leaf_val_bytes_vec.len()..].copy_from_slice(&leaf_val_bytes_vec);

        self.merkle_tree.update(
            self.next_index, &leaf_val_bytes
        ).map_err(|_| eyre!("unable to update arkworks merkle tree"))?;

        debug!("Inserting {leaf_val} into Merkle contract...");
        utils::send(&self.contract_address, "insert", vec![&leaf_val.to_string()])?;

        self.next_index += 1;

        Ok(())
    }

    fn insert_random_val(&mut self) -> Result<()> {
        let mut rng = rand::thread_rng();
        let leaf_val = rng.gen_biguint(251);

        self.insert_val(leaf_val)?;

        Ok(())
    }

}

