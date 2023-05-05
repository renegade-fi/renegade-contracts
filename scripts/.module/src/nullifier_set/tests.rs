use eyre::Result;
use starknet_crypto::FieldElement;
use tracing::log::{debug, info};

use crate::utils::{common_utils, devnet_utils};

// -------------
// | CONSTANTS |
// -------------

const CONTRACT_NAME: &'static str = "NullifierSet";
const IS_NULLIFIER_USED_FN_NAME: &'static str = "is_nullifier_used";
const MARK_NULLIFIER_USED_FN_NAME: &'static str = "mark_nullifier_used";
const NULLIFIER_HALF_BITSIZE: u64 = 124;

pub async fn run() -> Result<()> {
    let contract_name = String::from(CONTRACT_NAME);
    let contract_address = devnet_utils::prep_contract(&contract_name).await?;
    let nullifier_set_test = NullifierSetTest::new(contract_name, contract_address, 20);

    info!("Running test `test_valid_nullifier__fuzz`");
    nullifier_set_test.test_valid_nullifier__fuzz()?;
    info!("Test succeeded!");

    Ok(())
}

type Nullifier = [FieldElement; 2];

struct NullifierSetTest {
    contract_name: String,
    contract_address: String,
    fuzz_rounds: usize,
}

#[allow(non_snake_case)]
impl NullifierSetTest {
    // ---------------
    // | CONSTRUCTOR |
    // ---------------

    fn new(contract_name: String, contract_address: String, fuzz_rounds: usize) -> Self {
        Self {
            contract_name,
            contract_address,
            fuzz_rounds,
        }
    }

    // ---------
    // | TESTS |
    // ---------

    fn test_valid_nullifier__fuzz(&self) -> Result<()> {
        for _ in 0..self.fuzz_rounds {
            let nullifier = Self::gen_random_nullifier()?;
            // Assert that nullifier is initially unused
            assert!(!self.is_nullifier_used(nullifier)?);
            // Mark nullifier as used
            self.mark_nullifier_used(nullifier)?;
            // Check that nullifier is now used
            assert!(self.is_nullifier_used(nullifier)?);
        }

        Ok(())
    }

    // -----------
    // | HELPERS |
    // -----------

    fn gen_random_nullifier() -> Result<Nullifier> {
        let low = common_utils::gen_random_felt(NULLIFIER_HALF_BITSIZE)?;
        let high = common_utils::gen_random_felt(NULLIFIER_HALF_BITSIZE)?;

        Ok([low, high])
    }

    fn nullifier_to_calldata(nullifier: Nullifier) -> Vec<String> {
        vec![
            common_utils::felt_to_dec_str(nullifier[0]),
            common_utils::felt_to_dec_str(nullifier[1]),
        ]
    }

    fn is_nullifier_used(&self, nullifier: Nullifier) -> Result<bool> {
        let nullifier_calldata = Self::nullifier_to_calldata(nullifier);
        debug!(
            "Checking {} contract if nullifier: u256 {{ low: {}, high: {} }} is used...",
            &self.contract_name, &nullifier_calldata[0], &nullifier_calldata[1]
        );
        let bool_felt = devnet_utils::call(
            self.contract_address.clone(),
            IS_NULLIFIER_USED_FN_NAME.to_string(),
            nullifier_calldata,
        )?[0];
        Ok(bool_felt == FieldElement::ONE)
    }

    fn mark_nullifier_used(&self, nullifier: Nullifier) -> Result<()> {
        let nullifier_calldata = Self::nullifier_to_calldata(nullifier);
        debug!(
            "Marking nullifier: u256 {{ low: {}, high: {} }} as used in {} contract...",
            &nullifier_calldata[0], &nullifier_calldata[1], &self.contract_name
        );
        devnet_utils::send(
            self.contract_address.clone(),
            MARK_NULLIFIER_USED_FN_NAME.to_string(),
            nullifier_calldata,
        )
    }
}
