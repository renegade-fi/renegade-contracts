use eyre::Result;
use starknet_crypto::FieldElement;
use tracing::log::{debug, info};

use crate::utils::{common_utils::*, devnet_utils};

pub async fn run() -> Result<()> {
    let nullifier_set_test = NullifierSetTest::new(
        NULLIFIER_SET_CONTRACT_NAME.to_string(),
        get_once_cell_string(&NULLIFIER_SET_CONTRACT_ADDRESS)?.clone(),
        20,
    );

    info!("Running test `test_valid_nullifier__fuzz`");
    nullifier_set_test.test_valid_nullifier__fuzz()?;
    info!("Test succeeded!");

    Ok(())
}

struct NullifierSetTest {
    nullifier_set_contract_name: String,
    nullifier_set_contract_address: String,
    fuzz_rounds: usize,
}

#[allow(non_snake_case)]
impl NullifierSetTest {
    // ---------------
    // | CONSTRUCTOR |
    // ---------------

    fn new(
        nullifier_set_contract_name: String,
        nullifier_set_contract_address: String,
        fuzz_rounds: usize,
    ) -> Self {
        Self {
            nullifier_set_contract_name,
            nullifier_set_contract_address,
            fuzz_rounds,
        }
    }

    // ---------
    // | TESTS |
    // ---------

    fn test_valid_nullifier__fuzz(&self) -> Result<()> {
        for _ in 0..self.fuzz_rounds {
            let nullifier = gen_random_felt(MAX_FELT_BIT_SIZE)?;
            // Assert that nullifier is initially unused
            assert!(!is_nullifier_used(
                &self.nullifier_set_contract_name,
                &self.nullifier_set_contract_address,
                nullifier
            )?);
            // Mark nullifier as used
            self.mark_nullifier_used(nullifier)?;
            // Check that nullifier is now used
            assert!(is_nullifier_used(
                &self.nullifier_set_contract_name,
                &self.nullifier_set_contract_address,
                nullifier
            )?);
        }

        Ok(())
    }

    // -----------
    // | HELPERS |
    // -----------

    fn mark_nullifier_used(&self, nullifier: FieldElement) -> Result<()> {
        let nullifier_str = &felt_to_dec_str(nullifier);
        let nullifier_calldata: Vec<&str> = vec![nullifier_str];
        debug!(
            "Marking nullifier: {} as used in {} contract...",
            &nullifier_calldata[0], &self.nullifier_set_contract_name
        );
        devnet_utils::send(
            &self.nullifier_set_contract_address,
            MARK_NULLIFIER_USED_FN_NAME,
            nullifier_calldata,
            0,
        )
        .map(|_| ())
    }
}
