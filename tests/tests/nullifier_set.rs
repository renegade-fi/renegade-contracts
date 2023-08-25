use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use rand::thread_rng;
use tests::{
    nullifier_set::utils::{
        is_nullifier_spent, mark_nullifier_spent, FUZZ_ROUNDS, NULLIFIER_SET_ADDRESS,
    },
    utils::{global_teardown, setup_sequencer, TestConfig},
};

#[tokio::test]
async fn test_nullifier_set_fuzz() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::NullifierSet).await?;
    let account = sequencer.account();

    for _ in 0..FUZZ_ROUNDS {
        let nullifier = Scalar::random(&mut thread_rng());
        assert!(
            !is_nullifier_spent(&account, *NULLIFIER_SET_ADDRESS.get().unwrap(), nullifier).await?
        );
        mark_nullifier_spent(&account, nullifier).await?;
        assert!(
            is_nullifier_spent(&account, *NULLIFIER_SET_ADDRESS.get().unwrap(), nullifier).await?
        );
    }

    global_teardown(sequencer);

    Ok(())
}
