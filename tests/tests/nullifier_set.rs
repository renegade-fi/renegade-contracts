use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use rand::thread_rng;
use tests::{
    nullifier_set::utils::{
        mark_nullifier_used, setup_nullifier_set_test, FUZZ_ROUNDS, NULLIFIER_SET_ADDRESS,
    },
    utils::{global_teardown, is_nullifier_used},
};

#[tokio::test]
async fn test_nullifier_set_fuzz() -> Result<()> {
    let sequencer = setup_nullifier_set_test().await?;
    let account = sequencer.account();

    for _ in 0..FUZZ_ROUNDS {
        let nullifier = Scalar::random(&mut thread_rng());
        assert!(
            !is_nullifier_used(&account, *NULLIFIER_SET_ADDRESS.get().unwrap(), nullifier).await?
        );
        mark_nullifier_used(&account, nullifier).await?;
        assert!(
            is_nullifier_used(&account, *NULLIFIER_SET_ADDRESS.get().unwrap(), nullifier).await?
        );
    }

    global_teardown(sequencer);

    Ok(())
}
