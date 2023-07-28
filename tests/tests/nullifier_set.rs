use eyre::Result;
use tests::{
    nullifier_set::utils::{
        contract_is_nullifier_used, contract_mark_nullifier_used, setup_nullifier_set_test,
        FUZZ_ROUNDS,
    },
    utils::{global_teardown, random_scalar_as_felt},
};

#[tokio::test]
async fn test_nullifier_set_fuzz() -> Result<()> {
    let sequencer = setup_nullifier_set_test().await?;
    let account = sequencer.account();

    for _ in 0..FUZZ_ROUNDS {
        let nullifier = random_scalar_as_felt();
        assert!(!contract_is_nullifier_used(&account, nullifier).await?);
        contract_mark_nullifier_used(&account, nullifier).await?;
        assert!(contract_is_nullifier_used(&account, nullifier).await?);
    }

    global_teardown(sequencer);

    Ok(())
}
