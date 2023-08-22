use eyre::Result;
use tests::{
    poseidon::utils::{get_random_input_hashes, FUZZ_ROUNDS},
    utils::{global_teardown, setup_sequencer, TestConfig},
};

#[tokio::test]
async fn test_poseidon_fuzz() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Poseidon).await?;
    let account = sequencer.account();

    for _ in 0..FUZZ_ROUNDS {
        let (contract_hash, ark_hash) = get_random_input_hashes(&account).await?;
        assert!(contract_hash == ark_hash);
    }

    global_teardown(sequencer);

    Ok(())
}
