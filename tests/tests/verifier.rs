use eyre::Result;
use tests::{
    utils::{global_teardown, random_felt},
    verifier::utils::{
        check_verification_job_status, queue_verification_job, setup_verifier_test,
        singleprover_prove_dummy_circuit, step_verification, FUZZ_ROUNDS,
    },
};

#[tokio::test]
async fn test_full_verification_fuzz() -> Result<()> {
    let sequencer = setup_verifier_test().await?;
    let account = sequencer.account();

    for _ in 0..FUZZ_ROUNDS {
        let (proof, witness_commitments) = singleprover_prove_dummy_circuit()?;
        let verification_job_id = random_felt();
        queue_verification_job(&account, &proof, &witness_commitments, verification_job_id).await?;

        while check_verification_job_status(&account, verification_job_id)
            .await?
            .is_none()
        {
            step_verification(&account, verification_job_id).await?;
        }

        assert!(check_verification_job_status(&account, verification_job_id)
            .await?
            .unwrap());
    }

    global_teardown(sequencer);
    Ok(())
}
