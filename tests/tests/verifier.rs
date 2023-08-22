use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use rand::thread_rng;
use tests::{
    utils::{
        check_verification_job_status, global_teardown, random_felt, setup_sequencer,
        singleprover_prove_dummy_circuit, TestConfig,
    },
    verifier::utils::{queue_verification_job, step_verification, FUZZ_ROUNDS, VERIFIER_ADDRESS},
};

#[tokio::test]
async fn test_full_verification_fuzz() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Verifier).await?;
    let account = sequencer.account();

    for _ in 0..FUZZ_ROUNDS {
        let (proof, witness_commitments) = singleprover_prove_dummy_circuit()?;
        let verification_job_id = random_felt();
        queue_verification_job(&account, &proof, &witness_commitments, verification_job_id).await?;

        while check_verification_job_status(
            &account,
            *VERIFIER_ADDRESS.get().unwrap(),
            verification_job_id,
        )
        .await?
        .is_none()
        {
            step_verification(&account, verification_job_id).await?;
        }

        assert!(check_verification_job_status(
            &account,
            *VERIFIER_ADDRESS.get().unwrap(),
            verification_job_id
        )
        .await?
        .unwrap());
    }

    global_teardown(sequencer);
    Ok(())
}

#[tokio::test]
async fn test_full_verification_invalid_proof() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Verifier).await?;
    let account = sequencer.account();

    let (mut proof, witness_commitments) = singleprover_prove_dummy_circuit()?;
    // Fuzz a part of the proof so it becomes invalid
    proof.t_x = Scalar::random(&mut thread_rng());
    let verification_job_id = random_felt();
    queue_verification_job(&account, &proof, &witness_commitments, verification_job_id).await?;

    while check_verification_job_status(
        &account,
        *VERIFIER_ADDRESS.get().unwrap(),
        verification_job_id,
    )
    .await?
    .is_none()
    {
        step_verification(&account, verification_job_id).await?;
    }

    assert!(!check_verification_job_status(
        &account,
        *VERIFIER_ADDRESS.get().unwrap(),
        verification_job_id
    )
    .await?
    .unwrap());

    global_teardown(sequencer);
    Ok(())
}
