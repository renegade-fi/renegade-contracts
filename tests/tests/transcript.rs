use eyre::Result;
use mpc_bulletproof::TranscriptProtocol;
use mpc_stark::{algebra::scalar::Scalar, random_point};
use rand::{thread_rng, Rng};
use tests::{
    transcript::utils::{
        append_point, append_scalar, challenge_scalar, get_challenge_scalar,
        innerproduct_domain_sep, r1cs_1phase_domain_sep, r1cs_domain_sep, rangeproof_domain_sep,
        setup_transcript_test, validate_and_append_point, FUZZ_ROUNDS,
    },
    utils::global_teardown,
};

#[tokio::test]
async fn test_transcript_fuzz() -> Result<()> {
    let (sequencer, mut hash_chain_transcript) = setup_transcript_test().await?;
    let account = sequencer.account();
    let mut rng = thread_rng();

    for _ in 0..FUZZ_ROUNDS {
        let rand_n: u64 = rng.gen();
        let rand_m: u64 = rng.gen();
        rangeproof_domain_sep(&account, rand_n, rand_m).await?;
        hash_chain_transcript.rangeproof_domain_sep(rand_n, rand_m);

        let rand_n: u64 = rng.gen();
        innerproduct_domain_sep(&account, rand_n).await?;
        hash_chain_transcript.innerproduct_domain_sep(rand_n);

        r1cs_domain_sep(&account).await?;
        hash_chain_transcript.r1cs_domain_sep();

        r1cs_1phase_domain_sep(&account).await?;
        hash_chain_transcript.r1cs_1phase_domain_sep();

        let rand_scalar = Scalar::random(&mut rng);
        let label = "append_scalar";
        append_scalar(&account, label, &rand_scalar).await?;
        hash_chain_transcript.append_scalar(label.as_bytes(), &rand_scalar);

        let rand_point = random_point();
        let label = "append_point";
        append_point(&account, label, &rand_point).await?;
        hash_chain_transcript.append_point(label.as_bytes(), &rand_point);

        let rand_point = random_point();
        let label = "append_val_point";
        validate_and_append_point(&account, label, &rand_point).await?;
        hash_chain_transcript.validate_and_append_point(label.as_bytes(), &rand_point)?;

        let label = "challenge_scalar";
        challenge_scalar(&account, label).await?;
        let challenge_scalar = get_challenge_scalar(&account).await?;
        let expected_challenge_scalar = hash_chain_transcript.challenge_scalar(label.as_bytes());

        assert!(challenge_scalar == expected_challenge_scalar);
    }

    global_teardown(sequencer);

    Ok(())
}
