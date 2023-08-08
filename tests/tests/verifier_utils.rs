use eyre::Result;
use merlin::HashChainTranscript;
use mpc_bulletproof::{r1cs::Verifier, PedersenGens};
use tests::{
    utils::{global_teardown, TRANSCRIPT_SEED},
    verifier_utils::utils::{
        get_expected_dummy_circuit_s, get_s_elem, setup_verifier_utils_test,
        squeeze_challenge_scalars, squeeze_expected_dummy_circuit_challenge_scalars,
    },
};

#[tokio::test]
async fn test_squeeze_challenge_scalars_dummy_circuit() -> Result<()> {
    let mut transcript = HashChainTranscript::new(TRANSCRIPT_SEED.as_bytes());
    let mut transcript_clone = transcript.clone();
    let pc_gens = PedersenGens::default();
    let mut verifier = Verifier::new(&pc_gens, &mut transcript);

    let (sequencer, proof, witness_commitments) = setup_verifier_utils_test(&mut verifier).await?;

    let (challenge_scalars, u) =
        squeeze_challenge_scalars(&sequencer.account(), &proof, &witness_commitments).await?;

    let (expected_challenge_scalars, expected_u) =
        squeeze_expected_dummy_circuit_challenge_scalars(
            &mut transcript_clone,
            &proof,
            &witness_commitments,
        )?;

    assert_eq!(challenge_scalars, expected_challenge_scalars);
    assert_eq!(u, expected_u);

    global_teardown(sequencer);
    Ok(())
}

#[tokio::test]
async fn test_get_s_elem() -> Result<()> {
    let mut transcript = HashChainTranscript::new(TRANSCRIPT_SEED.as_bytes());
    let mut transcript_clone = transcript.clone();
    let pc_gens = PedersenGens::default();
    let mut verifier = Verifier::new(&pc_gens, &mut transcript);

    let (sequencer, proof, witness_commitments) = setup_verifier_utils_test(&mut verifier).await?;
    let account = sequencer.account();

    let (_, u) = squeeze_expected_dummy_circuit_challenge_scalars(
        &mut transcript_clone,
        &proof,
        &witness_commitments,
    )?;

    let expected_s = get_expected_dummy_circuit_s(&u);

    for (i, expected_s_elem) in expected_s.iter().enumerate().take(u.len()) {
        let s_elem = get_s_elem(&account, &u, i).await?;
        assert_eq!(&s_elem, expected_s_elem);
    }

    global_teardown(sequencer);

    Ok(())
}
