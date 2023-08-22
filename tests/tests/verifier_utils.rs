use eyre::Result;
use merlin::HashChainTranscript;
use mpc_bulletproof::{
    r1cs::{ConstraintSystem, Verifier},
    util::exp_iter,
    PedersenGens,
};
use tests::{
    utils::{global_teardown, TRANSCRIPT_SEED},
    verifier::utils::DUMMY_CIRCUIT_N,
    verifier_utils::utils::{
        calc_delta, get_expected_dummy_circuit_delta, get_expected_dummy_circuit_s, get_s_elem,
        setup_verifier_utils_test, squeeze_challenge_scalars,
        squeeze_expected_dummy_circuit_challenge_scalars,
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
    let mut challenge_scalars_transcript_clone = transcript.clone();
    let mut s_transcript_clone = transcript.clone();
    let pc_gens = PedersenGens::default();
    let mut verifier = Verifier::new(&pc_gens, &mut transcript);

    let (sequencer, proof, witness_commitments) = setup_verifier_utils_test(&mut verifier).await?;
    let account = sequencer.account();

    let (_, u) = squeeze_expected_dummy_circuit_challenge_scalars(
        &mut challenge_scalars_transcript_clone,
        &proof,
        &witness_commitments,
    )?;

    let expected_s =
        get_expected_dummy_circuit_s(&proof, &witness_commitments, &mut s_transcript_clone)?;

    for (i, expected_s_elem) in expected_s.iter().enumerate().take(u.len()) {
        let s_elem = get_s_elem(&account, &u, i).await?;
        assert_eq!(&s_elem, expected_s_elem);
    }

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_calc_delta() -> Result<()> {
    let mut transcript = HashChainTranscript::new(TRANSCRIPT_SEED.as_bytes());
    let mut transcript_clone = transcript.clone();
    let pc_gens = PedersenGens::default();
    let mut verifier = Verifier::new(&pc_gens, &mut transcript);

    let (sequencer, proof, witness_commitments) = setup_verifier_utils_test(&mut verifier).await?;

    let (challenge_scalars, _) = squeeze_expected_dummy_circuit_challenge_scalars(
        &mut transcript_clone,
        &proof,
        &witness_commitments,
    )?;

    let y_inv_powers_to_n = exp_iter(challenge_scalars[0].inverse())
        .take(DUMMY_CIRCUIT_N)
        .collect();
    let z = challenge_scalars[1];

    let circuit_weights = verifier.get_weights();

    let delta = calc_delta(
        &sequencer.account(),
        &y_inv_powers_to_n,
        z,
        circuit_weights.w_l,
        circuit_weights.w_r,
    )
    .await?;

    let expected_delta = get_expected_dummy_circuit_delta(&mut verifier, &y_inv_powers_to_n, &z);

    assert_eq!(delta, expected_delta);

    global_teardown(sequencer);

    Ok(())
}
