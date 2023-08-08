use eyre::Result;
use merlin::HashChainTranscript;
use mpc_bulletproof::{r1cs::Verifier, PedersenGens};
use tests::{
    utils::{global_teardown, TRANSCRIPT_SEED},
    verifier::utils::squeeze_expected_challenge_scalars,
    verifier_utils::utils::{setup_verifier_utils_test, squeeze_challenge_scalars},
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
        squeeze_expected_challenge_scalars(&mut transcript_clone, &proof, &witness_commitments)?;

    assert_eq!(challenge_scalars, expected_challenge_scalars);
    assert_eq!(u, expected_u);

    global_teardown(sequencer);
    Ok(())
}
