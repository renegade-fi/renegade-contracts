use std::env;
use std::error::Error;

use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use mpc_plonk::transcript::{PlonkTranscript, SolidityTranscript};
use renegade_constants::Scalar;

/// Type alias for the base field of the Bn254 curve
type BaseField = <Bn254 as Pairing>::BaseField;

fn main() -> Result<(), Box<dyn Error>> {
    // Skip the first argument
    let args: Vec<String> = env::args().skip(1).collect();
    assert!(args.len() == 1, "Expected 1 argument, got {}", args.len());

    // Parse the hex string
    let trimmed = args[0].trim_start_matches("0x");
    let bytes = hex::decode(trimmed)?;

    // Create a transcript, append the input, and compute the challenge
    let mut ts = <SolidityTranscript as PlonkTranscript<BaseField>>::new(b"unused_label");
    <SolidityTranscript as PlonkTranscript<BaseField>>::append_message(
        &mut ts,
        b"unused_label",
        &bytes,
    )?;
    let challenge = <SolidityTranscript as PlonkTranscript<BaseField>>::get_and_append_challenge::<
        Bn254,
    >(&mut ts, b"unused_label")?;

    // Return the challenge as a hex string
    let scalar = Scalar::new(challenge);
    let hex_str = format!("{:#x}", scalar.to_biguint());

    // Prefix with RES: to ensure consistent string parsing
    println!("RES:{hex_str}");
    Ok(())
}
