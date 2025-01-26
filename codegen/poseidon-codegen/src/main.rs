use anyhow::Result;
use clap::Parser;
use itertools::Itertools;
use num_bigint::BigUint;
use renegade_constants::Scalar;
use renegade_crypto::fields::scalar_to_biguint;
use renegade_crypto::hash::{FULL_ROUND_CONSTANTS, PARTIAL_ROUND_CONSTANTS, R_F, R_P};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Output file path for the generated Huff code
    #[arg(short, long)]
    output: PathBuf,
}

// --- Code Generation --- //

/// Generates the Huff source code as a string
///
/// Maintains the invariant that the state is always the first three words of the stack
fn generate_huff_code() -> String {
    let mut code = String::new();
    const HALF_FULL: usize = R_F / 2;
    let partial_rounds = R_P;

    for i in 0..HALF_FULL {
        code.push_str(&generate_full_round(i));
    }

    for i in 0..partial_rounds {
        code.push_str(&generate_partial_round(i));
    }

    for i in HALF_FULL..R_F {
        code.push_str(&generate_full_round(i));
    }

    code
}

/// Generate a full round of the hash function
fn generate_full_round(i: usize) -> String {
    let mut code = String::new();
    let round_constants = FULL_ROUND_CONSTANTS[i];
    let round_constants_str = round_constants
        .iter()
        .map(|fp| Scalar::new(*fp))
        .map(scalar_to_hex)
        .collect_vec();

    code.push_str(&format!("// --- Full Round {i} --- //\n"));
    code.push_str(&format!(
        "EXTERNAL_ROUND({}, {}, {})\n\n",
        round_constants_str[0], round_constants_str[1], round_constants_str[2]
    ));
    code
}

/// Generate a partial round of the hash function
fn generate_partial_round(i: usize) -> String {
    let mut code = String::new();

    let round_constant = PARTIAL_ROUND_CONSTANTS[i];
    let round_constant_str = scalar_to_hex(Scalar::new(round_constant));

    code.push_str(&format!("// --- Partial Round {i} --- //\n"));
    code.push_str(&format!("INTERNAL_ROUND({round_constant_str})\n\n"));
    code
}

// --- Helpers --- //

/// Convert a `Scalar` element to a big-endian hex string
fn scalar_to_hex(scalar: Scalar) -> String {
    let biguint = scalar_to_biguint(&scalar);
    format!("{biguint:#x}")
}

// --- Main --- //

fn main() -> Result<()> {
    let args = Args::parse();

    // Generate the Huff code
    let huff_code = generate_huff_code();

    // Write to the output file
    fs::write(&args.output, huff_code)?;
    println!(
        "Successfully generated Huff code at: {}",
        args.output.display()
    );

    Ok(())
}
