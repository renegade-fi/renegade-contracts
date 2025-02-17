mod mul_two;
mod sum_pow;
mod types;

use alloy_sol_types::SolValue;
use clap::{Parser, Subcommand};
use itertools::Itertools;
use renegade_constants::Scalar;
use types::*;

// -------
// | CLI |
// -------

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Reference implementation for PLONK circuit verification"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Multiply two witness values and constrain their product to a public input
    MulTwo {
        #[command(subcommand)]
        action: MulTwoAction,
    },
    /// Compute (x₁ + x₂ + ... + xₙ)^5
    SumPow {
        #[command(subcommand)]
        action: SumPowAction,
    },
}

#[derive(Subcommand)]
enum MulTwoAction {
    /// Print the verification key for the mul-two circuit
    PrintVkey,
    /// Generate a proof for the mul-two circuit
    Prove {
        /// First witness value (as hex string)
        a: String,
        /// Second witness value (as hex string)
        b: String,
        /// Expected product (as hex string)
        c: String,
    },
}

#[derive(Subcommand)]
enum SumPowAction {
    /// Print the verification key for the sum-pow circuit
    PrintVkey,
    /// Generate a proof for the sum-pow circuit
    Prove {
        /// Input values to sum and raise to the fifth power (as hex strings)
        #[arg(required = true, num_args = 10)]
        inputs: Vec<String>,
        /// Expected result of (sum)^5 (as hex string)
        expected: String,
    },
}

// --------------
// | Entrypoint |
// --------------

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::MulTwo { action } => match action {
            MulTwoAction::PrintVkey => {
                let vk = mul_two::generate_verification_key();
                let encoded = vk.abi_encode();
                println!("RES:{}", hex::encode(encoded));
            }
            MulTwoAction::Prove { a, b, c } => {
                let a = Scalar::from_hex_string(&a).unwrap();
                let b = Scalar::from_hex_string(&b).unwrap();
                let c = Scalar::from_hex_string(&c).unwrap();
                let proof = mul_two::generate_proof(a, b, c);
                let encoded = proof.abi_encode();
                println!("RES:{}", hex::encode(encoded));
            }
        },
        Commands::SumPow { action } => match action {
            SumPowAction::PrintVkey => {
                let vk = sum_pow::generate_verification_key();
                let encoded = vk.abi_encode();
                println!("RES:{}", hex::encode(encoded));
            }
            SumPowAction::Prove { inputs, expected } => {
                let inputs = inputs
                    .iter()
                    .map(|s| Scalar::from_hex_string(s).unwrap())
                    .collect_vec();
                let expected = Scalar::from_hex_string(&expected).unwrap();

                let proof = sum_pow::generate_proof(inputs, expected);
                let encoded = proof.abi_encode();
                println!("RES:{}", hex::encode(encoded));
            }
        },
    }
}
