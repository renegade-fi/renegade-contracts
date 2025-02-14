mod mul_two;
mod sum_pow;
mod types;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use clap::{Parser, Subcommand};
use ethabi::{encode, Token};
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
                let vk_token = encode_verification_key(&vk);
                let encoded = encode(&[vk_token]);
                println!("RES:{}", hex::encode(encoded));
            }
            MulTwoAction::Prove { a, b, c } => {
                let a = Scalar::from_hex_string(&a).unwrap();
                let b = Scalar::from_hex_string(&b).unwrap();
                let c = Scalar::from_hex_string(&c).unwrap();
                let proof = mul_two::generate_proof(a, b, c);
                let proof_token = encode_proof(&proof);
                println!("RES:{}", hex::encode(encode(&[proof_token])));
            }
        },
        Commands::SumPow { action } => match action {
            SumPowAction::PrintVkey => {
                let vk = sum_pow::generate_verification_key();
                let vk_token = encode_verification_key(&vk);
                let encoded = encode(&[vk_token]);
                println!("RES:{}", hex::encode(encoded));
            }
            SumPowAction::Prove { inputs, expected } => {
                let inputs = inputs
                    .iter()
                    .map(|s| Scalar::from_hex_string(s).unwrap())
                    .collect_vec();
                let expected = Scalar::from_hex_string(&expected).unwrap();

                let proof = sum_pow::generate_proof(inputs, expected);
                let proof_token = encode_proof(&proof);
                println!("RES:{}", hex::encode(encode(&[proof_token])));
            }
        },
    }
}

// Helper function to encode proof
fn encode_proof(proof: &PlonkProof) -> Token {
    Token::Tuple(vec![
        encode_g1_points(&proof.wire_comms),
        encode_g1_point(&proof.z_comm),
        encode_g1_points(&proof.quotient_comms),
        encode_g1_point(&proof.w_zeta),
        encode_g1_point(&proof.w_zeta_omega),
        encode_scalars(&proof.wire_evals),
        encode_scalars(&proof.sigma_evals),
        encode_scalar(&proof.z_bar),
    ])
}

// Helper function to encode verification key
fn encode_verification_key(vk: &VerificationKey) -> Token {
    Token::Tuple(vec![
        Token::Uint(vk.n.into()),
        Token::Uint(vk.l.into()),
        encode_scalars(&vk.k),
        encode_g1_points(&vk.q_comms),
        encode_g1_points(&vk.sigma_comms),
        encode_g1_point(&vk.g),
        encode_g2_point(&vk.h),
        encode_g2_point(&vk.x_h),
    ])
}

// Helper functions to encode various types as ethabi tokens
fn encode_g1_point(point: &G1Point) -> Token {
    Token::Tuple(vec![
        Token::Uint(ethabi::ethereum_types::U256::from_little_endian(
            &point.x.into_bigint().to_bytes_le(),
        )),
        Token::Uint(ethabi::ethereum_types::U256::from_little_endian(
            &point.y.into_bigint().to_bytes_le(),
        )),
    ])
}

fn encode_g2_point(point: &G2Point) -> Token {
    Token::Tuple(vec![
        Token::Array(vec![
            Token::Uint(ethabi::ethereum_types::U256::from_little_endian(
                &point.x.c0.into_bigint().to_bytes_le(),
            )),
            Token::Uint(ethabi::ethereum_types::U256::from_little_endian(
                &point.x.c1.into_bigint().to_bytes_le(),
            )),
        ]),
        Token::Array(vec![
            Token::Uint(ethabi::ethereum_types::U256::from_little_endian(
                &point.y.c0.into_bigint().to_bytes_le(),
            )),
            Token::Uint(ethabi::ethereum_types::U256::from_little_endian(
                &point.y.c1.into_bigint().to_bytes_le(),
            )),
        ]),
    ])
}

fn encode_g1_points<const N: usize>(points: &[G1Point; N]) -> Token {
    Token::Array(points.iter().map(encode_g1_point).collect())
}

fn encode_scalar(scalar: &Fr) -> Token {
    Token::Uint(ethabi::ethereum_types::U256::from_little_endian(
        &scalar.into_bigint().to_bytes_le(),
    ))
}

fn encode_scalars<const N: usize>(scalars: &[Fr; N]) -> Token {
    Token::Array(scalars.iter().map(encode_scalar).collect())
}
