use alloy_primitives::Address;
use clap::Parser;
use eyre::{eyre, Result};
use renegade_circuit_types::elgamal::{DecryptionKey, EncryptionKey};
use renegade_circuit_types::fixed_point::FixedPoint;
use renegade_crypto::fields::jubjub_to_scalar;
use renegade_util::hex::scalar_to_hex_string;
use std::fs::File;
use std::io::Write;
use std::process::Command;
use std::str::FromStr;
use tool_utils::{prompt_for_eth_address as prompt_for_address, prompt_for_f64, run_command};

/// The signature of the `run` function in the `DeployScript` contract
///
/// Args are:
/// - The protocol fee encryption key x-coordinate
/// - The protocol fee encryption key y-coordinate  
/// - The protocol fee rate
/// - The protocol fee recipient address
/// - The permit2 contract address
/// - The weth contract address
const RUN_SIGNATURE: &str = "run(uint256,uint256,uint256,address,address,address)";
/// The path to which we write the decryption key
const DECRYPTION_KEY_PATH: &str = "fee_decryption_key.txt";

// -------
// | CLI |
// -------

/// Deploy Renegade contracts to an EVM chain
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// RPC URL to deploy to
    #[arg(short, long, env = "RPC_URL", default_value = "http://localhost:8545")]
    rpc_url: String,
    /// Permit2 contract address
    #[arg(long)]
    permit2: Option<String>,
    /// WETH contract address
    #[arg(long)]
    weth: Option<String>,
    /// The protocol fee rate
    #[arg(long)]
    protocol_fee_rate: Option<f64>,
    /// Protocol fee recipient address
    #[arg(long)]
    fee_recipient: Option<String>,
    /// Private key for signing transactions
    #[arg(long = "pkey", env = "PKEY")]
    private_key: String,
    /// Verbosity level (v, vv, vvv)
    #[arg(long, default_value = "v")]
    verbosity: String,
}

fn main() -> Result<()> {
    // Prompt for required arguments if not provided
    let mut args = Args::parse();
    prompt_for_missing_args(&mut args)?;

    // Unwrap the Option values now that we're sure they're present and valid
    let permit2 = args.permit2.unwrap();
    let weth = args.weth.unwrap();
    let fee_recipient = args.fee_recipient.unwrap();
    let fee_rate = args.protocol_fee_rate.unwrap();
    println!("Deploying to RPC URL: {}", args.rpc_url);
    println!("\tPermit2 address: {}", permit2);
    println!("\tWETH address: {}", weth);
    println!("\tFee recipient: {}", fee_recipient);
    println!("\tProtocol fee rate: {}", fee_rate);

    // Generate an encryption key for internal protocol fees
    let enc_key = generate_fee_encryption_key()?;
    println!("Fee encryption key");
    println!("\tx: {}", enc_key.x);
    println!("\ty: {}", enc_key.y);

    // Convert the protocol fee rate to a fixed point value
    let protocol_fee_fp = FixedPoint::from_f64_round_down(fee_rate);
    let protocol_fee_repr = protocol_fee_fp.repr;

    // Build the forge script command
    let mut cmd = Command::new("forge");
    cmd.arg("script")
        .arg("script/Deploy.s.sol:DeployScript") // Specify contract name with path
        .arg("--rpc-url")
        .arg(&args.rpc_url)
        .arg("--sig")
        .arg(RUN_SIGNATURE)
        .arg(format!("{}", enc_key.x))
        .arg(format!("{}", enc_key.y))
        .arg(format!("{protocol_fee_repr}"))
        .arg(&fee_recipient)
        .arg(&permit2)
        .arg(&weth)
        .arg("--ffi") // Add FFI flag to allow external commands (huffc)
        .arg("--broadcast") // Always use broadcast
        .arg("--private-key")
        .arg(&args.private_key)
        .arg(format!("-{}", args.verbosity));

    // Execute the command
    run_command(cmd)?;

    println!("\nDeployment completed successfully!");
    println!("Decryption key written to {}", DECRYPTION_KEY_PATH);
    Ok(())
}

// -----------
// | Helpers |
// -----------

/// Prompt for missing arguments
fn prompt_for_missing_args(args: &mut Args) -> Result<()> {
    if args.permit2.is_none() || !is_valid_eth_address(args.permit2.as_ref().unwrap()) {
        let addr = prompt_for_address("Enter Permit2 contract address")?;
        args.permit2 = Some(addr);
    }

    if args.weth.is_none() || !is_valid_eth_address(args.weth.as_ref().unwrap()) {
        let addr = prompt_for_address("Enter WETH contract address")?;
        args.weth = Some(addr);
    }

    if args.fee_recipient.is_none() || !is_valid_eth_address(args.fee_recipient.as_ref().unwrap()) {
        let addr = prompt_for_address("Enter protocol fee recipient address")?;
        args.fee_recipient = Some(addr);
    }

    if args.protocol_fee_rate.is_none() {
        let rate = prompt_for_f64("Enter protocol fee rate", 0.0, 1.0)?;
        args.protocol_fee_rate = Some(rate);
    }

    Ok(())
}

// Function to validate Ethereum address using Alloy
fn is_valid_eth_address(address: &str) -> bool {
    Address::from_str(address).is_ok()
}

/// Generate a random encryption key
///
/// Writes the decryption key to a file and returns the encryption key
fn generate_fee_encryption_key() -> Result<EncryptionKey> {
    let mut rng = rand::thread_rng();
    let (dec_key, enc_key) = DecryptionKey::random_pair(&mut rng);

    let key_inner = jubjub_to_scalar(dec_key.key);
    let dec_key_str = scalar_to_hex_string(&key_inner);
    let mut file = File::create(DECRYPTION_KEY_PATH)?;
    file.write_all(dec_key_str.as_bytes())?;

    Ok(enc_key)
}
