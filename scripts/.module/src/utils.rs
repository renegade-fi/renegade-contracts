//! Home-spun nile-rs scripting utilities.
//! Assumes that `nile-rs` binary is available to the OS, and assumes that scripts are being run from the project root.

use eyre::{eyre, Result, WrapErr};
use lazy_static::lazy_static;
use regex::Regex;
use starknet_core::types::{BlockId, FieldElement};
use starknet_providers::{Provider, SequencerGatewayProvider};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};
use std::{env, str};

// Assumes `starknet-devnet` binary is available and `CAIRO_COMPILER_MANIFEST` is a set env var
pub async fn spawn_devnet() -> Child {
    let cairo_compiler_manifest = env::var("CAIRO_COMPILER_MANIFEST").unwrap();
    let provider = SequencerGatewayProvider::starknet_nile_localhost();

    println!("spawning devnet...");
    let devnet = Command::new("starknet-devnet")
        .args(vec!["--cairo-compiler-manifest", &cairo_compiler_manifest])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // Janky spinwait for the devnet to finish spinning up
    let timeout = Duration::from_secs(300);
    let start = Instant::now();
    let mut is_ready = provider.get_block(BlockId::Latest).await;
    while is_ready.is_err() {
        is_ready = provider.get_block(BlockId::Latest).await;
        if start.elapsed() >= timeout {
            panic!("devnet taking too long to spin up")
        }
    }

    devnet
}

fn execute_nile_rs_command(args: Vec<&str>) -> Result<Output> {
    Command::new("nile-rs")
        .args(args)
        .output()
        .wrap_err("failed to execute nile-rs command")
}

pub fn compile() -> Result<()> {
    execute_nile_rs_command(vec!["compile"]).map(|_| ())
}

pub fn declare(contract: &str) -> Result<()> {
    let full_contract_name: &str = &format!("renegade_contracts_{contract}");
    execute_nile_rs_command(vec!["declare", full_contract_name, "-d", "0", "-t"]).map(|_| ())
}

pub fn deploy(contract: &str) -> Result<String> {
    let full_contract_name: &str = &format!("renegade_contracts_{contract}");
    let output = execute_nile_rs_command(vec!["deploy", full_contract_name, "-d", "0", "-t"])?;
    parse_contract_address_from_output(output)
}

fn parse_contract_address_from_output(output: Output) -> Result<String> {
    lazy_static! {
        static ref CONTRACT_ADDRESS_REGEX: Regex = Regex::new(r"Contract address: ").unwrap();
    }
    let stdout = str::from_utf8(&output.stdout)?;
    Ok(CONTRACT_ADDRESS_REGEX
        .split(stdout)
        .nth(1)
        .ok_or_else(|| eyre!("malformed deploy output"))?[..66]
        .into())
}

pub fn call(
    contract_address: &str,
    function_name: &str,
    calldata: Vec<&str>,
) -> Result<Vec<FieldElement>> {
    let mut args = vec!["raw-call", contract_address, function_name];
    args.extend(calldata);
    let output = execute_nile_rs_command(args)?;
    let res = String::from_utf8(output.stdout)?;
    lazy_static! {
        static ref FELT_INNER_REGEX: Regex = Regex::new(r"inner: (0x[[:xdigit:]]+),").unwrap();
    }
    let mut field_elements: Vec<FieldElement> = Vec::new();

    for cap in FELT_INNER_REGEX.captures_iter(&res) {
        field_elements.push(cap[1].parse()?);
    }

    Ok(field_elements)
}

pub fn send(contract_address: &str, function_name: &str, calldata: Vec<&str>) -> Result<()> {
    let mut args = vec!["send", "--address", contract_address, function_name];
    args.extend(calldata);
    args.extend(vec!["-d", "0", "-t"]);
    execute_nile_rs_command(args).map(|_| ())
}
