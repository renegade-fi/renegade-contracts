//! Home-spun nile-rs scripting utilities.
//! Assumes that `nile-rs` binary is available to the OS, and assumes that scripts are being run from the project root.

use eyre::{eyre, Result, WrapErr};
use lazy_static::lazy_static;
use regex::Regex;
use reqwest::Client;
use starknet_core::types::{BlockId, FieldElement};
use starknet_providers::{Provider, SequencerGatewayProvider};
use std::collections::HashMap;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};
use std::{env, str};
use tracing::log::{debug, trace};

// Assumes `starknet-devnet` binary is available and `CAIRO_COMPILER_MANIFEST` is a set env var
pub async fn spawn_devnet() -> Child {
    let cairo_compiler_manifest = env::var("CAIRO_COMPILER_MANIFEST").unwrap();
    let provider = SequencerGatewayProvider::starknet_nile_localhost();

    debug!("Spawning devnet...");
    let devnet = Command::new("starknet-devnet")
        .args(vec![
            "--cairo-compiler-manifest",
            &cairo_compiler_manifest,
            "-t",
            "180",
            "--lite-mode",
        ])
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

pub async fn dump_devnet_state() -> Result<()> {
    let client = Client::new();
    let mut body = HashMap::new();
    let devnet_state_path = env::var("DEVNET_STATE_PATH").unwrap();
    body.insert("path", &devnet_state_path);
    debug!("Dumping devnet state...");
    Ok(client
        .post("http://localhost:5050/dump")
        .json(&body)
        .send()
        .await
        .map(|_| ())?)
}

pub async fn load_devnet_state() -> Result<()> {
    let client = Client::new();
    let mut body = HashMap::new();
    let devnet_state_path = env::var("DEVNET_STATE_PATH").unwrap();
    body.insert("path", &devnet_state_path);
    debug!("Loading devnet state...");
    Ok(client
        .post("http://localhost:5050/load")
        .json(&body)
        .send()
        .await
        .map(|_| ())?)
}

pub async fn prep_contract(contract_name: &str) -> Result<String> {
    debug!("Declaring {} contract...", &contract_name);
    declare(&contract_name)?;

    debug!("Deploying {} contract...", &contract_name);
    let contract_address = deploy(&contract_name)?;

    dump_devnet_state().await?;

    Ok(contract_address)
}

fn execute_nile_rs_command(args: Vec<String>) -> Result<Output> {
    let output = Command::new("nile-rs")
        .args(args)
        .output()
        .wrap_err("failed to execute nile-rs command")?;

    let output_str = str::from_utf8(&output.stdout)?;

    if !output.status.success() {
        return Err(eyre!(
            "nile-rs command failed:\n{}\n{}",
            output_str,
            str::from_utf8(&output.stderr)?,
        ));
    } else {
        trace!("{}", output_str);
    }

    Ok(output)
}

pub fn compile() -> Result<()> {
    execute_nile_rs_command(vec!["compile".to_string()]).map(|_| ())
}

pub fn declare(contract: &str) -> Result<()> {
    let full_contract_name = format!("renegade_contracts_{contract}");
    execute_nile_rs_command(
        vec!["declare", &full_contract_name, "-d", "0", "-t"]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
    )
    .map(|_| ())
}

pub fn deploy(contract: &str) -> Result<String> {
    let full_contract_name = format!("renegade_contracts_{contract}");
    let output = execute_nile_rs_command(
        vec!["deploy", &full_contract_name, "-d", "0", "-t"]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
    )?;
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
    contract_address: String,
    function_name: String,
    calldata: Vec<String>,
) -> Result<Vec<FieldElement>> {
    let mut args: Vec<String> = vec!["raw-call".to_string(), contract_address, function_name];
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

pub fn send(contract_address: String, function_name: String, calldata: Vec<String>) -> Result<()> {
    let mut args: Vec<String> = vec!["send", "--address", &contract_address, &function_name]
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    args.extend(calldata);
    args.extend(
        vec!["-d", "0", "-t"]
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<String>>(),
    );
    execute_nile_rs_command(args).map(|_| ())
}
