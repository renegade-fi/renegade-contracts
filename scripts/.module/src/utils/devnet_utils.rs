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
            "300",
            "--lite-mode",
            "--seed",
            "0",
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

pub async fn prep_contract(contract_name: &str, calldata: Vec<&str>) -> Result<(String, String)> {
    let class_hash = declare(contract_name)?;
    let contract_address = deploy(&contract_name, calldata)?;

    dump_devnet_state().await?;

    Ok((class_hash, contract_address))
}

fn execute_nile_rs_command(args: Vec<&str>) -> Result<Output> {
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

pub fn compile(manifest_path: &str) -> Result<()> {
    execute_nile_rs_command(vec!["compile", "--manifest-path", manifest_path]).map(|_| ())
}

pub fn declare(contract_name: &str) -> Result<String> {
    debug!("Declaring {} contract...", &contract_name);
    let output = execute_nile_rs_command(vec!["declare", contract_name, "-d", "0", "-t"])?;
    parse_hash_from_output(output, "Class hash: ")
}

pub fn deploy(contract_name: &str, calldata: Vec<&str>) -> Result<String> {
    debug!("Deploying {} contract...", contract_name);
    let mut args = vec!["deploy", contract_name, "-d", "0", "-t"];

    args.extend(calldata);

    let output = execute_nile_rs_command(args)?;
    parse_hash_from_output(output, "Contract address: ")
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

pub fn send(
    contract_address: &str,
    function_name: &str,
    calldata: Vec<&str>,
    account_index: usize,
) -> Result<String> {
    let mut args = vec!["send", "--address", contract_address, function_name];
    args.extend(calldata);
    let account_index_str = account_index.to_string();
    args.extend(vec!["-d", &account_index_str, "-t"]);
    let output = execute_nile_rs_command(args)?;
    parse_hash_from_output(output, "Transaction hash: ")
}

fn parse_hash_from_output(output: Output, hash_prefix: &str) -> Result<String> {
    let hash_prefix_regex = Regex::new(hash_prefix).unwrap();
    let stdout = str::from_utf8(&output.stdout)?;
    let hash = hash_prefix_regex
        .split(stdout)
        .nth(1)
        .ok_or_else(|| eyre!("malformed deploy output"))?[..66]
        .into();
    Ok(hash)
}

pub fn get_predeployed_account(index: usize) -> Result<String> {
    assert!(index < 10);
    let output = execute_nile_rs_command(vec!["get-accounts", "--predeployed-accounts"])?;
    parse_account_from_output(output, index)
}

fn parse_account_from_output(output: Output, index: usize) -> Result<String> {
    let stdout = str::from_utf8(&output.stdout)?;
    let account = stdout
        .split('\n')
        .nth(index + 1)
        .ok_or_else(|| eyre!("malformed get-accounts output"))?[11..]
        .into();
    Ok(account)
}
