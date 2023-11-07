//! Utilities for running integration tests

use std::{fs::File, io::Read, str::FromStr, sync::Arc};

use alloy_primitives::{Address as AlloyAddress, U256 as AlloyU256};
use ark_std::UniformRand;
use common::types::{
    ExternalTransfer, MatchPayload, Proof, ScalarField, ValidCommitmentsStatement,
    ValidMatchSettleStatement, ValidReblindStatement, VerificationKey,
};
use ethers::{
    abi::{Address, Detokenize, Tokenize},
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{Bytes, U256},
};
use eyre::{eyre, Result};
use rand::Rng;
use serde::Serialize;
use test_helpers::renegade_circuits::{dummy_circuit_bundle, Circuit};

use crate::{
    abis::{DarkpoolTestContract, DummyErc20Contract},
    cli::Tests,
    constants::{
        DARKPOOL_TEST_CONTRACT_KEY, DEPLOYMENTS_KEY, N, PRECOMPILE_TEST_CONTRACT_KEY,
        TRANSFER_AMOUNT, VERIFIER_TEST_CONTRACT_KEY,
    },
};

/// Sets up the address and client with which to instantiate a contract for testing,
/// reading in the private key, RPC url, and contract address from the environment.
pub(crate) async fn setup_client(
    priv_key: String,
    rpc_url: String,
) -> Result<Arc<impl Middleware>> {
    let provider = Provider::<Http>::try_from(rpc_url)?;

    let wallet = LocalWallet::from_str(&priv_key)?;
    let chain_id = provider.get_chainid().await?.as_u64();
    let client = Arc::new(SignerMiddleware::new(
        provider,
        wallet.clone().with_chain_id(chain_id),
    ));

    Ok(client)
}

pub(crate) fn parse_addr_from_deployments_file(
    file_path: String,
    contract_key: &'static str,
) -> Result<Address> {
    let mut file_contents = String::new();
    File::open(file_path)?.read_to_string(&mut file_contents)?;

    let parsed_json = json::parse(&file_contents)?;
    Ok(Address::from_str(
        parsed_json[DEPLOYMENTS_KEY][contract_key]
            .as_str()
            .ok_or_else(|| eyre!("Could not parse contract address from deployments file"))?,
    )?)
}

pub(crate) fn get_test_contract_address(test: Tests, deployments_file: String) -> Result<Address> {
    Ok(match test {
        Tests::EcAdd => {
            parse_addr_from_deployments_file(deployments_file, PRECOMPILE_TEST_CONTRACT_KEY)?
        }
        Tests::EcMul => {
            parse_addr_from_deployments_file(deployments_file, PRECOMPILE_TEST_CONTRACT_KEY)?
        }
        Tests::EcPairing => {
            parse_addr_from_deployments_file(deployments_file, PRECOMPILE_TEST_CONTRACT_KEY)?
        }
        Tests::EcRecover => {
            parse_addr_from_deployments_file(deployments_file, PRECOMPILE_TEST_CONTRACT_KEY)?
        }
        Tests::NullifierSet => {
            parse_addr_from_deployments_file(deployments_file, DARKPOOL_TEST_CONTRACT_KEY)?
        }
        Tests::Verifier => {
            parse_addr_from_deployments_file(deployments_file, VERIFIER_TEST_CONTRACT_KEY)?
        }
        Tests::Ownership => {
            parse_addr_from_deployments_file(deployments_file, DARKPOOL_TEST_CONTRACT_KEY)?
        }
        Tests::ExternalTransfer => {
            parse_addr_from_deployments_file(deployments_file, DARKPOOL_TEST_CONTRACT_KEY)?
        }
        Tests::UpdateWallet => {
            parse_addr_from_deployments_file(deployments_file, DARKPOOL_TEST_CONTRACT_KEY)?
        }
        Tests::ProcessMatchSettle => {
            parse_addr_from_deployments_file(deployments_file, DARKPOOL_TEST_CONTRACT_KEY)?
        }
    })
}

pub fn serialize_to_calldata<T: Serialize>(t: &T) -> Result<Bytes> {
    Ok(postcard::to_allocvec(t)?.into())
}

pub(crate) async fn setup_darkpool_test_contract(
    contract: &DarkpoolTestContract<impl Middleware + 'static>,
    verifier_address: Address,
    vkeys: Vec<(Circuit, Bytes)>,
) -> Result<()> {
    // Set verifier address
    contract
        .set_verifier_address(verifier_address)
        .send()
        .await?
        .await?;

    // Set verification keys
    for (circuit, vkey_bytes) in vkeys {
        match circuit {
            Circuit::ValidWalletCreate => contract.set_valid_wallet_create_vkey(vkey_bytes),
            Circuit::ValidWalletUpdate => contract.set_valid_wallet_update_vkey(vkey_bytes),
            Circuit::ValidCommitments => contract.set_valid_commitments_vkey(vkey_bytes),
            Circuit::ValidReblind => contract.set_valid_reblind_vkey(vkey_bytes),
            Circuit::ValidMatchSettle => contract.set_valid_match_settle_vkey(vkey_bytes),
        }
        .send()
        .await?
        .await?;
    }

    Ok(())
}

pub struct ProcessMatchSettleData {
    pub party_0_match_payload: MatchPayload,
    pub party_0_valid_commitments_proof: Proof,
    pub party_0_valid_reblind_proof: Proof,
    pub party_1_match_payload: MatchPayload,
    pub party_1_valid_commitments_proof: Proof,
    pub party_1_valid_reblind_proof: Proof,
    pub valid_match_settle_proof: Proof,
    pub valid_match_settle_statement: ValidMatchSettleStatement,
    pub valid_commitments_vkey: VerificationKey,
    pub valid_reblind_vkey: VerificationKey,
    pub valid_match_settle_vkey: VerificationKey,
}

pub(crate) fn get_process_match_settle_data(rng: &mut impl Rng) -> Result<ProcessMatchSettleData> {
    let (
        party_0_valid_commitments_statement,
        valid_commitments_vkey,
        party_0_valid_commitments_proof,
    ) = dummy_circuit_bundle::<ValidCommitmentsStatement>(N, rng)?;
    let (party_0_valid_reblind_statement, valid_reblind_vkey, party_0_valid_reblind_proof) =
        dummy_circuit_bundle::<ValidReblindStatement>(N, rng)?;
    let (party_1_valid_commitments_statement, _, party_1_valid_commitments_proof) =
        dummy_circuit_bundle::<ValidCommitmentsStatement>(N, rng)?;
    let (party_1_valid_reblind_statement, _, party_1_valid_reblind_proof) =
        dummy_circuit_bundle::<ValidReblindStatement>(N, rng)?;
    let (valid_match_settle_statement, valid_match_settle_vkey, valid_match_settle_proof) =
        dummy_circuit_bundle::<ValidMatchSettleStatement>(N, rng)?;

    let party_0_wallet_blinder_share = ScalarField::rand(rng);
    let party_1_wallet_blinder_share = ScalarField::rand(rng);

    let party_0_match_payload = MatchPayload {
        wallet_blinder_share: party_0_wallet_blinder_share,
        valid_commitments_statement: party_0_valid_commitments_statement,
        valid_reblind_statement: party_0_valid_reblind_statement,
    };

    let party_1_match_payload = MatchPayload {
        wallet_blinder_share: party_1_wallet_blinder_share,
        valid_commitments_statement: party_1_valid_commitments_statement,
        valid_reblind_statement: party_1_valid_reblind_statement,
    };

    Ok(ProcessMatchSettleData {
        party_0_match_payload,
        party_0_valid_commitments_proof,
        party_0_valid_reblind_proof,
        party_1_match_payload,
        party_1_valid_commitments_proof,
        party_1_valid_reblind_proof,
        valid_match_settle_proof,
        valid_match_settle_statement,
        valid_commitments_vkey,
        valid_reblind_vkey,
        valid_match_settle_vkey,
    })
}

pub(crate) async fn mint_dummy_erc20(
    contract: &DummyErc20Contract<impl Middleware + 'static>,
    addresses: &[Address],
) -> Result<()> {
    for address in addresses {
        contract
            .mint(*address, U256::from(TRANSFER_AMOUNT))
            .send()
            .await?
            .await?;
    }

    Ok(())
}

fn dummy_erc20_external_transfer(
    account_addr: Address,
    mint: Address,
    is_withdrawal: bool,
) -> ExternalTransfer {
    ExternalTransfer {
        account_addr: AlloyAddress::from_slice(account_addr.as_bytes()),
        mint: AlloyAddress::from_slice(mint.as_bytes()),
        amount: AlloyU256::from(TRANSFER_AMOUNT),
        is_withdrawal,
    }
}

pub(crate) fn dummy_erc20_deposit(account_addr: Address, mint: Address) -> ExternalTransfer {
    dummy_erc20_external_transfer(account_addr, mint, false)
}

pub(crate) fn dummy_erc20_withdrawal(account_addr: Address, mint: Address) -> ExternalTransfer {
    dummy_erc20_external_transfer(account_addr, mint, true)
}

pub(crate) async fn execute_transfer_and_get_balances(
    darkpool_test_contract: &DarkpoolTestContract<impl Middleware + 'static>,
    dummy_erc20_contract: &DummyErc20Contract<impl Middleware + 'static>,
    transfer: &ExternalTransfer,
    account_address: Address,
) -> Result<(U256, U256)> {
    darkpool_test_contract
        .execute_external_transfer(serialize_to_calldata(transfer)?)
        .send()
        .await?
        .await?;
    let darkpool_balance = dummy_erc20_contract
        .balance_of(darkpool_test_contract.address())
        .call()
        .await?;
    let user_balance = dummy_erc20_contract
        .balance_of(account_address)
        .call()
        .await?;

    Ok((darkpool_balance, user_balance))
}

pub(crate) async fn assert_only_owner<T, D>(
    darkpool_contract: &DarkpoolTestContract<impl Middleware + 'static>,
    dummy_signer_darkpool_contract: &DarkpoolTestContract<impl Middleware + 'static>,
    method_name: &str,
    args: T,
) -> Result<()>
where
    T: Tokenize + Clone,
    D: Detokenize,
{
    assert!(
        dummy_signer_darkpool_contract
            .method::<T, D>(method_name, args.clone())?
            .send()
            .await
            .is_err(),
        "{} succeeded as non-owner",
        method_name,
    );
    assert!(
        darkpool_contract
            .method::<T, D>(method_name, args)?
            .send()
            .await?
            .await
            .is_ok(),
        "{} failed as owner",
        method_name
    );

    Ok(())
}
