//! Utilities for running integration tests

use alloy_primitives::{Address as AlloyAddress, U256 as AlloyU256};
use ark_crypto_primitives::merkle_tree::MerkleTree as ArkMerkleTree;
use circuit_types::keychain::{NonNativeScalar, PublicSigningKey as CircuitPublicSigningKey};

use constants::Scalar;
use contracts_common::{
    constants::NUM_BYTES_FELT,
    custom_serde::{BytesDeserializable, BytesSerializable},
    types::{
        ExternalTransfer, Proof, PublicInputs, PublicSigningKey as ContractPublicSigningKey,
        ScalarField, VerificationKey,
    },
};
use contracts_core::crypto::poseidon::compute_poseidon_hash;
use ethers::{
    abi::Address,
    providers::Middleware,
    types::{Bytes, U256},
};
use eyre::{eyre, Result};
use itertools::Itertools;
use scripts::{
    constants::{
        DARKPOOL_PROXY_ADMIN_CONTRACT_KEY, DARKPOOL_PROXY_CONTRACT_KEY, MERKLE_CONTRACT_KEY,
    },
    utils::parse_addr_from_deployments_file,
};
use serde::Serialize;
use test_helpers::merkle::MerkleConfig;

use crate::{
    abis::{DarkpoolTestContract, DummyErc20Contract},
    cli::Tests,
    constants::{PRECOMPILE_TEST_CONTRACT_KEY, TRANSFER_AMOUNT, VERIFIER_TEST_CONTRACT_KEY},
};

pub(crate) fn get_test_contract_address(test: Tests, deployments_file: &str) -> Result<Address> {
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
            parse_addr_from_deployments_file(deployments_file, DARKPOOL_PROXY_CONTRACT_KEY)?
        }
        Tests::Merkle => parse_addr_from_deployments_file(deployments_file, MERKLE_CONTRACT_KEY)?,
        Tests::Verifier => {
            parse_addr_from_deployments_file(deployments_file, VERIFIER_TEST_CONTRACT_KEY)?
        }
        Tests::Upgradeable => {
            parse_addr_from_deployments_file(deployments_file, DARKPOOL_PROXY_ADMIN_CONTRACT_KEY)?
        }
        Tests::Initializable => {
            parse_addr_from_deployments_file(deployments_file, DARKPOOL_PROXY_CONTRACT_KEY)?
        }
        Tests::ExternalTransfer => {
            parse_addr_from_deployments_file(deployments_file, DARKPOOL_PROXY_CONTRACT_KEY)?
        }
        Tests::NewWallet => {
            parse_addr_from_deployments_file(deployments_file, DARKPOOL_PROXY_CONTRACT_KEY)?
        }
        Tests::UpdateWallet => {
            parse_addr_from_deployments_file(deployments_file, DARKPOOL_PROXY_CONTRACT_KEY)?
        }
        Tests::ProcessMatchSettle => {
            parse_addr_from_deployments_file(deployments_file, DARKPOOL_PROXY_CONTRACT_KEY)?
        }
    })
}

/// Converts a [`ScalarField`] to a [`ethers::types::U256`]
pub fn scalar_to_u256(scalar: ScalarField) -> U256 {
    U256::from_big_endian(&scalar.serialize_to_bytes())
}

/// Converts a [`ethers::types::U256`] to a [`ScalarField`]
pub fn u256_to_scalar(u256: U256) -> Result<ScalarField> {
    let mut scalar_bytes = [0_u8; NUM_BYTES_FELT];
    u256.to_big_endian(&mut scalar_bytes);
    ScalarField::deserialize_from_bytes(&scalar_bytes)
        .map_err(|_| eyre!("failed converting U256 to scalar"))
}

pub fn serialize_to_calldata<T: Serialize>(t: &T) -> Result<Bytes> {
    Ok(postcard::to_allocvec(t)?.into())
}

pub fn serialize_verification_bundle(
    vkey_batch: &[VerificationKey],
    proof_batch: &[Proof],
    public_inputs_batch: &[PublicInputs],
) -> Result<Bytes> {
    let vkey_batch_ser: Vec<u8> = vkey_batch
        .iter()
        .flat_map(|v| postcard::to_allocvec(v).unwrap())
        .collect();
    let proof_batch_ser: Vec<u8> = proof_batch
        .iter()
        .flat_map(|p| postcard::to_allocvec(p).unwrap())
        .collect();
    let public_inputs_batch_ser: Vec<u8> = public_inputs_batch
        .iter()
        .flat_map(|i| postcard::to_allocvec(i).unwrap())
        .collect();

    let bundle_bytes = [vkey_batch_ser, proof_batch_ser, public_inputs_batch_ser].concat();

    Ok(bundle_bytes.into())
}

pub fn to_circuit_pubkey(contract_pubkey: ContractPublicSigningKey) -> CircuitPublicSigningKey {
    let x = NonNativeScalar {
        scalar_words: contract_pubkey
            .x
            .into_iter()
            .map(Scalar::new)
            .collect_vec()
            .try_into()
            .unwrap(),
    };

    let y = NonNativeScalar {
        scalar_words: contract_pubkey
            .y
            .into_iter()
            .map(Scalar::new)
            .collect_vec()
            .try_into()
            .unwrap(),
    };

    CircuitPublicSigningKey { x, y }
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

pub(crate) fn insert_shares_and_get_root(
    ark_merkle: &mut ArkMerkleTree<MerkleConfig>,
    private_shares_commitment: ScalarField,
    public_shares: &[ScalarField],
    index: usize,
) -> Result<ScalarField> {
    let mut shares = vec![private_shares_commitment];
    shares.extend(public_shares);
    let commitment = compute_poseidon_hash(&shares);
    ark_merkle
        .update(index, &commitment)
        .map_err(|_| eyre!("Failed to update Arkworks Merkle tree"))?;

    Ok(ark_merkle.root())
}
