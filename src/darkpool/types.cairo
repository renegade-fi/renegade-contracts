use traits::TryInto;
use option::OptionTrait;
use clone::Clone;
use starknet::ContractAddress;

use renegade_contracts::{verifier::{scalar::Scalar, types::Proof}, utils::serde::EcPointSerde};

// --------------
// | MISC TYPES |
// --------------

/// Represents an external transfer of an ERC20 token
#[derive(Copy, Drop, Serde, PartialEq)]
struct ExternalTransfer {
    /// The address of the account contract to deposit from or withdraw to
    account_addr: ContractAddress,
    /// The mint (contract address) of the token being transferred
    mint: ContractAddress,
    /// The amount of the token transferred
    amount: u256,
    /// Whether or not the transfer is a withdrawal (otherwise a deposit)
    is_withdrawal: bool,
}

impl ExternalTransferDefault of Default<ExternalTransfer> {
    fn default() -> ExternalTransfer {
        ExternalTransfer {
            account_addr: 0.try_into().unwrap(),
            mint: 0.try_into().unwrap(),
            amount: Default::default(),
            is_withdrawal: false,
        }
    }
}

/// Represents the artifacts produced by one of the parties in a match
#[derive(Drop, Serde, Clone)]
struct MatchPayload {
    wallet_blinder_share: Scalar,
    old_shares_nullifier: Scalar,
    wallet_share_commitment: Scalar,
    public_wallet_shares: Array<Scalar>,
    valid_commitments_proof: Proof,
    valid_commitments_witness_commitments: Array<EcPoint>,
    valid_reblind_proof: Proof,
    valid_reblind_witness_commitments: Array<EcPoint>,
}

// --------------------------
// | CALLBACK ELEMENT TYPES |
// --------------------------

#[derive(Drop, Serde, Copy)]
struct NewWalletCallbackElems {
    wallet_blinder_share: Scalar,
    private_shares_commitment: Scalar,
    tx_hash: felt252,
}

#[derive(Drop, Serde, Clone)]
struct UpdateWalletCallbackElems {
    wallet_blinder_share: Scalar,
    old_shares_nullifier: Scalar,
    new_private_shares_commitment: Scalar,
    external_transfer: Option<ExternalTransfer>,
    tx_hash: felt252,
}

#[derive(Drop, Serde, Copy)]
struct ProcessMatchCallbackElems {
    party_0_wallet_blinder_share: Scalar,
    party_0_wallet_share_commitment: Scalar,
    party_0_old_shares_nullifier: Scalar,
    party_1_wallet_blinder_share: Scalar,
    party_1_wallet_share_commitment: Scalar,
    party_1_old_shares_nullifier: Scalar,
    tx_hash: felt252,
}
