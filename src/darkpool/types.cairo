use traits::{TryInto, Into};
use option::OptionTrait;
use clone::Clone;
use array::ArrayTrait;
use starknet::ContractAddress;

use renegade_contracts::{
    verifier::{scalar::{Scalar, ScalarSerializable}, types::Proof}, utils::serde::EcPointSerde
};

use super::statements::{ValidReblindStatement, ValidCommitmentsStatement};

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

impl ExternalTransferToScalarsImpl of ScalarSerializable<ExternalTransfer> {
    fn to_scalars(self: @ExternalTransfer) -> Array<Scalar> {
        let mut scalars: Array<Scalar> = ArrayTrait::new();

        scalars.append((*self.account_addr).into());
        scalars.append((*self.mint).into());
        scalars.append((*self.amount).into());
        scalars.append((if *self.is_withdrawal {
            1
        } else {
            0
        }).into());

        scalars
    }
}

/// Represents the artifacts produced by one of the parties in a match
#[derive(Drop, Serde, Clone)]
struct MatchPayload {
    wallet_blinder_share: Scalar,
    valid_commitments_statement: ValidCommitmentsStatement,
    valid_commitments_witness_commitments: Array<EcPoint>,
    valid_commitments_proof: Proof,
    valid_reblind_statement: ValidReblindStatement,
    valid_reblind_witness_commitments: Array<EcPoint>,
    valid_reblind_proof: Proof,
}

// --------------------------
// | CALLBACK ELEMENT TYPES |
// --------------------------

#[derive(Drop, Serde, Clone)]
struct NewWalletCallbackElems {
    wallet_blinder_share: Scalar,
    public_wallet_shares: Array<Scalar>,
    private_shares_commitment: Scalar,
    tx_hash: felt252,
}

#[derive(Drop, Serde, Clone)]
struct UpdateWalletCallbackElems {
    wallet_blinder_share: Scalar,
    old_shares_nullifier: Scalar,
    new_public_shares: Array<Scalar>,
    new_private_shares_commitment: Scalar,
    external_transfer: Option<ExternalTransfer>,
    tx_hash: felt252,
}

#[derive(Drop, Serde, Copy)]
struct ProcessMatchCallbackElems {
    party_0_wallet_blinder_share: Scalar,
    party_0_reblinded_private_shares_commitment: Scalar,
    party_0_original_shares_nullifier: Scalar,
    party_1_wallet_blinder_share: Scalar,
    party_1_reblinded_private_shares_commitment: Scalar,
    party_1_original_shares_nullifier: Scalar,
    tx_hash: felt252,
}

// ------------
// | CIRCUITS |
// ------------

#[derive(Drop, Serde, Copy, PartialEq)]
enum Circuit {
    ValidWalletCreate: (),
    ValidWalletUpdate: (),
    ValidCommitments: (),
    ValidReblind: (),
    ValidMatchMpc: (),
    ValidSettle: (),
}
