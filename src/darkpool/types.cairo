use traits::{TryInto, Into};
use option::OptionTrait;
use clone::Clone;
use array::ArrayTrait;
use starknet::ContractAddress;

use renegade_contracts::{
    verifier::{scalar::{Scalar, ScalarSerializable}, types::Proof},
    utils::{serde::EcPointSerde, eq::ArrayTPartialEq}
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

/// Represents the affine coordinates of an ECDSA public key over the STARK curve.
/// Since each coordinate is an element of the base field, it takes 2 scalars to represent it.
#[derive(Drop, Serde, Clone, PartialEq)]
struct PublicSigningKey {
    x: Array<Scalar>,
    y: Array<Scalar>,
}

#[generate_trait]
impl PublicSigningKeyImpl of PublicSigningKeyTrait {
    fn get_x(self: @PublicSigningKey) -> felt252 {
        let x_u256 = u256 {
            low: (*self.x[0]).try_into().unwrap(), high: (*self.x[1]).try_into().unwrap()
        };
        x_u256.try_into().unwrap()
    }
}

/// Represents an ECDSA signature over the STARK curve
#[derive(Drop, Serde, Copy, PartialEq)]
struct Signature {
    r: Scalar,
    s: Scalar,
}

/// Represents which optional features to enable in the darkpool
#[derive(Drop, Serde, Copy, starknet::Store)]
struct FeatureFlags {
    /// Whether or not to use Poseidon over the base field
    use_base_field_poseidon: bool,
    /// Whether or not to verify proofs
    disable_verification: bool,
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

#[derive(Drop, Serde, Clone)]
struct ProcessMatchCallbackElems {
    party_0_wallet_blinder_share: Scalar,
    party_0_reblinded_private_shares_commitment: Scalar,
    party_0_modified_shares: Array<Scalar>,
    party_0_original_shares_nullifier: Scalar,
    party_1_wallet_blinder_share: Scalar,
    party_1_reblinded_private_shares_commitment: Scalar,
    party_1_modified_shares: Array<Scalar>,
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

impl CircuitIntoFelt of Into<Circuit, felt252> {
    fn into(self: Circuit) -> felt252 {
        match self {
            Circuit::ValidWalletCreate(()) => 0,
            Circuit::ValidWalletUpdate(()) => 1,
            Circuit::ValidCommitments(()) => 2,
            Circuit::ValidReblind(()) => 3,
            Circuit::ValidMatchMpc(()) => 4,
            Circuit::ValidSettle(()) => 5,
        }
    }
}
