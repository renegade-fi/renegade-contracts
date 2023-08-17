use clone::Clone;

use renegade_contracts::{verifier::scalar::Scalar, utils::eq::ArrayTPartialEq};

use super::types::ExternalTransfer;

// -------------------
// | STATEMENT TYPES |
// -------------------
/// All statement types are assumed to have the same serialization
/// to/from Scalars as the relayer-side implementation.

/// Statement for the VALID_WALLET_CREATE proof
#[derive(Drop, Serde, Clone, PartialEq)]
struct ValidWalletCreateStatement {
    /// The commitment to the private secret shares of the wallet
    private_shares_commitment: Scalar,
    /// The public secret shares of the wallet
    public_wallet_shares: Array<Scalar>,
}

/// Statement for the VALID_WALLET_UPDATE proof
#[derive(Drop, Serde, Clone, PartialEq)]
struct ValidWalletUpdateStatement {
    /// The nullifier of the old wallet's secret shares
    old_shares_nullifier: Scalar,
    /// A commitment to the new wallet's private secret shares
    new_private_shares_commitment: Scalar,
    /// The public secret shares of the new wallet
    new_public_shares: Array<Scalar>,
    /// A historic merkle root for which we prove inclusion of
    /// the commitment to the old wallet's private secret shares
    merkle_root: Scalar,
    /// The external transfer associated with this update
    external_transfer: ExternalTransfer,
    /// The public root key of the old wallet, rotated out after this update
    old_pk_root: Array<Scalar>,
    /// The timestamp this update was applied at
    timestamp: u64,
}

/// Statement for the VALID_REBLIND proof
#[derive(Drop, Serde, Copy, PartialEq)]
struct ValidReblindStatement {
    /// The nullifier of the original wallet's secret shares
    original_shares_nullifier: Scalar,
    /// A commitment to the private secret shares of the reblinded wallet
    reblinded_private_shares_commitment: Scalar,
    /// A historic merkle root for which we prove inclusion of
    /// the commitment to the original wallet's private secret shares
    merkle_root: Scalar,
}

/// Statememt for the VALID_COMMITMENTS proof
#[derive(Drop, Serde, Copy, PartialEq)]
struct ValidCommitmentsStatement {
    /// The index of the balance sent by the party if a successful match occurs
    balance_send_index: u64,
    /// The index of the balance received by the party if a successful match occurs
    balance_receive_index: u64,
    /// The index of the order being matched
    order_index: u64,
}

/// Statement for the VALID_SETTLE proof
#[derive(Drop, Serde, Clone, PartialEq)]
struct ValidSettleStatement {
    /// The modified public secret shares of the first party
    party0_modified_shares: Array<Scalar>,
    /// The modified public secret shares of the second party
    party1_modified_shares: Array<Scalar>,
    /// The index of the balance sent by the first party in the settlement
    party0_send_balance_index: u64,
    /// The index of the balance received by the first party in the settlement
    party0_receive_balance_index: u64,
    /// The index of the first party's matched order
    party0_order_index: u64,
    /// The index of the balance sent by the second party in the settlement
    party1_send_balance_index: u64,
    /// The index of the balance received by the second party in the settlement
    party1_receive_balance_index: u64,
    /// The index of the second party's matched order
    party1_order_index: u64,
}
