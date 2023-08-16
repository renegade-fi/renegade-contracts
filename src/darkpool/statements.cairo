use clone::Clone;

use renegade_contracts::verifier::scalar::Scalar;

use super::types::ExternalTransfer;

// -------------------
// | STATEMENT TYPES |
// -------------------
/// All statement types are assumed to have the same serialization
/// to/from Scalars as the relayer-side implementation.

/// Statement for the VALID_WALLET_CREATE proof
#[derive(Drop, Serde, Clone)]
struct ValidWalletCreateStatement {
    /// The commitment to the private secret shares of the wallet
    private_shares_commitment: Scalar,
    /// The public secret shares of the wallet
    public_wallet_shares: Array<Scalar>,
}

/// Statement for the VALID_WALLET_UPDATE proof
#[derive(Drop, Serde, Clone)]
struct ValidWalletUpdateStatement {
    /// The nullifier of the old wallet's secret shares
    old_shares_nullifier: Scalar,
    /// A commitment to the new wallet's private secret shares
    new_private_shares_commitment: Scalar,
    /// The public secret shares of the new wallet
    new_public_shares: Array<Scalar>,
    /// The global Merkle root that the wallet share proofs open to
    merkle_root: Scalar,
    /// The external transfer tuple
    external_transfer: ExternalTransfer,
    /// The public root key of the old wallet, rotated out after update
    old_pk_root: Array<Scalar>,
    /// The timestamp this update is at
    timestamp: u64,
}

/// Statement for the VALID_REBLIND proof
#[derive(Drop, Serde, Copy)]
struct ValidReblindStatement {
    /// The nullifier of the original wallet's secret shares
    original_shares_nullifier: Scalar,
    /// A commitment to the private secret shares of the reblinded wallet
    reblinded_private_shares_commitment: Scalar,
    /// The global merkle root to prove inclusion into
    merkle_root: Scalar,
}

/// Statememt for the VALID_COMMITMENTS proof
#[derive(Drop, Serde, Copy)]
struct ValidCommitmentsStatement {
    /// The index of the balance that holds the mint that the wallet will
    /// send if a successful match occurs
    balance_send_index: u64,
    /// The index of the balance that holds the mint that the wallet will
    /// receive if a successful match occurs
    balance_receive_index: u64,
    /// The index of the order that is to be matched
    order_index: u64,
}

/// Statement for the VALID_SETTLE proof
#[derive(Drop, Serde, Clone)]
struct ValidSettleStatement {
    /// The modified public secret shares of the first party
    party0_modified_shares: Array<Scalar>,
    /// The modified public secret shares of the second party
    party1_modified_shares: Array<Scalar>,
    /// The index of the balance that the first party sent in the settlement
    party0_send_balance_index: u64,
    /// The index of teh balance that the first party received in the settlement
    party0_receive_balance_index: u64,
    /// The index of the first party's order that was matched
    party0_order_index: u64,
    /// The index of the balance that the second party sent in the settlement
    party1_send_balance_index: u64,
    /// The index of teh balance that the second party received in the settlement
    party1_receive_balance_index: u64,
    /// The index of the second party's order that was matched
    party1_order_index: u64,
}
