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
