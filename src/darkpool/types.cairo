use starknet::ContractAddress;

use renegade_contracts::verifier::{scalar::Scalar, types::Proof};

/// Represents an external transfer of an ERC20 token
#[derive(Copy, Drop, Serde)]
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

/// Represents the artifacts produced by one of the parties in a match
#[derive(Drop, Serde)]
struct MatchPayload {
    wallet_blinder_share: Scalar,
    old_shares_nullifier: Scalar,
    wallet_share_commitment: Scalar,
    public_wallet_shares: Array<Scalar>,
    valid_commitments_proof: Proof,
    valid_commitments_witness_commitments: Array<Scalar>,
    valid_reblind_proof: Proof,
    valid_reblind_witness_commitments: Array<Scalar>,
}
