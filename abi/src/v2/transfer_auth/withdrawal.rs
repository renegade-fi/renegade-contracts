//! Withdrawal authorization helpers

use alloy::{
    primitives::{keccak256, B256, U256},
    signers::{local::PrivateKeySigner, Error as SignerError, SignerSync},
    sol_types::SolValue,
};

use crate::v2::IDarkpoolV2::WithdrawalAuth;

/// Create a withdrawal authorization signature
///
/// The signature is over the hash of the newBalanceCommitment and chain ID, matching what the contract expects.
pub fn create_withdrawal_auth(
    new_balance_commitment: U256,
    chain_id: u64,
    signer: &PrivateKeySigner,
) -> Result<WithdrawalAuth, SignerError> {
    // Hash commitment and chain ID together (matching EfficientHashLib.hash(uint256, uint256))
    let chain_id_u256 = U256::from(chain_id);
    let encoded = (new_balance_commitment, chain_id_u256).abi_encode();
    let commitment_hash = B256::from_slice(keccak256(&encoded).as_slice());

    let signature = signer.sign_hash_sync(&commitment_hash)?;
    let sig_bytes = signature.as_bytes().to_vec();
    Ok(WithdrawalAuth {
        signature: sig_bytes.into(),
    })
}
