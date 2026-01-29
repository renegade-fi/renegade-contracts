//! Conversion for bounded match result types

#[cfg(feature = "v2-auth-helpers")]
use crate::v2::IDarkpoolV2::{FeeRate, SignatureWithNonce};
use crate::v2::{relayer_types::{u128_to_u256, u256_to_u128}, IDarkpoolV2};
#[cfg(feature = "v2-auth-helpers")]
use alloy::signers::{local::PrivateKeySigner, Error as SignerError};
use darkpool_types::bounded_match_result::BoundedMatchResult as CircuitBoundedMatchResult;

impl From<CircuitBoundedMatchResult> for IDarkpoolV2::BoundedMatchResult {
    fn from(bounded_match_result: CircuitBoundedMatchResult) -> Self {
        Self {
            internalPartyInputToken: bounded_match_result.internal_party_input_token,
            internalPartyOutputToken: bounded_match_result.internal_party_output_token,
            price: bounded_match_result.price.into(),
            minInternalPartyAmountIn: u128_to_u256(
                bounded_match_result.min_internal_party_amount_in,
            ),
            maxInternalPartyAmountIn: u128_to_u256(
                bounded_match_result.max_internal_party_amount_in,
            ),
            blockDeadline: u128_to_u256(bounded_match_result.block_deadline as u128),
        }
    }
}

impl From<IDarkpoolV2::BoundedMatchResult> for CircuitBoundedMatchResult {
    fn from(bounded_match_result: IDarkpoolV2::BoundedMatchResult) -> Self {
        Self {
            internal_party_input_token: bounded_match_result.internalPartyInputToken,
            internal_party_output_token: bounded_match_result.internalPartyOutputToken,
            price: bounded_match_result.price.into(),
            min_internal_party_amount_in: u256_to_u128(bounded_match_result.minInternalPartyAmountIn),
            max_internal_party_amount_in: u256_to_u128(bounded_match_result.maxInternalPartyAmountIn),
            block_deadline: u256_to_u128(bounded_match_result.blockDeadline) as u64,
        }
    }
}

#[cfg(feature = "v2-auth-helpers")]
impl IDarkpoolV2::BoundedMatchResult {
    /// Build an executor signature for the bounded match result
    pub fn create_executor_signature(
        &self,
        relayer_fee_rate: FeeRate,
        chain_id: u64,
        signer: &PrivateKeySigner,
    ) -> Result<SignatureWithNonce, SignerError> {
        use alloy::sol_types::SolValue;

        let payload = (relayer_fee_rate, self.clone()).abi_encode();
        SignatureWithNonce::sign(payload.as_slice(), chain_id, signer)
    }
}
