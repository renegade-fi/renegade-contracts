//! Conversion for bounded match result types

#[cfg(feature = "v2-auth-helpers")]
use crate::v2::IDarkpoolV2::BoundedMatchResultBundle;
use crate::v2::{
    relayer_types::u128_to_u256,
    IDarkpoolV2::{self, BoundedMatchResultPermit},
};
use alloy::signers::Error as SignerError;
use alloy::{signers::local::PrivateKeySigner, sol_types::SolValue};
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

#[cfg(feature = "v2-auth-helpers")]
impl BoundedMatchResultBundle {
    pub fn new(
        bounded_match_result: &CircuitBoundedMatchResult,
        executor_signer: &PrivateKeySigner,
    ) -> Result<Self, SignerError> {
        use crate::v2::auth_helpers::sign_with_nonce;

        let permit = BoundedMatchResultPermit {
            matchResult: bounded_match_result.clone().into(),
        };
        let payload = permit.abi_encode();
        let executor_signature = sign_with_nonce(payload.as_slice(), executor_signer)?;

        Ok(Self {
            permit,
            executorSignature: executor_signature,
        })
    }
}
