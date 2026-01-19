//! Conversion for bounded match result types

use crate::v2::{relayer_types::u128_to_u256, IDarkpoolV2};
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
