//! Types related to darkpool fees
use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::serde_def_types::*;

use super::FixedPoint;

/// A fee take from a match
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct FeeTake {
    /// The fee the relayer takes
    #[serde_as(as = "U256Def")]
    pub relayer_fee: U256,
    /// The fee the protocol takes
    #[serde_as(as = "U256Def")]
    pub protocol_fee: U256,
}

#[cfg(any(feature = "core-settlement", feature = "test-helpers"))]
impl FeeTake {
    /// Get the total fee taken
    pub fn total(&self) -> U256 {
        self.relayer_fee.checked_add(self.protocol_fee).expect("fees overflow") // unwrap here for interface simplicity
    }
}

/// A pair of fee rates that generate a fee when multiplied by a match amount
#[serde_as]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct FeeRates {
    /// The fee rate for the relayer
    pub relayer_fee_rate: FixedPoint,
    /// The fee rate for the protocol
    pub protocol_fee_rate: FixedPoint,
}

impl FeeRates {
    /// Get a fee take from the fee rates given a receive amount
    pub fn get_fee_take(&self, receive_amount: U256) -> FeeTake {
        // SAFETY: The fee rates are constrained in-circuit to be less than 2^63, and
        // the receive amount is constrained to be less than 2^100, so the
        // product is less than 2^163, which fits in a uint256
        let relayer_fee = self.relayer_fee_rate.unsafe_fixed_point_mul(receive_amount);
        let protocol_fee = self.protocol_fee_rate.unsafe_fixed_point_mul(receive_amount);
        FeeTake { relayer_fee, protocol_fee }
    }
}
