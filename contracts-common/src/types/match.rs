//! Types related to matching

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::serde_def_types::*;

use super::FixedPoint;

/// The revert message when an invalid base amount is provided
pub const ERROR_INVALID_BASE_AMT: &[u8] = b"invalid base amount";

/// The result of an external match
/// The result of an atomic match
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct ExternalMatchResult {
    /// The mint (erc20 address) of the quote token
    #[serde_as(as = "AddressDef")]
    pub quote_mint: Address,
    /// The mint (erc20 address) of the base token
    #[serde_as(as = "AddressDef")]
    pub base_mint: Address,
    /// The amount of the quote token
    #[serde_as(as = "U256Def")]
    pub quote_amount: U256,
    /// The amount of the base token
    #[serde_as(as = "U256Def")]
    pub base_amount: U256,
    /// The direction of the trade
    ///
    /// `false` (0) corresponds to the internal party buying the base
    /// `true` (1) corresponds to the internal party selling the base
    pub direction: bool,
}

#[cfg(any(feature = "core-settlement", feature = "gas-sponsor", feature = "test-helpers"))]
impl ExternalMatchResult {
    /// Whether or not the external party is the base-mint seller
    pub fn is_external_party_sell(&self) -> bool {
        !self.direction
    }

    /// Get the mint sold by the external party in the match
    pub fn external_party_sell_mint_amount(&self) -> (Address, U256) {
        if self.direction {
            (self.quote_mint, self.quote_amount)
        } else {
            (self.base_mint, self.base_amount)
        }
    }

    /// Get the mint bought by the external party in the match
    pub fn external_party_buy_mint_amount(&self) -> (Address, U256) {
        if self.direction {
            (self.base_mint, self.base_amount)
        } else {
            (self.quote_mint, self.quote_amount)
        }
    }
}

/// A match result that specifies a range of match sizes rather than an exact
/// base amount
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct BoundedMatchResult {
    /// The mint (erc20 address) of the quote token
    #[serde_as(as = "AddressDef")]
    pub quote_mint: Address,
    /// The mint (erc20 address) of the base token
    #[serde_as(as = "AddressDef")]
    pub base_mint: Address,
    /// The price at which the match will be settled
    pub price: FixedPoint,
    /// The minimum base amount of the match
    #[serde_as(as = "U256Def")]
    pub min_base_amount: U256,
    /// The maximum base amount of the match
    #[serde_as(as = "U256Def")]
    pub max_base_amount: U256,
    /// The direction of the trade
    ///
    /// `false` (0) corresponds to the internal party buying the base
    /// `true` (1) corresponds to the internal party selling the base
    pub direction: bool,
}

impl BoundedMatchResult {
    /// Whether or not the external party is the base-mint seller
    pub fn is_external_party_sell(&self) -> bool {
        !self.direction
    }

    /// Convert the bounded match result into an external match result
    /// given a base amount
    pub fn to_external_match_result(
        &self,
        base_amount: U256,
    ) -> Result<ExternalMatchResult, Vec<u8>> {
        // Validate the match amount
        let amount_too_low = base_amount < self.min_base_amount;
        let amount_too_high = base_amount > self.max_base_amount;
        if amount_too_low || amount_too_high {
            return Err(ERROR_INVALID_BASE_AMT.into());
        }

        // Compute the quote amount
        let price = self.price;
        let quote_amount = price.unsafe_fixed_point_mul(base_amount);

        Ok(ExternalMatchResult {
            quote_mint: self.quote_mint,
            base_mint: self.base_mint,
            quote_amount,
            base_amount,
            direction: self.direction,
        })
    }
}
