//! Types related to matching

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::serde_def_types::*;

use super::FixedPoint;

/// The revert message when an invalid base amount is provided
pub const ERROR_INVALID_BASE_AMT: &[u8] = b"invalid base amount";
/// The revert message when an invalid quote amount is provided
pub const ERROR_INVALID_QUOTE_AMT: &[u8] = b"invalid quote amount";

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
        quote_amount: U256,
        base_amount: U256,
    ) -> Result<ExternalMatchResult, Vec<u8>> {
        self.validate_amounts(quote_amount, base_amount)?;
        Ok(ExternalMatchResult {
            quote_mint: self.quote_mint,
            base_mint: self.base_mint,
            quote_amount,
            base_amount,
            direction: self.direction,
        })
    }

    // --- Validation --- //

    /// Validate the base and quote amount for a match
    fn validate_amounts(&self, quote_amount: U256, base_amount: U256) -> Result<(), Vec<u8>> {
        self.validate_base_amount(base_amount)?;
        self.validate_quote_amount(quote_amount, base_amount)
    }

    /// Validate the base amount for a match
    ///
    /// This simply validates that the base amount lies in the range constructed
    /// by the relayer. This range is validated in-circuit to be well
    /// capitalized.
    fn validate_base_amount(&self, base_amount: U256) -> Result<(), Vec<u8>> {
        let amount_too_low = base_amount < self.min_base_amount;
        let amount_too_high = base_amount > self.max_base_amount;
        if amount_too_low || amount_too_high {
            return Err(ERROR_INVALID_BASE_AMT.into());
        }

        Ok(())
    }

    /// Validate the quote amount for a match
    ///
    /// We allow an external user to specify a quote amount, but we need to
    /// ensure that they have not given themselves an invalid amount or price
    /// improvement at the expense of the internal party.
    ///
    /// This involves two checks:
    /// 1. The quote amount must be within the range implied by the base amount
    ///    range. Let `min_quote = floor(min_base * price)` and `max_quote =
    ///    floor(max_base * price)`. The quote amount must lie in the range
    ///    `[min_quote, max_quote]`.
    /// 2. The quote amount must imply a price that improves upon the reference
    ///    price in the match result *for the internal party*. Let
    ///    `reference_quote = floor(base_amount * price)`. Then for an external
    ///    sell order, we assert `quote_amount <= reference_quote`; i.e. the
    ///    external party sells at a lower price. For an external buy order, we
    ///    assert `quote_amount >= reference_quote`; i.e. the external party
    ///    buys at a higher price.
    ///
    /// Note that we can combine these two checks by taking the intersection of
    /// their respective intervals. For an external party buy order, this is the
    /// interval:  `[ref_quote, inf) \cap [min_quote, max_quote] =
    /// [ref_quote, max_quote]`
    ///
    /// For an external party sell order, this is the interval:
    ///  `[0, ref_quote] \cap [min_quote, max_quote] = [min_quote, ref_quote]`
    ///
    /// So we check that the quote lies in the intersection interval
    ///
    /// SAFETY: All values below are constrained to be within 100 bits, and the
    /// price is constrained to be within 127 bits, so wraparound is impossible
    fn validate_quote_amount(&self, quote_amount: U256, base_amount: U256) -> Result<(), Vec<u8>> {
        // Compute the quote amount bounds
        let min_quote = self.price.unsafe_fixed_point_mul(self.min_base_amount);
        let max_quote = self.price.unsafe_fixed_point_mul(self.max_base_amount);
        let ref_quote = self.price.unsafe_fixed_point_mul(base_amount);

        // Check that the quote amount lies in the intersection interval
        let (range_min, range_max) = if self.is_external_party_sell() {
            (min_quote, ref_quote)
        } else {
            (ref_quote, max_quote)
        };

        let quote_too_low = quote_amount < range_min;
        let quote_too_high = quote_amount > range_max;
        if quote_too_low || quote_too_high {
            return Err(ERROR_INVALID_QUOTE_AMT.into());
        }

        Ok(())
    }
}
