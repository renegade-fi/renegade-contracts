/// SPDX-License-Identifier: Apache
pragma solidity ^0.8.24;

import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";

/// @notice A bounded match result for a trade between an internal and external party.
/// @dev A bounded match result is one in which the size is not known until transaction submission when
/// the settling (external) party chooses a size within the bounds defined by the match result.
struct BoundedMatchResult {
    /// @dev The input token of the match
    address internalPartyInputToken;
    /// @dev The output token of the match
    address internalPartyOutputToken;
    /// @dev The price of the match
    /// @dev This is in units of `outToken/inToken`
    FixedPoint price;
    /// @dev The minimum amount of the input token to trade
    uint256 minInternalPartyAmountIn;
    /// @dev The maximum amount of the input token to trade
    uint256 maxInternalPartyAmountIn;
    /// @dev The block deadline for the match
    uint256 blockDeadline;
}

/// @title Bounded Match Result Library
/// @author Renegade Eng
/// @notice Library for bounded match result operations
library BoundedMatchResultLib {
    using FixedPointLib for FixedPoint;

    /// @notice Build two `SettlementObligation`s from a `BoundedMatchResult` and an input amount.
    /// @param boundedMatchResult The `BoundedMatchResult` to build the `SettlementObligation`s from
    /// @param externalPartyAmountIn The amount of the input token to trade for the external party
    /// @return externalObligation The `SettlementObligation` for the external party
    /// @return internalObligation The `SettlementObligation` for the internal party
    function buildObligations(
        BoundedMatchResult calldata boundedMatchResult,
        uint256 externalPartyAmountIn
    )
        internal
        pure
        returns (SettlementObligation memory externalObligation, SettlementObligation memory internalObligation)
    {
        // TODO: Validate the bounded match result

        uint256 internalPartyAmountIn = computeInternalPartyAmountIn(boundedMatchResult, externalPartyAmountIn);

        internalObligation = SettlementObligation({
            inputToken: boundedMatchResult.internalPartyInputToken,
            outputToken: boundedMatchResult.internalPartyOutputToken,
            amountIn: internalPartyAmountIn,
            amountOut: externalPartyAmountIn
        });
        externalObligation = buildMatchingExternalObligation(internalObligation);

        return (externalObligation, internalObligation);
    }

    // --- Helpers --- //

    /// @notice Builds a `SettlementObligation` for the external party from a `SettlementObligation` for the internal
    /// party.
    /// @param internalObligation The `SettlementObligation` for the internal party from which we derive the external
    /// party's obligation.
    /// @return externalObligation The matching `SettlementObligation` for the external party
    function buildMatchingExternalObligation(SettlementObligation memory internalObligation)
        internal
        pure
        returns (SettlementObligation memory externalObligation)
    {
        return SettlementObligation({
            inputToken: internalObligation.outputToken,
            outputToken: internalObligation.inputToken,
            amountIn: internalObligation.amountOut,
            amountOut: internalObligation.amountIn
        });
    }

    /// @notice Converts an external party amount in to an internal party amount in
    /// @param boundedMatchResult The `BoundedMatchResult` to convert the amount for
    /// @param externalPartyAmountIn The amount to convert
    /// @return internalPartyAmountIn The internal party amount in
    function computeInternalPartyAmountIn(
        BoundedMatchResult calldata boundedMatchResult,
        uint256 externalPartyAmountIn
    )
        internal
        pure
        returns (uint256 internalPartyAmountIn)
    {
        // From the internal party's perspective, `externalPartyAmountIn` is the output amount of the match.
        uint256 internalPartyAmountOut = externalPartyAmountIn;

        // We divide by the price (outToken/inToken) to get the input amount for the internal party.
        internalPartyAmountIn = FixedPointLib.divIntegerByFixedPoint(internalPartyAmountOut, boundedMatchResult.price);
    }
}
