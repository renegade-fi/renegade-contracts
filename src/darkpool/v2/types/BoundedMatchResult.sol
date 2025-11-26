/// SPDX-License-Identifier: Apache
pragma solidity ^0.8.24;

import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";

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

    /// @notice Error thrown when an amount is out of bounds
    error AmountOutOfBounds(uint256 amount, uint256 minAmount, uint256 maxAmount);
    /// @notice Error thrown when the bounds are invalid
    error InvalidBounds();
    /// @notice Error thrown when the block deadline has passed
    error MatchExpired();
    /// @notice Error thrown when an amount is zero
    error ZeroAmount();

    /// @notice Build two `SettlementObligation`s from a `BoundedMatchResult` and an input amount.
    /// @param matchResult The `BoundedMatchResult` to build the `SettlementObligation`s from
    /// @param externalPartyAmountIn The amount of the input token to trade for the external party
    /// @return externalObligation The `SettlementObligation` for the external party
    /// @return internalObligation The `SettlementObligation` for the internal party
    function buildObligations(
        BoundedMatchResult calldata matchResult,
        uint256 externalPartyAmountIn
    )
        internal
        view
        returns (SettlementObligation memory externalObligation, SettlementObligation memory internalObligation)
    {
        // Validate the bounded match result
        validateBoundedMatchResult(matchResult, externalPartyAmountIn);
        uint256 internalPartyAmountIn = computeInternalPartyAmountIn(matchResult, externalPartyAmountIn);

        internalObligation = SettlementObligation({
            inputToken: matchResult.internalPartyInputToken,
            outputToken: matchResult.internalPartyOutputToken,
            amountIn: internalPartyAmountIn,
            amountOut: externalPartyAmountIn
        });
        externalObligation = buildMatchingExternalObligation(internalObligation);

        return (externalObligation, internalObligation);
    }

    // --- Helpers --- //

    /// @notice Validates a `BoundedMatchResult` along with the input amount supplied by the external party
    /// @param boundedMatchResult The `BoundedMatchResult` to validate
    /// @param externalPartyAmountIn The amount of the input token to trade for the external party
    function validateBoundedMatchResult(
        BoundedMatchResult calldata boundedMatchResult,
        uint256 externalPartyAmountIn
    )
        internal
        view
    {
        // 1. Validate input amount
        validateAmountIn(boundedMatchResult, externalPartyAmountIn);

        // 2. Validate bounds of bounded match result
        validateBounds(boundedMatchResult);

        // 3. Validate block deadline
        validateDeadline(boundedMatchResult);

        // 4. Validate price
        // We validate the price in Intent Libraries to avoid unnecessary denormalization of the intent.
        // TODO: validate price in Intent Libraries
    }

    /// @notice Validates an amount within the bounds of a `BoundedMatchResult`
    /// @param boundedMatchResult The `BoundedMatchResult` to validate the amount within
    /// @param externalPartyAmountIn The amount in of the external party
    function validateAmountIn(
        BoundedMatchResult calldata boundedMatchResult,
        uint256 externalPartyAmountIn
    )
        internal
        pure
    {
        // The external party input amount must be a valid amount
        DarkpoolConstants.validateAmount(externalPartyAmountIn);

        if (externalPartyAmountIn == 0) {
            revert ZeroAmount();
        }

        // Bounded match result is from the internal party's perspective, so we need to convert the external party input
        // amount to an internal party input amount.
        uint256 internalPartyAmountIn = computeInternalPartyAmountIn(boundedMatchResult, externalPartyAmountIn);

        bool amountTooLow = internalPartyAmountIn < boundedMatchResult.minInternalPartyAmountIn;
        bool amountTooHigh = internalPartyAmountIn > boundedMatchResult.maxInternalPartyAmountIn;
        if (amountTooLow || amountTooHigh) {
            revert AmountOutOfBounds(
                internalPartyAmountIn,
                boundedMatchResult.minInternalPartyAmountIn,
                boundedMatchResult.maxInternalPartyAmountIn
            );
        }
    }

    /// @notice Validates the bounds of a `BoundedMatchResult`
    /// @param boundedMatchResult The `BoundedMatchResult` to validate the bounds of
    function validateBounds(BoundedMatchResult calldata boundedMatchResult) internal pure {
        // The min/max amounts must be valid amounts
        DarkpoolConstants.validateAmount(boundedMatchResult.minInternalPartyAmountIn);
        DarkpoolConstants.validateAmount(boundedMatchResult.maxInternalPartyAmountIn);

        // The min amount must be less than or equal to the max amount
        bool boundsInvalid = boundedMatchResult.minInternalPartyAmountIn > boundedMatchResult.maxInternalPartyAmountIn;
        if (boundsInvalid) {
            revert InvalidBounds();
        }
    }

    /// @notice Validates that match result has not expired
    /// @param boundedMatchResult The `BoundedMatchResult` to validate the deadline of
    function validateDeadline(BoundedMatchResult calldata boundedMatchResult) internal view {
        bool deadlinePassed = block.number > boundedMatchResult.blockDeadline;
        if (deadlinePassed) revert MatchExpired();
    }

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
