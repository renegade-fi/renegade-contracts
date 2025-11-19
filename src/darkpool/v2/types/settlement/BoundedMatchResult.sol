/// SPDX-License-Identifier: Apache
pragma solidity ^0.8.24;

import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";

/// @notice A bounded match result for a trade between an internal and external party.
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

    /// @notice Constructs two `SettlementObligation`s from a `BoundedMatchResult` and an input amount.
    /// @dev A bounded match result is one in which the size is not known until transaction submission when
    /// the settling (external) party chooses a size within the bounds defined by the match result.
    /// @param matchResult The `BoundedMatchResult` to construct the `SettlementObligation`s from
    /// @param externalPartyAmountIn The amount of the input token to trade for the external party
    /// @return externalObligation The `SettlementObligation` for the external party
    /// @return internalObligation The `SettlementObligation` for the internal party
    function buildObligations(
        BoundedMatchResult memory matchResult,
        uint256 externalPartyAmountIn
    )
        internal
        pure
        returns (SettlementObligation memory externalObligation, SettlementObligation memory internalObligation)
    {
        // `externalPartyAmountIn`, from the perspective of the internal party, is the output amount of the match.
        uint256 internalPartyAmountOut = externalPartyAmountIn;

        // We divide by the price (outToken/inToken) to get the input amount for the internal party.
        uint256 internalPartyAmountIn = FixedPointLib.divIntegerByFixedPoint(internalPartyAmountOut, matchResult.price);

        internalObligation = SettlementObligation({
            inputToken: matchResult.internalPartyInputToken,
            outputToken: matchResult.internalPartyOutputToken,
            amountIn: internalPartyAmountIn,
            amountOut: internalPartyAmountOut
        });
        externalObligation = buildMatchingExternalObligation(internalObligation);

        return (externalObligation, internalObligation);
    }

    /// @notice Builds a `SettlementObligation` for the external party from a `SettlementObligation` for the internal
    /// party. @param internalObligation The `SettlementObligation` for the internal party
    /// @return externalObligation The `SettlementObligation` for the external party
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

    /// @notice Validates a `BoundedMatchResult`
    /// @param matchResult The `BoundedMatchResult` to validate
    function validate(BoundedMatchResult calldata matchResult, uint256 inputAmount) public pure {
        // Validate bounds (order, inputAmount within bounds)

        // Validate block deadline

        // Validate price

        // Validate input and output amounts
        // DarkpoolConstants.validateAmount(obligation0.amountIn);
        // DarkpoolConstants.validateAmount(obligation0.amountOut);
    }
}
