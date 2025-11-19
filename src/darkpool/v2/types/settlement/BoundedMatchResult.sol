/// SPDX-License-Identifier: Apache
pragma solidity ^0.8.24;

import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";

/// @notice A bounded match result for a trade between an internal and external party.
/// @dev A bounded match result used to derive settlement obligations once the trade size is known.
/// @dev Fields are internal party-centric, i.e. the input token is the internal party's input token and the output
/// token is the internal party's output token.
struct BoundedMatchResult {
    /// @dev The input token of the match
    address inputToken;
    /// @dev The output token of the match
    address outputToken;
    /// @dev The price of the match
    /// @dev This is in units of `outToken/inToken`
    FixedPoint price;
    /// @dev The minimum amount of the input token to trade
    uint256 minAmountIn;
    /// @dev The maximum amount of the input token to trade
    uint256 maxAmountIn;
    /// @dev The block deadline for the match
    uint256 blockDeadline;
}

/// @title Bounded Match Result Library
/// @author Renegade Eng
/// @notice Library for bounded match result operations
library BoundedMatchResultLib {
    using FixedPointLib for FixedPoint;

    /// @notice Constructs two `SettlementObligation`s from a `BoundedMatchResult` and an input amount.
    /// @param matchResult The `BoundedMatchResult` to construct the `SettlementObligation`s from
    /// @param externalInputAmount From internal party's perspective, this is the output amount of the match.
    /// @return obligation0 The first `SettlementObligation`
    /// @return obligation1 The second `SettlementObligation`
    function buildObligations(
        BoundedMatchResult memory matchResult,
        uint256 externalInputAmount
    )
        internal
        pure
        returns (SettlementObligation memory obligation0, SettlementObligation memory obligation1)
    {
        // `externalInputAmount`, from the perspective of the internal party, is the output amount of the match.
        // So we divide by the price (outToken/inToken) to get the input amount for the internal party.
        uint256 internalInputAmount = FixedPointLib.divIntegerByFixedPoint(externalInputAmount, matchResult.price);

        // TODO: Dynamically determine internal / external party index based on settlement bundles in
        // `settleExternalMatch`
        // For now, obligation0 corresponds to the external party and obligation1 corresponds to the internal party.
        obligation0 = SettlementObligation({
            inputToken: matchResult.outputToken,
            outputToken: matchResult.inputToken,
            amountIn: externalInputAmount,
            amountOut: internalInputAmount
        });
        obligation1 = SettlementObligation({
            inputToken: matchResult.inputToken,
            outputToken: matchResult.outputToken,
            amountIn: internalInputAmount,
            amountOut: externalInputAmount
        });
        return (obligation0, obligation1);
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
