// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { BoundedMatchResult, BoundedMatchResultLib } from "darkpoolv2-types/BoundedMatchResult.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { SignatureWithNonce } from "darkpoolv2-types/settlement/IntentBundle.sol";
import { FeeRate } from "darkpoolv2-types/Fee.sol";
import { SettlementTestUtils } from "../SettlementTestUtils.sol";

contract ExternalMatchTestUtils is SettlementTestUtils {
    using BoundedMatchResultLib for BoundedMatchResult;
    using FixedPointLib for FixedPoint;

    // ---------
    // | Utils |
    // ---------

    // --- Bounded Match Result --- //

    /// @dev Create executor signature for bounded match
    /// @param feeRate The relayer fee rate
    /// @param matchResult The bounded match result
    /// @param signerPrivateKey The private key to sign with
    /// @return The executor signature
    function createBoundedMatchExecutorSignature(
        FeeRate memory feeRate,
        BoundedMatchResult memory matchResult,
        uint256 signerPrivateKey
    )
        internal
        returns (SignatureWithNonce memory)
    {
        // Use the calldata version via external call for memory-to-calldata conversion
        return this._createBoundedMatchExecutorSignatureCalldata(feeRate, matchResult, signerPrivateKey);
    }

    /// @dev Create executor signature for bounded match (calldata version)
    function _createBoundedMatchExecutorSignatureCalldata(
        FeeRate memory feeRate,
        BoundedMatchResult calldata matchResult,
        uint256 signerPrivateKey
    )
        external
        returns (SignatureWithNonce memory)
    {
        bytes memory encoded = abi.encode(feeRate, matchResult);
        bytes32 digest = EfficientHashLib.hash(encoded);

        uint256 nonce = randomUint();
        bytes32 signatureHash = EfficientHashLib.hash(digest, bytes32(nonce), bytes32(block.chainid));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, signatureHash);
        return SignatureWithNonce({ nonce: nonce, signature: abi.encodePacked(r, s, v) });
    }

    /// @dev Create a bounded match result authorization for a given obligation
    /// @param obligation The obligation to create the bounded match result for
    /// @param price The price of the obligation (inToken/outToken)
    /// @return matchResult The bounded match result
    function createBoundedMatchResultForObligation(
        SettlementObligation memory obligation,
        FixedPoint memory price
    )
        internal
        view
        returns (BoundedMatchResult memory matchResult)
    {
        uint256 minInternalPartyAmountIn = 0;
        uint256 maxInternalPartyAmountIn = obligation.amountIn;
        uint256 blockDeadline = block.number + 100;
        matchResult = BoundedMatchResult({
            internalPartyInputToken: obligation.inputToken,
            internalPartyOutputToken: obligation.outputToken,
            price: price,
            minInternalPartyAmountIn: minInternalPartyAmountIn,
            maxInternalPartyAmountIn: maxInternalPartyAmountIn,
            blockDeadline: blockDeadline
        });

        return matchResult;
    }

    // --- External Match Helpers --- //

    /// @dev Generate a random external party amount in and expected amount out
    /// @param externalObligation The external party's obligation to generate the amount in for
    /// @param price The price of the obligation (inToken/outToken)
    /// @return externalPartyAmountIn The random external party amount in
    /// @return externalPartyAmountOut The expected amount out for the external party
    function randomExternalPartyAmountIn(
        SettlementObligation memory externalObligation,
        FixedPoint memory price
    )
        internal
        returns (uint256 externalPartyAmountIn, uint256 externalPartyAmountOut)
    {
        externalPartyAmountIn = vm.randomUint(0, externalObligation.amountIn);
        externalPartyAmountOut = FixedPointLib.divIntegerByFixedPoint(externalPartyAmountIn, price);
    }

    /// @dev Build obligations from a bounded match result and external party amount in
    /// @param matchResult The bounded match result to build obligations from
    /// @param externalPartyAmountIn The external party amount in
    /// @return externalObligation The external party obligation
    /// @return internalObligation The internal party obligation
    function buildObligationsFromMatchResult(
        BoundedMatchResult memory matchResult,
        uint256 externalPartyAmountIn
    )
        internal
        view
        returns (SettlementObligation memory externalObligation, SettlementObligation memory internalObligation)
    {
        // Use the calldata version via external call for memory-to-calldata conversion
        return this._buildObligationsFromMatchResultCalldata(matchResult, externalPartyAmountIn);
    }

    /// @dev Build obligations from a bounded match result (calldata version)
    function _buildObligationsFromMatchResultCalldata(
        BoundedMatchResult calldata matchResult,
        uint256 externalPartyAmountIn
    )
        external
        view
        returns (SettlementObligation memory externalObligation, SettlementObligation memory internalObligation)
    {
        return BoundedMatchResultLib.buildObligations(matchResult, externalPartyAmountIn);
    }
}
