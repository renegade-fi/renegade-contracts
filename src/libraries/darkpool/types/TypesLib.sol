// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";
import { ExternalTransfer, DepositWitness } from "./Transfers.sol";
import { EncryptionKey } from "./Ciphertext.sol";
import { OrderSettlementIndices, ExternalMatchResult, BoundedMatchResult } from "./Settlement.sol";
import { FeeTake, FeeTakeRate } from "./Fees.sol";
import { ExternalMatchDirection } from "./Settlement.sol";
import { DarkpoolConstants } from "renegade-lib/darkpool/Constants.sol";

// This file contains helpers for darkpool types

/// @dev The type hash for the DepositWitness struct
bytes32 constant DEPOSIT_WITNESS_TYPEHASH = keccak256("DepositWitness(uint256[4] pkRoot)");
/// @dev The type string for the DepositWitness struct
/// @dev We must include the `TokenPermission` type encoding as well as this is concatenated with
/// @dev the `PermitWitnessTransferFrom` type encoding stub of the form:
/// @dev `PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,`
/// @dev So we must prepare our type string to concatenate to the entire type encoding
/// @dev See:
/// https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/libraries/PermitHash.sol#L31-L32
string constant DEPOSIT_WITNESS_TYPE_STRING =
    "DepositWitness witness)DepositWitness(uint256[4] pkRoot)TokenPermissions(address token,uint256 amount)";

/// @notice A fixed point representation of a real number
/// @dev The precision used is specified in `DarkpoolConstants.FIXED_POINT_PRECISION_BITS`
/// @dev The real number represented is `repr / 2^{FIXED_POINT_PRECISION_BITS}`
struct FixedPoint {
    /// @dev The representation of the number
    uint256 repr;
}

/// @title TypesLib
/// @notice A library that allows us to define function on types in the darkpool
library TypesLib {
    // --- Fixed Point --- //

    /// @notice Wrap a uint256 into a FixedPoint
    /// @param x The uint256 to wrap
    /// @return A FixedPoint with the given representation
    function wrap(uint256 x) public pure returns (FixedPoint memory) {
        return FixedPoint({ repr: x });
    }

    /// @notice Multiply a fixed point by a scalar and return the truncated result
    /// @dev Computes `(self.repr * scalar) / DarkpoolConstants.FIXED_POINT_PRECISION_BITS`
    /// @dev The repr already has the fixed point scaling value, so we only need to undo the
    /// @dev scaling once to get the desired result. Because division naturally truncates in
    /// @dev Solidity, we can use this will implement the floor of the above division.
    /// @dev This function is unsafe because it does not check for overflows
    /// @param self The fixed point to multiply
    /// @param scalar The scalar to multiply by
    /// @return The truncated result of the multiplication
    function unsafeFixedPointMul(FixedPoint memory self, uint256 scalar) public pure returns (uint256) {
        return (self.repr * scalar) / (1 << DarkpoolConstants.FIXED_POINT_PRECISION_BITS);
    }

    // --- External Transfers --- //

    /// @notice Checks if an ExternalTransfer has zero values
    /// @param transfer The ExternalTransfer to check
    /// @return True if the amount is zero
    function isZero(ExternalTransfer memory transfer) public pure returns (bool) {
        return transfer.amount == 0;
    }

    /// @notice Computes the EIP-712 hash of a DepositWitness
    /// @param witness The DepositWitness to hash
    /// @return The EIP-712 hash of the DepositWitness
    function hashWitness(DepositWitness memory witness) public pure returns (bytes32) {
        // Hash the struct data according to EIP-712
        bytes32 pkRootHash = keccak256(abi.encode(witness.pkRoot));
        return keccak256(abi.encode(DEPOSIT_WITNESS_TYPEHASH, pkRootHash));
    }

    // --- Order Settlement Indices --- //

    /// @notice Return whether two sets of indices are equal
    /// @param a The first set of indices
    /// @param b The second set of indices
    /// @return True if the indices are equal, false otherwise
    function indicesEqual(
        OrderSettlementIndices memory a,
        OrderSettlementIndices memory b
    )
        public
        pure
        returns (bool)
    {
        return a.balanceSend == b.balanceSend && a.balanceReceive == b.balanceReceive && a.order == b.order;
    }

    // --- Match Settlement --- //

    /// @notice Return the sell mint and amount for the external party
    function externalPartySellMintAmount(ExternalMatchResult memory matchResult)
        public
        pure
        returns (address, uint256)
    {
        if (matchResult.direction == ExternalMatchDirection.InternalPartyBuy) {
            return (matchResult.baseMint, matchResult.baseAmount);
        } else {
            return (matchResult.quoteMint, matchResult.quoteAmount);
        }
    }

    /// @notice Return the buy mint and amount for the external party
    function externalPartyBuyMintAmount(ExternalMatchResult memory matchResult)
        public
        pure
        returns (address, uint256)
    {
        if (matchResult.direction == ExternalMatchDirection.InternalPartyBuy) {
            return (matchResult.quoteMint, matchResult.quoteAmount);
        } else {
            return (matchResult.baseMint, matchResult.baseAmount);
        }
    }

    /// @notice Build an `ExternalMatchResult` from a `BoundedMatchResult`
    /// @param baseAmount The base amount of the match, resolving in between the bounds
    /// @param boundedMatchResult The `BoundedMatchResult` to build the `ExternalMatchResult` from
    /// @return The `ExternalMatchResult`
    function buildExternalMatchResult(
        uint256 baseAmount,
        BoundedMatchResult memory boundedMatchResult
    )
        public
        pure
        returns (ExternalMatchResult memory)
    {
        // Verify that the base amount is within the bounds
        if (baseAmount < boundedMatchResult.minBaseAmount || baseAmount > boundedMatchResult.maxBaseAmount) {
            revert("base amount is out of `BoundedMatchResult` bounds");
        }

        // Use the price to compute the quote amount
        // SAFETY: Prices are constrained in-circuit to be less than 2^127 and all amounts
        // are constrained to be less than 2^100, so the product is less than 2^227, which fits
        // in a uint256
        FixedPoint memory price = boundedMatchResult.price;
        uint256 quoteAmount = unsafeFixedPointMul(price, baseAmount);

        // Build the external match result
        return ExternalMatchResult({
            quoteMint: boundedMatchResult.quoteMint,
            baseMint: boundedMatchResult.baseMint,
            quoteAmount: quoteAmount,
            baseAmount: baseAmount,
            direction: boundedMatchResult.direction
        });
    }

    // --- Fees --- //

    /// @notice Return the total fees due on a fee take
    /// @param feeTake The fee take to compute the total fees for
    /// @return The total fees due
    function total(FeeTake memory feeTake) public pure returns (uint256) {
        return feeTake.relayerFee + feeTake.protocolFee;
    }

    /// @notice Compute a fee take from a set of fee rates and receive amount
    /// @param feeRates The fee rates to compute the fee take from
    /// @param receiveAmount The amount to compute the fee take for
    /// @return The fee take
    function computeFeeTake(FeeTakeRate memory feeRates, uint256 receiveAmount) public pure returns (FeeTake memory) {
        // SAFETY: The fee rates are constrained in-circuit to be less than 2^63, and the receive amount
        // is constrained to be less than 2^100, so the product is less than 2^163, which fits in a uint256
        return FeeTake({
            relayerFee: unsafeFixedPointMul(feeRates.relayerFeeRate, receiveAmount),
            protocolFee: unsafeFixedPointMul(feeRates.protocolFeeRate, receiveAmount)
        });
    }

    // --- Encryption --- //

    /// @notice Check whether two encryption keys are equal
    /// @param a The first encryption key
    /// @param b The second encryption key
    /// @return Whether the keys are equal
    function encryptionKeyEqual(EncryptionKey memory a, EncryptionKey memory b) public pure returns (bool) {
        bool xEqual = BN254.ScalarField.unwrap(a.point.x) == BN254.ScalarField.unwrap(b.point.x);
        bool yEqual = BN254.ScalarField.unwrap(a.point.y) == BN254.ScalarField.unwrap(b.point.y);
        return xEqual && yEqual;
    }
}
