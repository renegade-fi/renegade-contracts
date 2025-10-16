// SPDX-License-Identifier: Apache
pragma solidity ^0.8.24;

import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

/// @notice A settlement obligation for a user
struct SettlementObligation {
    /// @dev The input token address
    address inputToken;
    /// @dev The output token address
    address outputToken;
    /// @dev The amount of the input token to trade
    uint256 amountIn;
    /// @dev The amount of the output token to receive, before fees
    uint256 amountOut;
}

/// @title Settlement Obligation Library
/// @author Renegade Eng
/// @notice Library for settlement obligation operations
library SettlementObligationLib {
    /// @notice Compute the obligation hash for a given settlement obligation
    /// @param obligation The settlement obligation to compute the hash for
    /// @return The hash of the obligation
    function computeObligationHash(SettlementObligation memory obligation) internal pure returns (bytes32) {
        bytes memory obligationBytes = abi.encode(obligation);
        return EfficientHashLib.hash(obligationBytes);
    }
}
