/// SPDX-License-Identifier: Apache
pragma solidity ^0.8.24;

import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";

// --------------------
// | Obligation Types |
// --------------------

/// @notice The settlement obligation bundle for a user
/// @dev This data represents the following based on the obligation type:
/// 1. *Public Obligation*: A plaintext settlement obligation
/// 2. TODO: Add private obligation data here
struct ObligationBundle {
    /// @dev The type of obligation
    ObligationType obligationType;
    /// @dev The data validating the obligation
    bytes data;
}

/// @notice The types of obligations possible in the darkpool
enum ObligationType {
    PUBLIC,
    PRIVATE
}

/// @title Obligation Library
/// @author Renegade Eng
/// @notice Library for decoding and hashing obligation data
library ObligationLib {
    /// @notice The error type emitted when an obligation type check fails
    error InvalidObligationType();

    /// @notice Decode a public obligation
    /// @param bundle The obligation bundle to decode
    /// @return obligation The decoded obligation
    function decodePublicObligation(ObligationBundle calldata bundle)
        internal
        pure
        returns (SettlementObligation memory obligation)
    {
        require(bundle.obligationType == ObligationType.PUBLIC, InvalidObligationType());
        obligation = abi.decode(bundle.data, (SettlementObligation));
    }
}
