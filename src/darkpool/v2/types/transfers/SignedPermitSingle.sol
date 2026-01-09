// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IAllowanceTransfer } from "permit2-lib/interfaces/IAllowanceTransfer.sol";

/// @notice A Permit2 PermitSingle bundled with its EIP-712 signature
/// @dev Used to register a Permit2 allowance during settlement of a ring 0 intent.
/// See: https://docs.uniswap.org/contracts/permit2/reference/allowance-transfer
struct SignedPermitSingle {
    /// @dev The Permit2 PermitSingle struct containing permit details, spender, and deadline
    IAllowanceTransfer.PermitSingle permitSingle;
    /// @dev The EIP-712 signature over the PermitSingle struct
    bytes signature;
}

/// @title SignedPermitSingleLib
/// @author Renegade Eng
/// @notice Library for SignedPermitSingle operations
library SignedPermitSingleLib {
    /// @notice Check if permit data is provided
    /// @dev A zero-length signature indicates no permit data exists
    /// @param data The permit data to check
    /// @return True if permit data exists (has a signature)
    function exists(SignedPermitSingle memory data) internal pure returns (bool) {
        return data.signature.length > 0;
    }
}
