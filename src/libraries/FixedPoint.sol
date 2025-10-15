// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice A fixed point representation of a real number
/// @dev The precision used is specified in `DarkpoolConstants.FIXED_POINT_PRECISION_BITS`
/// @dev The real number represented is `repr / 2^{FIXED_POINT_PRECISION_BITS}`
struct FixedPoint {
    /// @dev The representation of the number
    uint256 repr;
}

/// @title FixedPointLib
/// @author Renegade Eng
/// @notice A library for fixed point math
library FixedPointLib {
    /// @notice The fixed point precision used in the darkpool
    /// @dev This implies that the representation of a real number is floor(x * 2^{FIXED_POINT_PRECISION})
    uint256 internal constant FIXED_POINT_PRECISION_BITS = 63;

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
        /// forge-lint: disable-next-line(incorrect-shift)
        return (self.repr * scalar) / (1 << FIXED_POINT_PRECISION_BITS);
    }
}
