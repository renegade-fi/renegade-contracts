// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {BN254} from "solidity-bn254/BN254.sol";
import {console2} from "forge-std/console2.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";

/// @title Helper functions for BN254 curve operations
/// @notice This library contains utility functions for working with the BN254 curve
library BN254Helpers {
    /// @dev One in the scalar field
    BN254.ScalarField constant ONE = BN254.ScalarField.wrap(1);
    /// @dev Negative one in the scalar field
    BN254.ScalarField constant NEG_ONE = BN254.ScalarField.wrap(BN254.R_MOD - 1);

    /// @dev The 2-adicity of the BN254 scalar field's modulus
    uint256 constant SCALAR_FIELD_TWO_ADICITY = 28;
    /// @dev The 2-adic root of unity for the BN254 scalar field
    BN254.ScalarField constant TWO_ADIC_ROOT =
        BN254.ScalarField.wrap(19103219067921713944291392827692070036145651957329286315305642004821462161904);

    /// @dev Compute the nth root of unity for the BN254 scalar field
    /// @param n The exponent, assumed to be a power of 2
    /// @return The nth root of unity
    function rootOfUnity(uint256 n) internal pure returns (BN254.ScalarField) {
        uint256 log2n = Math.log2(n);

        // Compute the nth root from the base
        uint256 p = BN254.R_MOD;
        uint256 root = BN254.ScalarField.unwrap(TWO_ADIC_ROOT);
        assembly {
            for { let i := log2n } lt(i, SCALAR_FIELD_TWO_ADICITY) { i := add(i, 1) } { root := mulmod(root, root, p) }
        }

        return BN254.ScalarField.wrap(root);
    }

    /// @dev Compute the fifth power of a scalar field element
    /// @param a The scalar field element to raise to the fifth power
    /// @return The fifth power of the scalar field element
    function fifthPower(BN254.ScalarField a) internal pure returns (BN254.ScalarField) {
        BN254.ScalarField a2 = BN254.mul(a, a);
        BN254.ScalarField a4 = BN254.mul(a2, a2);
        BN254.ScalarField a5 = BN254.mul(a4, a);
        return a5;
    }
}
