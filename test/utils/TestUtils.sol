// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";

contract TestUtils is Test {
    /// @dev The BN254 field modulus from roundUtils.huff
    uint256 constant PRIME = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    /// @dev Generates a random input modulo the PRIME
    /// Note that this is not uniformly distributed over the prime field, because of the "wraparound"
    /// but it suffices for fuzzing test inputs
    function randomFelt() internal returns (uint256) {
        return vm.randomUint() % PRIME;
    }
}
