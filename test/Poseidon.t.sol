// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {HuffDeployer} from "foundry-huff/HuffDeployer.sol";

contract PoseidonTest is Test {
    /// @dev The Poseidon main contract
    PoseidonSuite public poseidonSuite;

    /// @dev The BN254 field modulus from roundUtils.huff
    uint256 PRIME = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    /// @dev The round constant used in testing
    uint256 TEST_RC1 = 0x1337;
    /// @dev The second round constant used in testing
    uint256 TEST_RC2 = 0x1338;
    /// @dev The third round constant used in testing
    uint256 TEST_RC3 = 0x1339;

    /// @dev Deploy the PoseidonSuite contract
    function setUp() public {
        poseidonSuite = PoseidonSuite(HuffDeployer.deploy("../test/huff/testPoseidonUtils"));
    }

    /// @dev Test the sbox function applied to a single input
    function testSboxSingle() public {
        uint256 testValue = vm.randomUint();
        uint256 result = poseidonSuite.testSboxSingle(testValue);

        // Calculate expected x^5 mod p
        uint256 expected = fifthPower(testValue);
        assertEq(result, expected, "Expected result to match x^5 mod p");
    }

    /// @dev Test the add round constant function applied to a single input
    function testAddRcSingle() public {
        uint256 testValue = vm.randomUint();
        uint256 result = poseidonSuite.testAddRc(testValue);
        uint256 expected = addmod(testValue, TEST_RC1, PRIME);
        assertEq(result, expected, "Expected result to match x + RC mod p");
    }

    /// @dev Test the internal MDS function applied to a single input
    /// The internal MDS adds the sum of the elements to each element
    function testInternalMds() public {
        uint256 a = vm.randomUint();
        uint256 b = vm.randomUint();
        uint256 c = vm.randomUint();
        (uint256 a1, uint256 b1, uint256 c1) = poseidonSuite.testInternalMds(a, b, c);

        // Calculate the expected results
        (uint256 expectedA, uint256 expectedB, uint256 expectedC) = internalMds(a, b, c);
        assertEq(a1, expectedA, "Expected result to match a + sum mod p");
        assertEq(b1, expectedB, "Expected result to match b + sum mod p");
        assertEq(c1, expectedC, "Expected result to match c + sum mod p");
    }

    /// @dev Test the external MDS function applied to a trio of inputs
    function testExternalMds() public {
        uint256 a = vm.randomUint();
        uint256 b = vm.randomUint();
        uint256 c = vm.randomUint();
        (uint256 a1, uint256 b1, uint256 c1) = poseidonSuite.testExternalMds(a, b, c);

        // Calculate the expected results
        (uint256 expectedA, uint256 expectedB, uint256 expectedC) = externalMds(a, b, c);
        assertEq(a1, expectedA, "Expected result to match a + sum mod p");
        assertEq(b1, expectedB, "Expected result to match b + sum mod p");
        assertEq(c1, expectedC, "Expected result to match c + sum mod p");
    }

    /// --- Helpers --- ///

    /// @dev Calculate the fifth power of an input
    function fifthPower(uint256 x) internal view returns (uint256) {
        uint256 x2 = mulmod(x, x, PRIME);
        uint256 x4 = mulmod(x2, x2, PRIME);
        return mulmod(x, x4, PRIME);
    }

    /// @dev Calculate the result of the internal MDS matrix applied to the inputs
    function internalMds(uint256 a, uint256 b, uint256 c) internal view returns (uint256, uint256, uint256) {
        uint256 sum = sumInputs(a, b, c);
        uint256 a1 = addmod(a, sum, PRIME);
        uint256 b1 = addmod(b, sum, PRIME);
        uint256 c1 = addmod(addmod(c, sum, PRIME), c, PRIME); // c is doubled
        return (a1, b1, c1);
    }

    /// @dev Calculate the result of the external MDS matrix applied to the inputs
    function externalMds(uint256 a, uint256 b, uint256 c) internal view returns (uint256, uint256, uint256) {
        uint256 sum = sumInputs(a, b, c);
        uint256 a1 = addmod(a, sum, PRIME);
        uint256 b1 = addmod(b, sum, PRIME);
        uint256 c1 = addmod(c, sum, PRIME);
        return (a1, b1, c1);
    }

    /// @dev Sum the inputs and return the result
    function sumInputs(uint256 a, uint256 b, uint256 c) internal view returns (uint256) {
        uint256 sum = addmod(a, b, PRIME);
        sum = addmod(sum, c, PRIME);
        return sum;
    }
}

interface PoseidonSuite {
    function testSboxSingle(uint256) external returns (uint256);
    function testAddRc(uint256) external returns (uint256);
    function testInternalMds(uint256, uint256, uint256) external returns (uint256, uint256, uint256);
    function testExternalMds(uint256, uint256, uint256) external returns (uint256, uint256, uint256);
    function testExternalRound(uint256, uint256, uint256) external returns (uint256, uint256, uint256);
}
