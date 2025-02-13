// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {TestUtils} from "./utils/TestUtils.sol";
import {BN254} from "solidity-bn254/BN254.sol";
import {BN254Helpers} from "../src/verifier/BN254Helpers.sol";
import {console2} from "forge-std/console2.sol";

contract BN254HelpersTest is TestUtils {
    struct RootOfUnityTest {
        uint256 powerOfTwo;
        BN254.ScalarField expectedRoot;
    }

    /// @notice Test the root of unity function
    function testRootOfUnity() public {
        RootOfUnityTest[] memory testCases = new RootOfUnityTest[](6);

        // Test case for n = 2^1
        testCases[0] = RootOfUnityTest({
            powerOfTwo: 1,
            expectedRoot: BN254.ScalarField.wrap(
                21888242871839275222246405745257275088548364400416034343698204186575808495616
            )
        });

        // Test case for n = 2
        testCases[1] = RootOfUnityTest({
            powerOfTwo: 2,
            expectedRoot: BN254.ScalarField.wrap(
                21888242871839275217838484774961031246007050428528088939761107053157389710902
            )
        });

        // Test case for n = 4
        testCases[2] = RootOfUnityTest({
            powerOfTwo: 4,
            expectedRoot: BN254.ScalarField.wrap(
                14940766826517323942636479241147756311199852622225275649687664389641784935947
            )
        });

        // Test case for n = 8
        testCases[3] = RootOfUnityTest({
            powerOfTwo: 8,
            expectedRoot: BN254.ScalarField.wrap(
                3478517300119284901893091970156912948790432420133812234316178878452092729974
            )
        });

        // Test case for n = 2^16
        testCases[4] = RootOfUnityTest({
            powerOfTwo: 16,
            expectedRoot: BN254.ScalarField.wrap(
                421743594562400382753388642386256516545992082196004333756405989743524594615
            )
        });

        // Test case for n = 2^20
        testCases[5] = RootOfUnityTest({
            powerOfTwo: 20,
            expectedRoot: BN254.ScalarField.wrap(
                17220337697351015657950521176323262483320249231368149235373741788599650842711
            )
        });

        // Run test cases
        for (uint256 i = 0; i < testCases.length; i++) {
            RootOfUnityTest memory tc = testCases[i];
            uint256 n = 1 << tc.powerOfTwo;
            BN254.ScalarField result = BN254Helpers.rootOfUnity(n);
            assertEq(
                BN254.ScalarField.unwrap(result),
                BN254.ScalarField.unwrap(tc.expectedRoot),
                string.concat("Root of unity test failed for n=", vm.toString(n))
            );
        }
    }
}
