// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {BN254} from "solidity-bn254/BN254.sol";

import {TestUtils} from "./utils/TestUtils.sol";
import {Verifier} from "../src/verifier/Verifier.sol";
import {PlonkProof, NUM_WIRE_TYPES} from "../src/verifier/Types.sol";

contract VerifierTest is TestUtils {
    Verifier public verifier;
    TestUtils public testUtils;

    function setUp() public {
        verifier = new Verifier();
    }

    /// @notice Test that the verifier properly validates all inputs in step 1 of Plonk verification
    function testMalformedInputs() public {
        // Create a valid scalar and EC point to use as a base
        BN254.G1Point memory validPoint = BN254.P1();
        BN254.G1Point memory invalidPoint = BN254.G1Point({x: BN254.BaseField.wrap(42), y: BN254.BaseField.wrap(0)});
        BN254.ScalarField validScalar = BN254.ScalarField.wrap(1);
        BN254.ScalarField invalidScalar = BN254.ScalarField.wrap(BN254.R_MOD);

        // Create fixed-size arrays
        BN254.G1Point[NUM_WIRE_TYPES] memory wire_comms;
        BN254.G1Point[NUM_WIRE_TYPES] memory quotient_comms;
        BN254.ScalarField[NUM_WIRE_TYPES] memory wire_evals;
        BN254.ScalarField[NUM_WIRE_TYPES - 1] memory sigma_evals;

        // Fill arrays with valid values
        for (uint256 i = 0; i < NUM_WIRE_TYPES; i++) {
            wire_comms[i] = validPoint;
            quotient_comms[i] = validPoint;
            wire_evals[i] = validScalar;
            if (i < NUM_WIRE_TYPES - 1) {
                sigma_evals[i] = validScalar;
            }
        }

        PlonkProof memory proof = PlonkProof({
            wire_comms: wire_comms,
            z_comm: validPoint,
            quotient_comms: quotient_comms,
            w_zeta: validPoint,
            w_zeta_omega: validPoint,
            wire_evals: wire_evals,
            sigma_evals: sigma_evals,
            z_bar: validScalar
        });

        // Test Case 1: Invalid wire commitment
        uint256 invalidIdx = randomUint(NUM_WIRE_TYPES);
        proof.wire_comms[invalidIdx] = invalidPoint;
        vm.expectRevert();
        verifier.verify(proof);
        proof.wire_comms[invalidIdx] = validPoint; // Reset

        // Test Case 2: Invalid z commitment
        invalidIdx = randomUint(NUM_WIRE_TYPES);
        proof.z_comm = invalidPoint;
        vm.expectRevert();
        verifier.verify(proof);
        proof.z_comm = validPoint; // Reset

        // Test Case 3: Invalid quotient commitment
        invalidIdx = randomUint(NUM_WIRE_TYPES);
        proof.quotient_comms[invalidIdx] = invalidPoint;
        vm.expectRevert();
        verifier.verify(proof);
        proof.quotient_comms[invalidIdx] = validPoint; // Reset

        // Test Case 4: Invalid w_zeta
        invalidIdx = randomUint(NUM_WIRE_TYPES);
        proof.w_zeta = invalidPoint;
        vm.expectRevert();
        verifier.verify(proof);
        proof.w_zeta = validPoint; // Reset

        // Test Case 5: Invalid w_zeta_omega
        invalidIdx = randomUint(NUM_WIRE_TYPES);
        proof.w_zeta_omega = invalidPoint;
        vm.expectRevert();
        verifier.verify(proof);
        proof.w_zeta_omega = validPoint; // Reset

        // Test Case 6: Invalid wire evaluation
        invalidIdx = randomUint(NUM_WIRE_TYPES);
        proof.wire_evals[invalidIdx] = invalidScalar;
        vm.expectRevert();
        verifier.verify(proof);
        proof.wire_evals[invalidIdx] = validScalar; // Reset

        // Test Case 7: Invalid sigma evaluation
        invalidIdx = randomUint(NUM_WIRE_TYPES - 1);
        proof.sigma_evals[invalidIdx] = invalidScalar;
        vm.expectRevert();
        verifier.verify(proof);
        proof.sigma_evals[invalidIdx] = validScalar; // Reset

        // Test Case 8: Invalid z_bar
        invalidIdx = randomUint(NUM_WIRE_TYPES);
        proof.z_bar = invalidScalar;
        vm.expectRevert();
        verifier.verify(proof);
        proof.z_bar = validScalar; // Reset
    }
}
